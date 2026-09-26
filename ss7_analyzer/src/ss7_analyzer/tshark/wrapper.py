"""Hardened subprocess wrapper for tshark execution.

Guarantees:
- shell=False is always used (never shell=True)
- Commands must be list[str] with cmd[0] == 'tshark'
- Timeout enforced on every call
- Exponential backoff retry (max 3 attempts)
- stderr captured separately and truncated for logging
"""

from __future__ import annotations

import shutil
import subprocess
import time
from typing import Optional

from ..core.logging import get_logger

logger = get_logger(__name__)


class TsharkError(Exception):
    """Raised when tshark execution fails."""
    pass


class TsharkNotFoundError(TsharkError):
    """Raised when the tshark binary is not found on the system."""
    pass


class TsharkWrapper:
    """Hardened wrapper around the tshark command-line tool."""

    def __init__(
        self,
        binary: str = "tshark",
        timeout: int = 60,
        max_retries: int = 3,
    ):
        self.binary = binary
        self.timeout = timeout
        self.max_retries = max_retries
        self._binary_checked = False

    def _ensure_binary(self) -> None:
        """Verify tshark binary exists (checked once per session)."""
        if self._binary_checked:
            return
        if shutil.which(self.binary) is None:
            raise TsharkNotFoundError(
                f"tshark binary '{self.binary}' not found. "
                "Install with: sudo apt install tshark"
            )
        self._binary_checked = True

    def execute(
        self,
        cmd: list[str],
        input_data: Optional[bytes] = None,
    ) -> str:
        """Execute a tshark command with hardened safeguards.

        Args:
            cmd: Command as a list of strings. Must start with 'tshark'.
            input_data: Optional stdin data.

        Returns:
            tshark stdout as a string.

        Raises:
            TsharkError: If execution fails after all retries.
            TsharkNotFoundError: If tshark is not installed.
            ValueError: If command structure is invalid.
        """
        # Validate command structure
        if not isinstance(cmd, list):
            raise ValueError("Command must be a list of strings")
        if not cmd:
            raise ValueError("Command list is empty")
        if cmd[0] != "tshark":
            raise ValueError(f"Only tshark commands allowed, got: {cmd[0]}")

        self._ensure_binary()

        # Replace cmd[0] with full binary path if needed
        full_cmd = list(cmd)
        full_cmd[0] = self.binary

        last_error: Optional[str] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(
                    "executing_tshark",
                    attempt=attempt,
                    max_retries=self.max_retries,
                    cmd_len=len(full_cmd),
                )

                # CRITICAL: shell=False is hardcoded
                result = subprocess.run(
                    full_cmd,
                    input=input_data,
                    capture_output=True,
                    timeout=self.timeout,
                    shell=False,  # NEVER set to True
                    text=False,
                )

                if result.returncode != 0:
                    stderr_str = result.stderr.decode("utf-8", errors="replace")
                    last_error = stderr_str[:500]
                    logger.warning(
                        "tshark_nonzero_return",
                        returncode=result.returncode,
                        stderr=last_error,
                        attempt=attempt,
                    )
                    if attempt < self.max_retries:
                        time.sleep(2 ** attempt)
                        continue
                    raise TsharkError(f"tshark failed (rc={result.returncode}): {last_error}")

                stdout_str = result.stdout.decode("utf-8", errors="replace")
                logger.info(
                    "tshark_success",
                    attempt=attempt,
                    stdout_bytes=len(stdout_str),
                )
                return stdout_str

            except subprocess.TimeoutExpired:
                logger.error(
                    "tshark_timeout",
                    timeout=self.timeout,
                    attempt=attempt,
                )
                last_error = f"timeout after {self.timeout}s"
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)
                    continue
                raise TsharkError(last_error)

            except FileNotFoundError as e:
                raise TsharkNotFoundError(str(e))

        raise TsharkError(f"tshark failed after {self.max_retries} attempts: {last_error}")

    def execute_fields(
        self,
        pcap_path: str,
        filter_expr: str,
        fields: list[str],
    ) -> str:
        """Execute tshark with field extraction (-T fields mode).

        Args:
            pcap_path: Path to the .pcap file.
            filter_expr: Display filter (already sanitized).
            fields: List of tshark -e field names to extract.

        Returns:
            Tab-separated tshark output.
        """
        cmd: list[str] = [
            "tshark",
            "-r", pcap_path,
            "-Y", filter_expr,
            "-T", "fields",
        ]
        for field in fields:
            cmd.extend(["-e", field])

        return self.execute(cmd)

    def write_subcapture(
        self,
        pcap_path: str,
        filter_expr: str,
        output_path: str,
    ) -> str:
        """Execute tshark to write a filtered sub-capture file.

        Args:
            pcap_path: Source .pcap file.
            filter_expr: Display filter (already sanitized).
            output_path: Path for the output .pcap file.

        Returns:
            tshark stderr/stdout output.
        """
        cmd: list[str] = [
            "tshark",
            "-r", pcap_path,
            "-Y", filter_expr,
            "-w", output_path,
        ]
        return self.execute(cmd)

    def check_available(self) -> bool:
        """Check if tshark is available without raising."""
        try:
            self._ensure_binary()
            return True
        except TsharkNotFoundError:
            return False
