"""Input sanitizers for injection prevention and path traversal blocking.

Multi-layer defense:
1. tshark filter sandbox (whitelist tokenizer + regex blocklist)
2. File path sanitization (realpath + base_dir containment)
3. Field validators (IMSI, GT, MSISDN, port)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..core.logging import get_logger

logger = get_logger(__name__)

# --- tshark filter sandbox ---

TSHARK_ALLOWED_OPERATORS = {
    "==", "!=", "<", ">", "<=", ">=",
    "and", "or", "not", "in",
    "(", ")", "[", "]", ".", ":",
}

TSHARK_DANGEROUS_PATTERNS = [
    r";\s*(rm|del|exec|system|fork|cat|sh|bash)",  # Command injection
    r"\$\{.*\}",                                     # Variable expansion
    r"`.*`",                                          # Backtick execution
    r"\|\s*[a-z]",                                    # Pipe to commands
    r">\s*/",                                         # File redirection
    r"&\s*[a-z]",                                     # Background execution
    r"\n",                                            # Newline injection
]

# Max filter length
MAX_FILTER_LENGTH = 500


def sanitize_tshark_filter(user_filter: str) -> str:
    """Validate and sanitize a custom tshark filter expression.

    Strategy:
    1. Reject non-string input.
    2. Enforce max length (500 chars).
    3. Scan for dangerous shell patterns.
    4. Tokenize and validate against a whitelist.
    5. Reject any token outside the allowed set.

    Args:
        user_filter: Raw user-provided filter string.

    Returns:
        The sanitized filter string.

    Raises:
        ValueError: If the filter fails validation.
    """
    if not isinstance(user_filter, str):
        raise ValueError("Filter must be a string")

    if len(user_filter) > MAX_FILTER_LENGTH:
        raise ValueError(f"Filter exceeds max length ({MAX_FILTER_LENGTH} chars)")

    # Check for dangerous patterns
    for pattern in TSHARK_DANGEROUS_PATTERNS:
        if re.search(pattern, user_filter, re.IGNORECASE):
            logger.warning("dangerous_filter_pattern", pattern=pattern)
            raise ValueError(f"Filter contains potentially dangerous pattern: {pattern}")

    # Tokenize: split on whitespace but keep operators
    tokens = re.findall(r'\S+|[()[\]:]', user_filter)

    for token in tokens:
        token_lower = token.lower()
        is_allowed = (
            token in TSHARK_ALLOWED_OPERATORS
            or token_lower in TSHARK_ALLOWED_OPERATORS
            # Protocol/field names: lowercase letters, digits, dots, underscores
            or re.match(r'^[a-z_][a-z0-9_.]*$', token_lower)
            # Quoted string values: "..."
            or re.match(r'^"[^"]*"$', token)
            # Numeric values
            or re.match(r'^\d+$', token)
            # Hex values (for TIDs)
            or re.match(r'^0x[0-9a-fA-F]+$', token)
        )

        if not is_allowed:
            logger.warning("invalid_filter_token", token=token)
            raise ValueError(f"Invalid token in filter: {token}")

    logger.info("filter_sanitized", length=len(user_filter))
    return user_filter


def sanitize_file_path(path: str, base_dir: str = "/tmp", max_size_mb: int = 500) -> Path:
    """Prevent path traversal attacks and validate file constraints.

    Strategy:
    1. Resolve path to canonical form (follows symlinks).
    2. Verify it doesn't escape base_dir.
    3. Verify file exists and is a regular file.
    4. Verify file size doesn't exceed limits.

    Args:
        path: User-provided file path.
        base_dir: Allowed base directory.
        max_size_mb: Maximum file size in MB.

    Returns:
        Resolved Path object.

    Raises:
        ValueError: If path validation fails.
        FileNotFoundError: If file doesn't exist.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("Path must be a non-empty string")

    try:
        resolved = Path(path).resolve()
        base_resolved = Path(base_dir).resolve()
    except Exception as e:
        raise ValueError(f"Path resolution failed: {e}")

    # Check containment — allow if the resolved path is under base_dir
    # or if base_dir is "/" (no restriction)
    if str(base_resolved) != "/" and base_resolved not in resolved.parents and resolved != base_resolved:
        raise ValueError("Path escape attempt detected")

    if not resolved.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not resolved.is_file():
        raise ValueError(f"Path is not a regular file: {path}")

    file_size_mb = resolved.stat().st_size / (1024 * 1024)
    if file_size_mb > max_size_mb:
        raise ValueError(f"PCAP exceeds max size ({max_size_mb}MB)")

    logger.info("path_validated", path=str(resolved), size_mb=round(file_size_mb, 2))
    return resolved


def sanitize_imsi(imsi: str) -> str:
    """Validate IMSI format: 15 digits, numeric only.

    Args:
        imsi: Raw IMSI string.

    Returns:
        Validated IMSI string.

    Raises:
        ValueError: If format is invalid.
    """
    if not isinstance(imsi, str):
        raise ValueError("IMSI must be a string")
    imsi = imsi.strip()
    if not re.match(r"^\d{15}$", imsi):
        raise ValueError("IMSI must be exactly 15 digits")
    return imsi


def sanitize_gt_digits(gt: str) -> str:
    """Validate Global Title format: 1-15 digits, optional + prefix.

    Args:
        gt: Raw GT string.

    Returns:
        Validated GT digits (without + prefix).

    Raises:
        ValueError: If format is invalid.
    """
    if not isinstance(gt, str):
        raise ValueError("GT must be a string")
    gt = gt.strip()
    if not re.match(r"^\+?[0-9]{1,15}$", gt):
        raise ValueError("Global Title must be 1-15 digits (optionally with + prefix)")
    return gt.lstrip("+")


def sanitize_msisdn(msisdn: str) -> str:
    """Validate MSISDN format: 6-15 digits, optional + prefix.

    Args:
        msisdn: Raw MSISDN string.

    Returns:
        Validated MSISDN (without + prefix).

    Raises:
        ValueError: If format is invalid.
    """
    if not isinstance(msisdn, str):
        raise ValueError("MSISDN must be a string")
    msisdn = msisdn.strip()
    if not re.match(r"^\+?[0-9]{6,15}$", msisdn):
        raise ValueError("MSISDN must be 6-15 digits (optionally with + prefix)")
    return msisdn.lstrip("+")


def sanitize_port(port: int) -> int:
    """Validate port range: 1-65535.

    Args:
        port: Port number.

    Returns:
        Validated port.

    Raises:
        ValueError: If port is out of range.
    """
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("Port must be an integer between 1 and 65535")
    return port
