"""Parser for raw tshark output into structured PacketRecord objects.

Converts tab-separated tshark -T fields output into validated Pydantic models.
Handles missing fields, malformed lines, and timestamp parsing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..core.constants import TSHARK_FIELDS
from ..core.logging import get_logger
from ..data.models import PacketRecord

logger = get_logger(__name__)


class TsharkParser:
    """Parses raw tshark field output into PacketRecord objects."""

    def __init__(self, field_order: Optional[list[str]] = None):
        """Initialize with the expected field order.

        Args:
            field_order: List of tshark -e field names in the order they
                         appear in tshark output. Defaults to TSHARK_FIELDS.
        """
        self.field_order = field_order or TSHARK_FIELDS

    def parse_line(self, line: str, frame_number: int = 0) -> Optional[PacketRecord]:
        """Parse a single tshark output line into a PacketRecord.

        tshark -T fields produces tab-separated values, one per packet.
        Missing fields appear as empty strings between tabs.

        Args:
            line: A single tab-separated line from tshark.
            frame_number: Frame number (for tracking).

        Returns:
            A PacketRecord, or None if the line is empty/malformed.
        """
        line = line.strip()
        if not line:
            return None

        parts = line.split("\t")

        # Pad or trim to match field count
        while len(parts) < len(self.field_order):
            parts.append("")
        parts = parts[: len(self.field_order)]

        values = dict(zip(self.field_order, parts))

        try:
            timestamp = self._parse_timestamp(values.get("frame.time_epoch", ""))
            op_code = self._safe_int(values.get("gsm_map.op_code", "0"), 0)

            packet = PacketRecord(
                frame_number=frame_number,
                timestamp=timestamp,
                ip_src=values.get("ip.src", "") or "",
                sctp_srcport=self._safe_int(values.get("sctp.srcport", "0"), 0),
                ip_dst=values.get("ip.dst", "") or "",
                sctp_dstport=self._safe_int(values.get("sctp.dstport", "0"), 0),
                sccp_calling_digits=self._clean_str(values.get("sccp.calling.digits")),
                sccp_called_digits=self._clean_str(values.get("sccp.called.digits")),
                gsm_map_op_code=op_code,
                gsm_map_msisdn=self._clean_str(values.get("gsm_map.msisdn")),
                e212_imsi=self._clean_str(values.get("e212.imsi")),
                tcap_src_tid=self._clean_str(values.get("tcap.src_tid")),
                tcap_dst_tid=self._clean_str(values.get("tcap.dst_tid")),
                tcap_package_type=self._clean_str(values.get("tcap.package_type")),
                sctp_ppid=self._safe_int_opt(values.get("sctp.ppid")),
                m3ua_routing_context=self._clean_str(values.get("m3ua.routing_context")),
                sccp_message_type=self._clean_str(values.get("sccp.message_type")),
                sccp_protocol_class=self._safe_int_opt(values.get("sccp.protocol_class")),
                sccp_nai=self._safe_int_opt(values.get("sccp.nai")),
                sccp_numbering_plan=self._safe_int_opt(values.get("sccp.numbering_plan")),
            )
            return packet
        except Exception as e:
            logger.warning("parse_error", error=str(e), line=line[:200])
            return None

    def parse_output(self, output: str) -> list[PacketRecord]:
        """Parse the full tshark output into a list of PacketRecords.

        Args:
            output: Raw tshark stdout (tab-separated, one packet per line).

        Returns:
            List of validated PacketRecord objects.
        """
        packets: list[PacketRecord] = []
        lines = output.strip().split("\n") if output.strip() else []

        for i, line in enumerate(lines):
            packet = self.parse_line(line, frame_number=i + 1)
            if packet:
                packets.append(packet)

        logger.info("parsed_packets", count=len(packets), total_lines=len(lines))
        return packets

    @staticmethod
    def _parse_timestamp(epoch_str: str) -> datetime:
        """Parse a Unix epoch timestamp string into a datetime."""
        if not epoch_str:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromtimestamp(float(epoch_str), tz=timezone.utc)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    @staticmethod
    def _safe_int(val: str, default: int = 0) -> int:
        """Safely parse an integer from a string."""
        try:
            return int(val) if val else default
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _safe_int_opt(val: Optional[str]) -> Optional[int]:
        """Safely parse an optional integer."""
        if not val:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _clean_str(val: Optional[str]) -> Optional[str]:
        """Clean a string field: strip whitespace, return None for empty."""
        if not val:
            return None
        val = val.strip()
        return val if val else None
