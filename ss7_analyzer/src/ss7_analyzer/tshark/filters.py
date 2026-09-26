"""Composable tshark display filter DSL.

Provides a builder API for constructing safe, validated tshark display
filter expressions without string concatenation.
"""

from __future__ import annotations

from ..core.constants import FILTER_GSM_MAP, FILTER_M3UA, FILTER_SCCP, FILTER_SCTP, FILTER_TCAP


class FilterBuilder:
    """Builder for composable tshark display filter expressions."""

    def __init__(self) -> None:
        self._parts: list[str] = []

    @staticmethod
    def all_map() -> "FilterBuilder":
        """Filter for all GSM MAP traffic."""
        return FilterBuilder().add(FILTER_GSM_MAP)

    @staticmethod
    def all_sctp() -> "FilterBuilder":
        """Filter for all SCTP traffic."""
        return FilterBuilder().add(FILTER_SCTP)

    @staticmethod
    def all_sccp() -> "FilterBuilder":
        """Filter for all SCCP traffic."""
        return FilterBuilder().add(FILTER_SCCP)

    @staticmethod
    def all_tcap() -> "FilterBuilder":
        """Filter for all TCAP traffic."""
        return FilterBuilder().add(FILTER_TCAP)

    @staticmethod
    def all_m3ua() -> "FilterBuilder":
        """Filter for all M3UA traffic."""
        return FilterBuilder().add(FILTER_M3UA)

    def add(self, expr: str) -> "FilterBuilder":
        """Add a raw filter expression component."""
        if self._parts:
            self._parts.append("and")
        self._parts.append(expr)
        return self

    def op_code(self, code: int) -> "FilterBuilder":
        """Filter for a specific MAP operation code."""
        return self.add(f"gsm_map.op_code == {int(code)}")

    def op_code_in(self, codes: list[int]) -> "FilterBuilder":
        """Filter for any of the given MAP operation codes."""
        parts = [f"gsm_map.op_code == {int(c)}" for c in codes]
        joined = " or ".join(parts)
        return self.add(f"({joined})")

    def not_from_port(self, port: int) -> "FilterBuilder":
        """Exclude traffic from a specific SCTP source port."""
        return self.add(f"not (sctp.srcport == {int(port)})")

    def from_port(self, port: int) -> "FilterBuilder":
        """Include only traffic from a specific SCTP source port."""
        return self.add(f"sctp.srcport == {int(port)}")

    def imsi(self, imsi: str) -> "FilterBuilder":
        """Filter for a specific IMSI."""
        return self.add(f'e212.imsi == "{imsi}"')

    def has_error(self) -> "FilterBuilder":
        """Filter for TCAP error responses."""
        return self.add("tcap.error")

    def package_type(self, pkg_type: str) -> "FilterBuilder":
        """Filter for a specific TCAP package type."""
        return self.add(f'tcap.package_type == "{pkg_type}"')

    def build(self) -> str:
        """Build the final filter expression string."""
        return " ".join(self._parts) if self._parts else ""

    def __str__(self) -> str:
        return self.build()


# --- Predefined filter recipes ---

def filter_location_tracking(trusted_port: int) -> str:
    """Filter for unauthorized PSI/SRI queries (op codes 3 and 22 from non-trusted ports)."""
    fb = FilterBuilder()
    fb.add("(gsm_map.op_code == 3 or gsm_map.op_code == 22)")
    fb.add(f"not (sctp.srcport == {trusted_port})")
    return fb.build()


def filter_failed_requests() -> str:
    """Filter for MAP messages returning error components."""
    fb = FilterBuilder()
    fb.add("gsm_map.op_code == 22")
    fb.add("tcap.error")
    return fb.build()


def filter_imsi_audit(imsi: str) -> str:
    """Filter for all traffic affecting a specific IMSI."""
    return FilterBuilder().imsi(imsi).build()


def filter_sri_for_sm() -> str:
    """Filter for Send Routing Info for SM (op code 45)."""
    return FilterBuilder().op_code(45).build()


def filter_update_location() -> str:
    """Filter for Update Location (op code 2)."""
    return FilterBuilder().op_code(2).build()


def filter_all_signaling() -> str:
    """Filter for all SS7/SIGTRAN signaling traffic."""
    return "sctp or m3ua or sccp or tcap or gsm_map"
