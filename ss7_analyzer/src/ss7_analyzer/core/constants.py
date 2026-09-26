"""Constants for SS7 protocol analysis.

Centralized definitions for MAP operation codes, TCAP package types,
SCCP message types, and risk-level thresholds.
"""

from __future__ import annotations

from enum import IntEnum

# --- MAP Operation Codes ---
class MAPOpCode(IntEnum):
    """GSM Mobile Application Part operation codes."""
    UPDATE_LOCATION = 2
    PROVIDE_SUBSCRIBER_INFO = 3
    SEND_ROUTING_INFO = 22
    SEND_ROUTING_INFO_FOR_SM = 45

# High-risk op codes and their default severity scores
OP_CODE_SEVERITY: dict[int, float] = {
    3: 1.0,   # PSI — critical (location tracking)
    22: 0.8,  # SRI — high (routing info leak)
    45: 0.8,  # SRI-for-SM — high (SMS interception)
    2: 0.5,   # Update Location — medium (DoS/redirect)
}
OP_CODE_DEFAULT_SEVERITY: float = 0.3

# --- TCAP Package Types ---
TCAP_BEGIN = "Begin"
TCAP_END = "End"
TCAP_CONTINUE = "Continue"
TCAP_ABORT = "Abort"
TCAP_RETURN_RESULT_LAST = "ReturnResultLast"

TCAP_REQUEST_TYPES = {TCAP_BEGIN}
TCAP_RESPONSE_TYPES = {TCAP_END, TCAP_RETURN_RESULT_LAST}

# --- SCCP Message Types ---
SCCP_VALID_MESSAGE_TYPES = {"UDT", "XUDT"}

# --- SCCP Header Constants ---
SCCP_PPID_M3UA = 3
SCCP_VALID_PROTOCOL_CLASSES = {0, 1}
SCCP_NAI_INTERNATIONAL = 4
SCCP_NUMBERING_PLAN_E164 = 1

# --- Risk Levels ---
class RiskLevelStr:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# Default alert thresholds (overridden by config)
DEFAULT_ALERT_THRESHOLDS: dict[str, float] = {
    "critical": 0.85,
    "high": 0.70,
    "medium": 0.50,
}

# --- Detection Defaults ---
DEFAULT_BURST_ZSCORE = 3.0
DEFAULT_BURST_QUERIES_PER_SEC = 100
DEFAULT_ORPHAN_TIMEOUT_SEC = 10
DEFAULT_LATENCY_THRESHOLD_SEC = 5.0
DEFAULT_ZERO_LATENCY_MS = 1.0
DEFAULT_GT_FREQUENCY_HIGH = 100
DEFAULT_GT_FREQUENCY_MODERATE = 50
DEFAULT_GT_FREQUENCY_WINDOW_HOURS = 1

# --- Tshark Field Names ---
TSHARK_FIELDS: list[str] = [
    "frame.time_epoch",
    "ip.src",
    "sctp.srcport",
    "ip.dst",
    "sctp.dstport",
    "sccp.calling.digits",
    "sccp.called.digits",
    "gsm_map.op_code",
    "gsm_map.msisdn",
    "e212.imsi",
    "tcap.src_tid",
    "tcap.dst_tid",
    "tcap.package_type",
    "sctp.ppid",
    "m3ua.routing_context",
    "sccp.message_type",
    "sccp.protocol_class",
    "sccp.nai",
    "sccp.numbering_plan",
]

# --- Filter Expressions ---
FILTER_GSM_MAP = "gsm_map"
FILTER_SCTP = "sctp"
FILTER_M3UA = "m3ua"
FILTER_SCCP = "sccp"
FILTER_TCAP = "tcap"

# --- Colors for Rich UI ---
RISK_COLORS: dict[str, str] = {
    "CRITICAL": "red",
    "HIGH": "red3",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "cyan",
}
