"""Pydantic v2 data models for packets, dialogs, alerts, and reports.

These models provide structured, validated representations of the data
extracted from tshark and produced by the analysis engines.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk severity levels for alerts."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PacketRecord(BaseModel):
    """Structured representation of a single MAP/TCAP packet."""

    frame_number: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ip_src: str = ""
    sctp_srcport: int = 0
    ip_dst: str = ""
    sctp_dstport: int = 0
    sccp_calling_digits: Optional[str] = None
    sccp_called_digits: Optional[str] = None
    gsm_map_op_code: int = 0
    gsm_map_msisdn: Optional[str] = None
    e212_imsi: Optional[str] = None
    tcap_src_tid: Optional[str] = None
    tcap_dst_tid: Optional[str] = None
    tcap_package_type: Optional[str] = None
    tcap_error_code: Optional[str] = None
    sctp_ppid: Optional[int] = None
    m3ua_routing_context: Optional[str] = None
    sccp_message_type: Optional[str] = None
    sccp_protocol_class: Optional[int] = None
    sccp_nai: Optional[int] = None
    sccp_numbering_plan: Optional[int] = None
    risk_score: float = 0.0
    risk_level: Optional[RiskLevel] = None


class DialogPair(BaseModel):
    """Correlated TCAP request-response pair."""

    transaction_id: str = ""
    begin_packet: Optional[PacketRecord] = None
    end_packet: Optional[PacketRecord] = None
    is_orphaned: bool = False
    latency_ms: Optional[float] = None
    has_error: bool = False
    error_code: Optional[str] = None
    anomaly_flags: list[str] = Field(default_factory=list)


class AnomalyAlert(BaseModel):
    """Structured alert for a detected anomaly."""

    alert_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_level: RiskLevel = RiskLevel.INFO
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    packet: Optional[PacketRecord] = None
    alert_type: str = ""
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    correlation_id: str = "N/A"


class AnalysisReport(BaseModel):
    """Summary of a complete analysis run."""

    pcap_file: str = ""
    analysis_start: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    analysis_end: Optional[datetime] = None
    total_packets: int = 0
    total_map_packets: int = 0
    total_alerts: int = 0
    alerts_by_risk: dict[str, int] = Field(default_factory=dict)
    dialogs_analyzed: int = 0
    orphaned_dialogs: int = 0
    high_latency_dialogs: int = 0
    suspected_spoofed_gts: int = 0
    suspected_location_tracking: int = 0
    top_suspicious_sources: list[dict[str, Any]] = Field(default_factory=list)
    top_targeted_isdn: list[dict[str, Any]] = Field(default_factory=list)
    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex)


class SpoofingScore(BaseModel):
    """Result of GT spoofing heuristic scoring for a single packet."""

    score: float = Field(default=0.0, ge=0.0, le=1.0)
    components: dict[str, float] = Field(default_factory=dict)
    reasoning: str = ""
