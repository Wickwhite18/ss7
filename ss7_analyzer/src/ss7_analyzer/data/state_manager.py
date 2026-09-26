"""SQLite-backed state manager for multi-session persistence.

Stores sessions, packets, dialogs, and alerts in SQLite for cross-session
correlation, trend analysis, and forensic preservation.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..core.logging import get_logger
from ..data.models import AnomalyAlert, DialogPair, PacketRecord, RiskLevel

logger = get_logger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    pcap_file TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    total_packets INTEGER DEFAULT 0,
    total_map_packets INTEGER DEFAULT 0,
    total_alerts INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS packets (
    session_id TEXT NOT NULL,
    packet_id TEXT NOT NULL,
    frame_number INTEGER,
    timestamp TIMESTAMP,
    ip_src TEXT,
    sctp_srcport INTEGER,
    gsm_map_op_code INTEGER,
    risk_score REAL,
    risk_level TEXT,
    sccp_calling_digits TEXT,
    gsm_map_msisdn TEXT,
    e212_imsi TEXT,
    PRIMARY KEY (session_id, packet_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS dialogs (
    session_id TEXT NOT NULL,
    transaction_id TEXT,
    begin_packet_id TEXT,
    end_packet_id TEXT,
    is_orphaned BOOLEAN DEFAULT 0,
    latency_ms REAL,
    anomaly_flags TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    risk_level TEXT,
    risk_score REAL,
    alert_type TEXT,
    packet_id TEXT,
    description TEXT,
    evidence TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS threat_intelligence (
    ip_address TEXT PRIMARY KEY,
    asn TEXT,
    country_code TEXT,
    reputation_score REAL,
    last_seen TIMESTAMP,
    threat_indicators TEXT
);

CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
CREATE INDEX IF NOT EXISTS idx_packets_ip_src ON packets(ip_src);
"""


class StateManager:
    """Manages SQLite-backed session state for forensic analysis."""

    def __init__(self, db_path: str = "ss7_analyzer_state.db"):
        self.db_path = str(Path(db_path).resolve())
        self._conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._init_schema()

    def _connect(self) -> None:
        """Open the SQLite connection with WAL mode for concurrency."""
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def create_session(self, pcap_file: str) -> str:
        """Create a new analysis session and return its ID."""
        session_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO sessions (session_id, pcap_file, created_at) VALUES (?, ?, ?)",
            (session_id, pcap_file, now),
        )
        self._conn.commit()
        logger.info("session_created", session_id=session_id, pcap_file=pcap_file)
        return session_id

    def complete_session(
        self,
        session_id: str,
        total_packets: int = 0,
        total_map_packets: int = 0,
        total_alerts: int = 0,
    ) -> None:
        """Mark a session as completed with summary counts."""
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """UPDATE sessions SET completed_at = ?, total_packets = ?,
               total_map_packets = ?, total_alerts = ? WHERE session_id = ?""",
            (now, total_packets, total_map_packets, total_alerts, session_id),
        )
        self._conn.commit()

    def store_packet(self, session_id: str, packet: PacketRecord) -> None:
        """Store a single packet record."""
        packet_id = uuid.uuid4().hex
        self._conn.execute(
            """INSERT OR REPLACE INTO packets
               (session_id, packet_id, frame_number, timestamp, ip_src,
                sctp_srcport, gsm_map_op_code, risk_score, risk_level,
                sccp_calling_digits, gsm_map_msisdn, e212_imsi)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                packet_id,
                packet.frame_number,
                packet.timestamp.isoformat(),
                packet.ip_src,
                packet.sctp_srcport,
                packet.gsm_map_op_code,
                packet.risk_score,
                packet.risk_level.value if packet.risk_level else None,
                packet.sccp_calling_digits,
                packet.gsm_map_msisdn,
                packet.e212_imsi,
            ),
        )
        self._conn.commit()

    def store_packets_batch(self, session_id: str, packets: list[PacketRecord]) -> None:
        """Store multiple packets in a single transaction."""
        rows = []
        for packet in packets:
            packet_id = uuid.uuid4().hex
            rows.append(
                (
                    session_id,
                    packet_id,
                    packet.frame_number,
                    packet.timestamp.isoformat(),
                    packet.ip_src,
                    packet.sctp_srcport,
                    packet.gsm_map_op_code,
                    packet.risk_score,
                    packet.risk_level.value if packet.risk_level else None,
                    packet.sccp_calling_digits,
                    packet.gsm_map_msisdn,
                    packet.e212_imsi,
                )
            )
        self._conn.executemany(
            """INSERT OR REPLACE INTO packets
               (session_id, packet_id, frame_number, timestamp, ip_src,
                sctp_srcport, gsm_map_op_code, risk_score, risk_level,
                sccp_calling_digits, gsm_map_msisdn, e212_imsi)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self._conn.commit()

    def store_dialog(self, session_id: str, dialog: DialogPair) -> None:
        """Store a correlated dialog pair."""
        self._conn.execute(
            """INSERT INTO dialogs
               (session_id, transaction_id, begin_packet_id, end_packet_id,
                is_orphaned, latency_ms, anomaly_flags)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                dialog.transaction_id,
                None,  # begin_packet_id would be resolved separately
                None,
                dialog.is_orphaned,
                dialog.latency_ms,
                json.dumps(dialog.anomaly_flags),
            ),
        )
        self._conn.commit()

    def store_alert(self, session_id: str, alert: AnomalyAlert) -> None:
        """Store an alert record."""
        self._conn.execute(
            """INSERT OR REPLACE INTO alerts
               (alert_id, session_id, risk_level, risk_score, alert_type,
                packet_id, description, evidence, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.alert_id,
                session_id,
                alert.risk_level.value,
                alert.risk_score,
                alert.alert_type,
                None,
                alert.description,
                json.dumps(alert.evidence),
                alert.timestamp.isoformat(),
            ),
        )
        self._conn.commit()

    def store_alerts_batch(self, session_id: str, alerts: list[AnomalyAlert]) -> None:
        """Store multiple alerts in a single transaction."""
        rows = [
            (
                alert.alert_id,
                session_id,
                alert.risk_level.value,
                alert.risk_score,
                alert.alert_type,
                None,
                alert.description,
                json.dumps(alert.evidence),
                alert.timestamp.isoformat(),
            )
            for alert in alerts
        ]
        self._conn.executemany(
            """INSERT OR REPLACE INTO alerts
               (alert_id, session_id, risk_level, risk_score, alert_type,
                packet_id, description, evidence, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self._conn.commit()

    def get_session_alerts(self, session_id: str) -> list[dict[str, Any]]:
        """Retrieve all alerts for a given session."""
        cursor = self._conn.execute(
            "SELECT * FROM alerts WHERE session_id = ? ORDER BY risk_score DESC",
            (session_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_repeat_offenders(self, min_alerts: int = 3) -> list[dict[str, Any]]:
        """Find source IPs that triggered alerts across multiple sessions."""
        cursor = self._conn.execute(
            """
            SELECT p.ip_src, COUNT(DISTINCT a.session_id) as session_count,
                   COUNT(a.alert_id) as alert_count,
                   MAX(a.created_at) as last_seen
            FROM alerts a
            JOIN packets p ON a.packet_id IS NOT NULL
            GROUP BY p.ip_src
            HAVING alert_count >= ?
            ORDER BY alert_count DESC
            """,
            (min_alerts,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all analysis sessions."""
        cursor = self._conn.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC"
        )
        return [dict(row) for row in cursor.fetchall()]

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
