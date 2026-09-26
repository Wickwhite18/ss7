"""Configuration loader for SS7 Analyzer.

Loads YAML configuration, validates against a JSON schema, and merges
environment variable overrides (prefixed with SS7_).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from jsonschema import validate as schema_validate

from ..core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Config:
    """Runtime configuration loaded from YAML + environment variables."""

    max_pcap_size_mb: int = 500
    tshark_timeout_sec: int = 60
    tshark_max_retries: int = 3
    tshark_binary: str = "tshark"

    trusted_ports: list[int] = field(default_factory=lambda: [2905, 2906])
    trusted_cidrs: list[str] = field(
        default_factory=lambda: ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
    )
    expected_gt_country_codes: list[str] = field(
        default_factory=lambda: ["1", "44", "49", "33", "39", "34", "31"]
    )

    risk_weights: dict[str, float] = field(
        default_factory=lambda: {
            "operation_severity": 0.4,
            "source_trust": 0.3,
            "behavior_anomaly": 0.2,
            "temporal_anomaly": 0.1,
        }
    )

    alert_thresholds: dict[str, float] = field(
        default_factory=lambda: {"critical": 0.85, "high": 0.70, "medium": 0.50}
    )

    detection: dict[str, Any] = field(
        default_factory=lambda: {
            "burst_zscore": 3.0,
            "burst_queries_per_sec": 100,
            "orphan_timeout_sec": 10,
            "latency_threshold_sec": 5.0,
            "zero_latency_ms": 1.0,
            "gt_frequency_high": 100,
            "gt_frequency_moderate": 50,
            "gt_frequency_window_hours": 1,
        }
    )

    op_code_severity: dict[str, float] = field(
        default_factory=lambda: {"3": 1.0, "22": 0.8, "45": 0.8, "2": 0.5, "default": 0.3}
    )

    geoip_enabled: bool = False
    geoip_database_path: str = ""

    state_sqlite_path: str = "ss7_analyzer_state.db"
    state_cache_size: int = 100

    logging_level: str = "INFO"
    logging_format: str = "json"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Build a Config from a raw dictionary."""
        cfg = cls()
        cfg.max_pcap_size_mb = data.get("max_pcap_size_mb", cfg.max_pcap_size_mb)
        cfg.tshark_timeout_sec = data.get("tshark_timeout_sec", cfg.tshark_timeout_sec)
        cfg.tshark_max_retries = data.get("tshark_max_retries", cfg.tshark_max_retries)
        cfg.tshark_binary = data.get("tshark_binary", cfg.tshark_binary)
        cfg.trusted_ports = data.get("trusted_ports", cfg.trusted_ports)
        cfg.trusted_cidrs = data.get("trusted_cidrs", cfg.trusted_cidrs)
        cfg.expected_gt_country_codes = data.get(
            "expected_gt_country_codes", cfg.expected_gt_country_codes
        )
        cfg.risk_weights = data.get("risk_weights", cfg.risk_weights)
        cfg.alert_thresholds = data.get("alert_thresholds", cfg.alert_thresholds)
        cfg.detection = data.get("detection", cfg.detection)

        # op_code_severity keys come as strings from YAML
        raw_severity = data.get("op_code_severity", {})
        cfg.op_code_severity = {str(k): v for k, v in raw_severity.items()}

        geoip = data.get("geoip", {})
        cfg.geoip_enabled = geoip.get("enabled", False)
        cfg.geoip_database_path = geoip.get("database_path", "")

        state = data.get("state", {})
        cfg.state_sqlite_path = state.get("sqlite_path", cfg.state_sqlite_path)
        cfg.state_cache_size = state.get("cache_size", cfg.state_cache_size)

        log_cfg = data.get("logging", {})
        cfg.logging_level = log_cfg.get("level", cfg.logging_level)
        cfg.logging_format = log_cfg.get("format", cfg.logging_format)

        return cfg

    def get_op_code_severity(self, op_code: int) -> float:
        """Look up the severity score for a MAP op code."""
        return self.op_code_severity.get(str(op_code), self.op_code_severity.get("default", 0.3))

    def get_alert_threshold(self, level: str) -> float:
        """Get the score threshold for a risk level."""
        return self.alert_thresholds.get(level.lower(), 0.5)


def load_config(config_path: str | None = None) -> Config:
    """Load configuration from YAML file, validate against schema, and apply env overrides.

    Args:
        config_path: Path to config.yaml. If None, searches for config.yaml
                     in the project root.

    Returns:
        A validated Config instance.
    """
    raw: dict[str, Any] = {}

    # Find and load YAML config
    if config_path:
        yaml_path = Path(config_path)
    else:
        # Search relative to this file for the default config
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        yaml_path = project_root / "config.yaml"

    if yaml_path.exists():
        with open(yaml_path) as f:
            raw = yaml.safe_load(f) or {}
        logger.info("config_loaded", path=str(yaml_path))
    else:
        logger.warning("config_not_found", path=str(yaml_path), msg="Using defaults")

    # Validate against JSON schema
    schema_path = yaml_path.parent / "config.schema.json"
    if schema_path.exists():
        with open(schema_path) as f:
            schema = json.load(f)
        try:
            schema_validate(instance=raw, schema=schema)
            logger.info("config_validated")
        except Exception as e:
            logger.error("config_validation_failed", error=str(e))
            raise ValueError(f"Config validation failed: {e}") from e

    # Apply environment variable overrides (SS7_ prefix, uppercase, nested with _)
    raw = _apply_env_overrides(raw)

    return Config.from_dict(raw)


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """Apply SS7_-prefixed environment variable overrides to the config dict."""
    env_map: dict[str, str] = {
        "SS7_MAX_PCAP_SIZE_MB": "max_pcap_size_mb",
        "SS7_TSHARK_TIMEOUT_SEC": "tshark_timeout_sec",
        "SS7_TSHARK_MAX_RETRIES": "tshark_max_retries",
        "SS7_TSHARK_BINARY": "tshark_binary",
        "SS7_GEOIP_ENABLED": "geoip.enabled",
        "SS7_GEOIP_DATABASE_PATH": "geoip.database_path",
        "SS7_STATE_SQLITE_PATH": "state.sqlite_path",
        "SS7_LOGGING_LEVEL": "logging.level",
        "SS7_LOGGING_FORMAT": "logging.format",
    }

    for env_key, config_key in env_map.items():
        env_val = os.environ.get(env_key)
        if env_val is not None:
            _set_nested(raw, config_key, _coerce_env_value(env_val))
            logger.info("config_env_override", key=config_key, env=env_key)

    return raw


def _set_nested(d: dict[str, Any], dotted_key: str, value: Any) -> None:
    """Set a value in a nested dict using dot notation."""
    keys = dotted_key.split(".")
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def _coerce_env_value(val: str) -> Any:
    """Coerce environment variable strings to appropriate types."""
    if val.lower() in ("true", "yes", "1"):
        return True
    if val.lower() in ("false", "no", "0"):
        return False
    if re.match(r"^-?\d+$", val):
        return int(val)
    if re.match(r"^-?\d+\.\d+$", val):
        return float(val)
    return val
