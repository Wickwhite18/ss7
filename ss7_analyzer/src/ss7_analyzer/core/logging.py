"""Structured logging setup with correlation IDs using structlog.

Provides a configured logger that emits JSON or console-formatted log lines
with a correlation ID for tracing analysis decisions across sessions.
"""

from __future__ import annotations

import contextvars
import logging
import sys
from typing import Any

import structlog

# Context variable for correlation ID propagation
correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default="N/A"
)


def configure_logging(level: str = "INFO", fmt: str = "json") -> structlog.stdlib.BoundLogger:
    """Configure structlog with the specified level and format.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR).
        fmt: Output format — "json" for structured JSON, "console" for human-readable.

    Returns:
        A configured structlog logger instance.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Configure stdlib logging to capture structlog output
    logging.basicConfig(
        level=log_level,
        stream=sys.stderr,
        format="%(message)s",
    )

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        _add_correlation_id,
        structlog.processors.TimeStamper(fmt="iso"),
    ]

    if fmt == "json":
        processors = shared_processors + [structlog.processors.JSONRenderer()]
    else:
        processors = shared_processors + [structlog.dev.ConsoleRenderer()]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Inject correlation ID processor into context
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id_var.get())

    return structlog.get_logger("ss7_analyzer")


def _add_correlation_id(
    _logger: Any, _method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Add the current correlation ID to every log event."""
    event_dict["correlation_id"] = correlation_id_var.get()
    return event_dict


def set_correlation_id(cid: str) -> None:
    """Set the correlation ID for the current context."""
    correlation_id_var.set(cid)
    structlog.contextvars.bind_contextvars(correlation_id=cid)


def get_logger(name: str = "ss7_analyzer") -> structlog.stdlib.BoundLogger:
    """Get a named logger instance."""
    return structlog.get_logger(name)
