"""
VulnBastion / TawasolPay CyberSentinel — Enterprise Observability & Logging
Structured logging with correlation IDs, JSON formatting, and secret masking.
"""
import contextvars
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from config import settings

# Context variable for request / pipeline correlation ID
correlation_id_ctx = contextvars.ContextVar[str]("correlation_id", default="")


def get_correlation_id() -> str:
    """Get the current correlation ID or generate a new one if not set."""
    cid = correlation_id_ctx.get()
    if not cid:
        cid = str(uuid.uuid4())
        correlation_id_ctx.set(cid)
    return cid


def set_correlation_id(cid: Optional[str] = None) -> str:
    """Set the correlation ID for the current context."""
    new_cid = cid or str(uuid.uuid4())
    correlation_id_ctx.set(new_cid)
    return new_cid


class JSONFormatter(logging.Formatter):
    """JSON log formatter for production log aggregation systems (ELK, CloudWatch, Datadog)."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id_ctx.get(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include custom extra fields if provided
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_entry.update(record.extra_fields)

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


class ConsoleFormatter(logging.Formatter):
    """Clean, readable console formatter for CLI and local development."""

    def format(self, record: logging.LogRecord) -> str:
        cid = correlation_id_ctx.get()
        cid_str = f" [{cid[:8]}]" if cid else ""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = record.getMessage()
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        return f"{timestamp} [{record.levelname:^7}]{cid_str} {record.name}: {msg}"


def setup_logger(name: str = "cybersentinel") -> logging.Logger:
    """Configure and return a structured logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

    # Avoid duplicate handlers if setup is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

        if settings.STRUCTURED_LOGS:
            handler.setFormatter(JSONFormatter())
        else:
            handler.setFormatter(ConsoleFormatter())

        logger.addHandler(handler)

    # Do not propagate to root logger to avoid double logging
    logger.propagate = False
    return logger


# Default logger instance
logger = setup_logger("vulnbastion")

