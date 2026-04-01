"""
Structured logging for the Shadow Proxy.
Provides colour-coded console output and file logging.
"""

import logging
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class StructuredFormatter(logging.Formatter):
    """JSON-structured log formatter for machine-readable output."""

    LEVEL_ICONS = {
        "DEBUG": "🔍",
        "INFO": "🛡️",
        "WARNING": "⚠️",
        "ERROR": "❌",
        "CRITICAL": "🚨",
    }

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "icon": self.LEVEL_ICONS.get(record.levelname, ""),
            "module": record.module,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        # Add extra fields if present
        for key in ("action", "data_class", "latency_ms", "packet_size", "remote_addr"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
        return json.dumps(log_entry)


class PlainFormatter(logging.Formatter):
    """Human-readable coloured formatter for development."""

    COLOURS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[41m",  # Red background
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        colour = self.COLOURS.get(record.levelname, self.RESET)
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = f"{colour}[{timestamp}] [{record.levelname:>8}]{self.RESET}"
        message = record.getMessage()
        return f"{prefix} {message}"


def setup_logger(
    level: str = "INFO",
    fmt: str = "plain",
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    Configure and return the application logger.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        fmt: Format style — "structured" (JSON) or "plain" (coloured)
        log_file: Optional path to a log file
    """
    logger = logging.getLogger("shadow_proxy")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    if fmt == "structured":
        console.setFormatter(StructuredFormatter())
    else:
        console.setFormatter(PlainFormatter())
    logger.addHandler(console)

    # File handler (always structured JSON for parsing)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_path))
        file_handler.setFormatter(StructuredFormatter())
        logger.addHandler(file_handler)

    return logger


def get_logger() -> logging.Logger:
    """Get the existing shadow_proxy logger (call setup_logger first)."""
    return logging.getLogger("shadow_proxy")
