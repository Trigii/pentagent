"""Rich-based logging, with a single place to set log levels."""
from __future__ import annotations

import logging
import sys

from rich.logging import RichHandler


def configure_logging(level: str = "INFO") -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    handler = RichHandler(
        rich_tracebacks=True,
        show_path=False,
        show_time=True,
        markup=True,
    )
    logging.basicConfig(
        level=numeric,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[handler],
    )
    # Quiet down noisy libraries
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


# Guard against double-configuration when imported repeatedly
if not getattr(sys, "_pentagent_logging_configured", False):  # pragma: no cover
    setattr(sys, "_pentagent_logging_configured", True)
