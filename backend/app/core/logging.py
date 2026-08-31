"""
Centralized logging configuration.

Every module in the app should obtain its logger via `get_logger(__name__)`
rather than calling `logging.getLogger` directly, so log formatting and
levels stay consistent across the whole application.
"""

import logging
import sys

from app.config import get_settings

_CONFIGURED = False


def configure_logging() -> None:
    """
    Configure the root logger once, at application startup.

    Idempotent: safe to call multiple times (e.g. in tests that re-import
    the app) without duplicating log handlers.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    settings = get_settings()

    if settings.LOG_JSON:
        fmt = (
            '{"time":"%(asctime)s","level":"%(levelname)s",'
            '"logger":"%(name)s","message":"%(message)s"}'
        )
    else:
        fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S"))

    root_logger = logging.getLogger()
    root_logger.setLevel(settings.LOG_LEVEL.upper())
    root_logger.handlers = [handler]

    # Keep uvicorn's own loggers aligned with our formatting/level instead
    # of the noisier defaults it ships with.
    for noisy_logger in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(noisy_logger).handlers = [handler]
        logging.getLogger(noisy_logger).propagate = False

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a module-level logger, configuring logging on first use."""
    configure_logging()
    return logging.getLogger(name)
