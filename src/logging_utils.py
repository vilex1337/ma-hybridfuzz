"""Shared logging configuration for MA-HybridFuzz."""

from __future__ import annotations

import logging
from pathlib import Path

VERBOSE_LEVEL = 15
VERBOSE_LEVEL_NAME = "VERBOSE"


def install_verbose_level() -> None:
    """Register the level used by verbosity=2."""
    if logging.getLevelName(VERBOSE_LEVEL) != VERBOSE_LEVEL_NAME:
        logging.addLevelName(VERBOSE_LEVEL, VERBOSE_LEVEL_NAME)


def verbosity_to_level(verbosity: int) -> int:
    """Map CLI/config verbosity values to Python logging levels."""
    if verbosity <= 0:
        return logging.WARNING
    if verbosity == 1:
        return logging.INFO
    if verbosity == 2:
        return VERBOSE_LEVEL
    return logging.DEBUG


def configure_logging(verbosity: int = 1, log_file: str | Path | None = None) -> None:
    """Configure root logging for console and optional file output."""
    install_verbose_level()
    level = verbosity_to_level(verbosity)
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s]: %(message)s")

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    root.addHandler(console_handler)

    if log_file is not None:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        root.addHandler(file_handler)


install_verbose_level()
