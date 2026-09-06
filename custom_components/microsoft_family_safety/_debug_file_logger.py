"""Passive rotating diagnostics for Microsoft Family Safety development builds.

This module only attaches a dedicated DEBUG file handler to the integration
logger tree. It deliberately does not monkey-patch or wrap any authentication,
HTTP, coordinator or config-flow method, so runtime behaviour stays identical
to upstream.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import platform
import re
import sys
from typing import Any

_LOGGER = logging.getLogger(__name__)
_PACKAGE_LOGGER_NAME = "custom_components.microsoft_family_safety"
_HANDLER_MARKER = "_hafs_passive_debug_handler"
DEBUG_BUILD_ID = "2.0.5-debug-20260906-2"
DEBUG_LOG_FILENAME = "microsoft_family_safety_debug.log"
DEBUG_LOG_MAX_BYTES = 10 * 1024 * 1024
DEBUG_LOG_BACKUPS = 5

_SECRET_KEY_RE = re.compile(
    r"(?i)(\b(?:access_token|refresh_token|web_family_token|"
    r"__RequestVerificationToken|authorization|cookie|set-cookie|"
    r"client_secret|password|oauth_code|epctrc)\b\s*[=:]\s*)"
    r'(?:"[^"]*"|\'[^\']*\'|[^\s,;&]+)'
)
_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+\-/=]+")
_MSAUTH_RE = re.compile(r'(?i)(MSAuth1\.0\s+usertoken=")[^"]+(")')


class _RedactingFormatter(logging.Formatter):
    """Redact obvious credentials from the dedicated diagnostic file."""

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        rendered = _SECRET_KEY_RE.sub(r"\1<redacted>", rendered)
        rendered = _BEARER_RE.sub(r"\1<redacted>", rendered)
        rendered = _MSAUTH_RE.sub(r"\1<redacted>\2", rendered)
        return rendered


def _resolve_log_path() -> Path:
    """Resolve the HA config directory without requiring a HomeAssistant object."""
    candidates = (
        os.environ.get("HASS_CONFIG"),
        "/config",
        os.getcwd(),
    )
    for raw in candidates:
        if not raw:
            continue
        path = Path(raw)
        try:
            if path.is_dir() and os.access(path, os.W_OK):
                return path / DEBUG_LOG_FILENAME
        except OSError:
            continue
    return Path(DEBUG_LOG_FILENAME)


def setup_debug_file_logging(*_args: Any, **_kwargs: Any) -> str | None:
    """Attach a passive rotating DEBUG handler.

    Logging must never be able to make integration setup fail.
    """
    package_logger = logging.getLogger(_PACKAGE_LOGGER_NAME)

    existing = next(
        (
            handler
            for handler in package_logger.handlers
            if getattr(handler, _HANDLER_MARKER, False)
        ),
        None,
    )
    if existing is not None:
        return str(getattr(existing, "baseFilename", DEBUG_LOG_FILENAME))

    path = _resolve_log_path()
    try:
        handler = RotatingFileHandler(
            path,
            maxBytes=DEBUG_LOG_MAX_BYTES,
            backupCount=DEBUG_LOG_BACKUPS,
            encoding="utf-8",
            delay=True,
        )
        setattr(handler, _HANDLER_MARKER, True)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(
            _RedactingFormatter(
                "%(asctime)s.%(msecs)03d %(levelname)s %(name)s "
                "[%(threadName)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        package_logger.addHandler(handler)
        package_logger.setLevel(logging.DEBUG)
        package_logger.info(
            "========== Microsoft Family Safety passive diagnostics start "
            "build=%s log=%s python=%s platform=%s pid=%s ==========",
            DEBUG_BUILD_ID,
            path,
            sys.version.replace("\n", " "),
            platform.platform(),
            os.getpid(),
        )
    except Exception as err:
        _LOGGER.warning(
            "Could not start dedicated Microsoft Family Safety debug file: %s",
            type(err).__name__,
        )
        return None
    return str(path)


def install_diagnostic_hooks() -> None:
    """Enable passive file logging only; intentionally install no hooks."""
    path = setup_debug_file_logging()
    if path:
        _LOGGER.debug(
            "Passive Microsoft Family Safety diagnostics enabled build=%s path=%s "
            "(no runtime methods patched)",
            DEBUG_BUILD_ID,
            path,
        )
