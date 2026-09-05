"""Dedicated rotating diagnostics for Microsoft Family Safety development builds.

This module deliberately never writes credential values.  Tokens and cookie
values are represented by short SHA-256 fingerprints so credential rotation can
be correlated across requests without making the resulting log file itself a
credential store.
"""
from __future__ import annotations

import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import re
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)
_PACKAGE_LOGGER_NAME = "custom_components.microsoft_family_safety"
_HANDLER_MARKER = "_hafs_dedicated_debug_handler"
_HOOK_MARKER = "_hafs_dedicated_debug_hook_v1"
DEBUG_BUILD_ID = "2.0.5-debug-20260905-1"
DEBUG_LOG_FILENAME = "microsoft_family_safety_debug.log"
DEBUG_LOG_MAX_BYTES = 10 * 1024 * 1024
DEBUG_LOG_BACKUPS = 5

_SECRET_KEY_RE = re.compile(
    r"(?i)(\b(?:access_token|refresh_token|web_family_token|"
    r"__RequestVerificationToken|authorization|cookie|set-cookie|"
    r"client_secret|password|oauth_code|epctrc|code)\b\s*[=:]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+\-/=]+")
_MSAUTH_RE = re.compile(r"(?i)(MSAuth1\.0\s+usertoken=\")[^\"]+(\")")


def _fingerprint(value: Any) -> str | None:
    """Return a stable non-reversible short fingerprint for a secret value."""
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]


def _secret_meta(value: Any) -> dict[str, Any]:
    text = "" if value is None else str(value)
    return {
        "present": bool(text),
        "length": len(text),
        "fp": _fingerprint(text),
    }


def _safe_url(value: Any) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        parsed = urlsplit(str(value))
        port = parsed.port
    except ValueError:
        return {"invalid": True}
    from urllib.parse import parse_qsl

    return {
        "scheme": parsed.scheme or None,
        "host": parsed.hostname,
        "port": port,
        "path": parsed.path or "/",
        "query_keys": sorted(key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)),
    }


def _safe_mapping(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    result: dict[str, Any] = {}
    for key, item in value.items():
        lowered = str(key).lower()
        if any(part in lowered for part in ("token", "secret", "password", "cookie", "authorization", "code")):
            result[str(key)] = _secret_meta(item)
        elif isinstance(item, Mapping):
            result[str(key)] = _safe_mapping(item)
        elif isinstance(item, (list, tuple)):
            result[str(key)] = f"<{type(item).__name__} len={len(item)}>"
        else:
            text = repr(item)
            result[str(key)] = text if len(text) <= 500 else text[:500] + "..."
    return result


def _cookie_item_from_mapping(cookie: Mapping[str, Any]) -> dict[str, Any]:
    value = cookie.get("value")
    return {
        "name": str(cookie.get("name") or ""),
        "domain": str(cookie.get("domain") or ""),
        "path": str(cookie.get("path") or "/"),
        "secure": bool(cookie.get("secure")),
        "httpOnly": bool(cookie.get("httpOnly") or cookie.get("httponly")),
        "sameSite": cookie.get("sameSite") or cookie.get("samesite"),
        "expires": cookie.get("expires"),
        "value_len": len(str(value or "")),
        "value_fp": _fingerprint(value),
    }


def _cookie_item_from_jar(cookie: Any) -> dict[str, Any]:
    try:
        http_only = bool(cookie.has_nonstandard_attr("HttpOnly"))
    except Exception:
        try:
            http_only = bool(cookie["httponly"])
        except Exception:
            http_only = False
    try:
        same_site = cookie.get_nonstandard_attr("SameSite")
    except Exception:
        same_site = None
    try:
        expires = cookie.expires
    except Exception:
        try:
            expires = cookie["expires"]
        except Exception:
            expires = None
    name = getattr(cookie, "name", None) or getattr(cookie, "key", "")
    value = getattr(cookie, "value", "")
    try:
        domain = cookie.domain
    except Exception:
        try:
            domain = cookie["domain"]
        except Exception:
            domain = ""
    try:
        path = cookie.path
    except Exception:
        try:
            path = cookie["path"]
        except Exception:
            path = "/"
    try:
        secure = bool(cookie.secure)
    except Exception:
        try:
            secure = bool(cookie["secure"])
        except Exception:
            secure = False
    return {
        "name": str(name or ""),
        "domain": str(domain or ""),
        "path": str(path or "/"),
        "secure": secure,
        "httpOnly": http_only,
        "sameSite": same_site,
        "expires": expires,
        "value_len": len(str(value or "")),
        "value_fp": _fingerprint(value),
    }


def _cookie_generation(items: list[dict[str, Any]]) -> str:
    material = [
        (
            item.get("name"),
            item.get("domain"),
            item.get("path"),
            item.get("value_fp"),
            item.get("expires"),
        )
        for item in sorted(
            items,
            key=lambda item: (
                str(item.get("domain") or ""),
                str(item.get("path") or ""),
                str(item.get("name") or ""),
            ),
        )
    ]
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:12]


def _stored_cookie_snapshot(api: Any) -> dict[str, Any]:
    items = [
        _cookie_item_from_mapping(cookie)
        for cookie in list(getattr(api, "_web_cookies", None) or [])
        if isinstance(cookie, Mapping)
    ]
    return {
        "count": len(items),
        "generation": _cookie_generation(items),
        "items": sorted(items, key=lambda x: (x["domain"], x["path"], x["name"])),
    }


def _live_cookie_snapshot(api: Any) -> dict[str, Any]:
    session = getattr(api, "_web_session", None)
    if session is None:
        return {"session": "none", "count": 0, "generation": None, "items": []}
    try:
        closed = bool(session.closed)
    except Exception:
        closed = False
    if closed:
        return {"session": "closed", "count": 0, "generation": None, "items": []}
    try:
        items = [_cookie_item_from_jar(cookie) for cookie in session.cookie_jar]
    except Exception as err:
        return {
            "session": "open",
            "error": type(err).__name__,
            "count": -1,
            "generation": None,
            "items": [],
        }
    return {
        "session": "open",
        "count": len(items),
        "generation": _cookie_generation(items),
        "items": sorted(items, key=lambda x: (x["domain"], x["path"], x["name"])),
    }


def _web_state_snapshot(api: Any) -> dict[str, Any]:
    authenticator = getattr(api, "_authenticator", None)
    relationships = getattr(api, "_relationship_tokens", {}) or {}
    relationship_meta: dict[str, Any] = {}
    for child_id, raw in relationships.items():
        token = raw[0] if isinstance(raw, tuple) and raw else None
        expires = raw[1] if isinstance(raw, tuple) and len(raw) > 1 else None
        relationship_meta[str(child_id)] = {
            "expires": expires,
            "token": _secret_meta(token),
        }
    return {
        "last_web_error_code": getattr(api, "last_web_error_code", None),
        "web_session_state": getattr(api, "web_session_state", None),
        "web_session_last_checked": getattr(api, "web_session_last_checked", None),
        "web_session_last_http_status": getattr(api, "web_session_last_http_status", None),
        "web_api_state": getattr(api, "web_api_state", None),
        "web_api_last_checked": getattr(api, "web_api_last_checked", None),
        "web_api_last_http_status": getattr(api, "web_api_last_http_status", None),
        "web_api_last_endpoint": getattr(api, "web_api_last_endpoint", None),
        "screentime_policy_status": getattr(api, "screentime_policy_status", None),
        "screentime_policy_source": getattr(api, "screentime_policy_source", None),
        "family_context_state": getattr(api, "family_context_state", None),
        "family_context_last_checked": getattr(api, "family_context_last_checked", None),
        "family_context_last_http_status": getattr(api, "family_context_last_http_status", None),
        "family_context_last_path": getattr(api, "family_context_last_path", None),
        "family_token_source": getattr(api, "family_token_source", None),
        "family_token": _secret_meta(getattr(api, "_web_csrf", None)),
        "family_referer": _safe_url(getattr(api, "_family_referer", None)),
        "family_auth_required_until": getattr(api, "_family_auth_required_until", None),
        "family_auth_required_warned": getattr(api, "_family_auth_required_warned", None),
        "web_transport": getattr(api, "_hafs_web_transport", None),
        "web_timeout_phase": getattr(api, "_hafs_web_timeout_phase", None),
        "web_transport_error": getattr(api, "_hafs_web_transport_error", None),
        "web_probe_backoff_until": getattr(api, "_web_probe_backoff_until", None),
        "web_probe_backoff_error": getattr(api, "_web_probe_backoff_error", None),
        "family_web_backoff_until": getattr(api, "_family_web_backoff_until", None),
        "mobile_access_token": _secret_meta(
            getattr(authenticator, "access_token", None) if authenticator else None
        ),
        "mobile_refresh_token": _secret_meta(
            getattr(authenticator, "refresh_token", None) if authenticator else None
        ),
        "mobile_expires": str(getattr(authenticator, "expires", None)) if authenticator else None,
        "relationship_tokens": relationship_meta,
        "stored_cookies": _stored_cookie_snapshot(api),
        "live_cookies": _live_cookie_snapshot(api),
    }


def _runtime_state_snapshot(coordinator: Any) -> dict[str, Any]:
    state = dict(getattr(coordinator, "_runtime_auth_state", {}) or {})
    cookies = state.get("web_cookies")
    cookie_items = [
        _cookie_item_from_mapping(c)
        for c in cookies or []
        if isinstance(c, Mapping)
    ]
    return {
        "keys": sorted(state.keys()),
        "anchor": str(state.get("anchor") or "")[:16] or None,
        "updated_at": state.get("updated_at"),
        "refresh_token": _secret_meta(state.get("refresh_token")),
        "family_token": _secret_meta(state.get("web_family_token")),
        "family_referer": _safe_url(state.get("web_family_referer")),
        "family_token_rejected": state.get("web_family_token_rejected"),
        "cookie_count": len(cookie_items),
        "cookie_generation": _cookie_generation(cookie_items),
    }


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))


class _RedactingFormatter(logging.Formatter):
    """Last-resort redaction for messages produced by existing integration logs."""

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        rendered = _SECRET_KEY_RE.sub(r"\1<redacted>", rendered)
        rendered = _BEARER_RE.sub(r"\1<redacted>", rendered)
        rendered = _MSAUTH_RE.sub(r"\1<redacted>\2", rendered)
        return rendered


def setup_debug_file_logging(hass: HomeAssistant, entry: Any | None = None) -> str:
    """Attach a dedicated rotating DEBUG handler to the integration logger tree."""
    package_logger = logging.getLogger(_PACKAGE_LOGGER_NAME)
    path = hass.config.path(DEBUG_LOG_FILENAME)

    handler = next(
        (
            candidate
            for candidate in package_logger.handlers
            if getattr(candidate, _HANDLER_MARKER, False)
        ),
        None,
    )
    if handler is None:
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
        "========== Microsoft Family Safety dedicated diagnostics start "
        "build=%s entry=%s log=%s max_bytes=%d backups=%d ==========" ,
        DEBUG_BUILD_ID,
        _fingerprint(getattr(entry, "entry_id", None)),
        path,
        DEBUG_LOG_MAX_BYTES,
        DEBUG_LOG_BACKUPS,
    )
    return path


def install_diagnostic_hooks() -> None:
    """Instrument credential/session lifecycle methods with sanitized snapshots."""
    from .api_client import FamilySafetyWebAPI
    from .coordinator import FamilySafetyDataUpdateCoordinator
    from ._httpx_web_adapter import _RequestContext

    current = FamilySafetyWebAPI.set_web_cookies
    if not getattr(current, _HOOK_MARKER, False):
        original = current

        def patched_set_web_cookies(self, cookies, *, family_token=None, family_referer=None):
            incoming_items = [
                _cookie_item_from_mapping(c)
                for c in (cookies or [])
                if isinstance(c, Mapping)
            ]
            _LOGGER.debug(
                "DIAG set_web_cookies BEGIN incoming_count=%d incoming_generation=%s "
                "family_token=%s family_referer=%s before=%s",
                len(incoming_items),
                _cookie_generation(incoming_items),
                _json(_secret_meta(family_token)),
                _json(_safe_url(family_referer)),
                _json(_web_state_snapshot(self)),
            )
            try:
                return original(
                    self,
                    cookies,
                    family_token=family_token,
                    family_referer=family_referer,
                )
            finally:
                _LOGGER.debug("DIAG set_web_cookies END after=%s", _json(_web_state_snapshot(self)))

        setattr(patched_set_web_cookies, _HOOK_MARKER, True)
        FamilySafetyWebAPI.set_web_cookies = patched_set_web_cookies

    current = FamilySafetyWebAPI.sync_web_cookies_from_session
    if not getattr(current, _HOOK_MARKER, False):
        original = current

        def patched_sync(self):
            before_stored = _stored_cookie_snapshot(self)
            before_live = _live_cookie_snapshot(self)
            changed = original(self)
            after_stored = _stored_cookie_snapshot(self)
            after_live = _live_cookie_snapshot(self)
            if changed or before_stored.get("generation") != after_stored.get("generation"):
                _LOGGER.info(
                    "DIAG COOKIE_ROTATION changed=%s stored_generation=%s->%s "
                    "live_generation=%s->%s stored_count=%s->%s live_count=%s->%s "
                    "stored_after=%s",
                    changed,
                    before_stored.get("generation"),
                    after_stored.get("generation"),
                    before_live.get("generation"),
                    after_live.get("generation"),
                    before_stored.get("count"),
                    after_stored.get("count"),
                    before_live.get("count"),
                    after_live.get("count"),
                    _json(after_stored),
                )
            return changed

        setattr(patched_sync, _HOOK_MARKER, True)
        FamilySafetyWebAPI.sync_web_cookies_from_session = patched_sync

    current = FamilySafetyWebAPI._warm_family_context
    if not getattr(current, _HOOK_MARKER, False):
        original = current

        async def patched_warm_family(self):
            started = time.monotonic()
            before = _web_state_snapshot(self)
            _LOGGER.info("DIAG FAMILY_CONTEXT_BEGIN before=%s", _json(before))
            try:
                result = await original(self)
            except Exception:
                _LOGGER.exception(
                    "DIAG FAMILY_CONTEXT_EXCEPTION elapsed=%.3fs state=%s",
                    time.monotonic() - started,
                    _json(_web_state_snapshot(self)),
                )
                raise
            after = _web_state_snapshot(self)
            _LOGGER.info(
                "DIAG FAMILY_CONTEXT_END elapsed=%.3fs result=%s token_rotated=%s "
                "cookie_rotated=%s after=%s",
                time.monotonic() - started,
                _json(_secret_meta(result)),
                before["family_token"].get("fp") != after["family_token"].get("fp"),
                before["stored_cookies"].get("generation")
                != after["stored_cookies"].get("generation"),
                _json(after),
            )
            return result

        setattr(patched_warm_family, _HOOK_MARKER, True)
        FamilySafetyWebAPI._warm_family_context = patched_warm_family

    current = FamilySafetyWebAPI.async_check_web_session
    if not getattr(current, _HOOK_MARKER, False):
        original = current

        async def patched_check(self):
            started = time.monotonic()
            _LOGGER.debug("DIAG SESSION_PROBE_BEGIN state=%s", _json(_web_state_snapshot(self)))
            try:
                result = await original(self)
            except Exception:
                _LOGGER.exception(
                    "DIAG SESSION_PROBE_EXCEPTION elapsed=%.3fs state=%s",
                    time.monotonic() - started,
                    _json(_web_state_snapshot(self)),
                )
                raise
            _LOGGER.debug(
                "DIAG SESSION_PROBE_END elapsed=%.3fs result=%s state=%s",
                time.monotonic() - started,
                result,
                _json(_web_state_snapshot(self)),
            )
            return result

        setattr(patched_check, _HOOK_MARKER, True)
        FamilySafetyWebAPI.async_check_web_session = patched_check

    current = FamilySafetyWebAPI._web_request
    if not getattr(current, _HOOK_MARKER, False):
        original = current

        async def patched_web_request(
            self,
            method,
            url,
            params=None,
            json_data=None,
            relationship_child_id=None,
        ):
            started = time.monotonic()
            before = _web_state_snapshot(self)
            _LOGGER.info(
                "DIAG WEB_REQUEST_BEGIN method=%s target=%s params=%s json=%s "
                "relationship_child_id=%s state=%s",
                str(method).upper(),
                _json(_safe_url(url)),
                _json(_safe_mapping(params)),
                _json(_safe_mapping(json_data)),
                relationship_child_id,
                _json(before),
            )
            try:
                result = await original(
                    self,
                    method,
                    url,
                    params=params,
                    json_data=json_data,
                    relationship_child_id=relationship_child_id,
                )
            except Exception:
                _LOGGER.exception(
                    "DIAG WEB_REQUEST_EXCEPTION elapsed=%.3fs method=%s target=%s state=%s",
                    time.monotonic() - started,
                    str(method).upper(),
                    _json(_safe_url(url)),
                    _json(_web_state_snapshot(self)),
                )
                raise
            after = _web_state_snapshot(self)
            if isinstance(result, Mapping):
                result_meta: Any = {"type": "dict", "keys": sorted(str(k) for k in result.keys())[:100]}
            elif isinstance(result, list):
                result_meta = {"type": "list", "length": len(result)}
            else:
                result_meta = {"type": type(result).__name__, "is_none": result is None}
            _LOGGER.info(
                "DIAG WEB_REQUEST_END elapsed=%.3fs result=%s token_rotated=%s "
                "cookie_rotated=%s state=%s",
                time.monotonic() - started,
                _json(result_meta),
                before["family_token"].get("fp") != after["family_token"].get("fp"),
                before["stored_cookies"].get("generation")
                != after["stored_cookies"].get("generation"),
                _json(after),
            )
            return result

        setattr(patched_web_request, _HOOK_MARKER, True)
        FamilySafetyWebAPI._web_request = patched_web_request

    current = _RequestContext.__aenter__
    if not getattr(current, _HOOK_MARKER, False):
        original = current

        async def patched_httpx_enter(self):
            started = time.monotonic()
            _LOGGER.debug(
                "DIAG HTTPX_BEGIN method=%s target=%s kw_keys=%s",
                str(getattr(self, "_method", "")).upper(),
                _json(_safe_url(getattr(self, "_url", None))),
                sorted(str(k) for k in (getattr(self, "_kwargs", {}) or {}).keys()),
            )
            try:
                response_adapter = await original(self)
            except Exception:
                _LOGGER.exception(
                    "DIAG HTTPX_EXCEPTION elapsed=%.3fs method=%s target=%s",
                    time.monotonic() - started,
                    str(getattr(self, "_method", "")).upper(),
                    _json(_safe_url(getattr(self, "_url", None))),
                )
                raise
            response = getattr(response_adapter, "_response", None)
            set_cookie_names: list[str] = []
            if response is not None:
                try:
                    raw_headers = response.headers.get_list("set-cookie")
                except Exception:
                    raw = response.headers.get("set-cookie") if response.headers else None
                    raw_headers = [raw] if raw else []
                for raw in raw_headers:
                    if not raw:
                        continue
                    first = str(raw).split(";", 1)[0]
                    if "=" in first:
                        set_cookie_names.append(first.split("=", 1)[0].strip())
            location = response.headers.get("location") if response is not None else None
            _LOGGER.debug(
                "DIAG HTTPX_END elapsed=%.3fs status=%s final=%s content_type=%s "
                "content_length=%s location=%s set_cookie_count=%d set_cookie_names=%s",
                time.monotonic() - started,
                getattr(response_adapter, "status", None),
                _json(_safe_url(getattr(response_adapter, "url", None))),
                response.headers.get("content-type") if response is not None else None,
                response.headers.get("content-length") if response is not None else None,
                _json(_safe_url(location)),
                len(set_cookie_names),
                sorted(set(set_cookie_names)),
            )
            return response_adapter

        setattr(patched_httpx_enter, _HOOK_MARKER, True)
        _RequestContext.__aenter__ = patched_httpx_enter

    current = FamilySafetyDataUpdateCoordinator._async_load_web_cookies
    if not getattr(current, _HOOK_MARKER, False):
        original = current

        async def patched_load(self):
            _LOGGER.info(
                "DIAG LOAD_CREDENTIALS_BEGIN native_web_auth=%s loaded=%s runtime=%s web=%s",
                getattr(self, "_native_web_auth", None),
                getattr(self, "_web_cookies_loaded", None),
                _json(_runtime_state_snapshot(self)),
                _json(_web_state_snapshot(self.web_api)) if self.web_api else None,
            )
            try:
                return await original(self)
            finally:
                _LOGGER.info(
                    "DIAG LOAD_CREDENTIALS_END native_web_auth=%s loaded=%s runtime=%s web=%s",
                    getattr(self, "_native_web_auth", None),
                    getattr(self, "_web_cookies_loaded", None),
                    _json(_runtime_state_snapshot(self)),
                    _json(_web_state_snapshot(self.web_api)) if self.web_api else None,
                )

        setattr(patched_load, _HOOK_MARKER, True)
        FamilySafetyDataUpdateCoordinator._async_load_web_cookies = patched_load

    current = FamilySafetyDataUpdateCoordinator._async_persist_runtime_auth
    if not getattr(current, _HOOK_MARKER, False):
        original = current

        async def patched_persist(
            self,
            *,
            refresh_token=None,
            web_cookies=None,
            family_token=None,
            family_referer=None,
        ):
            incoming_items = [
                _cookie_item_from_mapping(c)
                for c in (web_cookies or [])
                if isinstance(c, Mapping)
            ]
            before = _runtime_state_snapshot(self)
            _LOGGER.info(
                "DIAG PERSIST_AUTH_BEGIN refresh=%s cookies_count=%d cookies_generation=%s "
                "family_token=%s family_referer=%s before=%s",
                _json(_secret_meta(refresh_token)),
                len(incoming_items),
                _cookie_generation(incoming_items),
                _json(_secret_meta(family_token)),
                _json(_safe_url(family_referer)),
                _json(before),
            )
            try:
                return await original(
                    self,
                    refresh_token=refresh_token,
                    web_cookies=web_cookies,
                    family_token=family_token,
                    family_referer=family_referer,
                )
            finally:
                after = _runtime_state_snapshot(self)
                _LOGGER.info(
                    "DIAG PERSIST_AUTH_END changed=%s after=%s",
                    before != after,
                    _json(after),
                )

        setattr(patched_persist, _HOOK_MARKER, True)
        FamilySafetyDataUpdateCoordinator._async_persist_runtime_auth = patched_persist

    current = FamilySafetyDataUpdateCoordinator._async_update_data
    if not getattr(current, _HOOK_MARKER, False):
        original = current

        async def patched_update(self):
            setup_debug_file_logging(self.hass, getattr(self, "entry", None))
            started = time.monotonic()
            _LOGGER.info(
                "DIAG POLL_BEGIN entry=%s reauth_requested=%s reauth_reason=%s "
                "family_auth_required_polls=%s runtime=%s web=%s",
                _fingerprint(getattr(self.entry, "entry_id", None)),
                getattr(self, "_reauth_requested", None),
                getattr(self, "_reauth_reason", None),
                getattr(self, "_family_auth_required_polls", None),
                _json(_runtime_state_snapshot(self)),
                _json(_web_state_snapshot(self.web_api)) if self.web_api else None,
            )
            try:
                result = await original(self)
            except Exception:
                _LOGGER.exception(
                    "DIAG POLL_EXCEPTION elapsed=%.3fs reauth_requested=%s "
                    "reauth_reason=%s runtime=%s web=%s",
                    time.monotonic() - started,
                    getattr(self, "_reauth_requested", None),
                    getattr(self, "_reauth_reason", None),
                    _json(_runtime_state_snapshot(self)),
                    _json(_web_state_snapshot(self.web_api)) if self.web_api else None,
                )
                raise
            try:
                connection = self.connection_state()
            except Exception as err:
                connection = {"error": type(err).__name__}
            _LOGGER.info(
                "DIAG POLL_END elapsed=%.3fs accounts=%d devices=%d "
                "reauth_requested=%s reauth_reason=%s family_auth_required_polls=%s "
                "connection=%s runtime=%s web=%s",
                time.monotonic() - started,
                len((result or {}).get("accounts", {})) if isinstance(result, Mapping) else -1,
                len((result or {}).get("devices", {})) if isinstance(result, Mapping) else -1,
                getattr(self, "_reauth_requested", None),
                getattr(self, "_reauth_reason", None),
                getattr(self, "_family_auth_required_polls", None),
                _json(connection),
                _json(_runtime_state_snapshot(self)),
                _json(_web_state_snapshot(self.web_api)) if self.web_api else None,
            )
            return result

        setattr(patched_update, _HOOK_MARKER, True)
        FamilySafetyDataUpdateCoordinator._async_update_data = patched_update

    _LOGGER.info("Dedicated diagnostic lifecycle hooks installed build=%s", DEBUG_BUILD_ID)
