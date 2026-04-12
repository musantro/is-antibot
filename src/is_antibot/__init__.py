"""Detect antibot protection from 30+ providers."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from urllib.parse import urlparse

logger = logging.getLogger("is_antibot")

# Detection type constants
_HEADERS = "headers"
_COOKIES = "cookies"
_HTML = "html"
_URL = "url"
_STATUS_CODE = "status_code"


@dataclass(frozen=True)
class AntibotResult:
    """Result of antibot detection."""

    detected: bool
    provider: str | None
    detection: str | None


def _load_providers() -> list[dict]:
    """Load provider definitions from the bundled providers.json."""
    source = resources.files("is_antibot").joinpath("providers.json")
    return json.loads(source.read_text(encoding="utf-8"))["providers"]


_PROVIDERS: list[dict] = _load_providers()


def _create_get_header(headers: Mapping[str, str | list[str] | None]):
    """Create a header getter function."""
    return lambda name: headers.get(name)


def create_test_pattern(value: str | None):
    """Create a pattern checker for the given value.

    Returns a function that checks whether a pattern (regex or string)
    matches the given value.
    """
    if not value:
        return lambda pattern: False
    lower_value = value.lower()

    def test(pattern: re.Pattern[str] | str) -> bool:
        if isinstance(pattern, re.Pattern):
            try:
                return pattern.search(value) is not None
            except Exception:
                return False
        return pattern.lower() in lower_value

    return test


def _split_set_cookie_string(cookie_str: str | list[str] | None) -> list[str]:
    """Split a Set-Cookie header string into individual cookie strings.

    Handles comma-separated cookies while correctly preserving commas in
    Expires date values. Port of the cookie-es splitSetCookieString algorithm.
    """
    if cookie_str is None:
        return []
    if isinstance(cookie_str, list):
        return cookie_str
    if not cookie_str:
        return []

    cookies: list[str] = []
    pos = 0
    start = 0
    length = len(cookie_str)

    while pos < length:
        # Scan for the next comma
        while pos < length and cookie_str[pos] != ",":
            pos += 1

        if pos >= length:
            break

        # Found a comma at pos. Look ahead to see if next token is a cookie name (has '=')
        lookahead = pos + 1
        # skip whitespace
        while lookahead < length and cookie_str[lookahead] == " ":
            lookahead += 1

        # Find next '=' or ';' to determine if this starts a new cookie
        scan = lookahead
        is_new_cookie = False
        while scan < length:
            ch = cookie_str[scan]
            if ch == "=":
                is_new_cookie = True
                break
            if ch == ";" or ch == ",":
                break
            scan += 1

        if is_new_cookie:
            # This comma separates two cookies
            cookies.append(cookie_str[start:pos].strip())
            start = pos + 1
            # skip whitespace after comma
            while start < length and cookie_str[start] == " ":
                start += 1
            pos = start
        else:
            # Comma is part of a date value (e.g., "Thu, 26-Mar-26 ...")
            pos += 1

    # Append the remaining segment
    remaining = cookie_str[start:].strip()
    if remaining:
        cookies.append(remaining)

    return cookies


def create_has_cookie(headers: Mapping[str, str | list[str] | None]):
    """Create a function that checks for cookie presence in Set-Cookie headers.

    Returns a function that takes a cookie prefix pattern and returns True if
    any Set-Cookie value starts with that pattern.
    """
    cookies = _split_set_cookie_string(headers.get("set-cookie"))

    def has_cookie(pattern: str) -> bool:
        return any(c.startswith(pattern) for c in cookies)

    return has_cookie


def _get_header_names(headers: Mapping[str, str | list[str] | None]) -> list[str]:
    """Return all header names as a list."""
    return list(headers.keys())


def _get_domain(url: str) -> str:
    """Extract the registrable domain from a URL (e.g. 'www.reddit.com' -> 'reddit.com')."""
    hostname = urlparse(url).hostname or ""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _compile_regex(pattern: str, flags: str = "") -> re.Pattern[str]:
    """Compile a regex pattern with the given flag string."""
    flag_map = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL, "u": re.UNICODE}
    flag_value = 0
    for ch in flags:
        flag_value |= flag_map.get(ch, 0)
    return re.compile(pattern, flag_value)


# Pre-compile all regex patterns in provider definitions at import time.
_REGEX_CACHE: dict[tuple[str, str], re.Pattern[str]] = {}


def _get_regex(pattern: str, flags: str = "") -> re.Pattern[str]:
    """Get a compiled regex, using a cache to avoid recompilation."""
    key = (pattern, flags)
    compiled = _REGEX_CACHE.get(key)
    if compiled is None:
        compiled = _compile_regex(pattern, flags)
        _REGEX_CACHE[key] = compiled
    return compiled


def _match_rule(  # noqa: C901
    rule: dict,
    *,
    get_header,
    has_cookie,
    html_has,
    url_has,
    header_names: list[str],
    status_code: int | None,
    detection_type: str,
) -> bool:
    """Evaluate a single rule against the current response data."""
    # --- header rules ---
    if "header" in rule:
        header_val = get_header(rule["header"])

        if "equals" in rule:
            return header_val == rule["equals"]

        if "startsWith" in rule:
            return header_val is not None and str(header_val).startswith(rule["startsWith"])

        if "oneOf" in rule:
            return header_val in rule["oneOf"]

        if "except" in rule:
            # exists-except: header present and value != except
            return header_val is not None and str(header_val).lower() != rule["except"].lower()

        if "exists" in rule:
            return header_val is not None

    # --- header name pattern ---
    if "headerNamePattern" in rule:
        regex = _get_regex(rule["headerNamePattern"], rule.get("flags", ""))
        return any(regex.search(name) for name in header_names)

    # --- cookie rules ---
    if "cookie" in rule:
        return has_cookie(rule["cookie"])

    # --- status code ---
    if "status" in rule:
        return status_code == rule["status"]

    # --- contains (html or url) ---
    if "contains" in rule:
        matcher = html_has if detection_type == _HTML else url_has
        return matcher(rule["contains"])

    # --- regex (html or url) ---
    if "regex" in rule:
        regex = _get_regex(rule["regex"], rule.get("flags", "i"))
        matcher = html_has if detection_type == _HTML else url_has
        return matcher(regex)

    return False


def _create_result(*, detected: bool, provider: str | None, detection: str | None) -> AntibotResult:
    """Create and log an antibot detection result."""
    logger.debug("detected=%s provider=%s detection=%s", detected, provider, detection)
    return AntibotResult(detected=detected, provider=provider, detection=detection)


def _detect(
    headers: Mapping[str, str | list[str] | None],
    html: str,
    url: str,
    status_code: int | None,
) -> AntibotResult:
    """Run the full detection chain. Returns on first match."""
    get_header = _create_get_header(headers)
    has_cookie = create_has_cookie(headers)
    html_has = create_test_pattern(html)
    url_has = create_test_pattern(url)
    header_names = _get_header_names(headers)
    domain = _get_domain(url)

    for provider in _PROVIDERS:
        for detection in provider["detections"]:
            # Skip domain-scoped detections that don't match
            if "domain" in detection and detection["domain"] != domain:
                continue

            detection_type = detection["type"]
            rules = detection["rules"]

            matched = any(
                _match_rule(
                    rule,
                    get_header=get_header,
                    has_cookie=has_cookie,
                    html_has=html_has,
                    url_has=url_has,
                    header_names=header_names,
                    status_code=status_code,
                    detection_type=detection_type,
                )
                for rule in rules
            )

            if matched:
                return _create_result(detected=True, provider=provider["name"], detection=detection_type)

    return _create_result(detected=False, provider=None, detection=None)


def is_antibot(
    *,
    headers: Mapping[str, str | list[str] | None] | None = None,
    html: str | None = None,
    body: str | None = None,
    url: str | None = None,
    status_code: int | None = None,
    status: int | None = None,
) -> AntibotResult:
    """Detect antibot protection from response data.

    Args:
        headers: Response headers as a dict-like mapping.
        html: Response HTML body.
        body: Alias for html.
        url: The request URL.
        status_code: HTTP status code.
        status: Alias for status_code.

    Returns:
        AntibotResult with detected, provider, and detection fields.
    """
    return _detect(
        headers=headers or {},
        html=html or body or "",
        url=url or "",
        status_code=status_code if status_code is not None else status,
    )


__all__ = ["is_antibot", "create_test_pattern", "create_has_cookie", "AntibotResult"]
