"""Whether a newer official release exists: an optional notice, never an updater.

One fixed GET, with no body, to the official repository's latest-release endpoint on the
GitHub REST API, at most once per backend start; the result is kept in memory. The
request carries only the fixed headers below: no SQL, login, target, schema or other
connection details. GitHub sees the requester's IP address and this User-Agent (which
names the installed version). Nothing is downloaded or installed.

The latest release is GitHub's most recent published release that is not a draft or a
prerelease. It is reported as newer only when its tag is a strict vX.Y.Z, numerically
greater than APP_VERSION, and its page is exactly the official release page for that tag.
Anything else (offline, timeout, failed TLS verification, any HTTP error including 403,
404 and 429 rate limiting, a redirect, an unexpected response) is "unavailable", never
"up to date". MDV_UPDATE_CHECK=off turns the check off: nothing is sent.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import threading
import urllib.request
from typing import Any, Optional

from .version import APP_VERSION

REPOSITORY = "realspinn/mysql-dba-validator"
LATEST_RELEASE_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASE_PAGE = f"https://github.com/{REPOSITORY}/releases/tag/"
REQUEST_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    "User-Agent": f"MySQL-DBA-Validator/{APP_VERSION}",
}
TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 256 * 1024
OFF_SWITCH = "MDV_UPDATE_CHECK"

UPDATE_AVAILABLE = "update_available"
UP_TO_DATE = "up_to_date"
UNAVAILABLE = "unavailable"
DISABLED = "disabled"

# No leading zeros, so the version text and its numbers map one to one.
_NUMBER = r"(0|[1-9][0-9]{0,3})"
_VERSION = re.compile(rf"{_NUMBER}\.{_NUMBER}\.{_NUMBER}\Z")

_lock = threading.Lock()
_result: Optional[dict] = None


def enabled() -> bool:
    return os.environ.get(OFF_SWITCH, "").strip().lower() != "off"


def check_for_update() -> dict:
    """The update state for the page; the first call per process does the one request."""
    global _result
    if not enabled():
        return {"state": DISABLED}
    with _lock:  # concurrent first calls wait for the one request instead of repeating it
        if _result is None:
            _result = _check()
        return dict(_result)


def _version(text: Any) -> Optional[tuple[int, int, int]]:
    match = _VERSION.match(text) if isinstance(text, str) else None
    return tuple(int(part) for part in match.groups()) if match else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is not followed: it ends as an HTTP error (unavailable)."""

    def redirect_request(self, *args, **kwargs):
        return None


def _open(request: urllib.request.Request):
    # Certificate and host name verification: ssl.create_default_context() requires both.
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context))
    return opener.open(request, timeout=TIMEOUT_SECONDS)


def _check() -> dict:
    current = _version(APP_VERSION)
    if current is None:
        return {"state": UNAVAILABLE}
    request = urllib.request.Request(LATEST_RELEASE_API, headers=REQUEST_HEADERS, method="GET")
    try:
        with _open(request) as response:
            if response.status != 200:
                return {"state": UNAVAILABLE}
            body = response.read(MAX_RESPONSE_BYTES + 1)
        release = json.loads(body) if len(body) <= MAX_RESPONSE_BYTES else None
    except Exception:  # network, TLS, HTTP (403/404/429, redirect) or JSON failure
        return {"state": UNAVAILABLE}
    if (not isinstance(release, dict) or release.get("draft") is not False
            or release.get("prerelease") is not False):
        return {"state": UNAVAILABLE}
    tag = release.get("tag_name")
    latest = _version(tag[1:]) if isinstance(tag, str) and tag.startswith("v") else None
    if latest is None or release.get("html_url") != RELEASE_PAGE + tag:
        return {"state": UNAVAILABLE}
    if latest <= current:
        return {"state": UP_TO_DATE}
    return {"state": UPDATE_AVAILABLE, "current": APP_VERSION, "version": tag[1:], "url": RELEASE_PAGE + tag}
