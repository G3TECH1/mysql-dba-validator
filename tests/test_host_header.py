"""Host header check: the web app answers only its own host names.

Contract:
- requests whose Host is 127.0.0.1 or localhost (any port) reach the routes;
- any other Host, such as another website's DNS name rebound to 127.0.0.1, the
  test client's default "testserver", or [::1] (the web app listens on IPv4
  loopback only), gets 400 on every route before the route runs, so no MySQL
  connection is attempted and no evidence is collected;
- the refusal still carries the security headers;
- MDV_ALLOWED_HOSTS adds exact host names for a trusted self-hosted setup;
  wildcards and anything that is not a plain host name or IPv4 address are ignored,
  so the check cannot be turned off.

Verification level: unit / TestClient. No MySQL server is contacted.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

import backend.main as backend_main

LOOPBACK_URLS = ("http://127.0.0.1:8420", "http://localhost:8420", "http://localhost")
FOREIGN_HOSTS = (
    "evil.example:8420",                      # DNS rebinding to 127.0.0.1
    "127.0.0.1.evil.example:8420",
    "testserver",                             # TestClient default
    "10.0.0.5:8420",                          # a LAN address, not configured
    "[::1]:8420",                             # not served: IPv4 loopback only
)
LOCAL_LOGIN = {"host": "127.0.0.1", "port": 3306, "username": "u", "password": "Host-Check-Secret-6610"}
ROUTES = (
    ("GET", "/", None),
    ("GET", "/api/health", None),
    ("GET", "/static/assets/favicon.svg", None),
    ("POST", "/api/validate", {"sql": "SELECT 1"}),
    ("POST", "/api/validate", {"sql": "SELECT 1", **LOCAL_LOGIN, "database": "app"}),
    ("POST", "/api/connections/test", LOCAL_LOGIN),
    ("POST", "/api/connections/discover-databases", LOCAL_LOGIN),
    ("POST", "/api/heartbeat", None),
    ("POST", "/api/update-status", None),
    ("POST", "/api/evidence", {"sql": "SELECT 1"}),
)


@pytest.fixture
def no_database(monkeypatch):
    """Record any attempt to reach MySQL; refused requests must not make one."""
    calls = []

    def record(name):
        def fake(*args, **kwargs):
            calls.append(name)
            raise AssertionError(f"{name} must not run for a refused Host")
        return fake

    for name in ("probe_connection", "discover_databases", "open_evidence_connection", "get_client"):
        monkeypatch.setattr(backend_main, name, record(name))
    return calls


@pytest.mark.parametrize("host", FOREIGN_HOSTS)
@pytest.mark.parametrize("method, path, body", ROUTES)
def test_foreign_host_is_refused_before_any_route_runs(no_database, host, method, path, body):
    client = TestClient(backend_main.app, base_url="http://127.0.0.1:8420")
    response = client.request(method, path, json=body,
                              headers={"Host": host, "Origin": f"http://{host}"})

    assert response.status_code == 400
    assert response.text == "Invalid host header"
    assert no_database == []
    assert "access-control-allow-origin" not in response.headers
    assert "Host-Check-Secret-6610" not in response.text


def test_default_test_client_host_is_refused():
    response = TestClient(backend_main.app).get("/api/health")

    assert response.status_code == 400


def test_refusal_keeps_the_security_headers():
    response = TestClient(backend_main.app, base_url="http://evil.example:8420").get("/api/health")

    assert response.status_code == 400
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("base_url", LOOPBACK_URLS)
def test_loopback_hosts_reach_the_routes(base_url):
    client = TestClient(backend_main.app, base_url=base_url)

    assert client.get("/").status_code == 200
    assert client.get("/api/health").status_code == 200
    response = client.post("/api/validate", json={"sql": "SELECT 1"})
    assert response.status_code == 200
    assert response.json()["statement_count"] == 1


def test_loopback_connection_test_still_reaches_the_local_probe(monkeypatch):
    seen = []
    monkeypatch.setattr(backend_main, "probe_connection",
                        lambda session: seen.append(session.connection_profile.host)
                        or {"status": "ok", "connected": True})
    client = TestClient(backend_main.app, base_url="http://127.0.0.1:8420")

    response = client.post("/api/connections/test", json=LOCAL_LOGIN)

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "connected": True}
    assert seen == ["127.0.0.1"]


def test_the_check_is_registered_without_www_redirect():
    middleware = next(m for m in backend_main.app.user_middleware
                      if m.cls.__name__ == "TrustedHostMiddleware")

    assert middleware.kwargs["allowed_hosts"] == ["127.0.0.1", "localhost"]
    assert middleware.kwargs["www_redirect"] is False


def test_default_allowed_hosts_are_the_loopback_names(monkeypatch):
    monkeypatch.delenv("MDV_ALLOWED_HOSTS", raising=False)

    assert backend_main.configured_allowed_hosts() == ["127.0.0.1", "localhost"]


def test_configured_host_names_are_added(monkeypatch):
    monkeypatch.setenv("MDV_ALLOWED_HOSTS", " Review.Internal , 10.0.0.5,localhost,")

    assert backend_main.configured_allowed_hosts() == [
        "127.0.0.1", "localhost", "review.internal", "10.0.0.5"]


@pytest.mark.parametrize("entry", [
    "*", "*.example.com", "evil.*", "review.internal:8420", "[::1]", "a b",
    "-bad.example", "bad-.example", "bad..example", ".example", "évil.example",
])
def test_wildcards_and_malformed_entries_are_ignored(monkeypatch, entry):
    monkeypatch.setenv("MDV_ALLOWED_HOSTS", entry)

    assert backend_main.configured_allowed_hosts() == ["127.0.0.1", "localhost"]


def test_configured_host_is_served_and_a_wildcard_does_not_open_the_check(monkeypatch):
    monkeypatch.setenv("MDV_ALLOWED_HOSTS", "review.internal,*")
    importlib.reload(backend_main)
    try:
        configured = TestClient(backend_main.app, base_url="https://review.internal")
        assert configured.get("/api/health").status_code == 200
        assert configured.post("/api/validate", json={"sql": "SELECT 1"}).status_code == 200

        for base_url in ("http://evil.example:8420", "http://testserver"):
            other = TestClient(backend_main.app, base_url=base_url)
            assert other.get("/api/health").status_code == 400
        loopback = TestClient(backend_main.app, base_url="http://127.0.0.1:8420")
        assert loopback.get("/api/health").status_code == 200
    finally:
        monkeypatch.delenv("MDV_ALLOWED_HOSTS", raising=False)
        importlib.reload(backend_main)
