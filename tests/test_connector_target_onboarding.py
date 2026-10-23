"""Adding and re-approving company targets from the page.

The page may only *ask* for a target. The connector shows the exact request (host,
port, every resolved address, TLS trust) and a one-time code in its console, and
only that code, entered back in the same paired session, approves it. A request
never opens a connection. Trust is per target and fails closed: an unknown policy,
a missing or changed CA bundle, or an unusable store is never replaced by another
trust source, unverified TLS or plaintext.

Verification level: unit / TestClient. DNS, sockets and the MySQL server are fake;
the real PyMySQL Connection runs over an in-memory socket. No live MySQL or TLS
handshake is involved.
"""

import hashlib
import json
import logging
import re
import socket
import ssl
import sys

import pymysql
import pytest
from fastapi.testclient import TestClient

import connector.server as connector_server
from connector import launcher
from connector.policy import (
    CompanyTarget,
    TARGET_MODE_COMPANY,
    console_text,
    validate_company_target,
    validate_display_name,
)
from connector.registry_store import TargetRegistryStore
from connector.server import ConnectorRuntime, create_app, validate_ca_bundle
from tests.test_connector_connection_errors import (
    StreamSocket,
    cert_error,
    patch_connector_socket,
    server_greeting,
)
from tests.tls_test_ca import ca_pem, company_ca_path

ORIGIN = "http://127.0.0.1:8420"
HOST = "db.company.example"
ADDRESSES = ["203.0.113.10", "203.0.113.11"]
CODE_RE = re.compile(r"\n      ([0-9A-Z]{4}-[0-9A-Z]{4})\n")


# ---------------------------------------------------------------- helpers


@pytest.fixture
def dns(monkeypatch):
    answers = {HOST: list(ADDRESSES)}

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host not in answers:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in answers[host]]

    monkeypatch.setattr("connector.server.socket.getaddrinfo", fake_getaddrinfo)
    return answers


REAL_DRIVER = pymysql.connections.Connection


@pytest.fixture
def no_network(monkeypatch):
    """Records (and refuses) every socket or MySQL connection attempt."""
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("no connection may be opened here")

    patch_connector_socket(monkeypatch, refuse)
    monkeypatch.setattr(connector_server.pymysql, "connect", refuse)
    return attempts


def make_runtime(tmp_path, *, console=True):
    runtime = ConnectorRuntime(
        allowed_origins=[ORIGIN], company_tls_ca_path=company_ca_path(),
        registry_store=TargetRegistryStore(tmp_path / "targets.json"))
    runtime.console = []
    if console:
        runtime.approval_notifier = runtime.console.append
    return runtime


def pair(runtime, client=None):
    client = client or TestClient(create_app(runtime=runtime))
    code = runtime.issue_browser_pairing_token()
    response = client.post("/pair", headers={"Origin": ORIGIN, "Content-Type": "application/json"},
                           json={"pairing_token": code})
    assert response.status_code == 200
    return client, response.json()["session_token"]


def hdrs(session):
    return {"Origin": ORIGIN, "Authorization": f"Bearer {session}", "Content-Type": "application/json"}


def new_target(**overrides):
    body = {"display_name": "Reporting DB", "host": HOST, "port": 3306, "trust": "configured"}
    body.update(overrides)
    return body


def ask(client, session, body):
    return client.post("/company/target-requests", headers=hdrs(session), json=body)


def confirm(client, session, request_id, code):
    return client.post("/company/target-requests/confirm", headers=hdrs(session),
                       json={"request_id": request_id, "approval_code": code})


def last_code(runtime):
    return CODE_RE.findall(runtime.console[-1])[-1]


def requested(runtime, client, session, body=None):
    response = ask(client, session, body or new_target())
    assert response.status_code == 200, response.text
    return response.json()["request_id"], last_code(runtime)


# ---------------------------------------------------------------- host and name rules


@pytest.mark.parametrize("host", [
    "db.company.example", "DB.Company.Example", "db_1.internal", "dbserver",
    "xn--cmpany-wqf.example", "a" * 63 + ".example", ".".join(["a" * 63] * 3 + ["b" * 61]),  # 253
])
def test_valid_ascii_host_names_are_accepted(host):
    target = validate_company_target(CompanyTarget(
        target_id="t", display_name="n", mode=TARGET_MODE_COMPANY, host=host, port=3306, approval_state="pending"))
    assert target.host == host


@pytest.mark.parametrize("host", [
    "db.cоmpany.example",  # Cyrillic o: looks identical on screen
    "db.exa​mple.com",      # zero-width space
    "10.1", "127.1", "2130706433", "0x7f.0x1", "1.2.3.4", "db.1example",
    "db..example", ".db.example", "db.example.", "-db.example", "db-.example",
    "a" * 64 + ".example", ".".join(["a" * 60] * 5), "db example", "db:3306", "[::1]", "localhost",
])
def test_unsafe_or_malformed_host_names_are_rejected(host):
    with pytest.raises(ValueError):
        validate_company_target(CompanyTarget(
            target_id="t", display_name="n", mode=TARGET_MODE_COMPANY, host=host, port=3306,
            approval_state="pending"))


@pytest.mark.parametrize("name", ["Reporting DB", "Prod (EU) #2", "Café"])
def test_valid_display_names(name):
    assert validate_display_name(name) == name


@pytest.mark.parametrize("name", [
    "", "   ", "x" * 65, "a\x1b[2Kb", "a\nb", "a\rb", "a‮b", "a b", "a\x00b", "a‏b"])
def test_display_names_that_could_alter_a_terminal_are_rejected(name):
    with pytest.raises(ValueError):
        validate_display_name(name)


def test_console_text_escapes_everything_but_printable_ascii():
    assert console_text("a\x1b[31m\nb\\c‮é") == "a\\x1b[31m\\nb\\\\c\\u202e\\xe9"


def test_existing_target_listing_escapes_names(tmp_path):
    runtime = make_runtime(tmp_path)
    runtime.company_targets.targets["t1"] = CompanyTarget(
        target_id="t1", display_name="ok\x1b[2K\nFAKE approved line", host=HOST, port=3306,
        approval_state="pending")
    output = launcher.run_operator_command(runtime, "targets")
    assert "\x1b" not in output and "\n" not in output
    assert "ok\\x1b[2K\\nFAKE approved line" in output


# ---------------------------------------------------------------- request and console


def test_request_shows_the_exact_target_and_opens_no_connection(tmp_path, dns, no_network):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    response = ask(client, session, new_target(host="DB.Company.Example"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "awaiting_approval" and body["expires_in_seconds"] == 300
    block = runtime.console[-1]
    assert "  host       : db.company.example\n" in block
    assert "  port       : 3306\n" in block
    assert "  addresses  : 203.0.113.10, 203.0.113.11\n" in block
    assert "  TLS trust  : connector CA bundle " in block
    code = last_code(runtime)
    assert code not in response.text  # the code is shown only in the console
    assert runtime.company_targets.targets == {}  # nothing registered yet
    assert not (tmp_path / "targets.json").exists()
    assert no_network == []


def test_confirm_registers_and_approves_the_shown_target(tmp_path, dns, no_network):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    request_id, code = requested(runtime, client, session)
    response = confirm(client, session, request_id, code.lower())  # Crockford: case-insensitive
    assert response.status_code == 200, response.text
    target_id = response.json()["target"]["target_id"]
    assert response.json()["target"]["approval_state"] == "approved"
    saved = json.loads((tmp_path / "targets.json").read_text())["targets"]
    assert [(t["target_id"], t["host"], t["port"], t["tls_policy"], t["approval_state"],
             t["dns_identity_snapshot"]["addresses"]) for t in saved] == [
        (target_id, HOST, 3306, "configured", "approved", ADDRESSES)]
    listed = client.get("/company/targets", headers=hdrs(session)).json()["targets"]
    assert [t["target_id"] for t in listed] == [target_id]


def test_request_without_an_interactive_console_is_refused(tmp_path, dns, no_network):
    runtime = make_runtime(tmp_path, console=False)
    client, session = pair(runtime)
    response = ask(client, session, new_target())
    assert response.status_code == 409 and response.json()["error_code"] == "approval_console_unavailable"
    assert runtime.target_requests == {}


@pytest.mark.parametrize("body, code", [
    (new_target(username="alice", password="secret"), "invalid_target_request"),
    (new_target(port="3306"), "invalid_target_request"),
    (new_target(host="db.cоmpany.example"), "invalid_company_target_host"),
    (new_target(host="10.1"), "invalid_company_target_host"),
    (new_target(display_name="x\x1b[2K\nFAKE"), "invalid_company_target_name"),
    (new_target(trust="none"), "invalid_trust_policy"),
    (new_target(trust="configured", ca_pem=ca_pem()), "invalid_target_request"),
])
def test_invalid_requests_never_reach_the_console(tmp_path, dns, no_network, body, code):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    response = ask(client, session, body)
    assert response.status_code == 400 and response.json()["error_code"] == code
    assert runtime.console == [] and runtime.target_requests == {}


@pytest.mark.parametrize("answers, code", [
    (["203.0.113.10", "127.0.0.1"], "company_target_address_not_allowed"),
    (["169.254.169.254"], "company_target_address_not_allowed"),
    ([], "company_dns_validation_failed"),
])
def test_unsafe_or_mixed_dns_answers_are_refused_at_request_time(tmp_path, dns, no_network, answers, code):
    dns[HOST] = answers
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    response = ask(client, session, new_target())
    assert response.status_code == 400 and response.json()["error_code"] == code
    assert runtime.console == []


def test_existing_host_and_port_cannot_be_requested_again(tmp_path, dns, no_network):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    request_id, code = requested(runtime, client, session)
    assert confirm(client, session, request_id, code).status_code == 200
    again = ask(client, session, new_target(display_name="Other name", host="DB.COMPANY.EXAMPLE"))
    assert again.status_code == 409 and again.json()["error_code"] == "company_target_exists"


# ---------------------------------------------------------------- the approval code


def test_wrong_session_cannot_confirm_and_does_not_consume_the_request(tmp_path, dns, no_network):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    _, other = pair(runtime, client)
    request_id, code = requested(runtime, client, session)
    stolen = confirm(client, other, request_id, code)
    assert stolen.status_code == 404 and stolen.json()["error_code"] == "target_request_not_found"
    assert confirm(client, session, request_id, code).status_code == 200


def test_a_code_is_single_use(tmp_path, dns, no_network):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    request_id, code = requested(runtime, client, session)
    assert confirm(client, session, request_id, code).status_code == 200
    replay = confirm(client, session, request_id, code)
    assert replay.status_code == 404 and replay.json()["error_code"] == "target_request_not_found"


def test_a_request_expires(tmp_path, dns, no_network, monkeypatch):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    request_id, code = requested(runtime, client, session)
    now = runtime._now()
    monkeypatch.setattr(runtime, "_now", lambda: now + 301)  # the session (3600 s) is still valid
    late = confirm(client, session, request_id, code)
    assert late.status_code == 404 and late.json()["error_code"] == "target_request_not_found"
    assert runtime.company_targets.targets == {}


def test_three_wrong_codes_cancel_the_request(tmp_path, dns, no_network):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    request_id, code = requested(runtime, client, session)
    wrong = "0000-0000" if code != "0000-0000" else "1111-1111"
    assert [confirm(client, session, request_id, wrong).json()["error_code"] for _ in range(3)] == [
        "approval_code_invalid", "approval_code_invalid", "target_request_cancelled"]
    after = confirm(client, session, request_id, code)
    assert after.status_code == 404 and runtime.company_targets.targets == {}


def test_approval_failures_are_rate_limited_without_locking_out_pairing(tmp_path, dns, no_network):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    for _ in range(5):
        assert confirm(client, session, "no-such-request", "0000-0000").status_code == 404
    request_id, code = requested(runtime, client, session)
    limited = confirm(client, session, request_id, code)
    assert limited.status_code == 429 and limited.json()["error_code"] == "approval_rate_limited"
    assert not runtime.is_pairing_rate_limited()
    pair(runtime, client)  # pairing still works


def test_one_request_per_session_and_a_global_cap(tmp_path, dns, no_network):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    first_id, first_code = requested(runtime, client, session)
    second_id, _ = requested(runtime, client, session)
    replaced = confirm(client, session, first_id, first_code)
    assert replaced.status_code == 404  # the new request replaced the old one
    assert list(runtime.target_requests) == [second_id]
    for _ in range(2):
        _, other = pair(runtime, client)
        requested(runtime, client, other)
    _, fourth = pair(runtime, client)
    over = ask(client, fourth, new_target())
    assert over.status_code == 429 and over.json()["error_code"] == "target_request_limit_reached"


def test_unpair_session_expiry_and_shutdown_drop_requests(tmp_path, dns, no_network, monkeypatch):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    requested(runtime, client, session)
    assert client.post("/unpair", headers=hdrs(session)).status_code == 200
    assert runtime.target_requests == {}

    client, session = pair(runtime)
    requested(runtime, client, session)
    runtime.sessions[session].expires_at = runtime._now() - 1
    assert client.get("/company/targets", headers=hdrs(session)).status_code == 401
    assert runtime.target_requests == {}

    client, session = pair(runtime)
    requested(runtime, client, session)
    runtime.shutdown()
    assert runtime.target_requests == {}


def test_dns_change_between_request_and_confirmation_is_refused(tmp_path, dns, no_network):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    request_id, code = requested(runtime, client, session)
    dns[HOST] = ["203.0.113.10", "198.51.100.7"]
    changed = confirm(client, session, request_id, code)
    assert changed.status_code == 409 and changed.json()["error_code"] == "dns_changed_since_request"
    assert runtime.company_targets.targets == {}


def test_codes_tokens_and_bundles_never_reach_responses_or_logs(tmp_path, dns, no_network, caplog):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    bundle = ca_pem("Log Check CA")
    with caplog.at_level(logging.DEBUG):
        created = ask(client, session, new_target(trust="bundle", ca_pem=bundle))
        code = last_code(runtime)
        wrong = confirm(client, session, created.json()["request_id"], "0000-0000")
        right = confirm(client, session, created.json()["request_id"], code)
    assert right.status_code == 200, right.text
    for text in (created.text, wrong.text, right.text, caplog.text):
        assert code not in text and code.replace("-", "") not in text
        assert session not in text
        assert "BEGIN CERTIFICATE" not in text
    request_id = created.json()["request_id"]
    assert request_id not in caplog.text


# ---------------------------------------------------------------- re-approval


def approved_target(tmp_path, dns, **body):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    request_id, code = requested(runtime, client, session, new_target(**body))
    target_id = confirm(client, session, request_id, code).json()["target"]["target_id"]
    return runtime, client, session, target_id


def test_changed_addresses_need_an_explicit_reapproval(tmp_path, dns, no_network):
    runtime, client, session, target_id = approved_target(tmp_path, dns)
    dns[HOST] = ["198.51.100.7"]
    with pytest.raises(ValueError, match="dns_identity_mismatch"):
        runtime.resolve_and_validate_approved_company_target(target_id)
    assert runtime.company_targets.get(target_id).dns_identity_snapshot["addresses"] == ADDRESSES  # never refreshed

    response = ask(client, session, {"target_id": target_id})
    assert response.status_code == 200, response.text
    block = runtime.console[-1]
    assert "(RE-APPROVAL)" in block and "  addresses  : 198.51.100.7\n" in block
    assert "  previously : 203.0.113.10, 203.0.113.11\n" in block
    assert confirm(client, session, response.json()["request_id"], last_code(runtime)).status_code == 200
    assert runtime.company_targets.get(target_id).dns_identity_snapshot["addresses"] == ["198.51.100.7"]
    assert runtime.resolve_and_validate_approved_company_target(target_id).validated_ip == "198.51.100.7"


def test_reapproval_cannot_change_the_target_or_revive_a_revoked_one(tmp_path, dns, no_network):
    runtime, client, session, target_id = approved_target(tmp_path, dns)
    changed = ask(client, session, {"target_id": target_id, "host": "other.company.example"})
    assert changed.status_code == 400 and changed.json()["error_code"] == "invalid_target_request"
    runtime.revoke_company_target(target_id)
    revoked = ask(client, session, {"target_id": target_id})
    assert revoked.status_code == 409 and revoked.json()["error_code"] == "company_target_not_reapprovable"


# ---------------------------------------------------------------- trust material


@pytest.mark.parametrize("pem, code", [
    (ca_pem() + "-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----\n", "ca_bundle_contains_private_key"),
    ("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMII\n-----END ENCRYPTED PRIVATE KEY-----\n",
     "ca_bundle_contains_private_key"),
    ("not a certificate", "invalid_ca_bundle"),
    ("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "invalid_ca_bundle"),
    ("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", "invalid_ca_bundle"),
    (ca_pem() + "é", "invalid_ca_bundle"),
    (ca_pem() * 600, "ca_bundle_too_large"),
], ids=["private_key", "encrypted_private_key", "not_pem", "bad_certificate", "public_key",
        "non_ascii", "oversize"])
def test_ca_bundle_must_be_ca_certificates_only(pem, code):
    with pytest.raises(ValueError, match=code):
        validate_ca_bundle(pem)


def test_leaf_certificate_is_not_a_ca_bundle(tmp_path):
    from tests.test_connector_b2_workflow import _write_cert
    leaf = _write_cert(tmp_path / "leaf.pem", ca=False).read_text()
    with pytest.raises(ValueError, match="ca_bundle_has_no_ca_certificate"):
        validate_ca_bundle(leaf)


def test_bundle_is_stored_by_hash_and_is_the_only_trust_for_its_target(tmp_path, dns, no_network):
    bundle = ca_pem("Uploaded Bundle CA")
    digest = hashlib.sha256(bundle.encode("ascii")).hexdigest()
    runtime, client, session, target_id = approved_target(tmp_path, dns, trust="bundle", ca_pem=bundle)
    assert f"SHA-256 {digest}, 1 CA certificate(s)" in runtime.console[0]
    assert "CN=Uploaded Bundle CA" in runtime.console[0] or "commonName=Uploaded Bundle CA" in runtime.console[0]
    stored = tmp_path / "trust" / f"{digest}.pem"
    assert stored.read_bytes() == bundle.encode("ascii")
    target = runtime.company_targets.get(target_id)
    assert target.tls_policy == f"bundle:{digest}"
    context = runtime._company_tls_context(target.tls_policy)
    assert [c["subject"] for c in context.get_ca_certs()] == [((("commonName", "Uploaded Bundle CA"),),)]


@pytest.mark.parametrize("damage", ["modify", "delete"])
def test_changed_or_missing_bundle_fails_closed_before_any_socket(tmp_path, dns, no_network, damage):
    runtime, client, session, target_id = approved_target(tmp_path, dns, trust="bundle", ca_pem=ca_pem())
    digest = runtime.company_targets.get(target_id).tls_policy.split(":", 1)[1]
    stored = tmp_path / "trust" / f"{digest}.pem"
    if damage == "modify":
        stored.write_text(ca_pem("Swapped CA"), encoding="ascii")
    else:
        stored.unlink()
    with pytest.raises(ValueError, match="^database_connection_failed$"):
        runtime.connect_company_target_mysql(
            runtime.resolve_and_validate_approved_company_target(target_id),
            username="u", password="p", tls_hostname=HOST, tls_ca_path=runtime.company_tls_ca_path)
    assert no_network == []  # failed before any socket, with no fallback to the configured CA


@pytest.mark.parametrize("policy", ["weird", "bundle:" + "0" * 63, "bundle:" + "A" * 64, "SYSTEM", ""])
def test_unknown_policy_fails_closed_even_with_a_configured_ca(tmp_path, policy):
    runtime = make_runtime(tmp_path)
    assert runtime.company_tls_ca_path  # a configured CA exists, and must not be used instead
    with pytest.raises(ValueError, match="^database_connection_failed$"):
        runtime._company_tls_context(policy)


def test_failed_bundle_write_approves_nothing(tmp_path, dns, no_network, monkeypatch):
    runtime = make_runtime(tmp_path)
    client, session = pair(runtime)
    request_id, code = requested(runtime, client, session, new_target(trust="bundle", ca_pem=ca_pem()))

    def disk_full(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(runtime, "_store_trust_bundle", disk_full)
    response = confirm(client, session, request_id, code)
    assert response.status_code == 500 and response.json()["error_code"] == "trust_bundle_unavailable"
    assert runtime.company_targets.targets == {} and not (tmp_path / "targets.json").exists()


def test_system_trust_is_windows_only(tmp_path, dns, no_network, monkeypatch):
    runtime = make_runtime(tmp_path)
    monkeypatch.setattr(connector_server, "SYSTEM_TRUST_PLATFORM", "not-" + sys.platform)
    with pytest.raises(ValueError, match="^database_connection_failed$"):
        runtime._company_tls_context("system")
    client, session = pair(runtime)
    response = ask(client, session, new_target(trust="system"))
    assert response.status_code == 409 and response.json()["error_code"] == "trust_policy_unsupported"


def test_empty_system_store_fails_closed(tmp_path, monkeypatch):
    runtime = make_runtime(tmp_path)
    monkeypatch.setattr(connector_server, "SYSTEM_TRUST_PLATFORM", sys.platform)
    monkeypatch.setattr(ssl.SSLContext, "get_ca_certs", lambda self, binary_form=False: [])
    with pytest.raises(ValueError, match="^database_connection_failed$"):
        runtime._company_tls_context("system")


def test_windows_store_context_verifies_certificate_and_host(tmp_path):
    # Runs on every platform (the macOS CI skip check allows no skip here).
    runtime = make_runtime(tmp_path)
    if sys.platform != "win32":
        with pytest.raises(ValueError, match="^database_connection_failed$") as raised:
            runtime._company_tls_context("system")
        assert str(raised.value.__cause__) == "trust_policy_unsupported"
        return
    context = runtime._company_tls_context("system")
    assert context.get_ca_certs()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True


@pytest.mark.parametrize("policy", ["configured", None, "bundle"])
def test_every_context_requires_certificate_hostname_and_tls12(tmp_path, policy):
    runtime = make_runtime(tmp_path)
    if policy == "bundle":
        data = ca_pem().encode("ascii")
        digest = hashlib.sha256(data).hexdigest()
        runtime._store_trust_bundle(data, digest)
        policy = f"bundle:{digest}"
    context = runtime._company_tls_context(policy)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    # Unchanged on purpose (PyMySQL cleared it before); a separate decision.
    assert not context.verify_flags & ssl.VERIFY_X509_STRICT


# ---------------------------------------------------------------- PyMySQL receives the context


def test_driver_gets_the_context_in_required_mode():
    context = ssl.create_default_context(cafile=company_ca_path())
    connection = REAL_DRIVER(host=HOST, user="u", password="p", ssl=context, defer_connect=True)
    assert connection.ctx is context and connection._ssl_required is True
    # The other mode (no ssl argument) is opportunistic TLS with plaintext fallback.
    fallback = REAL_DRIVER(host=HOST, user="u", password="p", defer_connect=True)
    assert fallback._ssl_required is False


@pytest.mark.parametrize("same_context, required", [(False, True), (True, False)],
                         ids=["other_context", "tls_not_required"])
def test_connector_refuses_a_driver_connection_not_in_required_mode(tmp_path, monkeypatch, same_context, required):
    runtime = make_runtime(tmp_path)
    attempts = []

    class Socket:
        def __init__(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def connect(self, address):
            pass

        def close(self):
            pass

    class Downgraded:
        def __init__(self, given):
            self.ctx = given if same_context else ssl.create_default_context()
            self._ssl_required = required

        def connect(self, sock=None):
            attempts.append(sock)

        def close(self):
            pass

    patch_connector_socket(monkeypatch, Socket)
    monkeypatch.setattr(connector_server.pymysql, "connect", lambda **kwargs: Downgraded(kwargs["ssl"]))
    destination = connector_server.CompanyTargetDestination(
        hostname=HOST, validated_ip=ADDRESSES[0], address_family=socket.AF_INET, port=3306)
    with pytest.raises(ValueError, match="^database_connection_failed$"):
        runtime.connect_company_target_mysql(destination, username="u", password="p", tls_hostname=HOST)
    assert attempts == []  # no handshake, so no login was sent


def test_real_driver_uses_the_targets_bundle_and_approved_host_name(tmp_path, dns, no_network, monkeypatch):
    runtime, client, session, target_id = approved_target(
        tmp_path, dns, trust="bundle", ca_pem=ca_pem("Real Driver Bundle CA"))
    plain = StreamSocket(server_greeting(tls=True))
    patch_connector_socket(monkeypatch, lambda family, type_: plain)
    monkeypatch.setattr(connector_server.pymysql, "connect", REAL_DRIVER)
    seen = {}

    def wrap_socket(ctx, sock, server_hostname=None, **kwargs):
        seen.update(ctx=ctx, hostname=server_hostname, before=b"".join(plain.sent))
        raise cert_error()

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap_socket)
    with pytest.raises(ValueError, match="^tls_verification_failed$"):
        runtime.connect_company_target_mysql(
            runtime.resolve_and_validate_approved_company_target(target_id),
            username="alice_dba", password="Secret-123", tls_hostname=HOST,
            tls_ca_path=runtime.company_tls_ca_path)
    assert [c["subject"] for c in seen["ctx"].get_ca_certs()] == [((("commonName", "Real Driver Bundle CA"),),)]
    assert seen["ctx"].check_hostname is True and seen["ctx"].verify_mode == ssl.CERT_REQUIRED
    assert seen["hostname"] == HOST and plain.address == (ADDRESSES[0], 3306)
    assert b"alice_dba" not in seen["before"] and b"Secret-123" not in seen["before"]


def test_no_tls_server_gets_no_credentials_with_a_bundle_target(tmp_path, dns, no_network, monkeypatch):
    runtime, client, session, target_id = approved_target(tmp_path, dns, trust="bundle", ca_pem=ca_pem())
    plain = StreamSocket(server_greeting(tls=False))
    patch_connector_socket(monkeypatch, lambda family, type_: plain)
    monkeypatch.setattr(connector_server.pymysql, "connect", REAL_DRIVER)
    with pytest.raises(ValueError, match="^tls_not_offered$"):
        runtime.connect_company_target_mysql(
            runtime.resolve_and_validate_approved_company_target(target_id),
            username="alice_dba", password="Secret-123", tls_hostname=HOST)
    assert plain.sent == []


# ---------------------------------------------------------------- registry compatibility


def test_registry_round_trips_policies_and_old_entries_mean_configured(tmp_path, dns, no_network):
    runtime, client, session, target_id = approved_target(tmp_path, dns, trust="bundle", ca_pem=ca_pem())
    reloaded = make_runtime(tmp_path)
    reloaded.load_registry()
    assert reloaded.company_targets.get(target_id).tls_policy.startswith("bundle:")
    old = CompanyTarget(target_id="old", display_name="Old", host="old.company.example", port=3306,
                        approval_state="pending")
    assert old.tls_policy is None
    assert reloaded._company_tls_context(old.tls_policy).get_ca_certs()  # the configured CA


def test_launcher_disables_the_access_log_and_prints_codes_only_to_a_terminal(tmp_path, monkeypatch):
    import uvicorn
    calls = {}
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: calls.update(kwargs))
    monkeypatch.setattr(launcher.sys.stdin, "isatty", lambda: False, raising=False)
    built = {}
    original = launcher.build_runtime
    monkeypatch.setattr(launcher, "build_runtime", lambda config: built.setdefault("runtime", original(config)))
    assert launcher.main(["--allow-origin", ORIGIN, "--registry", str(tmp_path / "t.json")]) == 0
    assert calls.get("access_log") is False
    assert built["runtime"].approval_notifier is None  # no terminal, so no approval requests
