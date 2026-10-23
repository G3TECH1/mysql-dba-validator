"""Company connection failures reach the page as stable, non-sensitive codes.

The classifier (connector.server.classify_company_connection_error) uses exception
types and MySQL error numbers only. Driver exceptions here are built the way the
pinned PyMySQL builds them: server errors through pymysql.err.raise_mysql_exception
from a real error packet, OSErrors during connect wrapped as error 2003 with
original_exception, read failures as 2013 raised while handling the OSError. Their
messages carry canary values that must never reach a response or a log.

The last tests drive the real PyMySQL Connection.connect() over an in-memory socket
to pin the TLS context, the verified host name, and that nothing but the TLS request
is written before the TLS handshake.
"""

import datetime
import errno
import io
import logging
import socket
import ssl
import struct

import pymysql
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pymysql.constants import CLIENT

import connector.server as connector_server
from connector.policy import CompanyTarget, TARGET_MODE_COMPANY
from connector.server import (
    COMPANY_CONNECTION_ERROR_CODES,
    CompanyTargetDestination,
    ConnectorRuntime,
    classify_company_connection_error,
    create_app,
)
from tests.tls_test_ca import company_ca_path

VALID_ORIGIN = "http://127.0.0.1:8420"
HOST = "db.company.example"
PINNED_IP = "93.184.216.34"
USER = "alice_dba"
SECRET = "Per-Request-Secret-Do-Not-Store-7731"
# Values a real driver message could contain; none may leave the connector.
CANARY_HOST = "canary-host.internal"
CANARY_IP = "10.9.8.7"
CANARY_USER = "canary_user"
CANARY_SECRET = "Canary-Secret-4471"
CANARY_SUBJECT = "CN=canary-cert-subject"
CANARIES = (CANARY_HOST, CANARY_IP, CANARY_USER, CANARY_SECRET, CANARY_SUBJECT, USER, SECRET, PINNED_IP)


def server_error(number, message=f"Access denied for user '{CANARY_USER}'@'{CANARY_IP}'"):
    """A MySQL error packet raised by the driver's own packet decoder."""
    data = b"\xff" + struct.pack("<h", number) + b"#HY000" + message.encode()
    try:
        pymysql.err.raise_mysql_exception(data)
    except pymysql.MySQLError as exc:
        return exc
    raise AssertionError("no exception raised")


def wrapped_os_error(cause):
    """PyMySQL Connection.connect() wraps every OSError, TLS errors included, as 2003."""
    exc = pymysql.err.OperationalError(2003, f"Can't connect to MySQL server on '{CANARY_HOST}' ({cause})")
    exc.original_exception = cause
    return exc


def lost_during_read(cause):
    """PyMySQL _read_bytes: an OSError while reading becomes 2013 (cause kept as __context__)."""
    try:
        try:
            raise cause
        except OSError as e:
            raise pymysql.err.OperationalError(2013, f"Lost connection to MySQL server during query ({e})")
    except pymysql.MySQLError as exc:
        return exc


def cert_error():
    return ssl.SSLCertVerificationError(
        1, f"certificate verify failed: Hostname mismatch, certificate is not valid for '{CANARY_HOST}' "
           f"({CANARY_SUBJECT}, {CANARY_IP})")


# Exceptions raised by the MySQL handshake (Connection.connect) and the expected code.
HANDSHAKE_CASES = {
    "cert_verification_wrapped_2003": (lambda: wrapped_os_error(cert_error()), "tls_verification_failed"),
    "tls_handshake_wrapped_2003": (lambda: wrapped_os_error(ssl.SSLError(1, f"[SSL] wrong version {CANARY_IP}")),
                                   "tls_handshake_failed"),
    "tls_not_offered_2026": (lambda: pymysql.err.OperationalError(
        2026, "SSL is required but the server doesn't support it"), "tls_not_offered"),
    "auth_failed_1045": (lambda: server_error(
        1045, f"Access denied for user '{CANARY_USER}'@'{CANARY_IP}' (using password: YES)"), "auth_failed"),
    "password_expired_1862": (lambda: server_error(1862, "Your password has expired."), "password_expired"),
    "password_expired_sandbox_1820": (lambda: server_error(1820, "You must reset your password"), "password_expired"),
    "account_locked_3118": (lambda: server_error(
        3118, f"Access denied for user '{CANARY_USER}'@'{CANARY_IP}'. Account is locked."), "account_locked"),
    "failed_login_lock_3955": (lambda: server_error(3955), "account_locked"),
    "host_not_allowed_1130": (lambda: server_error(
        1130, f"Host '{CANARY_IP}' is not allowed to connect to this MySQL server"), "host_not_allowed"),
    "host_blocked_1129": (lambda: server_error(1129, f"Host '{CANARY_IP}' is blocked"), "host_blocked"),
    "auth_mode_1251": (lambda: server_error(1251, "Client does not support authentication protocol"),
                       "auth_method_unsupported"),
    "auth_plugin_2059": (lambda: pymysql.err.OperationalError(
        2059, "Authentication plugin 'authentication_kerberos_client' not loaded"), "auth_method_unsupported"),
    "too_many_connections_1040": (lambda: server_error(1040, "Too many connections"), "connection_limit_reached"),
    "user_connections_1203": (lambda: server_error(1203, f"User {CANARY_USER} already has more than"),
                              "connection_limit_reached"),
    "user_resource_1226": (lambda: server_error(1226, f"User '{CANARY_USER}' has exceeded the resource"),
                           "connection_limit_reached"),
    "tls_handshake_timeout_2003": (lambda: wrapped_os_error(TimeoutError("timed out")), "network_timeout"),
    "read_timeout_2013": (lambda: lost_during_read(TimeoutError("timed out")), "network_timeout"),
    "connection_reset_2013": (lambda: lost_during_read(ConnectionResetError(errno.ECONNRESET, "reset")),
                              "unreachable"),
    "lost_2013": (lambda: pymysql.err.OperationalError(2013, "Lost connection to MySQL server"), "unreachable"),
    "gone_2006": (lambda: pymysql.err.OperationalError(2006, "MySQL server has gone away"), "unreachable"),
    # 3957 is ER_CLONE_NETWORK_PACKET in the 8.0 and 8.4 references, not an account lock.
    "clone_3957_is_not_a_lock": (lambda: server_error(3957), "database_connection_failed"),
    "unknown_database_1049_unclassified": (lambda: server_error(1049, "Unknown database 'canary'"),
                                           "database_connection_failed"),
    "packet_sequence_internal_error": (lambda: pymysql.err.InternalError("Packet sequence number wrong"),
                                       "database_connection_failed"),
    "unexpected_exception": (lambda: RuntimeError(f"{CANARY_USER} {CANARY_SECRET}"), "database_connection_failed"),
}

# Exceptions raised by the connector's own TCP connect to the pinned IP.
SOCKET_CASES = {
    "tcp_timeout": (lambda: TimeoutError("timed out"), "network_timeout"),
    "tcp_refused": (lambda: ConnectionRefusedError(errno.ECONNREFUSED, f"refused {CANARY_IP}"), "connection_refused"),
    "tcp_network_unreachable": (lambda: OSError(errno.ENETUNREACH, f"unreachable {CANARY_IP}"), "unreachable"),
}


# ---------------------------------------------------------------- classifier


@pytest.mark.parametrize("case", sorted(HANDSHAKE_CASES))
def test_classifier_table(case):
    build, expected = HANDSHAKE_CASES[case]
    assert classify_company_connection_error(build()) == expected


def test_wrapped_certificate_error_is_never_reported_as_a_network_failure():
    exc = wrapped_os_error(cert_error())
    assert pymysql.err.OperationalError is type(exc) and exc.args[0] == 2003
    assert classify_company_connection_error(exc) == "tls_verification_failed"
    # Without the TLS cause the same 2003 is a network failure.
    assert classify_company_connection_error(
        pymysql.err.OperationalError(2003, "Can't connect")) == "unreachable"


def test_certificate_and_handshake_failures_stay_distinguishable():
    assert classify_company_connection_error(wrapped_os_error(cert_error())) == "tls_verification_failed"
    assert classify_company_connection_error(wrapped_os_error(ssl.SSLError(1, "x"))) == "tls_handshake_failed"
    assert classify_company_connection_error(pymysql.err.OperationalError(2026, "x")) == "tls_not_offered"


def test_classifier_ignores_message_text():
    # A message that names another failure changes nothing: only types and numbers count.
    assert classify_company_connection_error(server_error(1045, "certificate verify failed timed out")) == "auth_failed"
    assert classify_company_connection_error(RuntimeError("Access denied (1045) timed out")) == "database_connection_failed"


def test_exception_chain_walk_is_bounded_and_cycle_safe():
    first, second = RuntimeError("a"), RuntimeError("b")
    first.__cause__, second.__cause__ = second, first
    assert classify_company_connection_error(first) == "database_connection_failed"
    deep = cert_error()
    for _ in range(20):
        outer = RuntimeError("wrapper")
        outer.__cause__ = deep
        deep = outer
    # Beyond the bound the TLS cause is not reached: the safe generic code, not a guess.
    assert classify_company_connection_error(deep) == "database_connection_failed"


def test_every_classified_code_is_a_browser_code():
    for build, expected in [*HANDSHAKE_CASES.values(), *SOCKET_CASES.values()]:
        assert expected == "database_connection_failed" or expected in COMPANY_CONNECTION_ERROR_CODES


# ---------------------------------------------------------------- connect_company_target_mysql


def destination():
    return CompanyTargetDestination(hostname=HOST, validated_ip=PINNED_IP, address_family=socket.AF_INET, port=3306)


def patch_connector_socket(monkeypatch, factory):
    """Intercept socket.socket() only inside connector.server (asyncio needs the real one)."""
    class SocketModuleProxy:
        def __getattr__(self, name):
            return getattr(socket, name)

    proxy = SocketModuleProxy()
    proxy.socket = factory
    monkeypatch.setattr(connector_server, "socket", proxy)


class FakeTcpSocket:
    instances = []

    def __init__(self, family=None, type_=None, connect_error=None):
        self.connect_error = connect_error
        self.closed = False
        FakeTcpSocket.instances.append(self)

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        self.address = address
        if self.connect_error is not None:
            raise self.connect_error

    def close(self):
        self.closed = True


class ReadOnlyCursor:
    def __init__(self, value):
        self.value = value

    def execute(self, sql, args=None):
        pass

    def fetchone(self):
        return {"transaction_read_only": self.value}

    def fetchmany(self, size):
        return [("appdb",)]

    def close(self):
        pass


class FakeDriverConnection:
    def __init__(self, error=None, read_only=1):
        self.error, self.read_only, self.closed = error, read_only, False

    def connect(self, sock=None):
        if self.error is not None:
            raise self.error

    def cursor(self):
        return ReadOnlyCursor(self.read_only)

    def close(self):
        self.closed = True


def install(monkeypatch, *, handshake_error=None, socket_error=None, read_only=1):
    FakeTcpSocket.instances = []
    connections = []

    def fake_connect(**kwargs):
        connection = FakeDriverConnection(handshake_error, read_only)
        connections.append(connection)
        return connection

    patch_connector_socket(monkeypatch, lambda family, type_: FakeTcpSocket(family, type_, socket_error))
    monkeypatch.setattr(connector_server.pymysql, "connect", fake_connect)
    return connections


def runtime_with_target():
    runtime = ConnectorRuntime(allowed_origins=[VALID_ORIGIN])
    runtime.company_tls_ca_path = company_ca_path()
    runtime.company_targets.targets["company-db"] = CompanyTarget(
        target_id="company-db", display_name="Company database", mode=TARGET_MODE_COMPANY,
        host=HOST, port=3306, approval_state="approved",
        dns_identity_snapshot={"host": HOST, "addresses": [PINNED_IP]}, tls_hostname=HOST)
    return runtime


def connect(runtime):
    return runtime.connect_company_target_mysql(
        destination(), username=USER, password=SECRET, tls_hostname=HOST,
        tls_ca_path=runtime.company_tls_ca_path)


@pytest.mark.parametrize("case", sorted(HANDSHAKE_CASES))
def test_handshake_failures_are_classified_and_the_connection_closed(monkeypatch, case):
    build, expected = HANDSHAKE_CASES[case]
    connections = install(monkeypatch, handshake_error=build())
    with pytest.raises(ValueError) as raised:
        connect(runtime_with_target())
    assert str(raised.value) == expected
    assert connections[0].closed and FakeTcpSocket.instances[0].closed


@pytest.mark.parametrize("case", sorted(SOCKET_CASES))
def test_tcp_connect_failures_are_classified(monkeypatch, case):
    build, expected = SOCKET_CASES[case]
    connections = install(monkeypatch, socket_error=build())
    with pytest.raises(ValueError, match=f"^{expected}$"):
        connect(runtime_with_target())
    assert connections == []  # the driver is never reached
    assert FakeTcpSocket.instances[0].closed


def test_unconfirmed_read_only_session_still_fails_closed_with_the_generic_code(monkeypatch):
    connections = install(monkeypatch, read_only=0)
    with pytest.raises(ValueError, match="^database_connection_failed$"):
        connect(runtime_with_target())
    assert connections[0].closed


def test_failures_outside_the_network_steps_keep_the_generic_code(monkeypatch):
    # Building the driver's TLS context (e.g. an unreadable CA file) is configuration,
    # not a handshake: it must not be reported as a TLS or network failure.
    install(monkeypatch)

    def failing_constructor(**kwargs):
        raise ssl.SSLError(1, "cannot load CA")

    monkeypatch.setattr(connector_server.pymysql, "connect", failing_constructor)
    with pytest.raises(ValueError, match="^database_connection_failed$"):
        connect(runtime_with_target())
    runtime = runtime_with_target()
    runtime.company_tls_ca_path = None
    FakeTcpSocket.instances = []
    with pytest.raises(ValueError, match="^database_connection_failed$"):
        runtime.connect_company_target_mysql(destination(), username=USER, password=SECRET, tls_hostname=HOST)
    assert FakeTcpSocket.instances == []  # no CA: no TCP connection at all


# ---------------------------------------------------------------- HTTP: discovery and validation


def paired(runtime):
    client = TestClient(create_app(runtime=runtime))
    code = runtime.issue_pairing_token(scope="browser")
    response = client.post("/pair", headers={"Origin": VALID_ORIGIN, "Content-Type": "application/json"},
                           json={"pairing_token": code})
    assert response.status_code == 200
    return client, response.json()["session_token"]


def hdrs(session):
    return {"Origin": VALID_ORIGIN, "Authorization": f"Bearer {session}", "Content-Type": "application/json"}


def discover_and_validate(client, session):
    login = {"username": USER, "password": SECRET}
    discovery = client.post("/company/targets/company-db/databases", headers=hdrs(session), json=login)
    validate = client.post("/company/targets/company-db/validate", headers=hdrs(session),
                           json={"sql": "SELECT 1", **login})
    return discovery, validate


def assert_safe(responses, caplog):
    for response in responses:
        for canary in CANARIES:
            assert canary not in response.text, canary
    for canary in CANARIES:
        assert canary not in caplog.text, canary


ENDPOINT_CASES = {**{name: ("handshake", case) for name, case in HANDSHAKE_CASES.items()},
                  **{name: ("socket", case) for name, case in SOCKET_CASES.items()}}


@pytest.mark.parametrize("case", sorted(ENDPOINT_CASES))
def test_discovery_and_validation_report_the_same_safe_code(monkeypatch, caplog, case):
    kind, (build, expected) = ENDPOINT_CASES[case]
    runtime = runtime_with_target()
    monkeypatch.setattr(runtime, "resolve_and_validate_approved_company_target", lambda target_id: destination())
    client, session = paired(runtime)
    install(monkeypatch, **{f"{kind}_error": build()})
    with caplog.at_level(logging.DEBUG):
        discovery, validate = discover_and_validate(client, session)
    # Existing statuses: validation 400, discovery 500. Each keeps its own generic fallback.
    assert validate.status_code == 400 and validate.json()["error_code"] == expected
    assert discovery.status_code == 500
    assert discovery.json()["error_code"] == (
        "database_discovery_failed" if expected == "database_connection_failed" else expected)
    assert_safe((discovery, validate), caplog)
    # A database login or network failure never ends the connector session.
    assert client.get("/company/targets", headers=hdrs(session)).status_code == 200


@pytest.mark.parametrize("code", ["dns_resolution_failed", "dns_identity_mismatch", "dns_result_invalid",
                                  "unsafe_destination", "target_needs_reapproval"])
def test_destination_codes_survive_the_discovery_endpoint(monkeypatch, code):
    runtime = runtime_with_target()

    def refuse(target_id):
        raise ValueError(code)

    monkeypatch.setattr(runtime, "resolve_and_validate_approved_company_target", refuse)
    connections = install(monkeypatch)
    client, session = paired(runtime)
    discovery, validate = discover_and_validate(client, session)
    assert discovery.status_code == 500 and discovery.json()["error_code"] == code
    assert validate.status_code == 400 and validate.json()["error_code"] == code
    assert connections == [] and FakeTcpSocket.instances == []


def test_discovery_never_echoes_an_unlisted_error_text(monkeypatch):
    runtime = runtime_with_target()

    def leaky(target_id):
        raise ValueError(f"Access denied for user '{CANARY_USER}'@'{CANARY_IP}'")

    monkeypatch.setattr(runtime, "resolve_and_validate_approved_company_target", leaky)
    client, session = paired(runtime)
    discovery = client.post("/company/targets/company-db/databases", headers=hdrs(session),
                            json={"username": USER, "password": SECRET})
    assert discovery.status_code == 500 and discovery.json()["error_code"] == "database_discovery_failed"
    assert CANARY_USER not in discovery.text and CANARY_IP not in discovery.text


# ---------------------------------------------------------------- real PyMySQL handshake


def write_ca(path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Connection Errors Test CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(path)


def packet(seq, payload):
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def server_greeting(*, tls):
    """Minimal MySQL protocol 10 handshake, as PyMySQL's _get_server_information reads it."""
    caps = (CLIENT.LONG_PASSWORD | CLIENT.PROTOCOL_41 | CLIENT.SECURE_CONNECTION | CLIENT.CONNECT_WITH_DB
            | CLIENT.PLUGIN_AUTH | CLIENT.PLUGIN_AUTH_LENENC_CLIENT_DATA | (CLIENT.SSL if tls else 0))
    payload = (b"\x0a" + b"8.4.0\0" + struct.pack("<I", 1) + b"A" * 8 + b"\0"
               + struct.pack("<H", caps & 0xFFFF) + bytes([255]) + struct.pack("<H", 2)
               + struct.pack("<H", caps >> 16) + bytes([21]) + b"\0" * 10 + b"B" * 12 + b"\0"
               + b"caching_sha2_password\0")
    return packet(0, payload)


class StreamSocket:
    """In-memory socket: serves fixed bytes, records everything written."""

    def __init__(self, incoming=b""):
        self.incoming, self.sent, self.closed = incoming, [], False

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        self.address = address

    def makefile(self, mode):
        return io.BytesIO(self.incoming)

    def sendall(self, data):
        self.sent.append(bytes(data))

    def close(self):
        self.closed = True


def real_driver_connect(monkeypatch, tmp_path, *, tls, after_tls=None):
    """Run connect_company_target_mysql with the real PyMySQL Connection over StreamSocket."""
    plain = StreamSocket(server_greeting(tls=tls))
    plain.factory_calls = 0  # every socket the connector creates (a retry would add one)

    def factory(family, type_):
        plain.factory_calls += 1
        return plain

    patch_connector_socket(monkeypatch, factory)
    seen = {}

    def wrap_socket(ctx, sock, server_hostname=None, **kwargs):
        seen.update(ctx=ctx, hostname=server_hostname, written_before_tls=b"".join(plain.sent))
        assert sock is plain
        return after_tls()

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap_socket)
    runtime = runtime_with_target()
    runtime.company_tls_ca_path = write_ca(tmp_path / "ca.pem")
    with pytest.raises(ValueError) as raised:
        runtime.connect_company_target_mysql(
            destination(), username=USER, password=SECRET, database="appdb",
            tls_hostname=HOST, tls_ca_path=runtime.company_tls_ca_path)
    return str(raised.value), plain, seen


def test_real_driver_verifies_the_approved_host_name_against_the_ca(monkeypatch, tmp_path):
    def reject():
        raise cert_error()

    code, plain, seen = real_driver_connect(monkeypatch, tmp_path, tls=True, after_tls=reject)
    assert code == "tls_verification_failed"
    ctx = seen["ctx"]
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert len(ctx.get_ca_certs()) == 1  # the configured CA bundle, and only it
    # TCP goes to the pinned IP; the certificate is checked against the approved name.
    assert plain.address == (PINNED_IP, 3306)
    assert seen["hostname"] == HOST


def test_real_driver_writes_only_the_tls_request_before_the_handshake(monkeypatch, tmp_path):
    tls_socket = StreamSocket(packet(3, b"\xff" + struct.pack("<h", 1045) + b"#28000"
                                     + f"Access denied for user '{CANARY_USER}'@'{CANARY_IP}'".encode()))
    code, plain, seen = real_driver_connect(monkeypatch, tmp_path, tls=True, after_tls=lambda: tls_socket)
    assert code == "auth_failed"
    before = seen["written_before_tls"]
    # Exactly one 32-byte TLS request packet (sequence 1) went out in plaintext...
    assert len(before) == 4 + 32 and before[3] == 1
    assert USER.encode() not in before and SECRET.encode() not in before
    assert b"".join(plain.sent) == before
    # ...and the login went only over the TLS socket.
    assert USER.encode() in b"".join(tls_socket.sent)


def test_real_driver_sends_nothing_when_the_server_offers_no_tls(monkeypatch, tmp_path):
    def never():
        raise AssertionError("no TLS handshake without server support")

    code, plain, seen = real_driver_connect(monkeypatch, tmp_path, tls=False, after_tls=never)
    assert code == "tls_not_offered"
    assert plain.sent == [] and seen == {}
    # One connection only (no retry), and it is closed after the failure.
    assert plain.factory_calls == 1
    assert plain.closed is True
