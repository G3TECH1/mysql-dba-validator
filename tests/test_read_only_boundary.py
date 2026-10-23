"""Security boundary of evidence collection (contract section 12, product decision Q3).

Submitted SQL is never executed. Every evidence connection, local and company, is a
session MySQL confirms as read-only before any evidence query; without confirmation
the connection is closed and nothing else is sent. UPDATE/DELETE plans are never
requested, so no write privilege is ever needed. EXPLAIN is sent only for one plain
SELECT that calls no stored function and no side-effecting built-in.

Verification level: unit / TestClient with fake MySQL servers. Whether a real server
reports @@SESSION.transaction_read_only = 1 after SET SESSION TRANSACTION READ ONLY,
and refuses EXPLAIN of writes with error 1792, is a live-server check (VERIFICATION.md).
"""

from __future__ import annotations

import inspect
import ssl

import pymysql
import pytest

import connector.server as connector_server
from backend.db import READ_ONLY_CHECK_SQL, READ_ONLY_SESSION_SQL
from backend.db_evidence import PERMITTED_CALL_NAMES, _is_plain_select_explain
from backend.parser import call_names
from sqlglot.dialects.dialect import Dialect
from connector.server import ConnectorRuntime
from tests import test_connector_remote_evidence as remote
from tests.tls_test_ca import company_ca_path
from tests.test_local_evidence_credentials import mysql, post  # noqa: F401  (mysql is a fixture)

# Statements that may reach a database during validation (prefixes of the exact text).
ALLOWED = (READ_ONLY_SESSION_SQL, READ_ONLY_CHECK_SQL, "EXPLAIN SELECT ", "EXPLAIN WITH ",
           "SELECT DATABASE()", "SELECT ENGINE", "SELECT INDEX_NAME", "SELECT COLUMN_NAME", "SHOW DATABASES")

SUBMITTED = [
    "UPDATE users SET active = 0 WHERE id = 1",
    "UPDATE users SET active = 0",
    "DELETE FROM users WHERE status = 'old'",
    "DELETE u FROM users u JOIN orders o ON o.user_id = u.id",
    "INSERT INTO users (id) VALUES (1)",
    "REPLACE INTO users (id) VALUES (1)",
    "DROP TABLE users",
    "ALTER TABLE users DROP COLUMN email",
    "TRUNCATE TABLE users",
    "CALL purge_users()",
    "EXPLAIN ANALYZE UPDATE users SET active = 0",
    "SELECT * FROM users, (SELECT cleanup()) AS t",
    "SELECT SLEEP(10) FROM users",
    "SELECT * FROM users WHERE id = 1 FOR UPDATE",
    "SELECT * FROM users WHERE id = 1; DELETE FROM users",
    "SELECT /*+ SET_VAR(transaction_read_only = OFF) */ * FROM users",
    # Review C1: names sqlglot knows that MySQL would resolve to a stored function.
    "SELECT SPLIT(name, ',') FROM users",
    "SELECT * FROM users WHERE id IN (SELECT LEVENSHTEIN(a, 'b') FROM orders)",
    "SELECT appdb.upper(name) FROM users",
    # Review H2/M2.
    "DESCRIBE DELETE FROM users",
    "SELECT * FROM users INTO @v",
    # An ordinary SELECT that is planned: its EXPLAIN must pass the same policy.
    "SELECT COUNT(*) FROM users WHERE id = 1",
]


def assert_only_allowed(statements):
    for sql in statements:
        text = sql.strip()
        assert text.startswith(ALLOWED), text
        upper = text.upper()
        assert "ANALYZE" not in upper, text
        assert not upper.startswith(("EXPLAIN UPDATE", "EXPLAIN DELETE", "EXPLAIN INSERT", "EXPLAIN REPLACE"))
        if text.startswith("EXPLAIN "):
            # Not just a prefix: the exact text sent passes the final check, and every
            # word before "(" in it is on the reviewed function list.
            assert _is_plain_select_explain(text), text
            names = call_names(Dialect.get_or_raise("mysql").tokenize(text[len("EXPLAIN "):-1]))
            assert names is not None and names <= PERMITTED_CALL_NAMES, (text, names)


@pytest.mark.parametrize("sql", SUBMITTED)
def test_local_validation_sends_only_allowed_queries(mysql, sql):
    response = post(sql)
    assert response.status_code == 200, response.text
    assert mysql.executed[:2] == [READ_ONLY_SESSION_SQL, READ_ONLY_CHECK_SQL]
    assert_only_allowed(mysql.executed)


@pytest.mark.parametrize("sql", SUBMITTED)
def test_company_validation_sends_only_allowed_queries(monkeypatch, sql):
    server = remote.FakeServer(explain=[remote.explain_row("ALL", 500)])
    response, _ = remote.remote_validate(monkeypatch, server, sql)
    assert response.status_code == 200, response.text
    executed = [statement for statement, _ in server.executed]
    validate_start = executed.index(READ_ONLY_SESSION_SQL)
    assert executed[validate_start:validate_start + 2] == [READ_ONLY_SESSION_SQL, READ_ONLY_CHECK_SQL]
    assert_only_allowed(executed)


class UnconfirmedServer(remote.FakeServer):
    """Accepts SET SESSION TRANSACTION READ ONLY but reports a writable session."""

    def rows_for(self, sql, args):
        if sql.strip() == READ_ONLY_CHECK_SQL:
            self.executed.append((sql, args))
            return [{"transaction_read_only": 0}]
        return super().rows_for(sql, args)


def test_company_validation_fails_closed_without_a_confirmed_read_only_session(monkeypatch):
    server = UnconfirmedServer(explain=[remote.explain_row("const", 1, key="PRIMARY")])
    response, _ = remote.remote_validate(monkeypatch, server, "SELECT * FROM users WHERE id = 1", database=None)
    assert response.status_code == 400
    assert response.json()["error_code"] == "database_connection_failed"
    assert remote.SECRET not in response.text and remote.USER not in response.text
    assert [sql for sql, _ in server.executed] == [READ_ONLY_SESSION_SQL, READ_ONLY_CHECK_SQL]


def test_require_read_only_session_closes_an_unconfirmed_connection():
    closed = []

    class Cursor:
        def execute(self, sql, args=None):
            pass

        def fetchone(self):
            return {"transaction_read_only": 0}

        def close(self):
            pass

    class Connection:
        def cursor(self):
            return Cursor()

        def close(self):
            closed.append(True)

    with pytest.raises(ValueError, match="database_connection_failed"):
        ConnectorRuntime.require_read_only_session(Connection())
    assert closed == [True]


def test_company_tls_still_requires_a_ca_and_verifies_certificate_and_host():
    runtime = ConnectorRuntime()
    with pytest.raises(ValueError):
        runtime._company_tls_context(None, ca_path=None)
    context = runtime._company_tls_context(None, ca_path=company_ca_path())
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True


def test_no_evidence_connection_enables_multi_statements():
    # PyMySQL's default client_flag does not include CLIENT.MULTI_STATEMENTS, and no
    # evidence connection sets client_flag at all.
    default = inspect.signature(pymysql.connections.Connection.__init__).parameters["client_flag"].default
    assert default & pymysql.constants.CLIENT.MULTI_STATEMENTS == 0
    import backend.db as backend_db
    for source in (inspect.getsource(backend_db.open_evidence_connection),
                   inspect.getsource(ConnectorRuntime.connect_company_target_mysql)):
        assert "client_flag" not in source and "MULTI_STATEMENTS" not in source


def test_explain_route_never_requests_a_write_plan():
    source = inspect.getsource(ConnectorRuntime.execute_bounded_explain_statement)
    assert 'if operation != "EXPLAIN_SELECT"' in source
    assert "plan_not_collected_read_only" in source
    assert connector_server.D2_EXPLAIN_OPERATIONS >= {"EXPLAIN_SELECT"}
