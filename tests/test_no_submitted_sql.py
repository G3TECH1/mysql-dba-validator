"""Submitted SQL reaches MySQL only as EXPLAIN of one eligible SELECT; it is never executed.

The local (/api/validate) and connector (/company/targets/{id}/validate) evidence paths
are driven with recording fake connections that capture every statement and every bound
parameter passed to them. Submitted statements carry distinctive markers in literals,
comments and identifiers. A marker may appear only inside one `EXPLAIN SELECT ...` (or
`EXPLAIN WITH ...`) request for an eligible SELECT; every other statement must be one of
the fixed session or metadata statements; `ANALYZE` never appears; writes are never sent.

Verification level: TestClient with fake connections. This covers these application
paths up to the database driver; it does not show what a real driver or server does
(the driver's own SET NAMES at connect is not visible here) or cover other clients.
"""

from __future__ import annotations

import pymysql
import pytest

import backend.db as backend_db
from backend.db import READ_ONLY_CHECK_SQL, READ_ONLY_SESSION_SQL
from backend.metadata import COLUMNS_SQL, STATISTICS_SQL, TABLES_SQL
from tests import test_connector_remote_evidence as remote
from tests.test_local_evidence_credentials import DB, DECOY, FakeMySQL, mysql_error, post

MARKED_SELECTS = [
    "SELECT * FROM users WHERE id = 987654",
    # A string literal, with an embedded quote.
    "SELECT * FROM users WHERE status = 'ZZMARK_LITERAL_O''Neil'",
    # Block and line comments (an executable comment is refused: see below).
    "SELECT id FROM users /* ZZMARK_BLOCK_COMMENT */ WHERE id = 42",
    "SELECT id FROM users WHERE id = 8 -- ZZMARK_LINE_COMMENT\n",
    # A distinctive column name and a subquery.
    "SELECT zzmark_column FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 31337)",
]
MARKERS = ("ZZMARK", "zzmark", "987654", "31337", "O''Neil")

FIXED_STATEMENTS = {" ".join(sql.split()) for sql in
                    (READ_ONLY_SESSION_SQL, READ_ONLY_CHECK_SQL, TABLES_SQL, STATISTICS_SQL, COLUMNS_SQL,
                     "SELECT DATABASE() AS db_name")}
METADATA_STATEMENTS = {" ".join(sql.split()) for sql in (TABLES_SQL, STATISTICS_SQL, COLUMNS_SQL)}


def plan_requests(recorded, schema):
    """The EXPLAIN requests among `recorded` ((statement, args) pairs as passed to the
    connection's cursors), after checking that nothing else carries submitted text."""
    assert recorded, "the evidence connection was expected to be used"
    explains = []
    for statement, args in recorded:
        normalised = " ".join(statement.split())
        assert "ANALYZE" not in normalised.upper(), statement
        assert "/*!" not in statement, statement  # never an executable comment
        if normalised.upper().startswith("EXPLAIN"):
            # Plain EXPLAIN of one SELECT: the statement itself is never sent to run.
            assert normalised.startswith(("EXPLAIN SELECT ", "EXPLAIN WITH ")), statement
            assert ";" not in normalised.rstrip(";"), statement
            assert not args, (statement, args)
            explains.append(normalised)
            continue
        assert normalised in FIXED_STATEMENTS, statement
        if normalised in METADATA_STATEMENTS:
            _, table, limit = args
            # Bound parameters only: the selected schema, a parsed table name, a row limit.
            assert args[0] == schema and table in {"users", "orders"} and isinstance(limit, int), args
        else:
            assert not args, (statement, args)
        for marker in MARKERS:
            assert marker not in statement, (marker, statement)
            assert not any(marker in str(arg) for arg in (args or ())), (marker, args)
    return explains


def assert_plan_reported_and_assessment_unchanged(statement, offline):
    assert statement["evidence"]["plan"]["state"] == "collected"
    assert statement["database_evidence"]["available"] is True
    assert statement["database_evidence"]["explain_available"] is True
    assert statement["database_evidence"]["access_type"] is not None
    # A plan only adds the documented plan points (full scan, large estimate); it never
    # lowers a score and never changes confidence.
    evidence = statement["database_evidence"]
    expected = (10 if evidence["full_table_scan"] else 0) + (10 if (evidence["estimated_rows"] or 0) >= 10_000 else 0)
    assert sum(f["points"] for f in statement["evidence_factors"]) == expected
    # Plus M2 when metadata shows no index leading with the filter column.
    assert statement["score"] == min(100, offline["score"] + expected + statement["metadata_score_adjustment"])
    assert statement["confidence"] == offline["confidence"]


class RecordingMySQL(FakeMySQL):
    """FakeMySQL that also records the bound parameters of every statement."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.recorded = []

    def rows_for(self, sql, args, connection):
        self.recorded.append((sql, args))
        return super().rows_for(sql, args, connection)


def use(monkeypatch, server):
    for key, value in DECOY.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(backend_db, "_client", None)
    monkeypatch.setattr(pymysql, "connect", lambda **kwargs: server.connect(**kwargs))
    return server


@pytest.fixture
def local_server(monkeypatch):
    return use(monkeypatch, RecordingMySQL())


@pytest.mark.parametrize("sql", MARKED_SELECTS)
def test_local_select_is_explained_once_and_never_executed(local_server, sql):
    offline = post(sql, username=None, password=None).json()["statements"][0]
    assert local_server.recorded == []  # without a login nothing is opened

    response = post(sql)
    assert response.status_code == 200, response.text
    assert len(plan_requests(local_server.recorded, DB)) == 1
    assert_plan_reported_and_assessment_unchanged(response.json()["statements"][0], offline)


@pytest.mark.parametrize("sql", MARKED_SELECTS)
def test_connector_select_is_explained_once_and_never_executed(monkeypatch, local_server, sql):
    offline = post(sql, username=None, password=None).json()["statements"][0]

    server = remote.FakeServer(explain=[remote.explain_row("const", 1, key="PRIMARY")])
    runtime, _ = remote.remote_runtime(monkeypatch, server)
    client, headers = remote.paired_client(runtime)
    discovered = client.post("/company/targets/t1/databases", headers=headers, json=remote.login())
    assert discovered.status_code == 200
    before = len(server.executed)  # discovery (SHOW DATABASES) is a separate request

    response = client.post("/company/targets/t1/validate", headers=headers,
                           json={"sql": sql, "database": remote.DB, **remote.login()})
    assert response.status_code == 200, response.text
    assert len(plan_requests(server.executed[before:], remote.DB)) == 1
    assert_plan_reported_and_assessment_unchanged(response.json()["statements"][0], offline)


def test_writes_in_a_batch_are_never_sent_not_even_as_explain(local_server):
    sql = ("SELECT * FROM users WHERE status = 'ZZMARK_A'; "
           "UPDATE users SET status = 'ZZMARK_B' WHERE id = 987654; "
           "DELETE FROM orders WHERE total = 31337")
    response = post(sql)
    assert response.status_code == 200, response.text
    explains = plan_requests(local_server.recorded, DB)
    assert explains == ["EXPLAIN SELECT * FROM users WHERE status = 'ZZMARK_A';"]
    assert not any(marker in statement for statement, _ in local_server.recorded
                   for marker in ("ZZMARK_B", "987654", "31337"))
    plans = [s["evidence"]["plan"]["state"] for s in response.json()["statements"]]
    assert plans == ["collected", "not_collected_read_only", "not_collected_read_only"]


@pytest.mark.parametrize("sql", ["SELECT SPLIT(name, ',') FROM users", "SELECT * FROM users INTO @v",
                                 "SELECT * FROM users; DELETE FROM users"])
def test_ineligible_and_multi_statement_input_gets_no_plan_request(local_server, sql):
    response = post(sql)
    assert response.status_code == 200, response.text
    explains = plan_requests(local_server.recorded, DB) if local_server.recorded else []
    statements = response.json()["statements"]
    planned = [s for s in statements if s["evidence"]["plan"]["state"] == "collected"]
    # Only a plain eligible SELECT is ever planned, one EXPLAIN each.
    assert len(explains) == len(planned)
    assert all(s["statement_type"] == "SELECT" for s in planned)
    assert not any("DELETE" in e.upper() or "INTO" in e.upper() or "SPLIT" in e.upper() for e in explains)


def test_a_plan_in_a_format_the_validator_cannot_read_is_not_reported(monkeypatch):
    # explain_format = TREE or JSON (MySQL 8.0.32+): plain EXPLAIN returns one text column.
    server = use(monkeypatch, RecordingMySQL(explain=[{"EXPLAIN": "-> Index lookup on users using PRIMARY"}]))
    statement = post("SELECT * FROM users WHERE id = 1").json()["statements"][0]
    assert len(plan_requests(server.recorded, DB)) == 1
    assert statement["evidence"]["plan"] == {"state": "failed", "reason": "explain_format_unsupported"}
    assert statement["database_evidence"]["available"] is False
    assert statement["database_evidence"]["status"] == "explain_format_unsupported"
    assert statement["database_evidence"]["access_type"] is None
    assert statement["database_evidence"]["full_table_scan"] is not True


@pytest.mark.parametrize("error, status", [
    (mysql_error(1142, "SELECT command denied to user"), "insufficient_privileges"),
    (mysql_error(1064, "You have an error in your SQL syntax"), "explain_failed"),
])
def test_a_failed_plan_request_is_never_reported_as_a_plan(monkeypatch, error, status):
    server = use(monkeypatch, RecordingMySQL(explain_error=error))
    response = post("SELECT * FROM users WHERE id = 1")
    statement = response.json()["statements"][0]
    assert len(plan_requests(server.recorded, DB)) == 1
    assert statement["evidence"]["plan"] == {"state": "failed", "reason": status}
    assert statement["database_evidence"]["available"] is False
    assert statement["database_evidence"]["status"] == status
    assert "command denied" not in response.text and "syntax" not in response.text


def test_a_connection_failure_sends_nothing_and_reports_no_plan(monkeypatch):
    server = use(monkeypatch, RecordingMySQL(connect_error=mysql_error(2003, "Can't connect")))
    statement = post("SELECT * FROM users WHERE id = 1").json()["statements"][0]
    assert server.recorded == []
    assert statement["evidence"]["connection"]["state"] == "failed"
    assert statement["evidence"]["plan"]["state"] == "not_attempted"
    assert statement["database_evidence"]["available"] is False


EXECUTABLE_COMMENT_SELECT = "SELECT id FROM users WHERE id = 7 /*!80000 AND zzmark_exec_comment() */"


def test_executable_comment_is_refused_before_any_submitted_text_is_sent(monkeypatch, local_server):
    # MySQL would run the comment's contents, so the request is refused as a whole,
    # locally and by the connector, before any connection is opened.
    response = post(EXECUTABLE_COMMENT_SELECT)
    assert response.status_code == 200
    assert response.json() == {"error": "executable_comment_not_supported"}
    assert local_server.recorded == []

    server = remote.FakeServer(explain=[remote.explain_row("const", 1, key="PRIMARY")])
    runtime, connects = remote.remote_runtime(monkeypatch, server)
    client, headers = remote.paired_client(runtime)
    response = client.post("/company/targets/t1/validate", headers=headers,
                           json={"sql": EXECUTABLE_COMMENT_SELECT, **remote.login()})
    assert response.status_code == 400
    assert response.json()["error_code"] == "executable_comment_not_supported"
    assert connects == []
    assert server.executed == []
