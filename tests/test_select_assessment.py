"""SELECT statements that are not plain reads: locking reads, function calls outside the
reviewed list, and SELECT ... INTO.

A locking read or a call whose effects were not established is never presented as a
read-only LOW / 0 / HIGH SELECT: it is MEDIUM at least with LIMITED confidence. SELECT
... INTO, which sqlglot reads as a new table (CREATE TABLE ... AS SELECT), is not
analysed. The plan-request gate is unchanged: none of these is ever planned.

Static checks send no login, so no database connection is made; the evidence checks use
the fake MySQL from test_local_evidence_credentials.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.risk_engine import LOCKING_READ_REASON, SELECT_SIDE_EFFECT_FLOOR
from tests.test_local_evidence_credentials import (  # noqa: F401  (mysql is a fixture)
    assert_read_only_boundary,
    explains,
    mysql,
    post,
)

client = TestClient(app)

READ_ONLY = "Read-only or no data mutation detected."
NOT_ANALYSED_CHECK = "Do not execute a statement that the validator could not analyze."


def only(sql: str) -> dict:
    response = client.post("/api/validate", json={"sql": sql})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["statement_count"] == 1, data
    return data["statements"][0]


def data_risk(statement: dict) -> dict:
    dimensions = statement["v2_assessment"]["dimensions"]
    return next(dimension for dimension in dimensions if dimension["name"] == "Data Risk")


def all_text(statement: dict) -> str:
    assessment = statement["v2_assessment"]
    return " ".join([*statement["reasons"], *(finding["description"] for finding in assessment["findings"]),
                     *(dimension["reason"] for dimension in assessment["dimensions"])])


def assert_not_presented_as_a_plain_read(statement: dict) -> None:
    assert statement["analysis_status"] == "analysed"
    assert statement["score"] >= SELECT_SIDE_EFFECT_FLOOR == 20
    assert statement["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert statement["confidence"] == statement["static_confidence"] == "LIMITED"
    assert READ_ONLY not in all_text(statement)


# ---------------------------------------------------------------- locking reads

LOCKING_READS = [
    "SELECT * FROM orders WHERE id = 1 FOR UPDATE",
    "SELECT * FROM orders FOR SHARE",
    "SELECT * FROM orders LOCK IN SHARE MODE",
    "SELECT * FROM orders FOR UPDATE SKIP LOCKED",
    "SELECT * FROM orders WHERE id = 1 FOR UPDATE NOWAIT",
    "SELECT * FROM orders o JOIN users u ON u.id = o.user_id FOR UPDATE OF o",
    # A locking clause in a subquery locks that subquery's rows.
    "SELECT * FROM users WHERE id = (SELECT user_id FROM orders WHERE id = 1 FOR UPDATE)",
]


@pytest.mark.parametrize("sql", LOCKING_READS)
def test_a_locking_read_is_medium_limited_and_says_it_can_lock_rows(sql):
    statement = only(sql)
    assert_not_presented_as_a_plain_read(statement)
    assert LOCKING_READ_REASON in statement["reasons"]
    findings = statement["v2_assessment"]["findings"]
    assert any(finding["description"] == LOCKING_READ_REASON for finding in findings)
    # Says what can happen and that it depends on the transaction, without claiming it blocks.
    assert "may have to wait" in LOCKING_READ_REASON and "autocommit" in LOCKING_READ_REASON
    assert "does not change data" in data_risk(statement)["reason"].lower()


def test_a_locking_read_scores_the_minimum_medium_and_says_why():
    statement = only("SELECT * FROM orders WHERE id = 1 FOR UPDATE")
    assert (statement["score"], statement["risk_level"]) == (20, "MEDIUM")
    assert sum(factor["points"] for factor in statement["factors"]) == 20
    assert any("MEDIUM" in factor["label"] for factor in statement["factors"])


def test_explain_analyze_of_a_locking_select_is_assessed_as_that_select():
    # MySQL runs the explained SELECT; the validator never sends EXPLAIN ANALYZE.
    statement = only("EXPLAIN ANALYZE SELECT * FROM orders WHERE id = 1 FOR UPDATE")
    assert_not_presented_as_a_plain_read(statement)
    assert LOCKING_READ_REASON in statement["reasons"]


# ---------------------------------------------------------------- function calls

UNREVIEWED_CALLS = [
    ("SELECT my_func(id) FROM orders", "MY_FUNC()"),
    ("SELECT db.f(1)", None),              # schema-qualified: resolves to a stored function
    ("SELECT GET_LOCK('job', 10)", "GET_LOCK()"),
    ("SELECT SLEEP(10)", "SLEEP()"),
    ("SELECT BENCHMARK(1000000, MD5('x'))", "BENCHMARK()"),
    ("SELECT LOAD_FILE('/etc/passwd')", "LOAD_FILE()"),
    ("SELECT LAST_INSERT_ID(5)", "LAST_INSERT_ID()"),
]


@pytest.mark.parametrize("sql, named", UNREVIEWED_CALLS)
def test_a_call_outside_the_reviewed_list_is_medium_limited_and_not_read_only(sql, named):
    statement = only(sql)
    assert_not_presented_as_a_plain_read(statement)
    text = " ".join(statement["reasons"])
    assert "effects were not established" in text
    if named:
        assert named in text
    # Never asserts that the function changes data: it says it can.
    assert "can change data" in text and "changes data" not in text.replace("can change data", "")
    assert data_risk(statement)["level"] == "UNKNOWN"


def test_explain_analyze_of_a_select_calling_an_unreviewed_function_is_not_read_only():
    statement = only("EXPLAIN ANALYZE SELECT my_func(id) FROM orders")
    assert_not_presented_as_a_plain_read(statement)
    assert "MY_FUNC()" in " ".join(statement["reasons"])


@pytest.mark.parametrize("sql", [
    "SELECT * FROM orders WHERE id = 1",
    "SELECT COUNT(*) FROM orders WHERE status = 'x'",
    "SELECT CONCAT(first, ' ', last) FROM users",
    "SELECT DATE_FORMAT(created_at, '%Y-%m') FROM orders",
    "SELECT * FROM orders WHERE id IN (SELECT order_id FROM items)",
])
def test_an_ordinary_select_with_reviewed_built_ins_is_unchanged(sql):
    statement = only(sql)
    assert (statement["score"], statement["risk_level"], statement["confidence"]) == (0, "LOW", "HIGH")
    assert data_risk(statement)["reason"] == READ_ONLY
    assert "effects were not established" not in all_text(statement)
    assert LOCKING_READ_REASON not in statement["reasons"]


@pytest.mark.parametrize("sql", [
    # Written before "(" but not function calls: the AST reads them as something else.
    "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 10) SELECT * FROM r",
    "SELECT * FROM (SELECT 1, 2) AS d(a, b)",
    "SELECT * FROM orders PARTITION (p0, p1)",
    "SELECT * FROM JSON_TABLE('[1]', '$[*]' COLUMNS (x INT PATH '$', "
    "NESTED PATH '$.y[*]' COLUMNS (z INT PATH '$'))) AS jt",
    "SELECT * FROM docs WHERE MATCH(body) AGAINST('mysql' IN BOOLEAN MODE)",
    "SELECT * FROM orders WHERE total = ANY (SELECT total FROM refunds)",
    "SELECT * FROM orders WHERE total > SOME (SELECT total FROM refunds) "
    "AND id <> ANY (SELECT order_id FROM items)",
])
def test_syntax_written_before_a_parenthesis_is_not_an_unreviewed_call(sql):
    from backend.db_evidence import select_not_eligible_for_plan
    from backend.parser import parse_sql

    statement = only(sql)
    assert (statement["score"], statement["risk_level"], statement["confidence"]) == (0, "LOW", "HIGH")
    assert data_risk(statement)["reason"] == READ_ONLY
    assert "effects were not established" not in all_text(statement)
    # The plan-request gate is unchanged: it still refuses these (fail closed).
    assert select_not_eligible_for_plan(parse_sql(sql)[0])


@pytest.mark.parametrize("sql, named", [
    # A real call inside JSON_TABLE, and a CTE that shares a function's name.
    ("SELECT * FROM JSON_TABLE(my_func(), '$[*]' COLUMNS (x INT PATH '$')) AS jt", "MY_FUNC()"),
    ("WITH sleep(n) AS (SELECT 1) SELECT SLEEP(5) FROM sleep", "SLEEP()"),
    ("SELECT * FROM orders PARTITION (p0) WHERE id = GET_LOCK('x', 1)", "GET_LOCK()"),
    ("SELECT * FROM docs WHERE MATCH(body) AGAINST('x') AND id = my_func(1)", "MY_FUNC()"),
    ("SELECT * FROM orders WHERE total = ANY (SELECT total FROM refunds) AND SLEEP(1)", "SLEEP()"),
])
def test_a_real_call_beside_that_syntax_is_still_an_unreviewed_call(sql, named):
    statement = only(sql)
    assert_not_presented_as_a_plain_read(statement)
    assert named in " ".join(statement["reasons"])


def test_a_quoted_cte_name_with_a_column_list_stays_conservative():
    # A quoted name before "(" is a stored-function call in MySQL, so call names are unknown
    # for the whole statement: not resolved here (documented limitation), never LOW / HIGH.
    statement = only("WITH RECURSIVE `r`(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM `r` WHERE n < 3) "
                     "SELECT * FROM `r`")
    assert_not_presented_as_a_plain_read(statement)
    assert "could not identify" in " ".join(statement["reasons"])


def test_plain_explain_is_not_treated_as_running_the_select():
    # EXPLAIN without ANALYZE does not run the SELECT: no locks are taken.
    statement = only("EXPLAIN SELECT * FROM orders WHERE id = 1 FOR UPDATE")
    assert LOCKING_READ_REASON not in statement["reasons"]


# ---------------------------------------------------------------- SELECT ... INTO

SELECT_INTO = [
    "SELECT * INTO @a FROM orders LIMIT 1",
    "SELECT id INTO @a FROM orders WHERE id = 1",
    "SELECT * INTO t2 FROM orders",
    "SELECT * FROM orders LIMIT 1 INTO @a",
    "SELECT * FROM orders INTO t2",
    "SELECT id INTO @a FROM orders WHERE id = 1 FOR UPDATE",
    "EXPLAIN ANALYZE SELECT * INTO @a FROM orders LIMIT 1",
]


@pytest.mark.parametrize("sql", SELECT_INTO)
def test_select_into_in_either_position_is_not_analysed_and_shown_as_submitted(sql):
    statement = only(sql)
    assert statement["analysis_status"] == "unreadable"
    assert statement["parse_error"]
    assert (statement["score"], statement["risk_level"], statement["confidence"]) == (100, "CRITICAL", "LOW")
    assert NOT_ANALYSED_CHECK in statement["checklist"]
    # The submitted text, never the parser's reading of it as a new table.
    assert statement["sql"] == sql and "CREATE TABLE" not in statement["sql"]
    assert statement["tables"] == [] and statement["analysis_text_differs"] is False


@pytest.mark.parametrize("sql", ["SELECT * INTO @a FROM users LIMIT 1", "SELECT * FROM users LIMIT 1 INTO @a"])
def test_select_into_gets_no_plan_and_no_metadata_lookup(mysql, sql):
    response = post(sql)
    assert response.status_code == 200
    statement = response.json()["statements"][0]
    assert statement["analysis_status"] == "unreadable"
    assert statement["evidence"]["plan"]["state"] != "collected"
    assert explains(mysql) == []
    assert not [sent for sent in mysql.executed if "information_schema" in sent]
    assert_read_only_boundary(mysql)


@pytest.mark.parametrize("sql", ["INSERT INTO orders (id) VALUES (1)", "INSERT INTO archive SELECT * FROM orders",
                                 "CREATE TABLE copy AS SELECT * FROM orders"])
def test_insert_into_and_create_table_as_select_are_not_select_into(sql):
    assert only(sql)["analysis_status"] == "analysed"


# ---------------------------------------------------------------- plan gate and batches

@pytest.mark.parametrize("sql", [
    "SELECT * FROM users WHERE id = 1 FOR UPDATE",
    "SELECT * FROM users LOCK IN SHARE MODE",
    "SELECT my_func(id) FROM users",
    "SELECT SLEEP(1) FROM users",
])
def test_the_plan_gate_still_refuses_these_selects(mysql, sql):
    statement = post(sql).json()["statements"][0]
    assert statement["evidence"]["plan"] == {"state": "not_eligible", "reason": "plan_not_eligible"}
    assert explains(mysql) == []
    assert_read_only_boundary(mysql)


def test_a_mixed_batch_keeps_each_statement_s_own_assessment(mysql):
    data = post("SELECT * FROM users WHERE id = 1; SELECT * FROM users WHERE id = 2 FOR UPDATE; "
                "SELECT * INTO @a FROM users LIMIT 1").json()
    plain, locking, into = data["statements"]
    assert plain["analysis_status"] == "analysed" and plain["evidence"]["plan"]["state"] == "collected"
    assert locking["confidence"] == "LIMITED" and locking["evidence"]["plan"]["state"] == "not_eligible"
    assert into["analysis_status"] == "unreadable" and into["sql"] == "SELECT * INTO @a FROM users LIMIT 1"
    # Only the plain SELECT was planned; the batch is not reassuring.
    assert len(explains(mysql)) == 1 and "FOR UPDATE" not in explains(mysql)[0]
    assert (data["overall_risk_level"], data["overall_confidence"]) == ("CRITICAL", "LOW")
    assert_read_only_boundary(mysql)
