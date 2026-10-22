"""Row scope, risk and confidence: acceptance criteria W1-W12 of the evidence contract.

docs/v2-database-evidence-contract.md, sections 7-9. A WHERE clause, a column name or
an "=" anywhere in a predicate never establishes a narrow scope; only a primary key or
unique index confirmed in table metadata does, and only for a single-table write
whose WHERE fixes every key column to a non-NULL literal of a compatible type.

Verification level: unit / TestClient. The MySQL server is the fake from
test_local_evidence_credentials, answering the fixed information_schema queries with
the explicit schema each test declares; uniqueness comes from NON_UNIQUE, never from
a column name. No real MySQL is involved (see VERIFICATION.md for live checks).
"""

from __future__ import annotations

import pymysql
import pytest

import backend.db as backend_db
from backend.parser import parse_sql
from backend.risk_engine import score_statement
from backend.row_scope import static_row_scope
from tests.test_local_evidence_credentials import DB, DECOY, FakeMySQL, mysql, post  # noqa: F401  (mysql is a fixture)


def column(name, data_type="int", nullable="NO", key=""):
    return {"COLUMN_NAME": name, "DATA_TYPE": data_type, "IS_NULLABLE": nullable,
            "COLUMN_KEY": key, "ORDINAL_POSITION": 1}


def index(name, columns, unique=True):
    return [{"INDEX_NAME": name, "COLUMN_NAME": col, "SEQ_IN_INDEX": position,
             "NON_UNIQUE": 0 if unique else 1, "CARDINALITY": 10, "SUB_PART": None,
             "INDEX_TYPE": "BTREE"} for position, col in enumerate(columns, 1)]


# users: PRIMARY(id int); customer_id is indexed but NOT unique; email is a nullable
# unique varchar; code is a unique varchar; (tenant_id, ref) is a composite unique key.
USERS_STATISTICS = [
    *index("PRIMARY", ["id"]),
    *index("idx_customer", ["customer_id"], unique=False),
    *index("uq_email", ["email"]),
    *index("uq_code", ["code"]),
    *index("uq_tenant_ref", ["tenant_id", "ref"]),
]
USERS_COLUMNS = [
    column("id", key="PRI"), column("customer_id", key="MUL"), column("status", "varchar"),
    column("email", "varchar", nullable="YES", key="UNI"), column("code", "varchar", key="UNI"),
    column("tenant_id"), column("ref", "varchar"), column("created_at", "datetime"),
    column("amount", "decimal"),
]


class SchemaMySQL(FakeMySQL):
    """FakeMySQL whose information_schema answers come from an explicit schema."""

    def __init__(self, statistics=USERS_STATISTICS, columns=USERS_COLUMNS, **kwargs):
        super().__init__(**kwargs)
        self.statistics, self.columns = statistics, columns

    def rows_for(self, sql, args, connection):
        text = sql.strip()
        if "information_schema.STATISTICS" in text and self.metadata_error is None:
            self.executed.append(text)
            return [dict(row) for row in self.statistics]
        if "information_schema.COLUMNS" in text and self.metadata_error is None:
            self.executed.append(text)
            return [dict(row) for row in self.columns]
        return super().rows_for(sql, args, connection)


@pytest.fixture
def schema(monkeypatch):
    server = SchemaMySQL()
    for key, value in DECOY.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(backend_db, "_client", None)
    monkeypatch.setattr(pymysql, "connect", lambda **kwargs: server.connect(**kwargs))
    return server


def with_metadata(sql):
    response = post(sql)
    assert response.status_code == 200, response.text
    return response.json()


def static(sql):
    response = post(sql, username=None, password=None)
    assert response.status_code == 200, response.text
    return response.json()


def only(data):
    assert data["statement_count"] == 1
    return data["statements"][0]


KEY_WORDS = ("key-scoped", "specific key", "single row", "at most one row")


def assert_not_narrow(statement):
    assert statement["scope"]["basis"] == "not_established", statement["scope"]
    assert statement["scope"]["factor"] is None
    assert statement["score"] >= 20 and statement["risk_level"] != "LOW"
    assert all(factor["points"] >= 0 for factor in statement["factors"] + statement["evidence_factors"])
    text = " ".join(statement["reasons"] + [f["label"] for f in statement["factors"]]).lower()
    assert not any(word in text for word in KEY_WORDS), text


# ---------------------------------------------------------------- W1-W5: no metadata


@pytest.mark.parametrize("sql", [
    "UPDATE users SET status = 'x' WHERE id = 10",                        # W2
    "DELETE FROM orders WHERE customer_id = 42",
    "UPDATE users SET status = 'x' WHERE id >= 5",                        # W3
    "UPDATE users SET status = 'x' WHERE id <= 999999999",
    "UPDATE users SET status = 'x' WHERE id BETWEEN 1 AND 100",
    "DELETE FROM orders WHERE id = 5 OR status <> 'open'",                # W4
    "UPDATE users SET status = 'x' WHERE tenant_id = 3 AND created_at < NOW()",
    "UPDATE customers SET status = 'inactive' WHERE status IS NOT NULL",  # W5
    "DELETE FROM orders WHERE customer_id IS NULL",
    "UPDATE users SET status = 'x' WHERE status = 'active'",
    "DELETE FROM orders WHERE id IN (SELECT order_id FROM refunds)",
])
def test_w1_where_without_metadata_is_never_narrow(mysql, sql):
    statement = only(static(sql))
    assert_not_narrow(statement)
    assert statement["confidence"] == "LIMITED"


def test_w4_constant_true_or_branch_matches_every_row(mysql):
    # Review H1: an always-true WHERE is scored and scoped exactly like no WHERE.
    statement = only(static("DELETE FROM orders WHERE order_id = 5 OR 1"))
    assert statement["where_looks_trivial"] is True
    assert {"label": "WHERE clause is always true — matches every row", "points": 65} in statement["factors"]
    assert statement["scope"]["basis"] == "all_rows"
    assert statement["score"] == 100 and statement["risk_level"] == "CRITICAL"
    assert statement["confidence"] == "HIGH"


@pytest.mark.parametrize("sql", [
    "UPDATE customers SET status = 'inactive' WHERE status IS NOT NULL",
    "DELETE FROM orders WHERE customer_id IS NULL",
])
def test_w5_null_predicates_are_called_out(mysql, sql):
    statement = only(static(sql))
    assert any("IS NULL or IS NOT NULL" in reason for reason in statement["reasons"])


@pytest.mark.parametrize("sql", ["UPDATE users SET status = 'x'", "DELETE FROM users"])
def test_unrestricted_single_table_write_is_all_rows_critical_and_high_confidence(mysql, sql):
    statement = only(static(sql))
    assert statement["scope"] == {"basis": "all_rows", "source": "sql", "table": "users",
                                  "index": None, "columns": [], "factor": None,
                                  "indirect_effects": "not_checked"}
    assert statement["score"] == 100 and statement["risk_level"] == "CRITICAL"
    assert statement["confidence"] == "HIGH"   # high risk, established scope


def test_limit_without_where_is_not_all_rows_and_stays_critical(mysql):
    statement = only(static("DELETE FROM users LIMIT 100"))
    assert statement["scope"]["basis"] == "not_established"
    assert statement["score"] == 100 and statement["confidence"] == "LIMITED"


# ---------------------------------------------------------------- W6-W10: with metadata


def test_w7_confirmed_primary_key_bounds_the_match(schema):
    statement = only(with_metadata("UPDATE users SET status = 'x' WHERE id = 10"))
    assert statement["scope"] == {
        "basis": "at_most_one_row", "source": "table_metadata", "table": f"{DB}.users",
        "index": "PRIMARY", "columns": ["id"],
        "factor": {"label": "Unique key PRIMARY limits the match to at most one row", "points": 0,
                   "medium_floor_applied": True},
        "indirect_effects": "not_checked"}
    # One-row write floor: the verified key is reported, but the write stays MEDIUM.
    assert (statement["static_score"], statement["score"], statement["risk_level"]) == (20, 20, "MEDIUM")
    assert any("MEDIUM is the minimum overall risk" in reason for reason in statement["reasons"])
    assert statement["confidence"] == "HIGH" and statement["static_confidence"] == "LIMITED"
    assert any("The row may not exist" in reason for reason in statement["reasons"])
    # Review H3: the bound is on the directly matched row only.
    assert any("foreign-key actions" in reason and "not checked" in reason
               for reason in statement["reasons"])


def test_same_statement_without_metadata_is_not_presented_as_verified(mysql):
    statement = only(static("UPDATE users SET status = 'x' WHERE id = 10"))
    assert_not_narrow(statement)


@pytest.mark.parametrize("sql", [
    "UPDATE users SET status = 'x' WHERE id = 10 AND status = 'old'",   # extra AND terms only narrow
    "UPDATE users SET status = 'x' WHERE id = 10 LIMIT 1",
    "UPDATE users SET status = 'x' WHERE id = 10 AND id = 11",          # zero rows: the bound still holds
    "DELETE FROM users WHERE code = 'A-17'",                             # unique varchar, string literal
    "DELETE FROM users WHERE email = 'a@example.com'",                   # nullable unique: '=' never matches NULL
    "UPDATE users SET status = 'x' WHERE tenant_id = 3 AND ref = 'R1'",  # every column of a composite key
])
def test_unique_key_equality_on_every_key_column_is_at_most_one_row(schema, sql):
    statement = only(with_metadata(sql))
    assert statement["scope"]["basis"] == "at_most_one_row", sql
    assert statement["confidence"] == "HIGH"


@pytest.mark.parametrize("sql", [
    "UPDATE users SET status = 'x' WHERE customer_id = 42",              # W6 non-unique index
    "UPDATE users SET status = 'x' WHERE id >= 5",
    "DELETE FROM users WHERE id = 5 OR status <> 'open'",
    "DELETE FROM users WHERE code = 5",                                  # W8 number vs varchar
    "UPDATE users SET status = 'x' WHERE id = '10'",                     # string vs int: not counted
    "UPDATE users SET status = 'x' WHERE id = -5",                       # not a plain literal
    "UPDATE users SET status = 'x' WHERE tenant_id = 3",                 # W9 partial composite key
    "DELETE FROM users WHERE email IS NULL",                             # nullable unique, IS NULL
    "DELETE FROM users WHERE email = NULL",
    "UPDATE users SET status = 'x' WHERE id IN (10)",
    "UPDATE users SET status = 'x' WHERE status = 'active'",            # broad predicate
    "UPDATE users SET status = 'x' WHERE NOT (id = 10)",
])
def test_predicates_that_do_not_fix_a_unique_key_are_not_narrow(schema, sql):
    assert_not_narrow(only(with_metadata(sql)))


@pytest.mark.parametrize("sql", [
    # W10: the key belongs to the joined table, not the written one.
    "UPDATE users JOIN orders ON orders.user_id = users.id SET users.status = 'x' WHERE orders.id = 7",
    "UPDATE users u JOIN customers c ON c.id = u.customer_id SET u.status = 'x' WHERE c.id = 7",
    "DELETE u FROM users u JOIN orders o ON o.user_id = u.id WHERE u.id = 7",
    "DELETE FROM users WHERE id = (SELECT MAX(id) FROM users)",
    "WITH x AS (SELECT id FROM users) DELETE FROM users WHERE id = 1",
])
def test_joined_multi_table_and_cte_writes_are_not_narrow(schema, sql):
    assert_not_narrow(only(with_metadata(sql)))


def test_metadata_failure_never_produces_a_verified_scope(monkeypatch):
    server = SchemaMySQL(metadata_error=pymysql.err.OperationalError(1142, "SELECT command denied"))
    monkeypatch.setattr(backend_db, "_client", None)
    monkeypatch.setattr(pymysql, "connect", lambda **kwargs: server.connect(**kwargs))
    statement = only(with_metadata("UPDATE users SET status = 'x' WHERE id = 10"))
    assert statement["evidence"]["metadata"]["state"] == "failed"
    assert_not_narrow(statement)
    assert statement["confidence"] == "LIMITED"


def test_missing_table_caps_confidence_and_is_not_narrow(monkeypatch):
    server = SchemaMySQL()
    real = server.rows_for

    def no_table(sql, args, connection):
        if "information_schema.TABLES" in sql:
            server.executed.append(sql.strip())
            return []
        return real(sql, args, connection)

    server.rows_for = no_table
    monkeypatch.setattr(backend_db, "_client", None)
    monkeypatch.setattr(pymysql, "connect", lambda **kwargs: server.connect(**kwargs))
    for sql in ("UPDATE users SET status = 'x' WHERE id = 10", "DELETE FROM users"):
        statement = only(with_metadata(sql))
        assert statement["evidence"]["metadata"]["tables"] == [{"name": "users", "found": False}]
        assert statement["scope"]["basis"] != "at_most_one_row"
        assert statement["confidence"] == "LIMITED", sql


# ---------------------------------------------------------------- confidence and batches


def test_batch_confidence_is_the_weakest_statement(schema):
    data = with_metadata("UPDATE users SET status = 'x' WHERE id = 10; "
                         "UPDATE users SET status = 'x' WHERE status = 'old'; DROP TABLE audit_log;")
    confidences = [statement["confidence"] for statement in data["statements"]]
    assert confidences == ["HIGH", "LIMITED", "HIGH"]
    assert data["overall_confidence"] == "LIMITED"
    assert data["overall_score"] == max(statement["score"] for statement in data["statements"])


def test_partly_read_sql_is_low_confidence_and_never_narrow(mysql):
    data = static("SELECT a FROM t INTO @x; DELETE FROM users WHERE id = 1 ORDER")
    assert all(statement["analysis_text_differs"] for statement in data["statements"])
    assert all(statement["confidence"] == "LOW" for statement in data["statements"])
    assert all(statement["scope"]["basis"] != "at_most_one_row" for statement in data["statements"])
    assert data["overall_confidence"] == "LOW"


def test_parse_error_is_low_confidence_critical(mysql):
    statement = only(static("UPDATE users SET WHERE"))
    assert statement["confidence"] == "LOW"


def test_high_confidence_never_means_low_risk(mysql):
    statement = only(static("DROP TABLE users"))
    assert statement["confidence"] == "HIGH" and statement["risk_level"] == "CRITICAL"


# ---------------------------------------------------------------- v2_assessment (Q5)


@pytest.mark.parametrize("sql", ["UPDATE users SET status = 'x' WHERE id = 10", "SELECT * FROM users",
                                 "DROP TABLE users", "UPDATE users SET status = 'x' WHERE status = 'old'"])
def test_v2_assessment_matches_the_result_and_is_never_a_placeholder(schema, sql):
    statement = only(with_metadata(sql))
    assessment = statement["v2_assessment"]
    assert assessment["overall_score"] == statement["score"]
    assert assessment["risk_level"] == statement["risk_level"] != "UNKNOWN"
    assert assessment["confidence"] == statement["confidence"]
    if statement["scope"]["basis"] == "at_most_one_row":
        # Review H3/M6: a bounded direct match never makes Data Risk LOW, and the
        # assessment says what is still not established.
        data_risk = next(d for d in assessment["dimensions"] if d["name"] == "Data Risk")
        assert data_risk["level"] != "LOW" and "metadata" in data_risk["reason"]
        assert "foreign-key actions" in data_risk["reason"]
        titles = [finding["title"] for finding in assessment["findings"]]
        assert "Affected-row count is unknown" not in titles
        assert "Direct match bounded; total impact not established" in titles


def test_v2_assessment_never_suggests_generated_sql(mysql):
    for sql in ("UPDATE users u JOIN orders o ON o.user_id = u.id SET u.status = 'x' WHERE o.id = 1",
                "WITH x AS (SELECT 1 AS id) DELETE FROM users WHERE id IN (SELECT id FROM x)"):
        statement = only(static(sql))
        checks = [gap["suggested_check"] for gap in statement["v2_assessment"]["evidence_missing"]]
        checks += [item for item in statement["checklist"]]
        assert not any("SELECT COUNT(*) FROM" in check or "EXPLAIN UPDATE" in check for check in checks)


# ---------------------------------------------------------------- API shape


def test_api_fields_and_types(schema):
    data = with_metadata("UPDATE users SET status = 'x' WHERE id = 10; SELECT * FROM users")
    assert data["overall_confidence"] in {"HIGH", "LIMITED", "LOW"}
    for statement in data["statements"]:
        assert statement["confidence"] in {"HIGH", "LIMITED", "LOW"}
        assert statement["static_confidence"] in {"HIGH", "LIMITED", "LOW"}
        assert isinstance(statement["analysis_text_differs"], bool)
        scope = statement["scope"]
        assert set(scope) == {"basis", "source", "table", "index", "columns", "factor", "indirect_effects"}
        assert scope["indirect_effects"] == (None if scope["basis"] == "not_applicable" else "not_checked")
        assert scope["basis"] in {"all_rows", "at_most_one_row", "not_established", "not_applicable"}
        assert isinstance(scope["columns"], list)
    assert data["statements"][1]["scope"]["basis"] == "not_applicable"


# ---------------------------------------------------------------- parser facts


@pytest.mark.parametrize("sql,tables", [
    ("DELETE o FROM orders o JOIN customers c ON c.id = o.customer_id WHERE c.region = 'EU'",
     ["orders", "customers"]),
    ("WITH x AS (SELECT id FROM orders) DELETE FROM orders WHERE id IN (SELECT id FROM x)", ["orders"]),
    ("DELETE FROM t1 USING t1 JOIN t2 ON t1.id = t2.id", ["t1", "t2"]),
    ("UPDATE shop.orders AS o SET o.status = 'x' WHERE o.id = 10", ["shop.orders"]),
])
def test_aliases_and_cte_names_are_not_tables(sql, tables):
    assert parse_sql(sql)[0].tables == tables


def test_static_scope_and_confidence_are_one_rule():
    facts = parse_sql("DELETE FROM users")[0]
    assert static_row_scope(facts) == "all_rows"
    assert score_statement(facts, 1).confidence == "HIGH"
