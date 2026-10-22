"""Batch contract: what the validator analyses, what it refuses, and how it says so.

Offline (no login, so no database connection). Covers three boundaries:

- invalid MySQL vs valid MySQL the validator does not analyse vs SQL it cannot read
  (analysis_status), none of which is ever scored as low risk;
- input without statements, refused instead of returned as a LOW-risk batch;
- stored programs and DELIMITER scripts, which cannot be split into statements by ";".
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.parser import parse_sql, unsupported_script

client = TestClient(app)

NOT_ANALYSED_CHECK = "Do not execute a statement that the validator could not analyze."


def validate(sql: str) -> dict:
    response = client.post("/api/validate", json={"sql": sql})
    assert response.status_code == 200, response.text
    return response.json()


def only(sql: str) -> dict:
    data = validate(sql)
    assert data["statement_count"] == 1, data
    return data["statements"][0]


def assert_not_analysed(statement: dict, status: str) -> None:
    assert statement["analysis_status"] == status
    # Never reassuring: maximum score, LOW confidence, never LOW risk.
    assert (statement["risk_level"], statement["score"], statement["confidence"]) == ("CRITICAL", 100, "LOW")
    assert NOT_ANALYSED_CHECK in statement["checklist"]
    assert statement["evidence"]["plan"]["state"] != "collected"


# --- Task A: invalid, unsupported, unreadable ---------------------------------------

@pytest.mark.parametrize("sql, shown", [
    ("SELEC * FRM orders", '"SELEC"'),
    ("UPDAT orders SET x = 1", '"UPDAT"'),
    ("'abc'", "a quoted string or identifier"),
])
def test_sql_that_mysql_rejects_is_reported_as_not_valid(sql, shown):
    statement = only(sql)
    assert_not_analysed(statement, "invalid")
    assert statement["parse_error"] == f"a MySQL statement cannot begin with {shown}"
    assert statement["reasons"][0].startswith("Not valid MySQL: ")
    assert statement["checklist"][0] == "Fix the SQL before proceeding."


def test_a_supported_select_is_analysed():
    statement = only("SELECT * FROM orders WHERE id = 1")
    assert statement["analysis_status"] == "analysed" and statement["parse_error"] is None
    assert (statement["statement_type"], statement["risk_level"], statement["confidence"]) == ("SELECT", "LOW", "HIGH")


@pytest.mark.parametrize("sql, statement_type", [
    # MySQL 8.0.19+ (VALUES, TABLE) and HANDLER: valid statements the validator does not analyse.
    ("VALUES ROW(1, 2), ROW(3, 4)", "VALUES"),
    ("TABLE orders", "TABLE"),
    ("TABLE orders ORDER BY id LIMIT 10", "TABLE"),
    ("HANDLER orders OPEN", "HANDLER"),
    ("HANDLER orders READ FIRST", "HANDLER"),
    ("handler orders close", "HANDLER"),
])
def test_valid_but_unsupported_statements_are_not_analysed_and_never_called_invalid(sql, statement_type):
    statement = only(sql)
    assert_not_analysed(statement, "unsupported")
    assert statement["statement_type"] == statement_type
    assert statement["sql"] == sql  # the submitted text, not the parser's reading of it
    assert statement["parse_error"] == f"{statement_type} is a valid MySQL statement that this validator does not analyse"
    assert statement["reasons"][0].startswith("Not analysed (statement type not supported): ")
    assert "Fix the SQL" not in " ".join(statement["checklist"])
    assert "valid MySQL" not in statement["reasons"][0].split(":")[0]


@pytest.mark.parametrize("sql", ["XA START 'x'", "GET DIAGNOSTICS @a = NUMBER", "DO"])
def test_a_statement_the_parser_cannot_read_is_not_called_invalid(sql):
    # Starts with a MySQL statement keyword; whether it is valid is not determined.
    statement = only(sql)
    assert_not_analysed(statement, "unreadable")
    assert statement["sql"] == sql and statement["analysis_text_differs"] is False
    assert statement["reasons"][0].startswith("Could not be read (it may be invalid, or valid MySQL")
    assert "Fix the SQL" not in " ".join(statement["checklist"])


@pytest.mark.parametrize("sql", [
    "LOCK TABLES orders WRITE", "UNLOCK TABLES", "WITH x AS (SELECT 1) SELECT * FROM x", "(SELECT 1)",
    "SHOW TABLES", "SET @a = 1", "CALL archive_orders(2024)", "START TRANSACTION", "DESC orders",
])
def test_statement_keywords_are_never_reported_as_invalid(sql):
    assert all(f.analysis_status != "invalid" for f in parse_sql(sql))


def test_a_mixed_batch_reports_each_statement_and_aggregates_the_worst():
    data = validate("SELECT * FROM orders WHERE id = 1; VALUES ROW(1); SELEC x; "
                    "XA START 'x'; DELETE FROM orders WHERE id = 2")
    statements = data["statements"]
    assert [s["analysis_status"] for s in statements] == [
        "analysed", "unsupported", "invalid", "unreadable", "analysed"]
    assert [s["statement_type"] for s in statements] == ["SELECT", "VALUES", "UNKNOWN", "UNKNOWN", "DELETE"]
    assert [s["index"] for s in statements] == [0, 1, 2, 3, 4]
    # The batch is as risky as its riskiest statement and as confident as its least confident.
    assert (data["overall_risk_level"], data["overall_score"], data["overall_confidence"]) == ("CRITICAL", 100, "LOW")
    assert statements[4]["risk_level"] != "CRITICAL"  # the analysed DELETE keeps its own result


# --- Task B: no statements -------------------------------------------------------

@pytest.mark.parametrize("sql", ["", " ", "\n\t \r\n", "-- only a comment", "/* block */", "# hash", ";;", "-- a\n;\n/* b */ ;"])
def test_input_without_statements_is_an_error_not_a_low_risk_result(sql):
    response = client.post("/api/validate", json={"sql": sql})
    assert response.status_code == 200
    assert response.json() == {"error": "no_statements"}


def test_normal_input_still_returns_a_batch():
    data = validate("-- check\nSELECT * FROM orders WHERE id = 1;")
    assert data["statement_count"] == 1 and data["overall_confidence"] == "HIGH"


# --- Task C: stored programs and DELIMITER ----------------------------------------

def test_call_is_analysed_but_never_claims_the_procedure_body():
    statement = only("CALL archive_orders(2024)")
    assert statement["statement_type"] == "CALL" and statement["confidence"] != "HIGH"
    assert "Stored procedure behavior cannot be fully determined from the CALL statement alone." in statement["reasons"]
    assert "Inspect the stored procedure definition before execution." in statement["checklist"]


@pytest.mark.parametrize("sql, kind", [
    ("CREATE PROCEDURE p() SELECT 1", "PROCEDURE"),
    ("CREATE DEFINER='admin'@'localhost' PROCEDURE p() SELECT 1;", "PROCEDURE"),
    ("CREATE FUNCTION f() RETURNS INT DETERMINISTIC RETURN 1", "FUNCTION"),
    ("CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET NEW.a = 1", "TRIGGER"),
    ("CREATE DEFINER = CURRENT_USER EVENT e ON SCHEDULE EVERY 1 DAY DO DELETE FROM t", "EVENT"),
])
def test_a_stored_program_definition_on_its_own_is_listed_as_not_analysed(sql, kind):
    statement = only(sql)
    assert_not_analysed(statement, "unsupported")
    assert statement["statement_type"] == f"CREATE {kind}"
    assert "does not analyse stored program bodies" in statement["parse_error"]


@pytest.mark.parametrize("sql", [
    "CREATE TABLE events (event VARCHAR(10), `procedure` INT)",
    "CREATE DEFINER=event@localhost VIEW v AS SELECT 1",
    "CREATE INDEX trigger_idx ON t (a)",
])
def test_other_create_statements_are_not_stored_programs(sql):
    assert unsupported_script(sql) is None
    assert parse_sql(sql)[0].analysis_status == "analysed"


@pytest.mark.parametrize("sql", [
    # A multi-statement body: ";" would split it into fragments read as statements.
    "CREATE PROCEDURE p() BEGIN UPDATE t SET a = 1; INSERT INTO t VALUES (1); END",
    "CREATE PROCEDURE p()\nBEGIN\n  DELETE FROM t;\nEND",
    # A stored program together with other statements.
    "SELECT 1; CREATE PROCEDURE p() BEGIN DELETE FROM t; END; SELECT 2",
    "CREATE PROCEDURE p() SELECT 1; SELECT 2",
])
def test_stored_program_scripts_that_cannot_be_split_are_refused(sql):
    assert validate(sql) == {"error": "stored_program_not_supported"}


@pytest.mark.parametrize("sql", [
    "DELIMITER //\nCREATE PROCEDURE p() BEGIN UPDATE t SET a = 1; END //\nDELIMITER ;",
    "delimiter $$\nCREATE PROCEDURE p() BEGIN SELECT 1; END$$\ndelimiter ;",
    "SELECT 1;\nDELIMITER //\nSELECT 2 //",
    "DELIMITER ;",
])
def test_delimiter_scripts_are_refused(sql):
    assert validate(sql) == {"error": "delimiter_not_supported"}


def test_semicolons_and_keywords_in_strings_and_comments_are_not_boundaries():
    sql = ("SELECT 'BEGIN; DELIMITER //' FROM t WHERE id = 1; -- DELIMITER ;\n"
           "/* CREATE PROCEDURE p() BEGIN x; END */ UPDATE t SET a = 'x;y' WHERE id = 1")
    data = validate(sql)
    assert [s["statement_type"] for s in data["statements"]] == ["SELECT", "UPDATE"]
    assert all(s["analysis_status"] == "analysed" for s in data["statements"])


def test_refusals_are_decided_before_any_database_connection(monkeypatch):
    import backend.main as main

    def no_connection(*args, **kwargs):
        raise AssertionError("no connection may be opened for a refused script")

    monkeypatch.setattr(main, "open_evidence_connection", no_connection)
    for sql in ("-- nothing", "DELIMITER //", "CREATE PROCEDURE p() BEGIN DELETE FROM t; END",
                "SELECT 1; /*!50000 DELETE FROM t */"):
        body = {"sql": sql, "host": "127.0.0.1", "username": "u", "password": "p", "database": "d"}
        response = client.post("/api/validate", json=body)
        assert response.status_code == 200 and "error" in response.json()


# ---------------------------------------------------------------- MySQL comment rules
# MySQL runs the contents of an executable comment (/*! ... */), and reads "--" as a
# comment only before whitespace, a control character or the end of the input
# (MySQL manual, "Comments"). sqlglot keeps every /* */ as a comment and reads every
# "--" as one, so either could hide SQL that MySQL runs.

EXECUTABLE_COMMENT = {"error": "executable_comment_not_supported"}


@pytest.mark.parametrize("sql", [
    # A hidden write after an ordinary statement: was one SELECT, LOW 0, HIGH confidence.
    "SELECT id FROM customers WHERE id = 1;\n/*!50000 DELETE FROM customers */;",
    # The only statement is in the comment: was "no_statements".
    "/*!50000 DELETE FROM customers */",
    "/*! DROP TABLE customers */;",
    # A predicate or an assignment widened inside the comment: was MEDIUM.
    "DELETE FROM orders WHERE id = 1 /*!50000 OR 1 = 1 */",
    "UPDATE orders SET status = 'x' /*!50000 , total = 0 */ WHERE id = 1",
    # After a string with comment-like text, and after a quoted identifier.
    "SELECT '/* not a comment */' FROM t /*!50000 , (SELECT 1) */",
    "SELECT `a``b` FROM t /*!80000 FOR UPDATE */",
])
def test_executable_comments_are_refused(sql):
    assert validate(sql) == EXECUTABLE_COMMENT


@pytest.mark.parametrize("sql", [
    "SELECT '/*!50000 DELETE FROM t */' FROM t WHERE id = 1",
    "SELECT 'it''s /*!50000 DELETE FROM t */' FROM t WHERE id = 1",
    'SELECT "/*! DELETE FROM t */" FROM t WHERE id = 1',
    "SELECT `/*!x*/` FROM t WHERE id = 1",
    "SELECT id FROM t /* ordinary comment */ WHERE id = 1",
    "SELECT id FROM t /* comments do not nest /*! not run */ WHERE id = 1",
    "SELECT id FROM t # /*! in a line comment */\nWHERE id = 1",
    "SELECT id FROM t -- /*! in a line comment */\nWHERE id = 1",
    "SELECT /*+ MAX_EXECUTION_TIME(1000) */ id FROM t WHERE id = 1",
])
def test_comment_like_text_that_mysql_does_not_run_is_analysed(sql):
    statement = only(sql)
    assert (statement["statement_type"], statement["analysis_status"]) == ("SELECT", "analysed")


def test_executable_comment_check_assumes_neither_backslash_mode():
    from backend.parser import has_executable_comment

    # With backslash escapes the comment is inside the string; under the
    # NO_BACKSLASH_ESCAPES SQL mode the string ends at the backslash and MySQL would run
    # the comment. The server's mode is not known, so it is reported.
    assert has_executable_comment("SELECT 'a\\'b /*!50000 c */' FROM t")
    assert not has_executable_comment("SELECT 'it''s /*!50000 c */' FROM t")
    assert not has_executable_comment("SELECT 1 /* a /*! b */")


def score(statement: dict) -> tuple:
    return (statement["statement_type"], statement["risk_level"], statement["score"],
            statement["confidence"], statement["has_where"])


def test_double_minus_before_a_non_space_is_two_minus_signs():
    # Was read as a comment from "--1": the WHERE vanished and a one-row UPDATE was
    # CRITICAL ("no WHERE clause") with HIGH confidence.
    statement = only("UPDATE accounts SET balance = balance--1 WHERE id = 1")
    assert statement["sql"] == "UPDATE accounts SET balance = balance - -1 WHERE id = 1"
    assert statement["analysis_status"] == "analysed" and statement["has_where"] is True
    assert score(statement) == score(only("UPDATE accounts SET balance = balance - -1 WHERE id = 1"))


def test_a_statement_after_double_minus_is_not_hidden():
    # Was one UPDATE: the ";" and the DELETE after "--1" were inside the "comment".
    data = validate("UPDATE accounts SET balance = balance--1;\nDELETE FROM accounts;")
    assert data["statement_count"] == 2
    assert [score(s)[:2] for s in data["statements"]] == [("UPDATE", "CRITICAL"), ("DELETE", "CRITICAL")]
    assert data["statements"][1]["sql"] == "DELETE FROM accounts"


@pytest.mark.parametrize("sql", [
    "SELECT id FROM t WHERE id = 1 -- a comment; DELETE FROM t",
    "SELECT id FROM t WHERE id = 1 --\ta comment after a tab; DELETE FROM t",
    "SELECT id FROM t WHERE id = 1 --",
    "SELECT id FROM t WHERE id = 1 --\nAND 1 = 1",
])
def test_double_minus_before_whitespace_is_still_a_comment(sql):
    statement = only(sql)
    assert (statement["statement_type"], statement["analysis_status"]) == ("SELECT", "analysed")


def test_minus_sign_rewrite_leaves_strings_identifiers_and_comments_alone():
    from backend.parser import mysql_minus_signs

    sql = "SELECT a--1, 'x--y', `p--q`, \"r--s\" FROM t /* u--v */ # w--z"
    assert mysql_minus_signs(sql) == sql.replace("a--1", "a- -1", 1)
    assert mysql_minus_signs("SELECT 5---1") == "SELECT 5- - -1"
    assert mysql_minus_signs("SELECT 1 -- note--x") == "SELECT 1 -- note--x"
    assert only("UPDATE t SET note = 'a--b' WHERE id = 1")["sql"] == "UPDATE t SET note = 'a--b' WHERE id = 1"


@pytest.mark.parametrize("sql", [
    # A line of dashes is minus signs to MySQL, which rejects it; sqlglot cannot write
    # back what it reads there, and that was an HTTP 500 (also with the spaces typed).
    "----------\nSELECT id FROM t WHERE id = 1",
    "- -",
    "SELECT - - - - FROM t",
])
def test_minus_signs_the_parser_cannot_read_are_not_analysed(sql):
    assert_not_analysed(only(sql), "unreadable")


def test_a_write_after_a_line_of_dashes_is_never_reported_as_low_risk():
    data = validate("SELECT id FROM t WHERE id = 1;\n----------\nDELETE FROM t;")
    assert data["statement_count"] == 2 and data["overall_risk_level"] == "CRITICAL"
    hidden = data["statements"][1]
    assert hidden["analysis_status"] in {"invalid", "unreadable"} and "DELETE FROM t" in hidden["sql"]
    assert_not_analysed(hidden, hidden["analysis_status"])
    # "-- " with a space is still a comment.
    assert only("-- ------ section ------\nSELECT id FROM t WHERE id = 1")["analysis_status"] == "analysed"
