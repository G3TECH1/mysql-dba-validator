"""SELECT plan assessment: full table scan and optimizer estimate, filter and index.

Fake MySQL servers only (no real connection). The example plan (access type ALL, an
optimizer estimate of 1,902,192 rows, no key) is the one reported for
`SELECT * FROM test_records`; nothing in the code depends on that table or number.
"""

from __future__ import annotations

import pytest

from tests.test_local_evidence_credentials import FakeMySQL, explain_row, mysql, mysql_error, post  # noqa: F401

LARGE_SCAN = [explain_row("ALL", 1_902_192)]


def statement_for(monkeypatch, sql, **server):
    import pymysql

    import backend.db as backend_db

    fake = FakeMySQL(**server)
    monkeypatch.setattr(backend_db, "_client", None)
    monkeypatch.setattr(pymysql, "connect", lambda **kwargs: fake.connect(**kwargs))
    response = post(sql)
    assert response.status_code == 200, response.text
    return response.json()["statements"][0]


def test_a_large_full_scan_select_is_assessed_from_its_plan(monkeypatch):
    s = statement_for(monkeypatch, "SELECT * FROM test_records", explain=LARGE_SCAN)
    evidence = s["database_evidence"]
    assert evidence["access_type"] == "ALL" and evidence["full_table_scan"] is True
    assert evidence["estimated_rows"] == 1_902_192
    assert evidence["estimated_rows_semantics"] == "optimizer estimate, not exact affected-row count"
    assert [f["points"] for f in s["evidence_factors"]] == [10, 10]
    assert (s["static_score"], s["score"], s["risk_level"]) == (0, 20, "MEDIUM")
    # A plan never raises confidence.
    assert s["confidence"] == s["static_confidence"] == "HIGH"
    why = " ".join(s["reasons"])
    assert "full table scan (access type ALL)" in why
    assert "1,902,192 rows examined" in why and "an estimate, not a measured count" in why
    assert s["filter_index"] == {"state": "no_filter"}
    # Review action: never suggests that LIMIT reduces the work.
    assert ("Confirm the read is intended at this volume; a selective, indexed filter narrows it. "
            "Consider the load before running it on a busy server.") in s["checklist"]
    assert not any("LIMIT narrows" in item for item in s["checklist"])


def test_limit_without_a_sort_keeps_the_scan_but_not_the_row_volume(monkeypatch):
    # MySQL may stop once it has sent the LIMIT rows: the full scan is still the chosen
    # access path, but how many rows are read is not known.
    s = statement_for(monkeypatch, "SELECT * FROM test_records LIMIT 10", explain=LARGE_SCAN)
    assert [f["label"] for f in s["evidence_factors"]] == ["EXPLAIN indicates a full table scan"]
    assert s["score"] == s["static_score"] + 10
    assert "may stop early, so how many rows are read is not known" in " ".join(s["reasons"])
    assert s["high_estimated_rows_applied"] is False


@pytest.mark.parametrize("extra", ["Using filesort", "Using temporary; Using filesort"])
def test_limit_with_a_sort_is_scored_as_without_limit(monkeypatch, extra):
    # "If a filesort must be done, all rows that match the query without the LIMIT clause
    # are selected" (MySQL 8.0 LIMIT Query Optimization).
    s = statement_for(monkeypatch, "SELECT * FROM test_records ORDER BY created_at LIMIT 10",
                      explain=[explain_row("ALL", 1_902_192, extra=extra)])
    assert [f["points"] for f in s["evidence_factors"]] == [10, 10]
    assert (s["score"], s["risk_level"]) == (s["static_score"] + 20, "MEDIUM")


def test_limit_with_a_filter_scores_the_scan_and_the_missing_index_together(monkeypatch):
    s = statement_for(monkeypatch, "SELECT * FROM users WHERE status = 'old' LIMIT 5", explain=LARGE_SCAN)
    assert [f["points"] for f in s["evidence_factors"]] == [10]
    assert [f["points"] for f in s["metadata_factors"]] == [5]


def test_an_unreadable_where_is_not_assessed_not_reported_as_absent(monkeypatch):
    s = statement_for(monkeypatch, "UPDATE users SET WHERE", explain=LARGE_SCAN)
    # The parser cannot read it in full: not analysed, so its WHERE is unknown, not absent.
    assert s["analysis_status"] == "unreadable" and s["has_where"] is not False
    # As for every statement that is not analysed; never "no_filter" (no WHERE).
    assert s["filter_index"] == {"state": "not_applicable"}


def test_a_small_full_scan_stays_low(monkeypatch):
    s = statement_for(monkeypatch, "SELECT * FROM lookup_codes", explain=[explain_row("ALL", 40)])
    assert [f["points"] for f in s["evidence_factors"]] == [10]
    assert s["risk_level"] == "LOW"


def test_filter_on_an_unindexed_column_is_reported_from_metadata(monkeypatch):
    # FakeMySQL metadata: one index, PRIMARY(id). The filter column has no index.
    s = statement_for(monkeypatch, "SELECT * FROM users WHERE status = 'old'", explain=LARGE_SCAN)
    assert s["filter_index"] == {"state": "no_matching_index", "column": "status", "table": "users"}
    assert [f["points"] for f in s["metadata_factors"]] == [5]


def test_filter_on_an_indexed_column_is_reported_and_not_scored(monkeypatch):
    s = statement_for(monkeypatch, "SELECT * FROM users WHERE id = 5", explain=[explain_row("const", 1, key="PRIMARY")])
    assert s["filter_index"] == {"state": "matching_index", "column": "id", "table": "users"}
    assert s["metadata_factors"] == [] and s["evidence_factors"] == []


def test_a_missing_selected_key_is_not_a_claim_about_indexes_without_metadata(monkeypatch):
    s = statement_for(monkeypatch, "SELECT * FROM users WHERE status = 'old'", explain=LARGE_SCAN,
                      metadata_error=mysql_error(1142, "SELECT command denied"))
    assert s["database_evidence"]["key"] is None
    assert s["filter_index"]["state"] == "not_checked"
    assert s["metadata_factors"] == []


@pytest.mark.parametrize("sql", ["SELECT * FROM users WHERE status IN ('a', 'b')",
                                 "SELECT * FROM users u JOIN orders o ON o.user_id = u.id WHERE u.id = 1"])
def test_other_filters_are_not_assessed(monkeypatch, sql):
    s = statement_for(monkeypatch, sql, explain=LARGE_SCAN)
    assert s["filter_index"] == {"state": "not_assessed"}


def test_without_a_login_nothing_is_assessed_from_the_database(mysql):
    s = post("SELECT * FROM users WHERE status = 'old'", username=None, password=None).json()["statements"][0]
    assert s["evidence_factors"] == [] and s["metadata_factors"] == []
    assert s["filter_index"]["state"] == "not_checked"
