import pytest

from backend.db_evidence import DatabaseEvidence
from backend.evidence_scoring import apply_evidence_adjustments
from backend.main import ValidateRequest, validate
from backend.metadata import MetadataEvidence
from tests.local_evidence import local_request, use_fake_evidence_connection
from backend.parser import parse_sql
from backend.risk_engine import score_batch


def static_report(sql: str):
    return score_batch(parse_sql(sql))[0]


def evidence(**kwargs):
    # A one-row plan: its fields describe the whole plan, so they may be interpreted.
    kwargs.setdefault("plan_row_count", 1)
    return DatabaseEvidence(available=True, explain_available=True, **kwargs)


def test_unavailable_update_evidence_is_an_exact_static_noop():
    report = static_report("UPDATE users SET active = 0 WHERE status = 'pending';")
    adjusted = apply_evidence_adjustments(report, DatabaseEvidence())
    assert adjusted.report.score == report.score == 20
    assert adjusted.report.risk_level == report.risk_level == "MEDIUM"
    assert adjusted.factors == []
    assert adjusted.report.confidence == report.confidence == "LIMITED"
    assert adjusted.high_estimated_rows_applied is False


def test_unavailable_delete_evidence_is_an_exact_static_noop():
    report = static_report("DELETE FROM users WHERE status = 'inactive';")
    adjusted = apply_evidence_adjustments(report, DatabaseEvidence())
    assert adjusted.report.score == report.score == 25
    assert adjusted.report.risk_level == report.risk_level == "MEDIUM"
    assert adjusted.factors == []


def test_unavailable_select_evidence_preserves_static_behavior():
    report = static_report("SELECT * FROM users WHERE id = 1;")
    adjusted = apply_evidence_adjustments(report, DatabaseEvidence())
    assert adjusted.report.score == report.score == 0
    assert adjusted.report.risk_level == report.risk_level == "LOW"
    assert adjusted.report.confidence == report.confidence == "HIGH"


def test_successful_select_explain_is_evidence_assisted_without_score_change():
    report = static_report("SELECT * FROM users WHERE id = 1;")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type="ref", key="PRIMARY", estimated_rows=1, full_table_scan=False),
    )
    assert adjusted.report.score == report.score == 0
    # Evidence never changes confidence; the evidence state reports what was collected.
    assert adjusted.report.confidence == report.confidence == "HIGH"
    assert adjusted.materially_supports_analysis is True


def test_update_full_scan_adds_bounded_evidence_factor():
    report = static_report("UPDATE users SET active = 0 WHERE status = 'pending';")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type="ALL", full_table_scan=True, estimated_rows=500),
    )
    assert adjusted.report.score == 30
    assert adjusted.report.risk_level == "MEDIUM"
    # An EXPLAIN estimate is not an affected-row count: DML confidence stays LIMITED.
    assert adjusted.report.confidence == report.confidence == "LIMITED"
    assert any(f.points == 10 and "full table scan" in f.label.lower() for f in adjusted.factors)
    assert any("EXPLAIN indicates a full table scan" in finding for finding in adjusted.report.findings)


def test_delete_full_scan_adds_bounded_evidence_factor():
    report = static_report("DELETE FROM users WHERE status = 'inactive';")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type="ALL", full_table_scan=True, estimated_rows=500),
    )
    assert adjusted.report.score == 35
    assert any("full table scan" in f.label.lower() for f in adjusted.factors)


def test_high_estimated_rows_adds_estimate_factor_without_claiming_exact_count():
    report = static_report("UPDATE users SET active = 0 WHERE status = 'pending';")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type="range", estimated_rows=10000, full_table_scan=False),
    )
    assert adjusted.report.score == 30
    assert any(f.points == 10 and "estimated rows" in f.label.lower() for f in adjusted.factors)
    assert any("optimizer estimates" in finding for finding in adjusted.report.findings)
    assert not any("will affect 10000" in finding for finding in adjusted.report.findings)
    assert adjusted.high_estimated_rows_applied is True


def test_a_select_plan_is_scored_as_load_and_limit_drops_only_the_row_volume():
    # The score is operational severity if the statement runs (contract 8.1): a large
    # optimizer estimate is load even for a read. With LIMIT and no sort, MySQL may stop
    # early: the full scan still counts, the row-volume estimate does not.
    report = static_report("SELECT * FROM users;")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type="ALL", estimated_rows=10000, full_table_scan=False),
    )
    assert report.score == 0 and adjusted.report.score == 10
    assert adjusted.high_estimated_rows_applied is True
    assert [f.label for f in adjusted.factors] == ["EXPLAIN estimated rows are high"]
    assert any("estimate, not a measured count" in reason for reason in adjusted.report.findings)

    limited = static_report("SELECT * FROM users LIMIT 10;")
    adjusted = apply_evidence_adjustments(
        limited,
        evidence(access_type="ALL", estimated_rows=10000, full_table_scan=True),
    )
    assert adjusted.report.score == limited.score + 10
    assert [f.label for f in adjusted.factors] == ["EXPLAIN indicates a full table scan"]
    assert adjusted.high_estimated_rows_applied is False

    sorted_limit = apply_evidence_adjustments(
        limited,
        evidence(access_type="ALL", estimated_rows=10000, full_table_scan=True, extra="Using filesort"),
    )
    assert sorted_limit.report.score == limited.score + 20 and sorted_limit.high_estimated_rows_applied is True


@pytest.mark.parametrize("access_type,key,rows", [
    ("ref", "idx_users_status", 7),
    ("ref", "idx_users_status", 9_000),
    ("range", "idx_users_status", 12),
    ("eq_ref", "PRIMARY", 1),
    ("const", "PRIMARY", 1),
])
def test_index_access_never_reduces_risk(access_type, key, rows):
    """W11: no access type lowers a score. `ref` cannot select a single row by
    definition, and a narrow scope comes only from a unique key in table metadata."""
    report = static_report("UPDATE users SET active = 0 WHERE status = 'pending';")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type=access_type, key=key, estimated_rows=rows, full_table_scan=False),
    )
    assert adjusted.report.score == report.score
    assert adjusted.factors == []
    assert not any("selective" in finding.lower() for finding in adjusted.report.findings)


def test_multi_row_plan_is_not_interpreted():
    """Plan fields describe EXPLAIN's first row only, so a multi-row plan is not scored."""
    report = static_report("UPDATE users SET active = 0 WHERE status = 'pending';")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type="ALL", estimated_rows=50_000, full_table_scan=True, plan_row_count=2),
    )
    assert adjusted.report.score == report.score and adjusted.factors == []


def test_ambiguous_evidence_does_not_reduce_risk():
    report = static_report("UPDATE users SET active = 0 WHERE status = 'pending';")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type="ref", key=None, estimated_rows=None, full_table_scan=None),
    )
    assert adjusted.report.score == report.score
    assert adjusted.factors == []
    assert adjusted.report.confidence == report.confidence


def test_delete_high_estimate_adds_only_estimate_factor():
    report = static_report("DELETE FROM users WHERE status = 'inactive';")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type="range", estimated_rows=10000, full_table_scan=False),
    )
    assert adjusted.report.score == 35
    assert len(adjusted.factors) == 1
    assert adjusted.factors[0].points == 10


def test_combined_write_evidence_has_two_explicit_adjustments():
    report = static_report("UPDATE users SET active = 0 WHERE status = 'pending';")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type="ALL", estimated_rows=10000, full_table_scan=True),
    )
    assert adjusted.report.score == 40
    assert [factor.points for factor in adjusted.factors] == [10, 10]
    assert adjusted.report.score == adjusted.static_score + sum(
        factor.points for factor in adjusted.factors
    )


def test_score_adjustment_is_clamped_to_100():
    report = static_report("UPDATE users SET active = 0 WHERE status = 1;")
    adjusted = apply_evidence_adjustments(
        report,
        evidence(access_type="ALL", estimated_rows=10000, full_table_scan=True),
    )
    assert 0 <= adjusted.report.score <= 100


def test_evidence_cannot_reduce_hard_critical_or_no_where_writes():
    for sql in ["DROP TABLE users;", "TRUNCATE TABLE users;", "UPDATE users SET active = 0;", "DELETE FROM users;"]:
        report = static_report(sql)
        adjusted = apply_evidence_adjustments(
            report,
            evidence(access_type="const", key="PRIMARY", estimated_rows=1, full_table_scan=False),
        )
        assert adjusted.report.score == 100
        assert adjusted.report.risk_level == "CRITICAL"


def test_api_exposes_static_final_and_evidence_scores_additively(monkeypatch):
    use_fake_evidence_connection(monkeypatch)
    monkeypatch.setattr(
        "backend.main.collect_statement_evidence",
        lambda sql, **_kwargs: evidence(
            access_type="ALL",
            full_table_scan=True,
            estimated_rows=12000,
        ),
    )
    monkeypatch.setattr("backend.main.collect_metadata",
                        lambda tables, **_kwargs: MetadataEvidence(status="unavailable"))
    result = validate(local_request("UPDATE users SET active = 0 WHERE status = 'pending';"))
    statement = result["statements"][0]
    assert statement["static_score"] == 20
    assert statement["static_risk_level"] == "MEDIUM"
    assert statement["score"] == 40
    assert statement["high_estimated_rows_applied"] is True
    assert all("EXPLAIN" not in factor["label"] for factor in statement["factors"])
    assert all("EXPLAIN" in factor["label"] for factor in statement["evidence_factors"])
    assert statement["risk_level"] == "MEDIUM"
    assert statement["database_evidence"]["estimated_rows_semantics"] == (
        "optimizer estimate, not exact affected-row count"
    )
    assert statement["evidence_factors"]
    assert result["analysis_mode"] == "DATABASE_EVIDENCE"
