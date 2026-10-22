"""Bounded, deterministic risk adjustments from Phase 1 database evidence.

Plan facts only ever raise a score. No access type lowers it: MySQL uses `ref`
exactly when a key "cannot select a single row", and a narrow row scope is
established only by a unique key confirmed in table metadata (backend.row_scope).
Plan fields describe EXPLAIN's first row, so they are used only for a one-row plan.

The score is operational severity if the statement runs (contract 8.1), so a
SELECT's plan is scored too: a full table scan or a large optimizer estimate is
load on the server even though nothing is written. With LIMIT, MySQL stops once
it has sent the requested rows unless it must first sort or group every matching
row ("If a filesort must be done, all rows that match the query without the LIMIT
clause are selected", MySQL 8.0 LIMIT Query Optimization). So a SELECT with LIMIT
whose plan shows Using filesort or Using temporary is scored as without LIMIT; any
other SELECT with LIMIT keeps the full-scan finding (how many rows are read is not
known) but not the row-volume one. Every evidence connection is read-only, so
UPDATE/DELETE plans are not collected in practice; the write rules stay correct
for any plan supplied to them.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .db_evidence import DatabaseEvidence
from .risk_engine import ScoreFactor, StatementReport, _risk_level


SUPPORTED_STATEMENTS = {"SELECT", "UPDATE", "DELETE"}
HIGH_ESTIMATED_ROWS = 10_000
FULL_SCAN_POINTS = 10
HIGH_ROWS_POINTS = 10


def plan_is_interpretable(evidence: DatabaseEvidence) -> bool:
    """True when the plan has exactly one row, so its fields describe the whole plan."""
    return getattr(evidence, "plan_row_count", None) == 1


@dataclass
class EvidenceAdjustmentResult:
    """The static report and its separately attributable evidence changes."""

    report: StatementReport
    static_score: int
    factors: list[ScoreFactor]
    materially_supports_analysis: bool = False
    high_estimated_rows_applied: bool = False


def apply_evidence_adjustments(
    report: StatementReport,
    evidence: DatabaseEvidence,
) -> EvidenceAdjustmentResult:
    """Apply small evidence adjustments without changing V1 static scoring.

    Unavailable, incomplete, unsupported, or ambiguous evidence is a no-op.
    Hard-critical and unrestricted write reports cannot be reduced by evidence.
    """
    static_score = report.score
    is_write = report.facts.statement_type in {"UPDATE", "DELETE"}
    is_select = report.facts.statement_type == "SELECT"
    scored = is_write or is_select
    extra = evidence.extra if isinstance(evidence.extra, str) else ""
    # A SELECT with LIMIT may stop early, unless every matching row is sorted or grouped
    # first; only then does the optimizer's estimate describe what is read.
    may_stop_early = (is_select and bool(getattr(report.facts, "has_limit", False))
                      and "Using filesort" not in extra and "Using temporary" not in extra)
    if (
        not evidence.available
        or not evidence.explain_available
        or not plan_is_interpretable(evidence)
        or report.facts.statement_type not in SUPPORTED_STATEMENTS
        or report.risk_level == "CRITICAL"
    ):
        return EvidenceAdjustmentResult(report, static_score, [], False, False)

    materially_supports = (
        isinstance(evidence.estimated_rows, int)
        or isinstance(evidence.full_table_scan, bool)
        or (
            bool(evidence.access_type)
            and (
                evidence.access_type == "ALL"
                or bool(evidence.key)
            )
        )
    )

    factors: list[ScoreFactor] = []
    findings = list(report.findings)
    checklist = list(report.checklist)
    score_adjustment = 0

    full_scan = evidence.full_table_scan is True
    if scored and full_scan:
        factors.append(ScoreFactor("EXPLAIN indicates a full table scan", FULL_SCAN_POINTS))
        findings.append(
            "EXPLAIN shows a full table scan (access type ALL); with LIMIT, MySQL may stop early, "
            "so how many rows are read is not known."
            if may_stop_early else
            "EXPLAIN shows a full table scan (access type ALL): the read examines the whole table."
            if is_select else
            "EXPLAIN indicates a full table scan; this may examine a broad portion of the table."
        )
        checklist.append("Review the EXPLAIN plan and confirm the access path is intended.")
        score_adjustment += FULL_SCAN_POINTS

    has_high_estimate = (
        scored
        and not may_stop_early
        and
        isinstance(evidence.estimated_rows, int)
        and not isinstance(evidence.estimated_rows, bool)
        and evidence.estimated_rows >= HIGH_ESTIMATED_ROWS
    )
    if has_high_estimate:
        factors.append(ScoreFactor("EXPLAIN estimated rows are high", HIGH_ROWS_POINTS))
        if is_select:
            findings.append(
                f"The optimizer estimates {evidence.estimated_rows:,} rows examined (at least "
                f"{HIGH_ESTIMATED_ROWS:,}); this is an estimate, not a measured count."
            )
            checklist.append("Confirm the read is intended at this volume; a selective, indexed filter "
                             "narrows it. Consider the load before running it on a busy server.")
        else:
            findings.append(
                "The optimizer estimates that EXPLAIN will examine a broad number of rows; "
                "this is not an exact affected-row count."
            )
            checklist.append("Review the EXPLAIN estimate and verify the expected business impact.")
        score_adjustment += HIGH_ROWS_POINTS

    # Confidence (HIGH/LIMITED/LOW) is never changed here: an EXPLAIN plan gives
    # optimizer estimates, not affected-row counts. What evidence a result has is
    # reported separately (backend.evidence_state).
    if not factors:
        return EvidenceAdjustmentResult(
            report,
            static_score,
            [],
            materially_supports,
            has_high_estimate,
        )

    final_score = max(0, min(100, static_score + score_adjustment))
    final_report = replace(
        report,
        score=final_score,
        risk_level=_risk_level(final_score),
        factors=report.factors,
        findings=findings,
        checklist=list(dict.fromkeys(checklist)),
    )
    return EvidenceAdjustmentResult(
        final_report,
        static_score,
        factors,
        materially_supports,
        has_high_estimate,
    )
