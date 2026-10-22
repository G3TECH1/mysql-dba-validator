"""
Evidence helpers

Centralize creation of EvidenceGap objects used by analyzer.py so the
analysis logic stays clear and easy to maintain.
"""
from __future__ import annotations

from typing import Optional, List

from . import models

# Static-view reason; backend.evidence_state restates it when evidence was attempted.
NO_CONNECTION_REASON = "No database connection"


# Manual guidance only. The validator never derives a query from submitted SQL: a
# COUNT(*) or EXPLAIN text built by string substitution can be wrong SQL, or count
# something else, for joins, aliases, CTEs and multi-table writes.
AFFECTED_ROW_COUNT_CHECK = (
    "Review the candidate rows with a read-only query you write for this statement's actual "
    "target table and predicate. A count is a point-in-time check: concurrent changes can alter "
    "what the write later affects, and UPDATE reports changed rows, not matched rows."
)
EXECUTION_PLAN_CHECK = (
    "Run EXPLAIN on the exact statement; EXPLAIN does not run an UPDATE or DELETE. Never use "
    "EXPLAIN ANALYZE for a review: it executes the statement."
)


def affected_row_count_gap(table: Optional[str], predicate: Optional[str] = None) -> models.EvidenceGap:
    """Return the gap for the unknown affected-row count, with manual guidance.

    table and predicate are accepted for compatibility and deliberately not
    interpolated into SQL.
    """

    return models.EvidenceGap(
        name="affected_row_count",
        reason=NO_CONNECTION_REASON,
        suggested_check=AFFECTED_ROW_COUNT_CHECK,
    )


def execution_plan_gap(table: Optional[str], predicate: Optional[str] = None, stmt_type: str = "UPDATE") -> models.EvidenceGap:
    """Return the gap for the missing execution plan, with manual guidance."""

    return models.EvidenceGap(
        name="execution_plan",
        reason=NO_CONNECTION_REASON,
        suggested_check=EXECUTION_PLAN_CHECK,
    )


def generic_gap(name: str, reason: str, suggested_check: Optional[str] = None) -> models.EvidenceGap:
    return models.EvidenceGap(name=name, reason=reason, suggested_check=suggested_check)
