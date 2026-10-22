"""Row scope of an UPDATE or DELETE: what is established about the rows it matches.

    all_rows         the SQL alone establishes that every row of the one target table
                     is matched (single-table write, no partition selection, no LIMIT,
                     and no WHERE or one that is always true, such as WHERE 1)
    at_most_one_row  table metadata confirms that the WHERE clause fixes every column
                     of a primary key or unique index of the target table to a non-NULL
                     literal of a compatible type, so at most one row can match
    not_established  anything else, including every WHERE clause that was not verified
    not_applicable   statements that do not match existing rows to change them

at_most_one_row is a bound, not a count: the row may not exist, and nothing here says
how many rows an UPDATE will actually change. Every scope describes the target table's
directly matched rows only: triggers, foreign-key actions (ON DELETE / ON UPDATE CASCADE,
SET NULL) and other indirect effects are not inspected (indirect_effects: not_checked). Column names (id, *_id), the presence of
a WHERE clause, an equality anywhere in it, and execution-plan access types are never
evidence of scope. See docs/v2-database-evidence-contract.md, section 8.
"""

from __future__ import annotations

from typing import Any, Optional

from .m2_scoring import _resolve_schema, _statistics_is_eligible, _table_metadata_is_eligible
from .parser import StatementFacts

ALL_ROWS = "all_rows"
AT_MOST_ONE_ROW = "at_most_one_row"
NOT_ESTABLISHED = "not_established"
NOT_APPLICABLE = "not_applicable"

SCOPED_STATEMENTS = {"UPDATE", "DELETE"}

# MySQL compares a string column with a number as floating point, so many strings
# match one number (for example '1', ' 1' and '1a'). A literal counts towards a key
# match only when it compares without conversion.
_INTEGER_TYPES = {"tinyint", "smallint", "mediumint", "int", "integer", "bigint"}
_DECIMAL_TYPES = {"decimal", "numeric"}
_STRING_TYPES = {"char", "varchar"}


def static_row_scope(facts: StatementFacts) -> str:
    """Scope from the SQL alone: all_rows, not_established or not_applicable."""
    if facts.statement_type not in SCOPED_STATEMENTS:
        return NOT_APPLICABLE
    if facts.parse_error or facts.lossy_parse:
        return NOT_ESTABLISHED
    if (facts.single_table_write and not facts.has_limit
            and (facts.has_where is False or facts.where_always_true)):
        return ALL_ROWS
    return NOT_ESTABLISHED


def _literal_compatible(data_type: Any, literal_kind: str) -> bool:
    if not isinstance(data_type, str):
        return False
    data_type = data_type.strip().lower()
    if data_type in _INTEGER_TYPES:
        return literal_kind == "integer"
    if data_type in _DECIMAL_TYPES:
        return literal_kind in {"integer", "decimal"}
    if data_type in _STRING_TYPES:
        return literal_kind == "string"
    return False


def _column_types(metadata: Any, schema: str, table: str) -> Optional[dict[str, Any]]:
    """Column name (lower case) -> DATA_TYPE, or None when not reliably known."""
    states = [
        state for state in getattr(metadata, "query_states", None) or []
        if getattr(state, "query_kind", "").lower() == "columns"
        and getattr(state, "schema", None) == schema
        and getattr(state, "table", None) == table
    ]
    if len(states) != 1 or states[0].status != "available" or states[0].malformed:
        return None
    types: dict[str, Any] = {}
    for column in getattr(metadata, "column_metadata", None) or []:
        if not isinstance(column, dict) or column.get("schema") != schema or column.get("table") != table:
            continue
        name = column.get("name")
        if not isinstance(name, str) or name.lower() in types:
            return None
        types[name.lower()] = column.get("data_type")
    return types


def verified_unique_key(facts: StatementFacts, metadata: Any) -> Optional[dict[str, Any]]:
    """The unique index whose columns the WHERE fixes, or None when not verified."""
    if (
        facts.statement_type not in SCOPED_STATEMENTS
        or facts.parse_error
        or facts.lossy_parse
        or not facts.single_table_write
        or facts.has_where is not True
        or facts.where_always_true
        or not facts.equality_terms
        or getattr(metadata, "status", None) != "available"
        or len(facts.table_bindings) != 1
    ):
        return None
    binding = facts.table_bindings[0]
    schema = _resolve_schema(metadata, binding)
    table = binding.table
    if not isinstance(schema, str) or not table:
        return None
    if not _table_metadata_is_eligible(metadata, schema, table):
        return None
    if not _statistics_is_eligible(metadata, schema, table):
        return None
    column_types = _column_types(metadata, schema, table)
    if column_types is None:
        return None

    target_names = {table.lower()}
    if binding.alias:
        target_names.add(binding.alias.lower())
    fixed: dict[str, set[str]] = {}
    for term in facts.equality_terms:
        if term.qualifier is not None and term.qualifier.lower() not in target_names:
            continue
        fixed.setdefault(term.column.lower(), set()).add(term.literal_kind)

    candidates = []
    for index in getattr(metadata, "indexes", None) or []:
        if not (isinstance(index, dict) and index.get("unique") is True
                and index.get("structure_valid") is True
                and index.get("schema") == schema and index.get("table") == table):
            continue
        columns = [detail.get("name") for detail in index.get("column_details") or []]
        if not columns or not all(isinstance(column, str) and column for column in columns):
            continue
        if all(
            column.lower() in fixed
            and column.lower() in column_types
            and any(_literal_compatible(column_types[column.lower()], kind) for kind in fixed[column.lower()])
            for column in columns
        ):
            candidates.append({"index": index.get("name"), "columns": columns})
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item["index"] != "PRIMARY", len(item["columns"]), str(item["index"])))
    chosen = candidates[0]
    return {"table": f"{schema}.{table}", "index": chosen["index"], "columns": chosen["columns"]}


def build_row_scope(facts: StatementFacts, metadata: Any) -> dict[str, Any]:
    """The per-statement scope object (JSON-ready)."""
    basis = static_row_scope(facts)
    scope: dict[str, Any] = {
        "basis": basis,
        "source": "sql" if basis == ALL_ROWS else None,
        "table": facts.tables[0] if basis == ALL_ROWS else None,
        "index": None,
        "columns": [],
        # Scope covers the target table's directly matched rows only. Triggers and
        # foreign-key actions are never inspected, whatever the basis.
        "indirect_effects": None if basis == NOT_APPLICABLE else "not_checked",
    }
    if basis == NOT_ESTABLISHED:
        key = verified_unique_key(facts, metadata)
        if key is not None:
            scope.update(basis=AT_MOST_ONE_ROW, source="table_metadata", **key)
    return scope
