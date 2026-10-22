"""
SQL parsing and static analysis for the MySQL DBA Validator.

Uses SQLGlot with the MySQL dialect to parse pasted SQL into one or more
statements, classify each statement, and extract structural facts that
the risk engine can evaluate.

This layer does NOT decide whether SQL is safe. It extracts facts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import sqlglot
from sqlglot import exp
from sqlglot.dialects.dialect import Dialect
from sqlglot.tokens import Token, TokenType


DIALECT = "mysql"


CATEGORY_MAP = {
    "select": "READ",
    "insert": "WRITE",
    "update": "WRITE",
    "delete": "WRITE",
    "replace": "WRITE",
    "create": "DDL",
    "alter": "DDL",
    "drop": "DDL",
    "truncatetable": "DDL",
    "grant": "DCL",
    "revoke": "DCL",
    "command": "OTHER",
    "call": "PROCEDURE",
    "transaction": "TRANSACTION",
    "commit": "TRANSACTION",
    "rollback": "TRANSACTION",
}


# What sqlglot returns when it reads a fragment as a value rather than a statement:
# "SELEC * FRM t" becomes an Alias, a bare word a Column, "foo(1)" an Anonymous
# function. None of these is a statement the validator understands.
NOT_A_STATEMENT = (
    exp.Alias, exp.Column, exp.Identifier, exp.Literal, exp.Binary, exp.Unary,
    exp.Paren, exp.Star, exp.Tuple, exp.Dot, exp.Func,
)


# Words a MySQL 8.0 statement can begin with (reference manual, chapter "SQL
# Statements"), plus "(" for a parenthesised query. Compound-statement words (DECLARE,
# IF, LOOP, ...) are listed too: they are only valid inside a stored program, but the
# validator does not claim that. A statement starting with any other word, or with a
# literal or quoted identifier, is rejected by MySQL: the validator reports it as not
# valid MySQL. A statement that starts with one of these words but cannot be read is
# reported as unreadable, never as invalid: the parser may simply not support it.
MYSQL_STATEMENT_KEYWORDS = frozenset({
    "(", "ALTER", "ANALYZE", "BEGIN", "BINLOG", "CACHE", "CALL", "CHANGE", "CHECK",
    "CHECKSUM", "CLONE", "COMMIT", "CREATE", "DEALLOCATE", "DELETE", "DESC", "DESCRIBE",
    "DO", "DROP", "EXECUTE", "EXPLAIN", "FLUSH", "GET", "GRANT", "HANDLER", "HELP",
    "IMPORT", "INSERT", "INSTALL", "KILL", "LOAD", "LOCK", "OPTIMIZE", "PREPARE", "PURGE",
    "RELEASE", "RENAME", "REPAIR", "REPLACE", "RESET", "RESIGNAL", "RESTART", "REVOKE",
    "ROLLBACK", "SAVEPOINT", "SELECT", "SET", "SHOW", "SHUTDOWN", "SIGNAL", "START",
    "STOP", "TABLE", "TRUNCATE", "UNINSTALL", "UNLOCK", "UPDATE", "USE", "VALUES", "WITH",
    "XA",
    "CASE", "CLOSE", "DECLARE", "END", "FETCH", "IF", "ITERATE", "LEAVE", "LOOP", "OPEN",
    "REPEAT", "RETURN", "WHILE",
})

# Valid MySQL 8.0 statements the validator does not analyse (VALUES and TABLE were
# added in 8.0.19). They are reported as not analysed, never scored as low risk.
UNSUPPORTED_STATEMENTS = frozenset({"VALUES", "TABLE", "HANDLER"})

# CREATE ... PROCEDURE/FUNCTION/TRIGGER/EVENT defines a stored program. The validator
# does not analyse stored program bodies.
STORED_PROGRAM_KINDS = frozenset({"PROCEDURE", "FUNCTION", "TRIGGER", "EVENT"})
# The object word of other CREATE statements: reaching one first means "not a stored program".
_OTHER_CREATE_OBJECTS = frozenset({
    "TABLE", "VIEW", "INDEX", "DATABASE", "SCHEMA", "USER", "ROLE", "TABLESPACE",
    "SERVER", "LOGFILE", "RESOURCE", "SPATIAL", "UNIQUE", "FULLTEXT", "TEMPORARY",
})

# analysis_status values: the statement was analysed, or why it was not.
ANALYSED = "analysed"
INVALID = "invalid"            # MySQL rejects it: it does not start with a statement keyword
UNSUPPORTED = "unsupported"    # valid MySQL the validator does not analyse
UNREADABLE = "unreadable"      # the parser could not read it; validity is not determined

# For a statement that was not analysed: (finding title, first checklist item). Shared
# by the analyzer and the risk engine so both say the same thing.
NOT_ANALYSED_WORDING = {
    INVALID: ("Not valid MySQL", "Fix the SQL before proceeding."),
    UNSUPPORTED: ("Not analysed (statement type not supported)",
                  "Review this statement manually; the validator did not assess its risk."),
    UNREADABLE: ("Could not be read (it may be invalid, or valid MySQL the validator cannot read)",
                 "Check the SQL before proceeding; the validator could not read it."),
}


COMMAND_KEYWORDS_TXN = {
    "BEGIN",
    "START",
    "COMMIT",
    "ROLLBACK",
}


COMMAND_KEYWORDS_DCL = {
    "GRANT",
    "REVOKE",
}


@dataclass
class StatementFacts:
    """
    Structured facts extracted from one SQL statement.

    The risk engine consumes this object instead of having to understand
    SQL syntax itself.
    """

    raw_sql: str
    index: int

    statement_type: str = "UNKNOWN"
    category: str = "OTHER"

    tables: list[str] = field(default_factory=list)
    table_bindings: list["TableBinding"] = field(default_factory=list)

    # None means the concept is not applicable to this statement.
    has_where: Optional[bool] = None

    where_looks_trivial: bool = False
    where_predicate_summary: Optional[str] = None
    columns_in_where: list[str] = field(default_factory=list)
    predicate_shape: str = "NO_WHERE"
    predicate_columns: list["PredicateColumn"] = field(default_factory=list)
    predicate_table_association: str = "NOT_APPLICABLE"

    has_limit: bool = False

    # UPDATE/DELETE whose target is exactly one physical table: no join, subquery,
    # CTE, USING or multi-table target list. Only this shape can have its row scope
    # established (backend.row_scope).
    single_table_write: bool = False

    # Top-level AND terms of the WHERE that compare one column with one non-NULL
    # literal: structural facts only; a match on a real key is decided with metadata.
    equality_terms: list["EqualityTerm"] = field(default_factory=list)

    # True when the WHERE tests IS NULL / IS NOT NULL anywhere: such predicates can
    # match many rows.
    where_has_null_test: bool = False

    # True when the WHERE is true for every row by its structure alone (WHERE 1,
    # WHERE TRUE, WHERE 1 = 1, WHERE id = 5 OR 1): it matches every row, exactly like
    # no WHERE clause. Decided from the AST, never from text.
    where_always_true: bool = False

    # EXPLAIN / DESCRIBE only. explain_analyze: the ANALYZE form, for which MySQL runs
    # the explained statement. explained_statement_type / explained_sql: the explained
    # statement, or None when it describes a table or could not be read.
    explain_analyze: bool = False
    explained_statement_type: Optional[str] = None
    explained_sql: Optional[str] = None

    # Upper-case words written directly before "(" in this statement's submitted text,
    # read from tokens (function calls and syntax such as IN (...)). None when they
    # cannot be attributed to the statement reliably, or a call is quoted or
    # schema-qualified. Used only by the execution-plan function policy.
    source_call_names: Optional[frozenset[str]] = None

    # True when the operation is capable of affecting an entire table
    # or making a broad schema/data change.
    is_full_table_ddl: bool = False

    parse_error: Optional[str] = None

    # ANALYSED, or why the statement was not analysed (INVALID, UNSUPPORTED or
    # UNREADABLE; parse_error is then set and says what was found).
    analysis_status: str = ANALYSED

    # True when the script only parsed with the permissive fallback, which can drop
    # tokens (for example a trailing SELECT ... INTO): raw_sql may then not be the
    # submitted statement. Set for every statement of that script.
    lossy_parse: bool = False


@dataclass(frozen=True)
class PredicateColumn:
    """A column reference retained from a parsed WHERE expression."""

    name: str
    table: Optional[str] = None
    schema: Optional[str] = None
    resolved_table: Optional[str] = None


@dataclass(frozen=True)
class EqualityTerm:
    """``column = literal`` as a top-level AND term of a WHERE clause.

    literal_kind is "integer" (digits only), "decimal" (digits with a point), or
    "string". Anything else (negative numbers, exponents, NULL, expressions) is not
    recorded, so it can never count towards a key match.
    """

    column: str
    qualifier: Optional[str]
    literal_kind: str
    literal: str


@dataclass(frozen=True)
class TableBinding:
    """One AST table occurrence, including its optional alias."""

    schema: Optional[str]
    table: str
    alias: Optional[str] = None




def _classify(expr: exp.Expression) -> tuple[str, str]:
    """
    Return:
        (statement_type, category)

    SQLGlot's internal AST names are normalized here so the rest of
    DBA Guard does not need to know parser-specific naming quirks.
    """

    key = (expr.key or "").lower()

    # Standard structured statement types.
    if isinstance(expr, exp.Select):
        return "SELECT", "READ"

    if isinstance(expr, exp.Insert):
        return "INSERT", "WRITE"

    if isinstance(expr, exp.Update):
        return "UPDATE", "WRITE"

    if isinstance(expr, exp.Delete):
        return "DELETE", "WRITE"

    if isinstance(expr, exp.Create):
        return "CREATE", "DDL"

    if isinstance(expr, exp.Alter):
        return "ALTER", "DDL"

    if isinstance(expr, exp.Drop):
        return "DROP", "DDL"

    # SQLGlot represents MySQL TRUNCATE TABLE as a TruncateTable
    # expression in some versions.
    #
    # We normalize it to the application's canonical statement type:
    # TRUNCATE.
    if key == "truncatetable":
        return "TRUNCATE", "DDL"

    # Some SQLGlot versions may represent certain statements as Command.
    if isinstance(expr, exp.Command):
        text = str(expr.this or "").upper().strip()

        first_word = text.split()[0] if text else ""

        if first_word == "TRUNCATE":
            return "TRUNCATE", "DDL"

        if first_word in COMMAND_KEYWORDS_DCL:
            return first_word, "DCL"

        if first_word in COMMAND_KEYWORDS_TXN:
            return first_word, "TRANSACTION"

        if first_word == "CALL":
            return "CALL", "PROCEDURE"

        if first_word == "REPLACE":
            return "REPLACE", "WRITE"

        if first_word:
            return first_word, "OTHER"

        return "UNKNOWN", "OTHER"

    # Final fallback.
    return key.upper() or "UNKNOWN", CATEGORY_MAP.get(key, "OTHER")


def _where_is_trivial(where_expr: exp.Expression) -> bool:
    """
    Best-effort detection of predicates that are likely to match
    most or all rows.

    True when the predicate is provably true for every row
    (_is_always_true), or when it is broad in a way the data decides
    (WHERE id > 0). Decided from the AST only: words and string literals
    such as 'untrue' are never read as Boolean constants.

    It does NOT replace EXPLAIN or actual row-count analysis.
    """

    return _is_always_true(where_expr) or _looks_broad(where_expr)


def _looks_broad(node: exp.Expression) -> bool:
    """WHERE id > 0 / id >= 0 (or a negative bound), unless AND narrows it.

    A conjunction is broad only when both sides are: WHERE id = 5 AND n > 0 is
    as narrow as WHERE id = 5. Such predicates are valid but may match almost
    every row depending on the data.
    """
    node = _unwrap_parentheses(node)
    if isinstance(node, exp.Or):
        return _looks_broad(node.this) or _looks_broad(node.expression)
    if isinstance(node, exp.And):
        return _looks_broad(node.this) and _looks_broad(node.expression)
    if isinstance(node, (exp.GT, exp.GTE)):
        right = _unwrap_parentheses(node.expression)
        if isinstance(right, exp.Literal) and right.is_number:
            try:
                return float(right.this) <= 0
            except (ValueError, TypeError):
                return False
    return False


def _numeric_literal_value(node: exp.Expression) -> Optional[float]:
    if isinstance(node, exp.Literal) and node.is_number:
        try:
            return float(node.this)
        except (TypeError, ValueError):
            return None
    return None


def _is_always_true(node: Optional[exp.Expression]) -> bool:
    """True when MySQL evaluates the predicate as TRUE for every row, by structure.

    TRUE, a non-zero number, an equality of two identical literals (1 = 1,
    'a' = 'a'), OR with an always-true side, AND of two always-true sides, and
    NOT of an always-false predicate. Anything that depends on a column, a
    function or NULL is not provably true and returns False.
    """
    if node is None:
        return False
    node = _unwrap_parentheses(node)
    if isinstance(node, exp.Boolean):
        return node.this is True
    value = _numeric_literal_value(node)
    if value is not None:
        return value != 0
    if isinstance(node, exp.Or):
        return _is_always_true(node.this) or _is_always_true(node.expression)
    if isinstance(node, exp.And):
        return _is_always_true(node.this) and _is_always_true(node.expression)
    if isinstance(node, exp.Not):
        return _is_always_false(node.this)
    if isinstance(node, exp.EQ):
        return _literals_compare(node.this, node.expression) is True
    return False


def _is_always_false(node: Optional[exp.Expression]) -> bool:
    """True when the predicate is FALSE (not NULL) for every row, by structure."""
    if node is None:
        return False
    node = _unwrap_parentheses(node)
    if isinstance(node, exp.Boolean):
        return node.this is False
    value = _numeric_literal_value(node)
    if value is not None:
        return value == 0
    if isinstance(node, exp.And):
        return _is_always_false(node.this) or _is_always_false(node.expression)
    if isinstance(node, exp.Or):
        return _is_always_false(node.this) and _is_always_false(node.expression)
    if isinstance(node, exp.Not):
        return _is_always_true(node.this)
    if isinstance(node, exp.EQ):
        return _literals_compare(node.this, node.expression) is False
    return False


def _literals_compare(left: exp.Expression, right: exp.Expression) -> Optional[bool]:
    """Equality of two literals of the same kind; None when it is not decidable here."""
    left, right = _unwrap_parentheses(left), _unwrap_parentheses(right)
    left_value, right_value = _numeric_literal_value(left), _numeric_literal_value(right)
    if left_value is not None and right_value is not None:
        return left_value == right_value
    if (isinstance(left, exp.Literal) and left.is_string
            and isinstance(right, exp.Literal) and right.is_string):
        # Only identical text is decided: collations can make different strings equal.
        return True if left.this == right.this else None
    return None


def _extract_where_columns(where_expr: exp.Expression) -> list[str]:
    """Extract unique column names referenced by a WHERE predicate."""

    columns: list[str] = []

    for column in where_expr.find_all(exp.Column):
        name = column.name

        if name and name not in columns:
            columns.append(name)

    return columns


def _unwrap_parentheses(node: exp.Expression) -> exp.Expression:
    while isinstance(node, exp.Paren):
        node = node.this
    return node


def _predicate_shape(where_expr: exp.Expression) -> str:
    """Classify only AST-observable WHERE shapes needed by M2."""
    expression = _unwrap_parentheses(where_expr)
    if expression.find(exp.Subquery):
        return "SUBQUERY"
    if expression.find(exp.Or):
        return "OR"
    if expression.find(exp.In):
        return "IN"
    if expression.find(exp.Between):
        return "BETWEEN"
    if expression.find((exp.LT, exp.LTE, exp.GT, exp.GTE)):
        return "RANGE"
    if expression.find(exp.Cast):
        return "CAST"
    if expression.find(exp.Func):
        return "FUNCTION"

    if isinstance(expression, exp.EQ):
        left = _unwrap_parentheses(expression.left)
        right = _unwrap_parentheses(expression.right)
        if isinstance(left, exp.Column) and isinstance(right, exp.Literal):
            return "DIRECT_COLUMN_LITERAL_EQUALITY"
        if isinstance(right, exp.Column) and isinstance(left, exp.Literal):
            return "DIRECT_COLUMN_LITERAL_EQUALITY"
        if isinstance(left, exp.Column) and isinstance(right, exp.Column):
            return "COLUMN_COMPARISON"
        return "COMPUTED_EXPRESSION"

    return "UNSUPPORTED"


def _table_references(expr: exp.Expression) -> dict[str, str]:
    references: dict[str, str] = {}
    for table in expr.find_all(exp.Table):
        name = table.name
        if not name:
            continue
        resolved = f"{table.db}.{name}" if table.db else name
        references[name] = resolved
        if table.db:
            references[resolved] = resolved
        if table.alias:
            references[table.alias] = resolved
    return references


def _predicate_columns(
    where_expr: exp.Expression,
    facts_tables: list[str],
    expression: exp.Expression,
) -> tuple[list[PredicateColumn], str]:
    references = _table_references(expression)
    columns: list[PredicateColumn] = []
    association = "UNAMBIGUOUS" if len(facts_tables) == 1 else "MULTIPLE_TABLES"

    for column in where_expr.find_all(exp.Column):
        qualifier = column.table or None
        schema = column.db or None
        resolved_table = None

        if len(facts_tables) == 1:
            statement_table = facts_tables[0]
            statement_schema, _, statement_name = statement_table.rpartition(".")
            if qualifier:
                resolved_table = references.get(qualifier)
                if resolved_table is None:
                    association = "UNRESOLVED"
                elif statement_name != resolved_table.rsplit(".", 1)[-1]:
                    association = "UNRESOLVED"
                elif schema and statement_schema and schema != statement_schema:
                    association = "UNRESOLVED"
            elif schema:
                if statement_schema and schema != statement_schema:
                    association = "UNRESOLVED"
                else:
                    resolved_table = statement_table
            else:
                resolved_table = statement_table

        columns.append(
            PredicateColumn(
                name=column.name,
                table=qualifier,
                schema=schema,
                resolved_table=resolved_table,
            )
        )

    if not columns and association == "UNAMBIGUOUS":
        association = "UNRESOLVED"
    return columns, association


def _physical_tables(expr: exp.Expression) -> list[exp.Table]:
    """Table nodes that name a real table, not an alias or CTE reference.

    Excluded: a reference to a CTE name, and an unqualified name that only repeats an
    alias declared elsewhere in the statement (the target list of
    ``DELETE o FROM orders o ...``).
    """
    cte_names = {cte.alias_or_name.lower() for cte in expr.find_all(exp.CTE) if cte.alias_or_name}
    tables = [table for table in expr.find_all(exp.Table) if table.name]
    aliases = {table.alias.lower() for table in tables if table.alias}
    physical = []
    for table in tables:
        name = table.name.lower()
        if not table.db and name in cte_names:
            continue
        if not table.db and not table.alias and name in aliases:
            continue
        physical.append(table)
    return physical


def _extract_tables(expr: exp.Expression) -> list[str]:
    """Extract unique physical table names referenced by a statement."""

    tables: list[str] = []

    for table in _physical_tables(expr):
        name = table.name

        if table.db:
            name = f"{table.db}.{name}"

        if name and name not in tables:
            tables.append(name)

    return tables


def _extract_table_bindings(expr: exp.Expression) -> list[TableBinding]:
    return [
        TableBinding(
            schema=table.db or None,
            table=table.name,
            alias=table.alias or None,
        )
        for table in _physical_tables(expr)
    ]


def _is_single_table_write(expr: exp.Expression, tables: list[str]) -> bool:
    """UPDATE/DELETE on exactly one physical table and nothing else."""
    if not isinstance(expr, (exp.Update, exp.Delete)) or len(tables) != 1:
        return False
    if expr.find(exp.Join) or expr.find(exp.Subquery) or expr.find(exp.With) or expr.find(exp.CTE):
        return False
    for key in ("using", "tables", "from", "from_"):
        if expr.args.get(key):
            return False
    if any(table.args.get("partition") for table in expr.find_all(exp.Table)):
        # DELETE FROM t PARTITION (p0): only the named partitions are in scope.
        return False
    return len(_extract_table_bindings(expr)) == 1


def _literal_kind(node: exp.Expression) -> Optional[str]:
    if not isinstance(node, exp.Literal):
        return None
    text = str(node.this)
    if node.is_string:
        return "string"
    if text.isdigit():
        return "integer"
    integer, dot, fraction = text.partition(".")
    if dot and integer.isdigit() and fraction.isdigit():
        return "decimal"
    return None


def _equality_terms(where_expr: exp.Expression) -> list[EqualityTerm]:
    """``column = literal`` terms joined only by top-level AND."""
    terms: list[EqualityTerm] = []
    pending = [where_expr]
    while pending:
        node = _unwrap_parentheses(pending.pop())
        if isinstance(node, exp.And):
            pending.extend([node.this, node.expression])
            continue
        if not isinstance(node, exp.EQ):
            continue
        left = _unwrap_parentheses(node.this)
        right = _unwrap_parentheses(node.expression)
        if isinstance(right, exp.Column) and not isinstance(left, exp.Column):
            left, right = right, left
        if not isinstance(left, exp.Column) or not left.name:
            continue
        kind = _literal_kind(right)
        if kind is None:
            continue
        terms.append(EqualityTerm(
            column=left.name,
            qualifier=left.table or None,
            literal_kind=kind,
            literal=str(right.this),
        ))
    return terms


# Token types whose text is a literal value, never a name written before "(".
_LITERAL_TOKEN_TYPES = frozenset(
    getattr(TokenType, name) for name in (
        "STRING", "NUMBER", "HEX_STRING", "BIT_STRING", "BYTE_STRING", "NATIONAL_STRING",
        "RAW_STRING", "HEREDOC_STRING", "UNICODE_STRING",
    ) if hasattr(TokenType, name)
)
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*\Z")
# Operators and punctuation that may directly precede "(" without naming anything:
# a * (b), x = (SELECT ...), IN ((1, 2)), f((a)).
_PUNCTUATION = re.compile(r"[()\[\]{},;.=<>!+\-*/%&|^~:?@]+\Z")


def call_names(tokens: list[Token]) -> Optional[frozenset[str]]:
    """Upper-case words written directly before "(" in a token list, or None.

    None (unknown: no policy can approve it) when anything other than a plain ASCII
    word or punctuation is written directly before "(":
    - a quoted name (`f`(...)) or a qualified one (db.f(...)), which MySQL resolves
      to a stored or loadable function;
    - a name that is not a plain ASCII word (fünf(...), 1split(...), $f(...),
      fullwidth letters), which the reviewed list cannot represent;
    - a literal (9e(...), 0x1f(...), 'x'(...)), which is not valid MySQL and which
      sqlglot may regenerate as a different statement (9e AS (a)).
    Comments are not tokens, so f/* x */(a) still counts as a call of f.
    """
    names = set()
    for index in range(len(tokens) - 1):
        if tokens[index + 1].token_type != TokenType.L_PAREN:
            continue
        token = tokens[index]
        text = token.text or ""
        if token.token_type in _LITERAL_TOKEN_TYPES or token.token_type == TokenType.IDENTIFIER:
            return None
        if _PUNCTUATION.match(text):
            continue
        if not _WORD.match(text):
            return None
        if index > 0 and tokens[index - 1].token_type == TokenType.DOT:
            return None
        names.add(text.upper())
    return frozenset(names)


def statement_call_names(sql: str, expected: int) -> list[Optional[frozenset[str]]]:
    """call_names() per statement, split on ";" exactly as sqlglot splits a script.

    Returns a list of `expected` entries, all None when the split does not line up
    with the parsed statements (the names then cannot be attributed reliably).
    """
    chunks = statement_chunks(sql)
    if chunks is None or len(chunks) != expected:
        return [None] * expected
    return [call_names(chunk) for chunk in chunks]


def statement_chunks(sql: str) -> Optional[list[list[Token]]]:
    """The script's tokens split on ";" exactly as sqlglot splits a script (one chunk per
    parsed statement, empty fragments included), or None when it cannot be tokenized.
    Strings and comments are single tokens, so a ";" inside them never splits."""
    try:
        tokens = Dialect.get_or_raise(DIALECT).tokenize(sql)
    except Exception:
        return None
    chunks: list[list[Token]] = [[]]
    total = len(tokens)
    for index, token in enumerate(tokens):
        if token.token_type == TokenType.SEMICOLON:
            if token.comments:
                chunks.append([token])
            if index < total - 1:
                chunks.append([])
        else:
            chunks[-1].append(token)
    return chunks


def _word(token: Token) -> Optional[str]:
    """An unquoted token's upper-case text; None for a string or quoted identifier."""
    if token.token_type in (TokenType.STRING, TokenType.IDENTIFIER):
        return None
    # Some tokens span words ("LOCK TABLES"): the first word is the keyword.
    words = token.text.split()
    return words[0].upper() if words else token.text


def stored_program_kind(chunk: list[Token]) -> Optional[str]:
    """PROCEDURE, FUNCTION, TRIGGER or EVENT when the chunk starts a stored program
    definition (CREATE [DEFINER = user] ... PROCEDURE ...), else None."""
    if not chunk or _word(chunk[0]) != "CREATE":
        return None
    index = 1
    while index < len(chunk):
        word = _word(chunk[index])
        if word == "DEFINER":
            # DEFINER = user[@host] or CURRENT_USER[()]: skip the account so a user
            # named "event" is never read as the object keyword.
            index += 3 if index + 1 < len(chunk) and chunk[index + 1].text == "=" else 1
            if index + 1 < len(chunk) and chunk[index].text == "@":
                index += 2
            elif (index + 1 < len(chunk) and chunk[index].text == "("
                    and chunk[index + 1].text == ")"):
                index += 2
            continue
        if word in STORED_PROGRAM_KINDS:
            return word
        if word in _OTHER_CREATE_OBJECTS or word == "(":
            return None
        index += 1
    return None


_DELIMITER_LINE = re.compile(r"^[ \t]*delimiter\b", re.IGNORECASE | re.MULTILINE)


def unsupported_script(sql: str) -> Optional[str]:
    """An error code when the script as a whole cannot be split into statements reliably:

    - "delimiter_not_supported": a DELIMITER line. DELIMITER is a mysql client command,
      not SQL; it changes where statements end, so the ";" split would be wrong.
    - "stored_program_not_supported": a stored program definition together with other
      statements, or with a body of several statements (BEGIN ... ; ... END). The body's
      ";" would split it into fragments read as separate statements.

    A stored program definition submitted on its own is not an error: it is returned as
    one statement that is not analysed (UNSUPPORTED). None when neither applies.
    """
    chunks = statement_chunks(sql)
    if chunks is None:
        # Cannot tokenize: look for a DELIMITER line in the raw text (may also match one
        # inside a string or comment, which only makes the check stricter).
        return "delimiter_not_supported" if _DELIMITER_LINE.search(sql) else None
    previous_line = None
    for chunk in chunks:
        for position, token in enumerate(chunk):
            # The mysql client reads "delimiter" as its command at the start of a line.
            if (_word(token) == "DELIMITER"
                    and (position == 0 or token.line != previous_line)):
                return "delimiter_not_supported"
            previous_line = token.line
    statements = [chunk for chunk in chunks
                  if any(token.token_type != TokenType.SEMICOLON for token in chunk)]
    if len(statements) > 1 and any(stored_program_kind(chunk) for chunk in statements):
        return "stored_program_not_supported"
    return None


def _explained_statement(expr: exp.Expression) -> Optional[exp.Expression]:
    """The statement an EXPLAIN/DESCRIBE explains, or None for a table or unreadable target."""
    target = expr.this if isinstance(expr, exp.Describe) else None
    if target is None or isinstance(target, (exp.Table, exp.Column, exp.Identifier)):
        return None
    return target


def _not_analysed(chunk: Optional[list[Token]],
                  expr: Optional[exp.Expression]) -> Optional[tuple[str, str, str]]:
    """(analysis_status, statement_type, detail) for a statement that is not analysed
    because MySQL rejects it or the validator does not support it; None otherwise.

    Decided from the submitted tokens when they can be attributed to the statement
    (chunk), else from the parsed expression for the unsupported types only: invalidity
    is never inferred from the parser's reading.
    """
    if chunk:
        first = chunk[0]
        word = _word(first)
        if word not in MYSQL_STATEMENT_KEYWORDS:
            shown = f'"{first.text}"' if word is not None else "a quoted string or identifier"
            return INVALID, "UNKNOWN", f"a MySQL statement cannot begin with {shown}"
        if word in UNSUPPORTED_STATEMENTS:
            return (UNSUPPORTED, word,
                    f"{word} is a valid MySQL statement that this validator does not analyse")
        kind = stored_program_kind(chunk)
    else:
        if isinstance(expr, exp.Values):
            return (UNSUPPORTED, "VALUES",
                    "VALUES is a valid MySQL statement that this validator does not analyse")
        kind = (str(expr.args.get("kind") or "").upper()
                if isinstance(expr, exp.Create) else None)
    if kind in STORED_PROGRAM_KINDS:
        return (UNSUPPORTED, f"CREATE {kind}",
                f"CREATE {kind} defines a stored program; the validator does not analyse "
                f"stored program bodies")
    return None


def _source_text(sql: str, chunk: Optional[list[Token]]) -> Optional[str]:
    """The submitted text of one statement (from its first to its last token)."""
    if not chunk:
        return None
    return sql[chunk[0].start:chunk[-1].end + 1]


def parse_sql(raw_sql: str) -> list[StatementFacts]:
    """
    Parse a possibly multi-statement MySQL script into StatementFacts.

    If strict parsing fails, a permissive second attempt is made so
    the validator can still surface useful information instead of
    immediately failing the entire request.
    """

    raw_sql = raw_sql.strip()

    if not raw_sql:
        return []

    lossy_parse = False
    try:
        expressions = sqlglot.parse(
            raw_sql,
            read=DIALECT,
            error_level=sqlglot.ErrorLevel.RAISE,
        )

    except Exception as strict_error:

        try:
            expressions = sqlglot.parse(
                raw_sql,
                read=DIALECT,
                error_level=sqlglot.ErrorLevel.IGNORE,
            )
            lossy_parse = True

        except Exception:
            facts = StatementFacts(
                raw_sql=raw_sql,
                index=0,
                parse_error=str(strict_error),
                analysis_status=UNREADABLE,
            )
            # The whole script is one result: its own status only when it is one statement.
            chunks = statement_chunks(raw_sql)
            not_analysed = _not_analysed(chunks[0] if chunks and len(chunks) == 1 else None, None)
            if not_analysed is not None:
                facts.analysis_status, facts.statement_type, facts.parse_error = not_analysed
            return [facts]

    facts_list: list[StatementFacts] = []
    source_names = statement_call_names(raw_sql, len(expressions))
    chunks = statement_chunks(raw_sql)
    if chunks is not None and len(chunks) != len(expressions):
        chunks = None  # the source text cannot be attributed to the parsed statements

    for index, expr in enumerate(expressions):

        # An empty or comment-only fragment (";;", or a comment before ";") is not a statement.
        if expr is None or isinstance(expr, exp.Semicolon):
            continue

        statement_sql = expr.sql(dialect=DIALECT)

        statement_type, category = _classify(expr)

        facts = StatementFacts(
            raw_sql=statement_sql,
            index=index,
            statement_type=statement_type,
            category=category,
            lossy_parse=lossy_parse,
            source_call_names=source_names[index],
        )

        not_analysed = _not_analysed(chunks[index] if chunks is not None else None, expr)
        if not_analysed is not None:
            # Invalid MySQL, or valid MySQL the validator does not analyse: treated like
            # a parse error (never scored as an analysed statement), with its own wording.
            facts.analysis_status, facts.statement_type, facts.parse_error = not_analysed
            facts.category = "OTHER"
            # Show what was submitted, not the parser's reading of it (nothing of it was
            # analysed, so the text shown no longer differs from the analysed text).
            source = _source_text(raw_sql, chunks[index] if chunks is not None else None)
            if source:
                facts.raw_sql, facts.lossy_parse = source, False
            facts_list.append(facts)
            continue

        if isinstance(expr, NOT_A_STATEMENT):
            # Treated like a parse error: never classified or scored as a statement.
            facts.statement_type, facts.category = "UNKNOWN", "OTHER"
            facts.parse_error = (f"not recognised as a SQL statement "
                                 f"(read as a {type(expr).__name__} expression)")
            facts.analysis_status = UNREADABLE
            source = _source_text(raw_sql, chunks[index] if chunks is not None else None)
            if source:
                facts.raw_sql, facts.lossy_parse = source, False
            facts_list.append(facts)
            continue

        # ---------------------------------------------------------
        # EXPLAIN / DESCRIBE
        # ---------------------------------------------------------

        if isinstance(expr, exp.Describe):
            facts.explain_analyze = str(expr.args.get("style") or "").upper() == "ANALYZE"
            explained = _explained_statement(expr)
            if explained is not None:
                facts.explained_statement_type = _classify(explained)[0]
                facts.explained_sql = explained.sql(dialect=DIALECT)

        # ---------------------------------------------------------
        # TABLES
        # ---------------------------------------------------------

        facts.tables = _extract_tables(expr)
        facts.table_bindings = _extract_table_bindings(expr)

        # ---------------------------------------------------------
        # WHERE
        # ---------------------------------------------------------

        where_node = (
            expr.args.get("where")
            if hasattr(expr, "args")
            else None
        )

        if statement_type in {
            "UPDATE",
            "DELETE",
            "SELECT",
            "REPLACE",
        }:

            facts.has_where = where_node is not None

            where_expr = (
                where_node.this
                if isinstance(where_node, exp.Where)
                else where_node
            )

            if where_node is not None and (where_expr is None or _unwrap_parentheses(where_expr) is None):
                # A WHERE the permissive parser could not read (UPDATE t SET WHERE):
                # present, but nothing about it is known.
                facts.predicate_shape = "UNSUPPORTED"
                facts.predicate_table_association = "UNRESOLVED"

            elif where_node is not None:

                facts.where_predicate_summary = (
                    where_expr.sql(dialect=DIALECT)
                )

                facts.where_looks_trivial = _where_is_trivial(
                    where_expr
                )

                facts.columns_in_where = _extract_where_columns(
                    where_expr
                )
                facts.predicate_shape = _predicate_shape(where_expr)
                (
                    facts.predicate_columns,
                    facts.predicate_table_association,
                ) = _predicate_columns(where_expr, facts.tables, expr)
                facts.equality_terms = _equality_terms(where_expr)
                facts.where_has_null_test = where_expr.find(exp.Is) is not None
                facts.where_always_true = _is_always_true(where_expr)
            else:
                facts.predicate_shape = "NO_WHERE"
                facts.predicate_table_association = "NOT_APPLICABLE"

        else:
            facts.has_where = None

        # ---------------------------------------------------------
        # LIMIT
        # ---------------------------------------------------------

        facts.has_limit = (
            expr.args.get("limit") is not None
            if hasattr(expr, "args")
            else False
        )
        facts.single_table_write = _is_single_table_write(expr, facts.tables)

        # ---------------------------------------------------------
        # DDL IMPACT
        # ---------------------------------------------------------

        if statement_type in {
            "DROP",
            "TRUNCATE",
        }:
            facts.is_full_table_ddl = True

        elif statement_type == "ALTER":

            sql_lower = statement_sql.lower()

            facts.is_full_table_ddl = (
                "drop" in sql_lower
                and "column" in sql_lower
            )

        facts_list.append(facts)

    return facts_list