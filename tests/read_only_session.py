"""Test helper: answer the read-only session statements the way MySQL 8 does.

Every evidence connection runs backend.db.READ_ONLY_SESSION_SQL and then reads
backend.db.READ_ONLY_CHECK_SQL, which must return transaction_read_only = 1
(backend.db.enforce_read_only_session). Fake connections use this to model a server
that confirms the read-only session; no MySQL server is involved.
"""

from __future__ import annotations

from backend.db import READ_ONLY_CHECK_SQL, READ_ONLY_SESSION_SQL

READ_ONLY_STATEMENTS = (READ_ONLY_SESSION_SQL, READ_ONLY_CHECK_SQL)
CONFIRMED_ROW = {"transaction_read_only": 1}


class ReadOnlySessionCursor:
    """A cursor that accepts only the two read-only session statements."""

    def __init__(self, log=None):
        self.log = log if log is not None else []
        self.row = None

    def execute(self, sql, args=None):
        self.log.append(sql)
        if sql not in READ_ONLY_STATEMENTS:
            raise AssertionError(f"unexpected statement on a fake connection: {sql[:60]}")
        self.row = CONFIRMED_ROW if sql == READ_ONLY_CHECK_SQL else None

    def fetchone(self):
        return self.row

    def close(self):
        pass


def is_read_only_statement(entry) -> bool:
    """True for a logged read-only session statement (a string or an ("execute", sql) pair)."""
    sql = entry[1] if isinstance(entry, tuple) and len(entry) == 2 else entry
    return sql in READ_ONLY_STATEMENTS


class ConfirmingConnection:
    """Wraps a fake connection so it confirms the read-only session first.

    enforce_read_only_session() uses one cursor for SET SESSION TRANSACTION READ ONLY
    and the read-back; that first cursor is a ReadOnlySessionCursor (MySQL confirms
    transaction_read_only = 1). Every later cursor comes from the wrapped connection,
    and close() reaches it.
    """

    def __init__(self, connection, log=None):
        self.connection = connection
        self.log = log if log is not None else []
        self.confirmed = False

    def cursor(self, *args, **kwargs):
        if not self.confirmed:
            self.confirmed = True
            return ReadOnlySessionCursor(self.log)
        return self.connection.cursor(*args, **kwargs)

    def close(self):
        return self.connection.close()
