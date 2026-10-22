"""Capture the validator's responses for the live-validation cases (Local Mode).

Run it yourself, in your own terminal, with the web app running on
http://127.0.0.1:8420 (uvicorn backend.main:app --host 127.0.0.1 --port 8420):

    python docs/v2-live-validation/capture_local_cases.py --case 1 --out <folder>

- The password is read with getpass (not echoed, not stored, never written).
- Requests go only to the local web app, exactly as the page sends them:
  host 127.0.0.1, port 3306, database validator_live_test.
- Each response is saved as JSON in --out, which must be outside this
  repository. Responses contain no credentials; the request is saved without
  the password.
- It sends one statement per request (batches add +10 to scores), except the
  case 4 batch, and stops at the first HTTP error or failed connection.

Take an observer snapshot (05-observer-snapshot.sql) before and after each --case.
It runs nothing against MySQL itself: the web app does, through its normal path.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

APP_URL = "http://127.0.0.1:8420/api/validate"   # fixed: the local web app only
TARGET = {"host": "127.0.0.1", "port": 3306, "database": "validator_live_test"}
REPO_ROOT = Path(__file__).resolve().parents[2]

CASES: dict[str, list[str]] = {
    "1": ["SELECT * FROM users WHERE id = 1"],
    "2": ["UPDATE users SET status = 'x' WHERE id = 1",
          "DELETE FROM users WHERE id = 1"],
    "3": ["SELECT split(code, ',') FROM users",
          "SELECT levenshtein(code, 'x') FROM users",
          "SELECT * FROM users WHERE id IN (SELECT split(code, ',') FROM users)",
          "SELECT validator_live_test.upper(code) FROM users",
          "SELECT `split`(code, ',') FROM users",
          "SELECT upper(code) FROM users"],
    "4": ["SELECT flip() FROM users; SELECT * FROM users WHERE id = 1"],
    "5": ["UPDATE users SET status = 'x' WHERE id = 1",
          "DELETE FROM users WHERE tenant_id = 1 AND ref = 'a'",
          "DELETE FROM users WHERE tenant_id = 1",
          "DELETE FROM users WHERE email = 'a@example.test'",
          "DELETE FROM users WHERE email IS NULL",
          "DELETE FROM users WHERE code = 'c01-0000001'",
          "DELETE FROM users WHERE customer_id = 10",
          "DELETE FROM users WHERE id = '1'",
          "DELETE FROM users WHERE LOWER(email) = 'a@example.test'",
          "DELETE FROM users_fx WHERE id = 1",
          # Not created by the fixture: metadata finds no such table.
          "SELECT * FROM vt_missing_table WHERE id = 1"],
    "7": ["SELECT * FROM users WHERE id = 1",
          "UPDATE users SET status = 'x' WHERE id = 1",
          "UPDATE users SET status = 'x' WHERE customer_id = 10",
          "DELETE FROM users",
          "DELETE FROM users WHERE 1 = 1",
          "EXPLAIN ANALYZE DELETE u FROM users u JOIN audit_log a ON a.id = u.id",
          "DESCRIBE DELETE FROM users WHERE id = 1",
          "DROP TABLE users",
          "UPDATE users SET WHERE"],
}


def _summary(statement: dict) -> str:
    scope = statement.get("scope") or {}
    plan = ((statement.get("evidence") or {}).get("plan") or {}).get("state")
    return (f"score={statement.get('score')} risk={statement.get('risk_level')} "
            f"confidence={statement.get('confidence')} scope={scope.get('basis')} plan={plan}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    parser.add_argument("--out", required=True, help="results folder, outside this repository")
    args = parser.parse_args(argv)

    out = Path(args.out).expanduser().resolve()
    if out == REPO_ROOT or REPO_ROOT in out.parents:
        print("refusing: --out must be outside the repository", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)

    username = input("MySQL username for the validator [vt_evidence]: ").strip() or "vt_evidence"
    password = getpass.getpass(f"Password for {username}@127.0.0.1 (not shown): ")

    try:
        for number, sql in enumerate(CASES[args.case], 1):
            body = {"sql": sql, "username": username, "password": password, **TARGET}
            request = urllib.request.Request(
                APP_URL, data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    status, payload = response.status, json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                status, payload = exc.code, {"error": "http_error"}
            record = {"case": args.case, "number": number, "sql": sql, "http_status": status,
                      "request": {"username": username, **TARGET}, "response": payload}
            path = out / f"case{args.case}-{number:02d}.json"
            path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            statements = payload.get("statements") or []
            print(f"[{args.case}.{number}] HTTP {status}  {sql}")
            for statement in statements:
                print("        " + _summary(statement))
            connection_state = ((statements[0].get("evidence") or {}).get("connection") or {}).get("state") \
                if statements else None
            if status != 200 or connection_state != "connected":
                print(f"stopping: HTTP {status}, connection {connection_state}; see {path}", file=sys.stderr)
                return 1
    finally:
        password = None  # noqa: F841  (drop the reference; Python cannot guarantee wiping)
    print(f"saved to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
