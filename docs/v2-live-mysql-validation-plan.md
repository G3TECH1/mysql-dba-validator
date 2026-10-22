# V2 evidence contract: live MySQL validation plan

Status: **prepared, not run.** Nothing here has been executed against a MySQL
server. Every server-behaviour claim in the contract
([v2-database-evidence-contract.md](v2-database-evidence-contract.md)) stays
unverified until the matching case is run and recorded in VERIFICATION.md.

Scripts referred to below are in [v2-live-validation/](v2-live-validation/).

**Execution plans restored (2026-10-22, contract section 1.1).** An eligible
`SELECT` is sent to MySQL as one plain `EXPLAIN` again. Where a case below
expects no `EXPLAIN` or `SELECT DATABASE()` digest, or `plan.state`
`not_collected`, for an eligible `SELECT`, expect instead exactly one `EXPLAIN`
of that `SELECT`, one `SELECT DATABASE()` and `plan.state` `collected`; writes
and ineligible statements still get no `EXPLAIN`. Cases 3 and 4 apply again.
These expectations come from the code and fake-connection tests, not a server.
MySQL 8.0 results never count as MySQL 8.4 certification.

## 1. Targets and what each run can show

| | Run A: local MySQL 8.0 (compatibility) | Run B: disposable MySQL 8.4 LTS (primary) |
| --- | --- | --- |
| Server | The Windows service `MySQL80` on this machine. `mysqld.exe` file version 8.0.45; the running version must be read with `SELECT VERSION()` (preflight) | A separate, disposable 8.4 instance (another machine or VM) |
| Authorisation | Not yet given. This service is not known to be disposable or isolated: the run touches only its own schema and accounts, changes no global variable and does not restart it | Not yet given; no target exists yet |
| Proves | Behaviour on 8.0 only; recorded as 8.0 compatibility evidence. Does **not** meet contract acceptance criterion 9 (8.4) and changes no declared compatibility | The contract's server claims on 8.4 |
| Cases | 1, 2, 3, 4, 5, 7 through Local Mode. **6 is blocked** (see below) | All seven. Local Mode cases need the validator on the 8.4 host (see 3.1) |

**Why case 6 cannot run against the local service.** Company Mode refuses
`localhost`, IP literals and any host name that resolves to a loopback, link-local,
multicast, unspecified or reserved address (`connector/policy.py`,
`connector/server.py`), and it requires a server certificate that verifies
against your CA *and* matches the host name. The local service has no such
certificate (MySQL's auto-generated certificate does not carry a usable host
name), and giving it one means changing its TLS configuration and adding a host
name mapping: server and system changes outside this plan. Use Run B for case 6.

**Shared versus version-specific expectations.**

| Case | Same expected result on 8.0 and 8.4 | Version-specific: record per version |
| --- | --- | --- |
| 1 | The application's statement sequence (fixed by the code) | Read-back value; temporary-table and error 1792 behaviour |
| 2 | (a) no write plan sent | (b) error 1142 vs 1792 order; (c) 1792; (d) plan without running |
| 3 | (a) refused calls never reach the server | (b) whether `EXPLAIN` evaluates a stored function; function creation privileges (8.0: `SET_USER_ID`/`SUPER`; 8.4 page: `SUPER`/`SET_ANY_DEFINER`) |
| 4 | App: unlisted function never sent | Whether a function may change `transaction_read_only` |
| 5 | Scope rules applied to the metadata returned | `STATISTICS` representation (`NON_UNIQUE` type, `SUB_PART`, functional key parts) |
| 6 | — | 8.4 only |
| 7 | Risk, confidence, scope, page text (product logic) | — |

## 2. Roles and least privilege

| Role | Account | Privileges | Used for |
| --- | --- | --- | --- |
| Server administrator | Your existing admin login (never stored by this plan) | `CREATE USER`, `GRANT OPTION`, `CREATE` on the new schema, `PROCESS` (for the cleanup session check, section 5.1); for 03/04 also `SET_USER_ID` or `SUPER` because binary logging is on | Preflight (read-only), creating/dropping the schema and accounts, creating the probe functions, cleanup |
| Fixture owner | `vt_fixture@127.0.0.1` | `SELECT, INSERT, UPDATE, CREATE, DROP, INDEX, ALTER, CREATE TEMPORARY TABLES, EXECUTE` on `validator_live_test.*` only | Fixture tables, direct probes in cases 1–4 |
| Validator evidence | `vt_evidence@127.0.0.1` | `SELECT` on `validator_live_test.*` only | Everything the validator does; your direct check in case 2(b) |
| Observer | `vt_observer@127.0.0.1` | `SELECT` on `performance_schema.events_statements_summary_by_digest` only | Seeing which statements reached the server |

**Privileges needed for V2 (review 2026-10-21).** Script 01 is unchanged and
still grants the table above. For V2:

- `vt_fixture` needs `SELECT, INSERT, CREATE, DROP, INDEX, ALTER, CREATE
  TEMPORARY TABLES` (02's tables and inserts; case 1(b)'s read-only probes).
  `EXECUTE` is needed only by the deferred function probes (03/04), which are
  not run for V2. `UPDATE` is needed only by case 2(c)–(d), optional checks of
  MySQL's own behaviour, not the validator's; no V2 acceptance check needs it.
  Removing either means editing 01, which needs separate authorisation; until
  then 01 grants both.
- `vt_observer` is kept: the digest snapshot is the only evidence that no
  `EXPLAIN` or submitted text reached the server (section 9, criterion 1), and
  this account reads it with one table-level `SELECT` instead of the
  administrator's login. It can read normalised statements of every schema on
  the server; filter on `SCHEMA_NAME = 'validator_live_test'` and keep no other
  rows. Running 05 as the administrator instead is acceptable, in which case
  `vt_observer` is unused.

Passwords are generated by MySQL (`IDENTIFIED BY RANDOM PASSWORD`, 8.0.18+) and
shown once in **your** client. Keep them in your own password manager; never
paste them into this conversation, a command line, a file in the repository,
or an issue.

**Not done by this plan, ever:** `SET GLOBAL` or `SET PERSIST` of anything
(including `general_log` and `log_bin_trust_function_creators`), stopping or
reconfiguring the service, changing replication, touching other schemas or
accounts, granting global privileges to the test accounts.

## 3. Connection setup (you enter every value)

### 3.1 Local Mode (cases 1–5, 7)

1. Start the web app (it opens no database connection until you validate):
   `uvicorn backend.main:app --host 127.0.0.1 --port 8420`.
2. In the page, **Local** target: Host `127.0.0.1` (Local Mode accepts only a
   loopback host on port 3306), Port `3306`, Username `vt_evidence`, Password
   typed into the password field. **Test connection**, then **Discover
   databases**, then select `validator_live_test`.
3. The page keeps the password only in the page's memory and sends it with each
   request to `127.0.0.1:8420`; nothing stores it. Local Mode has no TLS: the
   connection stays on the loopback interface.
4. To capture JSON for a whole case, run the helper in **your own terminal**
   (it prompts for the password without echoing it and saves responses without
   credentials, outside the repository):
   `python docs/v2-live-validation/capture_local_cases.py --case <n> --out <folder outside the repo>`.
   If you use the browser's developer tools instead, share only the **response**,
   never the request payload (it contains the password).

For Run B, Local Mode needs `127.0.0.1:3306` on the machine running the
validator to be the 8.4 server, so run the validator on the 8.4 host. On this
laptop that port belongs to `MySQL80`, which this plan does not stop.

### 3.2 Company Mode (case 6, Run B only)

| Item | You provide |
| --- | --- |
| Host name | A DNS name for the 8.4 server that resolves to a routable, non-loopback address, and appears in the server certificate's subjectAltName |
| Port | The server's TLS port (normally 3306) |
| CA | `ca.pem` (PEM) that issued the server certificate, passed to the connector |
| Login | `vt_evidence`, created for the connector machine's address instead of `127.0.0.1` |
| Database | `validator_live_test`, chosen after discovery |

1. Start the connector with a **separate test registry** and the CA:
   `python -m connector --allow-origin http://127.0.0.1:8420 --registry <test folder>/vt-registry.json --tls-ca <test folder>/ca.pem`.
   It never asks for MySQL logins; it prints a pairing code.
2. In the connector console: `register vt84 <host name> <port> V2 validation 8.4`,
   then `approve vt84` (it pins the resolved address).
3. In the page: pair with the code, choose target `vt84`, enter the username and
   password, discover, select `validator_live_test`, validate.

### 3.3 TLS for Run B (test CA and server certificate)

Create these in a folder **outside the repository** (OpenSSL 3, for example Git
Bash). Replace `<host>` with the server's host name. Never commit any of them.

```sh
openssl req -x509 -newkey rsa:3072 -sha256 -days 30 -nodes \
  -keyout ca-key.pem -out ca.pem -subj "/CN=V2 validation test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:3072 -sha256 -nodes -keyout server-key.pem -out server.csr \
  -subj "/CN=<host>"
printf "subjectAltName=DNS:<host>\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 30 -sha256 -extfile server.ext -out server-cert.pem
openssl verify -CAfile ca.pem server-cert.pem          # must print: OK
openssl x509 -in server-cert.pem -noout -ext subjectAltName
```

On the disposable 8.4 server only, its administrator sets `ssl_ca`, `ssl_cert`,
`ssl_key` to `ca.pem`, `server-cert.pem`, `server-key.pem` and
`require_secure_transport=ON`. For the failure cases also create
`wrong-ca.pem` (a second, unrelated CA made with the first command) and a second
DNS name for the same address that is **not** in the certificate.

## 4. Statement capture without the general log

The general query log needs a global change, so it is not used. Instead the
observer reads `performance_schema.events_statements_summary_by_digest`
([05-observer-snapshot.sql](v2-live-validation/05-observer-snapshot.sql)) before
and after each application action and compares `COUNT_STAR` per digest for
`SCHEMA_NAME = 'validator_live_test'`. Limits: digests replace literals with
`?`, are counted per default database rather than per account, and the table is
finite (`DIGEST IS NULL` counts overflow). So run fixture and admin statements
in the test schema only where the case says, take snapshots immediately around
each validator action, and treat any overflow growth as incomplete evidence.

**Statements the validator may cause on its evidence connection** (bound to
`validator_live_test`), and nothing else:

| Statement | When |
| --- | --- |
| `SET NAMES utf8mb4` (and `SET AUTOCOMMIT = 1` only if the server's default differs) | Issued by the PyMySQL driver at connect |
| `SET SESSION TRANSACTION READ ONLY` | Once per validation |
| `SELECT @@SESSION.transaction_read_only AS transaction_read_only` | Once after the `SET`, and again immediately before each plan request |
| `EXPLAIN SELECT …` | Only for an eligible `SELECT`, plain `EXPLAIN` (never `ANALYZE`) |
| `SELECT DATABASE() AS db_name` | After each collected plan |
| `SELECT ENGINE, TABLE_ROWS, … FROM information_schema.TABLES …`, `SELECT INDEX_NAME, … FROM information_schema.STATISTICS …`, `SELECT COLUMN_NAME, … FROM information_schema.COLUMNS …` | Per referenced table, per statement |

**Test connection** opens and closes a short connection and runs no SQL of its
own (only the driver's `SET NAMES`; if a database is already selected it is the
default database, so that digest can appear). **Discover databases** runs
`SHOW DATABASES` on a connection without a default database, so it does not
appear under the schema filter.

## 5. Run order and stop rules

1. **Preflight** (you, as administrator, read-only):
   [00-preflight-readonly.sql](v2-live-validation/00-preflight-readonly.sql).
   **Stop** if the schema or any `vt_*` account already exists, if the server
   replicates in either direction, if `performance_schema` or the
   `statements_digest` consumer is off, or if the version is not the one
   authorised. Also **stop** if the administrator lacks `PROCESS`: check
   read-only with `SHOW GRANTS;`, which must list `PROCESS` (or `ALL
   PRIVILEGES ON *.*`); it is needed for the cleanup session check (section
   5.1).
2. **Accounts** (administrator; authorised server change):
   [01-accounts-admin.sql](v2-live-validation/01-accounts-admin.sql), run in
   batch mode (section 5.1). Check the three `SHOW GRANTS` outputs match
   section 2 exactly.
3. **Fixture** (`vt_fixture`): [02-fixture.sql](v2-live-validation/02-fixture.sql),
   run in batch mode (section 5.1). Expected initial state: `users` 3 rows,
   `users_fx` 3 rows, `audit_log` 0.
4. **Probe functions** (administrator; separately authorised; only for cases 3(b)
   and 4): [03-functions-admin.sql](v2-live-validation/03-functions-admin.sql),
   then [04-session-probes-admin.sql](v2-live-validation/04-session-probes-admin.sql).
   Without this authorisation, run only cases 3(a), 4 (application part), 1, 2,
   5, 7 and mark 3(b) and 4 (server part) BLOCKED. **Not part of the planned
   V2 run:** 03 and 04 are not run for V2 (deferred plan path).
5. Cases in order 1 → 7.
6. **Cleanup** and **verification** (section 7).

**Partial failure.** If any setup step fails, stop, record the error number, and
run [90-cleanup-admin.sql](v2-live-validation/90-cleanup-admin.sql) (it removes
only this plan's names, `IF EXISTS`) **only under the conditions in section
5.1**, then
[91-verify-cleanup-readonly.sql](v2-live-validation/91-verify-cleanup-readonly.sql).
If 01's `CREATE SCHEMA validator_live_test` failed, do not run 90: the schema
is not this run's.

### 5.1 Running 01, 02 and 90 (batch mode, never `--force`)

Run each script on its own, in batch mode (input redirected from the file), in
a Windows **Command Prompt** (`cmd.exe`; PowerShell does not support `<`
redirection), from the repository folder. Never add `--force`. Type the
password only at the client's prompt, never on the command line; if no prompt
appears, stop.

| Script | Account | Command |
| --- | --- | --- |
| 01 | Administrator | `"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -h 127.0.0.1 -P 3306 -u ADMIN_USER -p --table --show-warnings < docs\v2-live-validation\01-accounts-admin.sql` |
| 02 | `vt_fixture` | `"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -h 127.0.0.1 -P 3306 -u vt_fixture -p --table --show-warnings < docs\v2-live-validation\02-fixture.sql` |
| 90 | Administrator | `"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -h 127.0.0.1 -P 3306 -u ADMIN_USER -p --table --show-warnings < docs\v2-live-validation\90-cleanup-admin.sql` |

Before running 01 or 90, replace `ADMIN_USER` with the intended MySQL
administrator username (do not type angle brackets: in Command Prompt `<` and
`>` are redirection operators). `--show-warnings` prints any warnings after
each statement; read them as part of the output.

After each command, run `echo %ERRORLEVEL%` and read the whole output before
going on.

- **Stopping on errors.** The MySQL manual says to use `--force` "if you want
  the script to continue even if some of the statements in it produce errors"
  (Using mysql in Batch Mode), which implies batch mode stops at the first
  error without it. The manual does not state this outright, and it has not
  been observed on this server. So do not rely on it alone: treat any `ERROR`
  line in the output, or a non-zero `%ERRORLEVEL%`, as a failed step, stop, and
  follow **Partial failure** above.
- **Expected output.** 01: three result sets, one generated password each, then
  the three `SHOW GRANTS` outputs matching section 2. 02: the counts 3, 3, 0
  and the three `users` rows. 90: no `ERROR` line.
- **01's output contains the generated passwords.** Do not redirect it to a
  file or use `tee`; copy each password into your password manager.
- **90 runs only if both hold:** (a) 01's `CREATE SCHEMA validator_live_test`
  succeeded in this run, so the schema is this run's; (b) no `vt_*` session is
  open (`DROP USER` does not close open sessions; it takes effect only when
  they end). Check (b) as the administrator, read-only:
  `SELECT ID, USER, HOST FROM information_schema.PROCESSLIST WHERE USER LIKE 'vt\_%';`
  must return no rows. Close the web app, the capture helper and every client
  session first. This check means something only if the inspecting account
  has `PROCESS`: without it, `PROCESSLIST` shows only that account's own
  sessions, so an empty result proves nothing. If the administrator does not
  have `PROCESS`, stop: do not treat an empty result as proof that no
  test-account sessions exist, and do not run 90.

**Stop and investigate (do not repeat the step)** on: a TLS failure in Run B
outside the failure tests; any change in `SHOW GRANTS`; `transaction_read_only`
reading 0 on the evidence connection; an `EXPLAIN` digest for a statement the
case says is refused; any `UPDATE`/`DELETE`/DDL digest from the evidence
connection; any change to `users` or `users_fx`; `audit_log` rows outside cases
3(b)/4; digest overflow growth; a local versus Company Mode difference in case 6.

## 6. Cases

Fixture rows: `users` (1, 1, 'a', 'a@example.test', 'c01-0000001', 10, 'open'),
(2, 1, 'b', NULL, 'c02-0000002', 10, 'open'), (3, 2, 'a', NULL, 'c03-0000003', 11,
'closed'); `users_fx` with a functional unique index on `LOWER(email)`.
Initial and final state of `users` and `users_fx`: unchanged throughout. The
validator never writes; only cases 3(b) and 4 write, to `audit_log`.

### Case 1: read-only session established and read back

| | |
| --- | --- |
| Preconditions | Steps 1–3 done; web app running; observer snapshot taken |
| Action | (a) `capture_local_cases.py --case 1` (`SELECT * FROM users WHERE id = 1`); take a snapshot. (b) As `vt_fixture`: `SET SESSION TRANSACTION READ ONLY; SELECT @@SESSION.transaction_read_only; INSERT INTO audit_log (note) VALUES ('ro');` then `CREATE TEMPORARY TABLE tmp (x INT); INSERT INTO tmp VALUES (1); DROP TEMPORARY TABLE tmp;` |
| Expected | (a) New digests are exactly section 4's V2 list: driver `SET NAMES`, `SET SESSION TRANSACTION READ ONLY`, the read-back counted once, the three metadata queries; no `EXPLAIN` and no `SELECT DATABASE()` digest, and no digest containing the submitted statement. Response: `connection.state` `connected`, `plan.state` `not_collected`, metadata collected, risk LOW, confidence HIGH. (b) Read-back 1; the `audit_log` insert fails with error 1792; the temporary-table insert succeeds (documented exception: read-only transactions do not protect temporary tables, and the read-only setting is not a privilege) |
| Evidence | Snapshot diff; `case1-01.json`; error numbers from (b) |
| Cleanup | The temporary table is dropped in (b); confirm `audit_log` still has 0 rows |

### Case 2: prohibited write plans

| | |
| --- | --- |
| Preconditions | Case 1 passed; snapshot taken; `SELECT * FROM users WHERE id = 1` output saved |
| Action | (a) `--case 2`; snapshot. (b) As `vt_evidence` in your client: `SET SESSION TRANSACTION READ ONLY; EXPLAIN UPDATE users SET status = 'x' WHERE id = 1;` (c) As `vt_fixture`: the same in a read-only session. (d) As `vt_fixture`, new session (writable): the same `EXPLAIN UPDATE`, then `SELECT * FROM users WHERE id = 1` |
| Expected | (a) No `EXPLAIN UPDATE`/`EXPLAIN DELETE` digest; both responses `plan.state` `not_collected_read_only`, metadata collected. (b) An error: record whether 1142 (privilege) or 1792 (read-only); the order is not documented. (c) Error 1792. (d) A plan is returned and the row is unchanged: plain `EXPLAIN` plans without running (8.4 EXPLAIN manual), unlike `EXPLAIN ANALYZE` |
| Evidence | Snapshot diff; JSON; error numbers; the row before and after (d) |
| Cleanup | None |

### Case 3: function names and evaluation during EXPLAIN

Deferred plan path: not required for V2 (V2 sends no `EXPLAIN`). Part (a)'s
check that no refused call reaches the server still holds and is covered by
case 1's V2 expectation.

**Pass rule for (a):** the case passes when a refused call never reaches the
server as an evidence query (no `EXPLAIN` digest for it) and the response says
`plan.state` `not_eligible`. It does not matter that `vt_evidence` lacks
`EXECUTE` and the server would refuse the call anyway; that privilege error is
not the control under test.

| | |
| --- | --- |
| Preconditions | Cases 1–2 done. (a) needs no functions. (b) needs 03-functions-admin.sql (separately authorised); record warning 1585 for `upper` and the `ROUTINES` listing |
| Action | (a) Snapshot; `--case 3` (six statements: `split(code, ',')`, `levenshtein(code, 'x')`, `split` in a subquery, `validator_live_test.upper(code)`, `` `split`(code, ',') ``, built-in `upper(code)`); snapshot; `SELECT COUNT(*) FROM audit_log`. (b) As `vt_fixture`, writable session: `EXPLAIN SELECT * FROM (SELECT vt_signal('x') AS v) d;` and `EXPLAIN SELECT * FROM users WHERE id = vt_signal('1');` (record whether each fails with SQLSTATE 45000 "vt_signal evaluated"); `EXPLAIN SELECT * FROM (SELECT split('x', 'y') AS v) d;` then count `audit_log`; the same `split` probe after `SET SESSION TRANSACTION READ ONLY` in a new session; `SELECT UPPER('x');` and `SELECT validator_live_test.upper('x');`, counting `audit_log` after each |
| Expected | (a) The first five: no `EXPLAIN` digest, `not_eligible`. The sixth: one `EXPLAIN` digest for the `UPPER(code)` query (exact digest spacing is MySQL's), `plan.state` `collected`, and `audit_log` still 0 (the built-in ran, not the stored function, per "Function Name Parsing and Resolution"). (b) Record whether 8.0/8.4 evaluates a function during plain `EXPLAIN` (on 8.0.21 and earlier it did, per Percona). In the read-only session the `split` insert must fail with 1792 or not happen. `UPPER('x')` adds no row; the qualified call adds one |
| Evidence | Snapshot diffs; JSON; `audit_log` counts; error texts |
| Cleanup | `TRUNCATE audit_log` (as `vt_fixture`); keep the functions for case 4 |

### Case 4: can evaluated SQL change the session's read-only state?

Deferred plan path: not required for V2.

| | |
| --- | --- |
| Preconditions | 04-session-probes-admin.sql run (separately authorised); record whether `CREATE FUNCTION flip` and `flip2` each succeeded |
| Action | Server part, for each function that exists, as `vt_fixture` in a new session: `SET SESSION TRANSACTION READ ONLY; SELECT @@SESSION.transaction_read_only; SELECT flip(); SELECT @@SESSION.transaction_read_only; INSERT INTO audit_log (note) VALUES ('after');`. Application part: snapshot; `--case 4` (`SELECT flip() FROM users; SELECT * FROM users WHERE id = 1`); snapshot |
| Expected | Server part: unknown; record exactly. If the read-back turns to 0 or the insert succeeds, evaluated SQL can undo the read-only setting, which is why the validator reads it back before every plan. Application part: no digest naming `flip`; first statement `not_eligible`; the read-back runs again before the second statement's `EXPLAIN` and that plan is collected |
| Evidence | CREATE outcomes, read-back values, `audit_log`, snapshot diffs, JSON |
| Cleanup | `TRUNCATE audit_log` |
| Limit | The validator's "read-back failed → close and stop" path cannot be triggered through the application on a real server without a function reaching `EXPLAIN`, which the function policy prevents. It remains covered by fake-server tests only |

### Case 5: index metadata and row scope

| | |
| --- | --- |
| Preconditions | Fixture present |
| Action | `--case 5`. Separately, as `vt_evidence`: `SELECT INDEX_NAME, COLUMN_NAME, EXPRESSION, SEQ_IN_INDEX, NON_UNIQUE, SUB_PART FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = 'validator_live_test' AND TABLE_NAME IN ('users', 'users_fx') ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX;` and the same for `COLUMNS` (`COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_KEY`) |
| Expected (per statement) | `UPDATE users … WHERE id = 1`: `at_most_one_row` (`PRIMARY`), score 20 MEDIUM, HIGH, `scope.factor.points` 0, `medium_floor_applied` true. `DELETE … tenant_id = 1 AND ref = 'a'`: `at_most_one_row` (`uq_tenant_ref`), 20 MEDIUM, HIGH, points −5, floor true. `… email = 'a@example.test'`: `at_most_one_row` (`uq_email`), same. `… code = 'c01-0000001'`: `at_most_one_row` (`uq_code_prefix`), same. `tenant_id = 1`, `email IS NULL`, `customer_id = 10`, `id = '1'`, `LOWER(email) = …`: `not_established`, 25 MEDIUM, LIMITED. `DELETE FROM users_fx WHERE id = 1`: `not_established`, 25 MEDIUM, LIMITED (see note). Every write: `indirect_effects` `not_checked`. `SELECT * FROM vt_missing_table WHERE id = 1` (the last statement; the fixture never creates this table): `evidence.metadata.tables` `[{"name": "vt_missing_table", "found": false}]`, and the page's metadata section shows `vt_missing_table` as not found in the selected database. No reason in `reasons` is required to name it: for a `SELECT` the not-found sentence is not added there. Expected from source, not yet observed live: score 0 LOW, confidence LIMITED (a SELECT is HIGH offline; a table not found caps it), `plan.state` `not_collected`. No `EXPLAIN` digest for any of them |
| Expected (metadata) | `NON_UNIQUE` an integer; `uq_code_prefix` `SUB_PART` 10; `uq_lower_email` has `COLUMN_NAME` NULL and a non-NULL `EXPRESSION` |
| Note | The validator currently treats a table whose `STATISTICS` contain a functional key part (NULL `COLUMN_NAME`) as having ineligible index metadata, so *no* key of that table verifies scope, including its primary key. This fails safe (MEDIUM, LIMITED) but is narrower than the contract's wording; it is a product question, not a server result |
| Evidence | JSON; the two metadata result sets |
| Cleanup | None |

### Case 6: Company Mode end to end (Run B only)

| | |
| --- | --- |
| Preconditions | Section 3.2 and 3.3 complete; `vt_evidence` created for the connector machine's address with `SELECT` on `validator_live_test.*`; fixture on the 8.4 server; observer available there |
| Action | (a) Discover and validate the case 5 statements and the case 7 statements through target `vt84`. (b) Restart the connector with `--tls-ca wrong-ca.pem`; repeat one validation. (c) Register and approve a second target with the DNS name that is not in the certificate; validate. (d) Register a third target and do not approve it; try to use it. (e) Optional, only if a proxy is in scope: a route where `transaction_read_only` does not read back 1 |
| Expected | (a) For each statement the same `scope`, `score`, `risk_level`, `confidence` as Local Mode on the same server; digests only from section 4's list. (b) and (c) `database_connection_failed` with no digest from the attempt. (d) `company_target_not_approved` (or not offered); no connection. (e) `database_connection_failed`, nothing after the read-back |
| Evidence | Connector responses (no credentials); snapshot diffs; the connector console output, checked for credentials |
| Cleanup | `delete` the test targets; stop the connector; delete the test registry file |

### Case 7: risk, confidence, API and UI consistency

| | |
| --- | --- |
| Preconditions | Fixture; web app in a browser |
| Action | `--case 7`; then enter each statement in the page one at a time and capture a screenshot |
| Expected | As in the table; the page shows the same level and confidence as the JSON; every write's scope line says triggers and foreign-key actions were not checked; no message claims a check that did not run; no `EXPLAIN` digest for any of these, the `SELECT` included, and no digest containing submitted text |
| Evidence | JSON and screenshots |
| Cleanup | None |

| SQL | Score / risk | Confidence | Scope |
| --- | --- | --- | --- |
| `SELECT * FROM users WHERE id = 1` | 0 LOW | HIGH | `not_applicable` |
| `UPDATE users SET status = 'x' WHERE id = 1` | 20 MEDIUM (floor) | HIGH | `at_most_one_row` |
| `UPDATE users SET status = 'x' WHERE customer_id = 10` | 20 MEDIUM | LIMITED | `not_established` |
| `DELETE FROM users` | 100 CRITICAL | HIGH | `all_rows` |
| `DELETE FROM users WHERE 1 = 1` | 100 CRITICAL | HIGH | `all_rows` |
| `EXPLAIN ANALYZE DELETE u FROM users u JOIN audit_log a ON a.id = u.id` | 100 CRITICAL (scored as the DELETE it runs) | LIMITED | `not_applicable` |
| `DESCRIBE DELETE FROM users WHERE id = 1` | 20 MEDIUM | HIGH | `not_applicable` |
| `DROP TABLE users` | 100 CRITICAL | HIGH | `not_applicable` |
| `UPDATE users SET WHERE` | 20 MEDIUM | LOW | `not_established` |

## 7. Cleanup and confirmation

1. As administrator: [90-cleanup-admin.sql](v2-live-validation/90-cleanup-admin.sql)
   (drops the schema, which removes its tables and functions, and the three
   accounts), in batch mode and only under the conditions in section 5.1.
2. As administrator: [91-verify-cleanup-readonly.sql](v2-live-validation/91-verify-cleanup-readonly.sql);
   every query must return no rows. Cleanup counts as confirmed only on that
   output, not on the cleanup commands succeeding.
3. Stop the web app and, for Run B, the connector; delete the test registry and,
   when no longer needed, the test CA and keys.
4. Left in place by design: in-memory digests (normalised statements, no
   credentials; lost at restart) and binary-log events for the fixture
   statements (kept until the server's normal expiry).
5. In the repository: `git status` must show no new files; captured JSON lives
   outside the repository.

## 8. Approval checklist before the first connection

- [ ] Target named (Run A: local `MySQL80`; or Run B: host) and authorised.
- [ ] Preflight output reviewed: exact version, no replication, schema and
      account names free, `performance_schema` and the digest consumer on.
- [ ] Accounts step (01) authorised as a server change on that server.
- [ ] Probe functions (03, 04) authorised, or cases 3(b) and 4 (server part)
      accepted as BLOCKED.
- [ ] For Run B: CA, server certificate and host name ready; failure-test CA and
      host name ready.

## 9. V2 acceptance coverage (Run A)

What a Run A on local MySQL 8.0.45 could establish for the V2 contract
(contract section 1.1). No live check in this plan has been run, so nothing
below has passed live. Statuses:

- **Live-verifiable — not yet run:** a Run A case can check it; automated
  tests (fake connections) also cover it.
- **Automated tests only:** covered by automated tests with fake connections;
  this plan has no live check for it on this server.
- **Not verified:** no automated test or live result establishes it.

| # | Criterion | Live check | Automated tests (fake connections) | Status |
| --- | --- | --- | --- | --- |
| 1 | No `EXPLAIN` and no submitted text reach MySQL on the local path | Digest snapshots around cases 1(a), 5 and 7 | `tests/test_no_submitted_sql.py` (local path) | **Live-verifiable — not yet run** |
| 2 | The local path sends only the fixed session and metadata queries | Case 1(a) digest list | `tests/test_no_submitted_sql.py`, `tests/test_read_only_boundary.py` | **Live-verifiable — not yet run** |
| 3 | The same on the connector path | Case 6 (Run B only; no 8.4 server) | `tests/test_no_submitted_sql.py` (connector path) | **Automated tests only** |
| 4 | A unique key gives `at_most_one_row` only when its conditions hold | Case 5 (primary, composite, nullable-unique, prefix, non-unique and functional keys) | `tests/test_row_scope.py` | **Live-verifiable — not yet run** |
| 5 | The verified one-row floor: score 20 MEDIUM | Cases 5 and 7 (`medium_floor_applied` true) | `tests/test_review_remediation.py` (floor tests) | **Live-verifiable — not yet run** |
| 6 | A table not found caps confidence at LIMITED | Case 5, `vt_missing_table` | `tests/test_row_scope.py::test_missing_table_caps_confidence_and_is_not_narrow` | **Live-verifiable — not yet run** |
| 7 | Table existence that cannot be determined (`found: null`) caps confidence | None: needs malformed metadata rows | None found | **Not verified** |
| 8 | Failed or unavailable evidence never raises confidence or lowers the offline score | None in this plan | `tests/test_evidence_contract.py::test_missing_evidence_never_reduces_risk_or_changes_confidence`, `tests/test_row_scope.py::test_metadata_failure_never_produces_a_verified_scope` | **Automated tests only** |
| 9 | No claim of affected-row counts, trigger or foreign-key effects | Case 7 page and JSON wording | `tests/test_frontend_evidence_rendering.py` | **Live-verifiable — not yet run** (wording only) |
| 10 | MySQL 8.4 behaviour | Run B | None (fake connections do not model a server version) | **Not verified** (8.0.45 results do not count) |
| 11 | Company Mode with company TLS | Case 6 | Unit tests assert the connector's TLS settings (CA required, certificate and host-name checks); none exercises a company TLS server | **Not verified** |

## 10. Sources

- MySQL 8.4 Reference Manual: EXPLAIN (plain `EXPLAIN` does not run the
  statement; `EXPLAIN ANALYZE` does), SET TRANSACTION (`READ ONLY` prohibits
  changes to tables, temporary tables excepted), CREATE INDEX, Function Name
  Parsing and Resolution, Stored Program Binary Logging, Restrictions on Stored
  Programs (a stored function cannot modify a table the calling statement uses;
  `START TRANSACTION` is not allowed in functions).
- MySQL 8.0 Reference Manual: Stored Program Binary Logging (`SET_USER_ID` or
  `SUPER` plus `CREATE ROUTINE`; `DETERMINISTIC`/`NO SQL`/`READS SQL DATA`
  required unless `log_bin_trust_function_creators` is 1).
- Percona, "When EXPLAIN can trash your database" (secondary source, 8.0.21
  and earlier).
