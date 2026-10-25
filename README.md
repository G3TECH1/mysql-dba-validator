<img src="frontend/assets/logo-mark.svg" alt="" width="48" height="48">

# MySQL DBA Validator

**How risky is this SQL, and how sure are we about that?**

MySQL DBA Validator helps DBAs review MySQL SQL from database tickets before it
is run. Paste up to 16 statements and get, for each one, a risk level and
score, a confidence level, the findings behind the score and a review
checklist. Optionally, it adds read-only evidence from a database (execution
plans and table metadata).

Scoring is rule-based and deterministic; no AI or LLM makes risk decisions.
The validator never runs the SQL you submit. It supports a DBA's judgement and
does not guarantee that SQL is safe.

**Current release: [v0.7.0](https://github.com/realspinn/mysql-dba-validator/releases/tag/v0.7.0)**
(pre-1.0), a portable Windows x64 app, plus an unsigned macOS (Apple Silicon)
build.

![Validation results for a batch of four statements: overall risk CRITICAL, score 100 of 100, static analysis, batch confidence LIMITED; the top finding (statement 2, a DELETE with no WHERE clause), execution-plan, filter, limitation and unknown rows; and a table listing each statement with its risk, confidence and key finding](docs/images/validator-batch-review.png)

*The v0.5.0 results page after validating four made-up statements with no
database connected, so the result is static analysis only.*

## What it does

- **Classifies and scores each statement** from explicit rules: risk `LOW`,
  `MEDIUM`, `HIGH` or `CRITICAL`, with a score from 0 to 100. A batch's overall
  score is its highest statement score, not a sum.
- **Reports confidence separately from risk** (`HIGH`, `LIMITED` or `LOW`).
  Confidence is how well the evidence supports the assessment, not a safety
  rating.
- **Explains the result:** findings with the points they add, the rows a write
  can change where that is known, what is unknown, and a DBA checklist.
- **Says when it could not assess SQL.** Each statement is either analysed,
  not valid MySQL, a statement type it does not analyse, or SQL it could not
  read. Anything not analysed is shown as `CRITICAL` with `LOW` confidence,
  never as low risk.
- **Adds database evidence on request.** With a MySQL login it collects
  `EXPLAIN` for a plain `SELECT` and table metadata, on a read-only
  connection. Company servers are reached only through a local connector, for
  targets an operator has approved, over verified TLS. Each result says what
  evidence was collected, not collected, or failed.
- **Suggests what to check for performance (advisory).** For a single `SELECT`
  it notes a `LIKE` pattern that starts with a wildcard, a filtered column inside
  a function or calculation, and `ORDER BY RAND()`, with caveats and how to
  verify. This advice comes from fixed rules, never changes the risk result,
  does not rewrite the SQL and is not a full performance review.
- **Keeps credentials out of storage.** Logins are used for one operation and
  never saved.

## Important limitations

- **Risk and confidence are assessments, not guarantees.** Review the SQL
  yourself before running it.
- **Statements the parser cannot read in full are not analysed.** Each
  statement is analysed only when the parser reads all of its text. Otherwise
  it is reported as not analysed (`CRITICAL`, `LOW` confidence, shown as
  submitted) and the review is marked incomplete; the other statements are
  still analysed. This includes valid MySQL the parser does not fully support,
  such as `SELECT ... INTO` in any position (`INTO OUTFILE`, `INTO @var`).
  When the statements cannot be told apart reliably (for example an
  unterminated string), the whole input is one unreadable result. A statement
  the parser reads in full is not proof that MySQL accepts it. Statements the
  parser reads only by their first keyword (`PREPARE`, `EXECUTE`,
  `LOCK TABLES`, `RENAME TABLE`, `OPTIMIZE TABLE`, `GRANT`, `CREATE USER`,
  `REPLACE`, ...), `KILL`, `SET` of anything but user variables, and
  `START REPLICA` are not analysed either. Execution risk is not assessed from
  the SQL alone; with an execution plan it reports the optimizer's estimates.
  Results show each statement's SQL as submitted, without comments before or
  after it.
- **A `SELECT` is not always a plain read.** A `SELECT` with a locking clause
  (`FOR UPDATE`, `FOR SHARE`, `LOCK IN SHARE MODE`), or one that calls a
  function outside the validator's reviewed list of MySQL built-ins (a stored
  function, `SLEEP`, `GET_LOCK`, `LOAD_FILE`, ...), is reported as at least
  `MEDIUM` with `LIMITED` confidence. This includes any part of a `UNION`,
  `INTERSECT` or `EXCEPT`, and the call (not the locking clause) in a
  `SELECT` that a plain `EXPLAIN` plans, because MySQL can evaluate functions
  while planning. The validator cannot see the transaction it runs in or what
  a stored function does.
- **Executable comments are refused.** MySQL runs the contents of executable
  comments (`/*! ... */`, `/*!50000 ... */`) as SQL, so input containing one
  is refused (`executable_comment_not_supported`) rather than assessed. This
  includes `mysqldump` headers such as `/*!40101 SET NAMES utf8mb4 */`. To
  validate, remove the comment or move its SQL out of it: the result then
  describes the edited SQL, not the original script. `/*!` inside a string,
  quoted identifier or ordinary comment is not refused, except in a string
  that also contains `\'`, which is refused because the server's backslash
  mode is not known.
- **`--` is read as MySQL reads it.** `--` starts a comment only when followed
  by whitespace, a control character or the end of the input. Otherwise it is
  two minus signs (`balance--1` is `balance - -1`), so a line of dashes such
  as `----------` is not a comment and the statement it starts is reported as
  not analysed (MySQL rejects it too). MariaDB `/*M! ... */` comments are
  treated as ordinary comments, and a comment ending at a lone carriage return
  may be read differently than by MySQL.
- **Refused input:** empty or comment-only input, `DELIMITER` scripts, and
  stored program definitions with a multi-statement body or mixed with other
  statements are refused rather than split unreliably. `CALL` never reports
  what a procedure does.
- **Little live MySQL validation since v0.5.0.** Changes since v0.5.0 are
  covered by automated tests. The only live check is v0.6.0's connector TLS
  behaviour (a trusted and an untrusted CA bundle, a host name not in the
  certificate) against one disposable local MySQL 8.0.45 server; a server that
  offers no TLS and MySQL 8.4 were not tested live. On earlier code, local
  evidence was verified against a real MySQL server, and the maintainer
  reported a successful test against an AWS RDS for MySQL test database.
  Company MySQL, VPN/LAN and company-issued TLS have never been verified.
- **Unsigned builds.** The Windows build is not code-signed. The macOS build
  is ad hoc signed only, not notarized, and has been tested only in CI, not on
  a real Mac.
- **Single user, local only.** There is no user authentication.

Details: the
[evidence contract](docs/v2-database-evidence-contract.md#17-open-questions-and-known-limitations),
[SECURITY.md](SECURITY.md#known-limitations) and
[VERIFICATION.md](VERIFICATION.md).

## Download and run

Download from the
[v0.7.0 release page](https://github.com/realspinn/mysql-dba-validator/releases/tag/v0.7.0).
Each file has a matching `.sha256` checksum file there.

| Platform | File | Status |
| --- | --- | --- |
| Windows x64 | `MySQL-DBA-Validator-v0.7.0-windows-x64.zip` | Built, audited and smoke-tested in CI; the release notes say which checks the maintainer repeated on the published zip |
| macOS, Apple Silicon only | `MySQL-DBA-Validator-v0.7.0-macos-arm64-unsigned.zip` | Built, audited and smoke-tested in CI only; ad hoc signed, not notarized |

**Windows**

1. Check the download in PowerShell, and compare the result with the
   `.sha256` file:

   ```powershell
   Get-FileHash .\MySQL-DBA-Validator-v0.7.0-windows-x64.zip -Algorithm SHA256
   ```

2. Extract the zip anywhere, for example `C:\Tools\`. No installer or Python
   is needed.
3. Run `MySQL-DBA-Validator.exe`. Your browser opens `http://127.0.0.1:8420`.
   SmartScreen may warn because the app is not code-signed; continue only if
   the checksum matched.
4. Paste SQL and choose **Validate SQL**. To stop, close the page; the app
   exits about 15 minutes later.

For approved company targets, run `MySQL-DBA-Validator Console.exe` instead:
its window is the local connector's operator console. The zip's `README.txt`
covers local evidence, company targets and troubleshooting.

**macOS (Apple Silicon)**

Check the download with
`shasum -a 256 -c MySQL-DBA-Validator-v0.7.0-macos-arm64-unsigned.zip.sha256`,
unzip it, and move `MySQL DBA Validator.app` to Applications. macOS blocks the
first launch because the app is not notarized; the
[release notes](https://github.com/realspinn/mysql-dba-validator/releases/tag/v0.7.0)
explain how to open it.

**Update notice (since v0.7.0).** When a newer official release exists, the
page shows a small notice with a link to its release notes; you can dismiss
it. Nothing is downloaded or installed. To check, the app asks GitHub once per
start for the latest release: GitHub sees your IP address and the installed
version, and no SQL, login or connection details are sent. Set
`MDV_UPDATE_CHECK=off` to turn it off; see
[SECURITY.md](SECURITY.md#security-model-in-brief).

## How it works

1. **Paste the SQL** from the ticket. Without a login, the result is static
   analysis of the SQL text, and says so.
2. **Optionally add evidence.** Open *Database connection*, enter a MySQL
   login, discover and select a database. For company servers, pair the page
   with the local connector and choose an approved target.
3. **Read the result:** overall risk and confidence first, then each
   statement's findings, row scope, evidence and limitations.
4. **Follow the checklist** and verify the change yourself before running it.

Evidence can adjust a score by small, bounded amounts. Missing evidence never
lowers a score. The rules are in [ARCHITECTURE.md](ARCHITECTURE.md#risk-scoring)
and the [evidence contract](docs/v2-database-evidence-contract.md).

## Running beyond one machine

The release is built for one user on one machine: both services bind to
`127.0.0.1`. Company MySQL is reached only through the local connector on
that machine, under an operator's approval; see
[connector/README.md](connector/README.md).

Serving the web app to other machines (`--host 0.0.0.0`, a reverse proxy or a
tunnel) is a trusted self-hosted setup only. In that setup there is no
authentication, rate limiting or egress control, and the connection-test and
discovery endpoints accept a user-supplied MySQL host. If you do it, set
`CORS_ALLOW_ORIGINS` to the exact HTTPS origin, terminate TLS in the proxy,
keep MySQL private and use a read-only MySQL account.

## Documentation

| Document | Covers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, request flows, what is sent to a database, scoring rules, stored data |
| [Evidence contract](docs/v2-database-evidence-contract.md) | What each result field means, the batch contract, known limitations |
| [SECURITY.md](SECURITY.md) | Security model, known limitations, vulnerability reporting |
| [VERIFICATION.md](VERIFICATION.md) | What has and has not been tested, and at which level |
| [connector/README.md](connector/README.md) | Local connector: configuration, operator console, sessions, credentials |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, tests, review areas, pull requests |
| [RELEASING.md](RELEASING.md) | Maintainer build and release procedure |
| [Releases](https://github.com/realspinn/mysql-dba-validator/releases) | Changes, test results and checksums for each version |

## Development

The project is developed and tested on Windows with Python 3.14. Setup, how
to run the web app and connector from source, and the test commands
(`python -m pytest -q` and `pip check`, no MySQL server needed) are in
[CONTRIBUTING.md](CONTRIBUTING.md#development-setup).

## Contributing and support

Bug reports with steps to reproduce, and suggestions, are welcome in
[GitHub Issues](https://github.com/realspinn/mysql-dba-validator/issues). Use
made-up SQL and never include credentials, hostnames or company data. Report
security vulnerabilities privately as described in [SECURITY.md](SECURITY.md),
not in a public issue. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request.

## License

[MIT](LICENSE).
