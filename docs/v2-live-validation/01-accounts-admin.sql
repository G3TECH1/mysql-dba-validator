-- V2 live validation: schema and accounts. SERVER-LEVEL CHANGE: creates one
-- schema and three accounts. Run only after the owner authorises it, and only
-- if 00-preflight-readonly.sql reported none of these names.
-- Run as the server administrator (needs CREATE USER and GRANT OPTION).
--
-- Passwords: IDENTIFIED BY RANDOM PASSWORD makes MySQL generate each password
-- and show it once, in YOUR client's output. Store them in your own password
-- manager. Never paste them into a chat, a terminal command line, a file in
-- the repository, or an issue.
--
-- Accounts are bound to 127.0.0.1: the validator's Local Mode connects over
-- TCP to 127.0.0.1:3306. Type 127.0.0.1 (not "localhost") in the page and in
-- your client so the right account matches.

CREATE SCHEMA validator_live_test;

CREATE USER 'vt_fixture'@'127.0.0.1'  IDENTIFIED BY RANDOM PASSWORD;
CREATE USER 'vt_evidence'@'127.0.0.1' IDENTIFIED BY RANDOM PASSWORD;
CREATE USER 'vt_observer'@'127.0.0.1' IDENTIFIED BY RANDOM PASSWORD;

-- Fixture owner: builds and probes the test schema only. UPDATE is needed for
-- case 2(d) (EXPLAIN UPDATE needs the privileges of the UPDATE it explains),
-- INSERT for the read-only probes, EXECUTE for the function probes.
GRANT SELECT, INSERT, UPDATE, CREATE, DROP, INDEX, ALTER,
      CREATE TEMPORARY TABLES, EXECUTE
   ON validator_live_test.* TO 'vt_fixture'@'127.0.0.1';

-- Validator evidence account: SELECT on the test schema and nothing else.
-- No INSERT, UPDATE, DELETE, EXECUTE, CREATE or any global privilege.
GRANT SELECT ON validator_live_test.* TO 'vt_evidence'@'127.0.0.1';

-- Observer: reads statement digests (which statements reached the server).
-- Read-only, one table. Its rows are server-wide; filter on
-- SCHEMA_NAME = 'validator_live_test' and do not export other rows.
GRANT SELECT ON performance_schema.events_statements_summary_by_digest
   TO 'vt_observer'@'127.0.0.1';

-- Confirm exactly these grants.
SHOW GRANTS FOR 'vt_fixture'@'127.0.0.1';
SHOW GRANTS FOR 'vt_evidence'@'127.0.0.1';
SHOW GRANTS FOR 'vt_observer'@'127.0.0.1';
