-- V2 live validation: preflight. READ-ONLY: changes nothing on the server.
-- Run as the server administrator, in your own MySQL client, for example:
--   "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -h 127.0.0.1 -P 3306 -u <admin> -p
--   mysql> SOURCE <path>/00-preflight-readonly.sql
-- The client prompts for the password; never put it on the command line.
-- Share only this script's output (it contains no credentials).

-- 1. Exact server version (the file version of mysqld.exe is not proof).
SELECT VERSION() AS version, @@version_comment AS version_comment;

-- 2. Settings the plan depends on (running values, including SET PERSIST).
SELECT @@log_bin                         AS log_bin,
       @@binlog_format                   AS binlog_format,
       @@log_bin_trust_function_creators AS log_bin_trust_function_creators,
       @@general_log                     AS general_log,
       @@performance_schema              AS performance_schema,
       @@require_secure_transport        AS require_secure_transport,
       @@skip_name_resolve               AS skip_name_resolve,
       @@bind_address                    AS bind_address,
       @@autocommit                      AS autocommit,
       @@transaction_isolation           AS transaction_isolation;

-- 3. Statement capture without the general log: the digest consumer must be on.
SELECT NAME, ENABLED FROM performance_schema.setup_consumers
WHERE NAME IN ('statements_digest', 'events_statements_current');
-- Rows that did not fit in the digest table (overflow). Note the number;
-- if it grows during the run, digest evidence is incomplete.
SELECT COUNT_STAR AS digest_overflow_count
FROM performance_schema.events_statements_summary_by_digest WHERE DIGEST IS NULL;

-- 4. STOP if any of these return a row: the names are reserved for this test
--    and must not already exist.
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'validator_live_test';
SELECT User, Host FROM mysql.user WHERE User IN ('vt_fixture', 'vt_evidence', 'vt_observer');

-- 5. STOP if this server replicates from, or to, another server: the fixture
--    statements are written to the binary log.
SELECT COUNT(*) AS inbound_replication_channels
FROM performance_schema.replication_connection_configuration;
SHOW REPLICAS;
