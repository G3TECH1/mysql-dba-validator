-- V2 live validation: which statements reached the server. READ-ONLY.
-- Run as vt_observer WITHOUT a default database, so these queries are not
-- counted under the test schema:
--   mysql -h 127.0.0.1 -P 3306 -u vt_observer -p
--   mysql> SOURCE <path>/05-observer-snapshot.sql
--
-- Take a snapshot before and after each application action and compare
-- COUNT_STAR per digest. Digests replace literals with "?" and are counted per
-- default database (SCHEMA_NAME), not per account, so run fixture and admin
-- statements in the test schema only between snapshot pairs where the plan
-- says so. The table is in memory: it is not a permanent log.

SELECT DIGEST, COUNT_STAR, LAST_SEEN, LEFT(DIGEST_TEXT, 160) AS digest_text
FROM performance_schema.events_statements_summary_by_digest
WHERE SCHEMA_NAME = 'validator_live_test'
ORDER BY LAST_SEEN, DIGEST;

-- Must not grow during the run (see preflight step 3).
SELECT COUNT_STAR AS digest_overflow_count
FROM performance_schema.events_statements_summary_by_digest WHERE DIGEST IS NULL;
