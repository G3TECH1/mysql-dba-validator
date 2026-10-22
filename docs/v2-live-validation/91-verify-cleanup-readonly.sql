-- V2 live validation: confirm cleanup. READ-ONLY. Run as the administrator.
-- Every query must return no rows.

SELECT SCHEMA_NAME FROM information_schema.SCHEMATA
WHERE SCHEMA_NAME = 'validator_live_test';

SELECT ROUTINE_SCHEMA, ROUTINE_NAME FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA = 'validator_live_test';

SELECT User, Host FROM mysql.user
WHERE User IN ('vt_fixture', 'vt_evidence', 'vt_observer');

-- Not removed by cleanup, by design (removing them would change server-wide
-- state): the in-memory statement digests for validator_live_test (they hold
-- normalised statement text, no credentials, and are lost at restart) and the
-- binary-log events for the fixture statements (kept until the server's normal
-- binary-log expiry).
