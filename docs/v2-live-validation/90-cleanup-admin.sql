-- V2 live validation: cleanup. Removes ONLY the objects this plan created.
-- Run as the server administrator, at the end of the run or after any
-- partial setup failure. Safe to run more than once (IF EXISTS).
-- Do not run it if the preflight found any of these names before setup: they
-- would then not be this plan's objects.

DROP SCHEMA IF EXISTS validator_live_test;   -- tables and stored functions in it
DROP USER IF EXISTS 'vt_fixture'@'127.0.0.1',
                    'vt_evidence'@'127.0.0.1',
                    'vt_observer'@'127.0.0.1';
