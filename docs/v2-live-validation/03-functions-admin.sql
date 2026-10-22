-- V2 live validation: probe functions for case 3. SEPARATE AUTHORISATION.
--
-- Why the administrator runs this: with binary logging on (preflight log_bin = 1)
-- and log_bin_trust_function_creators = 0, MySQL accepts CREATE FUNCTION only
-- from an account with SET_USER_ID or SUPER (8.0 manual; the 8.4 page names
-- SUPER and SET_ANY_DEFINER), and only if the function is declared DETERMINISTIC,
-- NO SQL or READS SQL DATA ("Stored Program Binary Logging"). This plan does NOT
-- set log_bin_trust_function_creators or any other global variable.
--
-- Every function is owned by vt_fixture (DEFINER) and runs with the CALLER's
-- privileges (SQL SECURITY INVOKER), so none is a privileged routine: called by
-- vt_evidence (no EXECUTE) it fails; called by vt_fixture it can touch only the
-- test schema. The functions that write declare DETERMINISTIC only to satisfy
-- the binary-log check; that is false and acceptable only because this schema
-- is disposable and the server has no replicas (preflight step 5).
--
-- Run as the administrator:  mysql -h 127.0.0.1 -P 3306 -u <admin> -p
--   mysql> SOURCE <path>/03-functions-admin.sql
-- If any CREATE fails, record the error number and stop case 3.

USE validator_live_test;

DELIMITER //

-- Writes nothing. Evaluating it raises SQLSTATE 45000 'vt_signal evaluated',
-- so an EXPLAIN that evaluates it fails visibly.
CREATE DEFINER = 'vt_fixture'@'127.0.0.1' FUNCTION vt_signal(x VARCHAR(255))
RETURNS VARCHAR(255) DETERMINISTIC NO SQL SQL SECURITY INVOKER
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'vt_signal evaluated';
  RETURN x;
END//

-- Names sqlglot knows from other dialects; not MySQL built-ins. Each leaves one
-- row in audit_log when it runs.
CREATE DEFINER = 'vt_fixture'@'127.0.0.1' FUNCTION split(x VARCHAR(255), y VARCHAR(255))
RETURNS VARCHAR(255) DETERMINISTIC MODIFIES SQL DATA SQL SECURITY INVOKER
BEGIN
  INSERT INTO audit_log (note) VALUES ('split');
  RETURN x;
END//

CREATE DEFINER = 'vt_fixture'@'127.0.0.1' FUNCTION levenshtein(x VARCHAR(255), y VARCHAR(255))
RETURNS VARCHAR(255) DETERMINISTIC MODIFIES SQL DATA SQL SECURITY INVOKER
BEGIN
  INSERT INTO audit_log (note) VALUES ('levenshtein');
  RETURN x;
END//

-- Same name as a built-in: expect warning 1585. Unqualified UPPER() must still
-- resolve to the built-in; only validator_live_test.upper() calls this one.
CREATE DEFINER = 'vt_fixture'@'127.0.0.1' FUNCTION upper(x VARCHAR(255))
RETURNS VARCHAR(255) DETERMINISTIC MODIFIES SQL DATA SQL SECURITY INVOKER
BEGIN
  INSERT INTO audit_log (note) VALUES ('upper');
  RETURN x;
END//

DELIMITER ;

SHOW WARNINGS;
SELECT ROUTINE_NAME, DEFINER, SECURITY_TYPE, SQL_DATA_ACCESS, IS_DETERMINISTIC
FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA = 'validator_live_test' ORDER BY ROUTINE_NAME;
