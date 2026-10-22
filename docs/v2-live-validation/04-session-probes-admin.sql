-- V2 live validation: session-state probe functions for case 4. SEPARATE
-- AUTHORISATION (same reasons as 03-functions-admin.sql).
--
-- Whether MySQL accepts SET TRANSACTION or setting transaction_read_only inside
-- a stored function is not stated in the manual's "Restrictions on Stored
-- Programs" page. Each CREATE is run on its own; an error is a result to
-- record, not a failure of the run. Neither function writes data.
--
-- Run as the administrator after 03-functions-admin.sql.

USE validator_live_test;

DELIMITER //

CREATE DEFINER = 'vt_fixture'@'127.0.0.1' FUNCTION flip()
RETURNS INT DETERMINISTIC NO SQL SQL SECURITY INVOKER
BEGIN
  SET SESSION TRANSACTION READ WRITE;
  RETURN 1;
END//

DELIMITER ;
SHOW WARNINGS;

DELIMITER //

CREATE DEFINER = 'vt_fixture'@'127.0.0.1' FUNCTION flip2()
RETURNS INT DETERMINISTIC NO SQL SQL SECURITY INVOKER
BEGIN
  SET @@SESSION.transaction_read_only = 0;
  RETURN 1;
END//

DELIMITER ;
SHOW WARNINGS;

SELECT ROUTINE_NAME FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA = 'validator_live_test' AND ROUTINE_NAME IN ('flip', 'flip2');
