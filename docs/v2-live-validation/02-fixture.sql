-- V2 live validation: fixture tables and rows.
-- Run as vt_fixture:  mysql -h 127.0.0.1 -P 3306 -u vt_fixture -p validator_live_test
-- If any statement fails, stop and run 90-cleanup-admin.sql (as the administrator).

USE validator_live_test;

-- users: keys whose row scope the validator should be able to verify.
-- Codes differ within their first 10 characters, so the 10-character prefix
-- unique key accepts them; each code is 11 characters, so the key is a true
-- prefix of the value.
CREATE TABLE users (
  id          INT PRIMARY KEY,
  tenant_id   INT NOT NULL,
  ref         VARCHAR(20) NOT NULL,
  email       VARCHAR(100) NULL,
  code        VARCHAR(255) NOT NULL,
  customer_id INT NOT NULL,
  status      VARCHAR(10) NOT NULL,
  UNIQUE KEY uq_tenant_ref (tenant_id, ref),
  UNIQUE KEY uq_email (email),
  UNIQUE KEY uq_code_prefix (code(10)),
  KEY idx_customer (customer_id)
);
INSERT INTO users VALUES
  (1, 1, 'a', 'a@example.test', 'c01-0000001', 10, 'open'),
  (2, 1, 'b', NULL,             'c02-0000002', 10, 'open'),
  (3, 2, 'a', NULL,             'c03-0000003', 11, 'closed');

-- users_fx: a primary key plus a functional unique index (MySQL 8.0.13+).
-- Kept separate because the validator currently treats a table that has a
-- functional key part as having ineligible index metadata (see case 5).
CREATE TABLE users_fx (
  id    INT PRIMARY KEY,
  email VARCHAR(100) NULL,
  UNIQUE KEY uq_lower_email ((LOWER(email)))
);
INSERT INTO users_fx VALUES (1, 'A@example.test'), (2, NULL), (3, NULL);

-- audit_log: trace table written only by the case 3 functions. Separate from
-- users because a stored function cannot modify a table the calling
-- statement is using (MySQL "Restrictions on Stored Programs").
CREATE TABLE audit_log (
  id   INT AUTO_INCREMENT PRIMARY KEY,
  note VARCHAR(50) NOT NULL
);

-- Expected initial state: 3, 3, 0.
SELECT (SELECT COUNT(*) FROM users)     AS users_rows,
       (SELECT COUNT(*) FROM users_fx)  AS users_fx_rows,
       (SELECT COUNT(*) FROM audit_log) AS audit_rows;
-- Keep this output: case 2(d) and the end-of-run check compare against it.
SELECT * FROM users ORDER BY id;
