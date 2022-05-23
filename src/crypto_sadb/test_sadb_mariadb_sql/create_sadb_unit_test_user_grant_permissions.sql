DROP USER IF EXISTS 'sadb_admin';
DROP USER IF EXISTS 'sadb_user';

CREATE USER IF NOT EXISTS sadb_admin IDENTIFIED BY 'sadb_admin_password';
CREATE USER IF NOT EXISTS sadb_user IDENTIFIED BY 'sadb_password';

GRANT ALL PRIVILEGES ON sadb.* TO 'sadb_admin'@'%';

GRANT UPDATE (arsn) ON sadb.security_associations TO 'sadb_user'@'%';
GRANT UPDATE (iv) ON sadb.security_associations TO 'sadb_user'@'%';
GRANT SELECT ON sadb.security_associations TO 'sadb_user'@'%';