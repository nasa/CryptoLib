DROP USER IF EXISTS 'sa_admin';
DROP USER IF EXISTS 'sa_user';

CREATE USER IF NOT EXISTS sa_admin IDENTIFIED BY 'sa_admin_password';
CREATE USER IF NOT EXISTS sa_user IDENTIFIED BY 'sa_password';

GRANT ALL PRIVILEGES ON sadb.* TO 'sa_admin'@'%';

GRANT UPDATE (arsn) ON sadb.security_associations TO 'sa_user'@'%';
GRANT UPDATE (iv) ON sadb.security_associations TO 'sa_user'@'%';
GRANT SELECT ON sadb.security_associations TO 'sa_user'@'%';