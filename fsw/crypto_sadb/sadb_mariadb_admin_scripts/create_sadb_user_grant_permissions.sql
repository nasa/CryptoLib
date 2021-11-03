Create User IF NOT EXISTS sadb_user IDENTIFIED BY 'sadb_password';

GRANT ALL PRIVILEGES ON sadb.* TO 'sadb_user' @ '%';