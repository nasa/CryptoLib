CREATE DATABASE IF NOT EXISTS sadb;

USE sadb;

-- IV_LEN should probably not have that default -- to be reviewed.

CREATE TABLE security_associations
(
  sa_id INT NOT NULL
  ,ekid MEDIUMINT NOT NULL DEFAULT sa_id
  ,akid MEDIUMINT NOT NULL DEFAULT sa_id
  ,sa_state SMALLINT NOT NULL DEFAULT 0
  ,tfvn TINYINT
  ,scid SMALLINT
  ,vcid TINYINT
  ,mapid TINYINT
  ,lpid SMALLINT
  ,est SMALLINT
  ,ast SMALLINT
  ,shivf_len SMALLINT
  ,shsnf_len SMALLINT
  ,shplf_len SMALLINT
  ,stmacf_len SMALLINT
  ,ecs_len SMALLINT
  ,ecs SMALLINT NOT NULL DEFAULT 0
  ,iv_len SMALLINT NOT NULL DEFAULT 12
  ,iv SMALLINT
  ,acs_len SMALLINT NOT NULL DEFAULT 0
  ,acs SMALLINT NOT NULL DEFAULT 0
  ,abm_len MEDIUMINT
  ,abm SMALLINT
  ,arc_len SMALLINT NOT NULL DEFAULT 0
  ,arc SMALLINT NOT NULL DEFAULT 5
  ,arcw_len SMALLINT
  ,arcw SMALLINT
);