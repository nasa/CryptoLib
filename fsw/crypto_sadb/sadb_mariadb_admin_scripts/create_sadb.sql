CREATE DATABASE IF NOT EXISTS sadb;

USE sadb;

CREATE TABLE security_associations
(
  sa_id INT NOT NULL
  ,ekid MEDIUMINT NOT NULL
  ,akid mediumint NOT NULL
  ,sa_state SMALLINT NOT NULL
  ,gvcid INT
  ,lpid SMALLINT
  ,est SMALLINT
  ,ast SMALLINT
  ,shivf_len SMALLINT
  ,shsnf_len SMALLINT
  ,shplf_len SMALLINT
  ,stmacf_len SMALLINT
  ,ecs_len SMALLINT
  ,ecs SMALLINT
  ,iv_len SMALLINT
  ,iv SMALLINT
  ,acs_len SMALLINT
  ,acs SMALLINT
  ,abm_len MEDIUMINT
  ,abm SMALLINT
  ,arc_len SMALLINT
  ,arc SMALLINT
  ,arcw_len SMALLINT
  ,arcw SMALLINT
);