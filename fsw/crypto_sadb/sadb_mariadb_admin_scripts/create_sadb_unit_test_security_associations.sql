USE sadb;

-- SA 1 - CLEAR MODE
INSERT INTO security_associations (spi,sa_state,est,ast,arc_len,arc,arcw_len,arcw,tfvn,scid,vcid,mapid)
VALUES (1,3,0,0,1,0,1,5,0,3,0,0);

-- SA 2 - KEYED;  ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: 128
INSERT INTO security_associations (spi,ekid,sa_state,est,ast,shivf_len,iv_len,iv,abm_len,abm,arcw_len,arcw,arc_len)
VALUES (2,128,2,1,1,12,12,0,20,0,1,5,11);

-- SA 3 - KEYED;   ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: 129
INSERT INTO security_associations (spi,ekid,sa_state,est,ast,shivf_len,stmacf_len,iv_len,iv,abm_len,abm,arcw_len,arcw,arc_len)
VALUES (3,129,2,1,1,12,16,12,0,20,0,1,5,11);

-- SA 4 - KEYED;  ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: 130
INSERT INTO security_associations (spi,ekid,sa_state,est,ast,shivf_len,iv_len,iv,abm_len,abm,arcw_len,arcw,arc_len,tfvn,scid,vcid,mapid)
VALUES (4,130,2,1,1,12,12,0,20,0,1,5,11,0,3,0,0);

-- SA 5 - KEYED;   ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: 131
INSERT INTO security_associations (spi,ekid,sa_state,est,ast,shivf_len,iv_len,iv,abm_len,abm,arcw_len,arcw,arc_len)
VALUES (5,131,2,1,1,12,12,0,20,0,1,5,11);

-- SA 6 - UNKEYED; ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: -
INSERT INTO security_associations (spi,sa_state,est,ast,shivf_len,iv_len,iv,abm_len,abm,arcw_len,arcw,arc_len)
VALUES (6,1,1,1,12,12,0,20,0,1,5,11);

-- SA 7 - KEYED;  ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: 130
INSERT INTO security_associations (spi,ekid,sa_state,est,ast,shivf_len,iv_len,iv,abm_len,abm,arcw_len,arcw,arc_len,tfvn,scid,vcid,mapid)
VALUES (7,130,2,1,1,12,12,0,20,0,1,5,11,0,3,1,0);

-- SA 8 - CLEAR MODE
INSERT INTO security_associations (spi,sa_state,est,ast,arc_len,arc,arcw_len,arcw,tfvn,scid,vcid,mapid)
VALUES (8,3,0,0,1,0,1,5,0,3,1,0);
