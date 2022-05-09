USE sadb;

-- SCID 44 (MMT) Security Associations AES/GCM/NoPadding --
-- SA 1 - OPERATIONAL; ENC + AUTH - ARSNW:5; AES-GCM; IV:00...01; IV-len:12; MAC-len:16; Key-ID: 130, SCID 44, VC-0
INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid)
VALUES (1,'itc/test/key1',3,X'01',1,1,12,12,16,X'000000000000000000000001',19,X'00000000000000000000000000000000000000',5,0,0,44,0,0);

-- SA 2 - OPERATIONAL; ENC; ARSNW:5; AES-GCM; IV:00...01; IV-len:12; MAC-len:16; Key-ID: 130, SCID 44, VC-0
INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid)
VALUES (2,'itc/test/key2',3,X'01',1,0,12,12,16,X'000000000000000000000001',19,X'00000000000000000000000000000000000000',5,0,0,3,0,0);

-- SA 3 - OPERATIONAL; ENC; ARSNW:5; AES-GCM; IV:00...01; IV-len:12; MAC-len:16; Key-ID: 130, SCID 44, VC-0
INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid)
VALUES (3,'itc/test/key3',3,X'01',1,1,12,12,16,X'000000000000000000000001',20,X'0000000000000000000000000000000000000000',5,0,0,3,1,0);

-- SA 4 - OPERATIONAL; ENC; ARSNW:5; AES-GCM; IV:00...01; IV-len:12; MAC-len:16; Key-ID: 130, SCID 44, VC-0
INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid)
VALUES (4,'itc/test/key4',3,X'01',1,1,6,12,16,X'000000000000FFFFFFFFFFFC',20,X'0000000000000000000000000000000000000000',5,0,0,3,2,0);

-- SA 5 - OPERATIONAL; ENC; ARSNW:5; AES-GCM; IV:00...01; IV-len:12; MAC-len:16; Key-ID: 130, SCID 44, VC-0              
INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,arsn,tfvn,scid,vcid,mapid,ecs_len,acs_len,acs,shsnf_len)
VALUES (5,'itc/test/key5',3,X'01',0,1,12,12,16,X'000000000000000000000001',36,X'000000000000000000000000000000000000000000000000000000000000000000000000',5,3,X'05FFFC',0,3,3,0,1,1,X'01',2);
