USE sadb;

select spi,ekid,akid,sa_state,tfvn,scid,vcid,mapid,est,ast,shivf_len,shsnf_len,shplf_len,stmacf_len,ecs_len,HEX(ecs),iv_len,HEX(iv),acs_len,HEX(acs),abm_len,arsn_len,HEX(arsn),arsnw from security_associations;
