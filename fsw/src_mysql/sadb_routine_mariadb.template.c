/*
 * Copyright 2021, by the California Institute of Technology.
 * ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
 * Any commercial use must be negotiated with the Office of Technology
 * Transfer at the California Institute of Technology.
 *
 * This software may be subject to U.S. export control laws. By accepting
 * this software, the user agrees to comply with all applicable U.S.
 * export laws and regulations. User has the responsibility to obtain
 * export licenses, or other export authority as may be required before
 * exporting such information to foreign countries or providing access to
 * foreign persons.
 */

#include "sadb_routine.h"
#include "crypto_structs.h"
#include "crypto_config.h"
#include "crypto_error.h"
#include "crypto_print.h"

#include <mysql/mysql.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Security Association Initialization Functions
static int32 sadb_config(void);
static int32 sadb_init(void);
static int32 sadb_close(void);
// Security Association Interaction Functions
static int32 sadb_get_sa_from_spi(uint16,SecurityAssociation_t**);
static int32 sadb_get_operational_sa_from_gvcid(uint8,uint16,uint16,uint8,SecurityAssociation_t**);
static int32 sadb_save_sa(SecurityAssociation_t* sa);
// Security Association Utility Functions
static int32 sadb_sa_start(TC_t* tc_frame);
static int32 sadb_sa_expire(void);
static int32 sadb_sa_rekey(void);
static int32 sadb_sa_status(char*);
static int32 sadb_sa_create(void);
static int32 sadb_sa_setARSN(void);
static int32 sadb_sa_setARSNW(void);
static int32 sadb_sa_delete(void);
//MySQL local functions
static int32 finish_with_error(MYSQL *con,int err);
//MySQL Queries
const static char* SQL_SADB_GET_SA_BY_SPI = "SELECT * FROM security_associations WHERE spi='%d';";
const static char* SQL_SADB_GET_SA_BY_GVCID = "SELECT * FROM security_associations WHERE tfvn='%d' AND scid='%d' AND vcid='%d' AND mapid='%d';";
const static char* SQL_SADB_UPDATE_IV_ARC_BY_SPI = "UPDATE security_associations "\
                                                        "SET iv='%d', arc='%d' "  \
                                                        "WHERE spi='%d'AND tfvn='%d' AND scid='%d' AND vcid='%d' AND mapid='%d';";

// sadb_routine mariaDB private helper functions
static int32 parse_sa_from_mysql_query(char* query, SecurityAssociation_t** security_association);


/*
** Global Variables
*/
// Security
static SadbRoutineStruct sadb_routine;
static SecurityAssociation_t sa[NUM_SA];
static MYSQL* con;

SadbRoutine get_sadb_routine_mariadb(void)
{
    sadb_routine.sadb_config = sadb_config;
    sadb_routine.sadb_init = sadb_init;
    sadb_routine.sadb_get_sa_from_spi = sadb_get_sa_from_spi;
    sadb_routine.sadb_get_operational_sa_from_gvcid = sadb_get_operational_sa_from_gvcid;
    sadb_routine.sadb_save_sa = sadb_save_sa;
    sadb_routine.sadb_sa_start = sadb_sa_start;
    sadb_routine.sadb_sa_expire = sadb_sa_expire;
    sadb_routine.sadb_sa_rekey = sadb_sa_rekey;
    sadb_routine.sadb_sa_status = sadb_sa_status;
    sadb_routine.sadb_sa_create = sadb_sa_create;
    sadb_routine.sadb_sa_setARSN = sadb_sa_setARSN;
    sadb_routine.sadb_sa_setARSNW = sadb_sa_setARSNW;
    sadb_routine.sadb_sa_delete = sadb_sa_delete;
    return &sadb_routine;
}

static int32 sadb_config(void)
{
    return OS_SUCCESS;
}

static int32 sadb_init(void)
{
    int32 status = OS_SUCCESS;
    con = mysql_init(NULL);

    //TODO - add mysql_options/mysql_get_ssl_cipher logic for mTLS connections.

    if (mysql_real_connect(con, MYSQL_HOST, MYSQL_USER, MYSQL_PASS, MYSQL_DB, MYSQL_PORT, NULL, 0) == NULL)
    { //0,NULL,0 are port number, unix socket, client flag
        status = finish_with_error(con,SADB_MARIADB_CONNECTION_FAILED);
    }

    return status;
}

static int32 sadb_close(void)
{
    mysql_close(con);
    return OS_SUCCESS;
}

// Security Association Interaction Functions
static int32 sadb_get_sa_from_spi(uint16 spi,SecurityAssociation_t** security_association)
{
    int32 status = OS_SUCCESS;

    char spi_query[2048];
    snprintf(spi_query, sizeof(spi_query),SQL_SADB_GET_SA_BY_SPI,spi);

    status = parse_sa_from_mysql_query(&spi_query[0],security_association);

    return status;
}
static int32 sadb_get_operational_sa_from_gvcid(uint8 tfvn,uint16 scid,uint16 vcid,uint8 mapid,SecurityAssociation_t** security_association)
{
    int32 status = OS_SUCCESS;

    char gvcid_query[2048];
    snprintf(gvcid_query, sizeof(gvcid_query),SQL_SADB_GET_SA_BY_GVCID,tfvn,scid,vcid,mapid);

    status = parse_sa_from_mysql_query(&gvcid_query[0],security_association);

    return status;
}
static int32 sadb_save_sa(SecurityAssociation_t* sa)
{
    int32 status = OS_SUCCESS;

    char gvcid_query[2048];
    snprintf(gvcid_query, sizeof(gvcid_query),SQL_SADB_UPDATE_IV_ARC_BY_SPI,sa->iv,sa->arc,sa->spi,sa->gvcid_tc_blk.tfvn,sa->gvcid_tc_blk.scid,sa->gvcid_tc_blk.vcid,sa->gvcid_tc_blk.mapid);

    Crypto_saPrint(sa);
    if(mysql_query(con,gvcid_query)) {
        status = finish_with_error(con,SADB_QUERY_FAILED); return status;
    }
    // todo - if query fails, need to push failure message to error stack instead of just return code.

    //We free the allocated SA memory in the save function.
    free(sa);
    return status;
}
// Security Association Utility Functions
static int32 sadb_sa_start(TC_t* tc_frame){return OS_SUCCESS;}
static int32 sadb_sa_expire(void){return OS_SUCCESS;}
static int32 sadb_sa_rekey(void){return OS_SUCCESS;}
static int32 sadb_sa_status(char* ingest){return OS_SUCCESS;}
static int32 sadb_sa_create(void){return OS_SUCCESS;}
static int32 sadb_sa_setARSN(void){return OS_SUCCESS;}
static int32 sadb_sa_setARSNW(void){return OS_SUCCESS;}
static int32 sadb_sa_delete(void){return OS_SUCCESS;}

// sadb_routine private helper functions
static int32 parse_sa_from_mysql_query(char* query, SecurityAssociation_t** security_association)
{
    int32 status = OS_SUCCESS;
    SecurityAssociation_t* sa = malloc(sizeof(SecurityAssociation_t));

    if(mysql_query(con,query)) {
        status = finish_with_error(con,SADB_QUERY_FAILED); return status;
    }
    // todo - if query fails, need to push failure message to error stack instead of just return code.

    MYSQL_RES *result = mysql_store_result(con);
    if(result == NULL) {
        status = finish_with_error(con,SADB_QUERY_EMPTY_RESULTS); return status;
    }

    int num_fields = mysql_num_fields(result);

    MYSQL_ROW row;
    MYSQL_FIELD *field;

    char *field_names[num_fields]; //[64]; 64 == max length of column name in MySQL


    while((row = mysql_fetch_row(result))){
        for(int i=0; i < num_fields; i++)
        {
            //Parse out all the field names.
            if(i == 0){
                int field_idx = 0;
                while(field = mysql_fetch_field(result)){
                    field_names[field_idx] = field->name;
                    field_idx++;
                }
            }
            //Handle query results
            int spi;
            uint8 tmp_uint8;
            if(row[i]==NULL){continue;} //Don't do anything with NULL fields from MySQL query.
            if(strcmp(field_names[i],"spi")==0){sa->spi = atoi(row[i]);continue;}
            if(strcmp(field_names[i],"ekid")==0){sa->ekid=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"akid")==0){sa->akid=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"sa_state")==0){sa->sa_state=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"tfvn")==0){sa->gvcid_tc_blk.tfvn=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"scid")==0){sa->gvcid_tc_blk.scid=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"vcid")==0){sa->gvcid_tc_blk.vcid=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"mapid")==0){sa->gvcid_tc_blk.mapid=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"lpid")==0){sa->lpid=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"est")==0){sa->est=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"ast")==0){sa->ast=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"shivf_len")==0){sa->shivf_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"shsnf_len")==0){sa->shsnf_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"shplf_len")==0){sa->shplf_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"stmacf_len")==0){sa->stmacf_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"ecs_len")==0){sa->ecs_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"ecs")==0){tmp_uint8 = (uint8)atoi(row[i]); memcpy(&(sa->ecs),&tmp_uint8,sizeof(tmp_uint8));continue;}
            if(strcmp(field_names[i],"iv_len")==0){sa->iv_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"iv")==0){memcpy(&(sa->iv),&row[i],sizeof(row[i]));continue;}
            if(strcmp(field_names[i],"acs_len")==0){sa->acs_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"acs")==0){sa->acs=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"abm_len")==0){sa->abm_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"abm")==0){tmp_uint8 = (uint8)atoi(row[i]);memcpy(&(sa->abm),&tmp_uint8,sizeof(tmp_uint8));continue;}
            if(strcmp(field_names[i],"arc_len")==0){sa->arc_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"arc")==0){memcpy(&(sa->arc),&row[i],sizeof(row[i]));continue;}
            if(strcmp(field_names[i],"arcw_len")==0){sa->arcw_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"arcw")==0){tmp_uint8 = (uint8)atoi(row[i]);memcpy(&(sa->arcw),&tmp_uint8,sizeof(tmp_uint8));continue;}
            //printf("%s:%s ",field_names[i], row[i] ? row[i] : "NULL");
        }
        //printf("\n");
    }

    *security_association = sa;
    mysql_free_result(result);

    return status;
}

static int32 finish_with_error(MYSQL *con, int err)
{
    fprintf(stderr, "%s\n", mysql_error(con));
    mysql_close(con);
    return err;
}