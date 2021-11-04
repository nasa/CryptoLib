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
const static char* SQL_SADB_GET_SA_BY_SPI = "SELECT * FROM security_associations WHERE sa_id='%d'";


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

    SecurityAssociation_t* sa = malloc(sizeof(SecurityAssociation_t));

    char spi_query[2048];
    snprintf(spi_query, sizeof(spi_query),SQL_SADB_GET_SA_BY_SPI,spi);
    if(mysql_query(con,spi_query)) { status = finish_with_error(con,SADB_QUERY_BY_SPI_FAILED); }

    MYSQL_RES *result = mysql_store_result(con);
    if(result == NULL) { status = finish_with_error(con,SADB_QUERY_BY_SPI_EMPTY_RESULTS); }

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
            int sa_id;
            uint8 tmp_uint8;
            if(row[i]==NULL){continue;} //Don't do anything with NULL fields from MySQL query.
            if(strcmp(field_names[i],"sa_id")==0){sa_id = atoi(row[i]);continue;}
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
            if(strcmp(field_names[i],"iv")==0){tmp_uint8 =(uint8) atoi(row[i]); memcpy(&(sa->iv),&tmp_uint8,sizeof(tmp_uint8));continue;}
            if(strcmp(field_names[i],"acs_len")==0){sa->acs_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"acs")==0){sa->acs=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"abm_len")==0){sa->abm_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"abm")==0){tmp_uint8 = (uint8)atoi(row[i]);memcpy(&(sa->abm),&tmp_uint8,sizeof(tmp_uint8));continue;}
            if(strcmp(field_names[i],"arc_len")==0){sa->arc_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"arc")==0){tmp_uint8 = (uint8)atoi(row[i]);memcpy(&(sa->arc),&tmp_uint8,sizeof(tmp_uint8));continue;}
            if(strcmp(field_names[i],"arcw_len")==0){sa->arcw_len=atoi(row[i]);continue;}
            if(strcmp(field_names[i],"arcw")==0){tmp_uint8 = (uint8)atoi(row[i]);memcpy(&(sa->arcw),&tmp_uint8,sizeof(tmp_uint8));continue;}
            //printf("%s:%s ",field_names[i], row[i] ? row[i] : "NULL");
        }
        printf("\n");
    }

    *security_association = sa;
    mysql_free_result(result);
    //set all the SA fields from the query results.
    //*security_association.vcid =

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


static int32 finish_with_error(MYSQL *con, int err)
{
    fprintf(stderr, "%s\n", mysql_error(con));
    mysql_close(con);
    return err;
}