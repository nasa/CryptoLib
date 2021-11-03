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

static int32 sadb_close(void){return OS_SUCCESS;};

// Security Association Interaction Functions
static int32 sadb_get_sa_from_spi(uint16 spi,SecurityAssociation_t** security_association){return OS_SUCCESS;}
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