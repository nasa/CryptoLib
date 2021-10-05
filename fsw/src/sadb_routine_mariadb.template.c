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

// Security Association Initialization Functions
static int32 sadb_config(void);
static int32 sadb_init(void);
// Security Association Interaction Functions
static int32 sadb_get_sa_from_spi(uint16,SecurityAssociation_t**);
// Security Association Utility Functions
static int32 sadb_sa_start(void);
static int32 sadb_sa_expire(void);
static int32 sadb_sa_rekey(void);
static int32 sadb_sa_status(char*);
static int32 sadb_sa_create(void);
static int32 sadb_sa_setARSN(void);
static int32 sadb_sa_setARSNW(void);
static int32 sadb_sa_delete(void);


/*
** Global Variables
*/
// Security
static SadbRoutineStruct sadb_routine;
static SecurityAssociation_t sa[NUM_SA];

static crypto_key_t ek_ring[NUM_KEYS];


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

int32 sadb_config(void){return 0;}
int32 sadb_init(void){return 0;}
// Security Association Interaction Functions
int32 sadb_get_sa_from_spi(uint16 spi,SecurityAssociation_t** security_association){return 0;}
// Security Association Utility Functions
int32 sadb_sa_start(void){return 0;}
int32 sadb_sa_expire(void){return 0;}
int32 sadb_sa_rekey(void){return 0;}
int32 sadb_sa_status(char* ingest){return 0;}
int32 sadb_sa_create(void){return 0;}
int32 sadb_sa_setARSN(void){return 0;}
int32 sadb_sa_setARSNW(void){return 0;}
int32 sadb_sa_delete(void){return 0;}
