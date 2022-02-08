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

static SadbRoutineStruct sadb_routine;

SadbRoutine get_sadb_routine_mariadb(void)
{
    fprintf(stderr,"ERROR: Loading mariadb stub source code. Rebuild CryptoLib with -DMYSQL=ON to use proper MariaDB implementation.\n");
    return &sadb_routine;
}