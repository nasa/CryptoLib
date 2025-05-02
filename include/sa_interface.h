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

#ifndef CRYPTOLIB_SA_INTERFACE_H
#define CRYPTOLIB_SA_INTERFACE_H

#ifdef NOS3 // NOS3/cFS build is ready
#include "common_types.h"
#include "osapi.h"
#else // Assume build outside of NOS3/cFS infrastructure
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include "crypto_structs.h"

typedef struct
{
    // Security Association Initialization & Management Functions
    int32_t (*sa_config)(void);
    int32_t (*sa_init)(void);
    int32_t (*sa_close)(void);
    // Security Association Interaction Functions
    int32_t (*sa_get_from_spi)(uint16_t, SecurityAssociation_t **);
    int32_t (*sa_get_operational_sa_from_gvcid)(uint8_t, uint16_t, uint16_t, uint8_t, SecurityAssociation_t **);
    int32_t (*sa_save_sa)(SecurityAssociation_t *);
    // Security Association Utility Functions
    int32_t (*sa_stop)(TC_t *tc_frame);
    int32_t (*sa_start)(TC_t *tc_frame);
    int32_t (*sa_expire)(TC_t *tc_frame);
    int32_t (*sa_rekey)(TC_t *tc_frame);
    int32_t (*sa_status)(uint8_t *);
    int32_t (*sa_create)(TC_t *tc_frame);
    int32_t (*sa_setARSN)(TC_t *tc_frame);
    int32_t (*sa_setARSNW)(TC_t *tc_frame);
    int32_t (*sa_delete)(TC_t *tc_frame);

} SaInterfaceStruct, *SaInterface;

SaInterface get_sa_interface_custom(void);
SaInterface get_sa_interface_inmemory(void);
SaInterface get_sa_interface_mariadb(void);

#endif // CRYPTOLIB_SA_INTERFACE_H
