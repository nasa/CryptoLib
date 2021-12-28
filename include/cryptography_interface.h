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

#ifndef CRYPTOLIB_CRYPTOGRAPHY_INTERFACE_H
#define CRYPTOLIB_CRYPTOGRAPHY_INTERFACE_H

#ifdef NOS3 // NOS3/cFS build is ready
#include "common_types.h"
#include "osapi.h"
#else // Assume build outside of NOS3/cFS infrastructure
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#endif


typedef struct
{
    // Cryptography Interface Initialization & Management Functions
    int32_t (*cryptography_config)(void);
    int32_t (*cryptography_init)(void);
    int32_t (*cryptography_close)(void);
    // Cryptography Interface Functions
    int32_t (*cryptography_encrypt)(void);
    int32_t (*cryptography_decrypt)(void);
    int32_t (*cryptography_authenticate)(void);
    int32_t (*cryptography_validate_authentication)(void);
    int32_t (*cryptography_aead_encrypt)(void);
    int32_t (*cryptography_aead_decrypt)(void);

} CryptographyInterfaceStruct, *CryptographyInterface;

CryptographyInterface get_cryptography_interface_libgcrypt(void);
CryptographyInterface get_cryptography_interface_kmc_crypto_service(void);

#endif // CRYPTOLIB_CRYPTOGRAPHY_INTERFACE_H
