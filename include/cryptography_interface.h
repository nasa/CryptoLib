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

#include "crypto_structs.h"

typedef struct
{
    // Cryptography Interface Initialization & Management Functions
    int32_t (*cryptography_config)(void);
    int32_t (*cryptography_init)(void);
    crypto_key_t* (*get_ek_ring)(void);
    int32_t (*cryptography_shutdown)(void);
    // Cryptography Interface Functions
    int32_t (*cryptography_encrypt)(void);
    int32_t (*cryptography_decrypt)(void);
    int32_t (*cryptography_authenticate)(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr, // For key index or key references (when key not passed in explicitly via key param)
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs);
    int32_t (*cryptography_validate_authentication)(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs);
    int32_t (*cryptography_aead_encrypt)(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t* ecs, uint8_t* acs);
    int32_t (*cryptography_aead_decrypt)(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t* ecs, uint8_t* acs);
    int32_t (*cryptography_get_acs_algo)(int8_t algo_enum);
    int32_t (*cryptography_get_ecs_algo)(int8_t algo_enum);

} CryptographyInterfaceStruct, *CryptographyInterface;

CryptographyInterface get_cryptography_interface_libgcrypt(void);
CryptographyInterface get_cryptography_interface_kmc_crypto_service(void);

#endif // CRYPTOLIB_CRYPTOGRAPHY_INTERFACE_H
