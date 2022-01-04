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

#include "crypto_error.h"
#include "cryptography_interface.h"

#include <stdio.h>

// Cryptography Interface Initialization & Management Functions
static int32_t cryptography_config(void);
static int32_t cryptography_init(void);
static crypto_key_t* get_ek_ring(void);
static int32_t cryptography_shutdown(void);
// Cryptography Interface Functions
static int32_t cryptography_encrypt(void);
static int32_t cryptography_decrypt(void);
static int32_t cryptography_authenticate(void);
static int32_t cryptography_validate_authentication(void);
static int32_t cryptography_aead_encrypt(uint8_t* data_out, uint32_t len_data_out,
                                         uint8_t* data_in, uint32_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool);
static int32_t cryptography_aead_decrypt(uint8_t* data_out, uint32_t len_data_out,
                                         uint8_t* data_in, uint32_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool);
/*
** Global Variables
*/
// Cryptography Interface
static CryptographyInterfaceStruct cryptography_if_struct;

CryptographyInterface get_cryptography_interface_kmc_crypto_service(void)
{
    cryptography_if_struct.cryptography_config = cryptography_config;
    cryptography_if_struct.cryptography_init = cryptography_init;
    cryptography_if_struct.get_ek_ring = get_ek_ring;
    cryptography_if_struct.cryptography_shutdown = cryptography_shutdown;
    cryptography_if_struct.cryptography_encrypt = cryptography_encrypt;
    cryptography_if_struct.cryptography_decrypt = cryptography_decrypt;
    cryptography_if_struct.cryptography_authenticate = cryptography_authenticate;
    cryptography_if_struct.cryptography_validate_authentication = cryptography_validate_authentication;
    cryptography_if_struct.cryptography_aead_encrypt = cryptography_aead_encrypt;
    cryptography_if_struct.cryptography_aead_decrypt = cryptography_aead_decrypt;
    return &cryptography_if_struct;
}

static int32_t cryptography_config(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_init(void){ return CRYPTO_LIB_SUCCESS; }
static crypto_key_t* get_ek_ring(void){ return NULL; }
static int32_t cryptography_shutdown(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_encrypt(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_decrypt(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_authenticate(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_validate_authentication(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_aead_encrypt(uint8_t* data_out, uint32_t len_data_out,
                                         uint8_t* data_in, uint32_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool)
{
    data_out = data_out;
    len_data_out = len_data_out;
    data_in = data_in;
    len_data_in = len_data_in;
    key = key;
    len_key = len_key;
    sa_ptr = sa_ptr;
    iv = iv;
    iv_len = iv_len;
    mac = mac;
    mac_size = mac_size;
    aad = aad;
    aad_len = aad_len;
    encrypt_bool = encrypt_bool;
    authenticate_bool = authenticate_bool;
    aad_bool = aad_bool;
    return CRYPTO_LIB_SUCCESS;
}
static int32_t cryptography_aead_decrypt(uint8_t* data_out, uint32_t len_data_out,
                                         uint8_t* data_in, uint32_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool)
{
    data_out = data_out;
    len_data_out = len_data_out;
    data_in = data_in;
    len_data_in = len_data_in;
    key = key;
    len_key = len_key;
    sa_ptr = sa_ptr;
    iv = iv;
    iv_len = iv_len;
    mac = mac;
    mac_size = mac_size;
    aad = aad;
    aad_len = aad_len;
    decrypt_bool = decrypt_bool;
    authenticate_bool = authenticate_bool;
    aad_bool = aad_bool;
    return CRYPTO_LIB_SUCCESS;
}
