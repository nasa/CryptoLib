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
static int32_t cryptography_close(void);
// Cryptography Interface Functions
static int32_t cryptography_encrypt(void);
static int32_t cryptography_decrypt(void);
static int32_t cryptography_authenticate(void);
static int32_t cryptography_validate_authentication(void);
static int32_t cryptography_aead_encrypt(void);
static int32_t cryptography_aead_decrypt(void);
/*
** Global Variables
*/
// Cryptography Interface
static CryptographyInterfaceStruct cryptography_if;

CryptographyInterface get_cryptography_interface_libgcrypt(void)
{
    cryptography_if.cryptography_config = cryptography_config;
    cryptography_if.cryptography_init = cryptography_init;
    cryptography_if.cryptography_close = cryptography_close;
    cryptography_if.cryptography_encrypt = cryptography_encrypt;
    cryptography_if.cryptography_decrypt = cryptography_decrypt;
    cryptography_if.cryptography_authenticate = cryptography_authenticate;
    cryptography_if.cryptography_validate_authentication = cryptography_validate_authentication;
    cryptography_if.cryptography_aead_encrypt = cryptography_aead_encrypt;
    cryptography_if.cryptography_aead_decrypt = cryptography_aead_decrypt;
    return &cryptography_if;
}

static int32_t cryptography_config(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_init(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_close(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_encrypt(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_decrypt(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_authenticate(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_validate_authentication(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_aead_encrypt(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_aead_decrypt(void){ return CRYPTO_LIB_SUCCESS; }
