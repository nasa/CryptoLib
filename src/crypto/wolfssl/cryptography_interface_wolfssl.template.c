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

// Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/version.h>

#include "crypto.h"
#include "crypto_error.h"
#include "cryptography_interface.h"


// Cryptography Interface Initialization & Management Functions
static int32_t cryptography_config(void);
static int32_t cryptography_init(void);
static int32_t cryptography_shutdown(void);
// Cryptography Interface Functions
static int32_t cryptography_encrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,uint8_t* ecs, uint8_t padding, char* cam_cookies);
static int32_t cryptography_decrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr, 
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* ecs, uint8_t* acs, char* cam_cookies);
static int32_t cryptography_authenticate(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs, char* cam_cookies);
static int32_t cryptography_validate_authentication(uint8_t* data_out, size_t len_data_out,
                                         const uint8_t* data_in, const size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         const uint8_t* iv, uint32_t iv_len,
                                         const uint8_t* mac, uint32_t mac_size,
                                         const uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs, char* cam_cookies);
static int32_t cryptography_aead_encrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t* ecs, uint8_t* acs, char* cam_cookies);
static int32_t cryptography_aead_decrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t* ecs, uint8_t* acs, char* cam_cookies);
static int32_t cryptography_get_acs_algo(int8_t algo_enum);
static int32_t cryptography_get_ecs_algo(int8_t algo_enum);

/*
** Module Variables
*/
// Cryptography Interface
static Aes enc;
static CryptographyInterfaceStruct cryptography_if_struct;

CryptographyInterface get_cryptography_interface_wolfssl(void)
{
    cryptography_if_struct.cryptography_config = cryptography_config;
    cryptography_if_struct.cryptography_init = cryptography_init;
    cryptography_if_struct.cryptography_shutdown = cryptography_shutdown;
    cryptography_if_struct.cryptography_encrypt = cryptography_encrypt;
    cryptography_if_struct.cryptography_decrypt = cryptography_decrypt;
    cryptography_if_struct.cryptography_authenticate = cryptography_authenticate;
    cryptography_if_struct.cryptography_validate_authentication = cryptography_validate_authentication;
    cryptography_if_struct.cryptography_aead_encrypt = cryptography_aead_encrypt;
    cryptography_if_struct.cryptography_aead_decrypt = cryptography_aead_decrypt;
    cryptography_if_struct.cryptography_get_acs_algo = cryptography_get_acs_algo;
    cryptography_if_struct.cryptography_get_ecs_algo = cryptography_get_ecs_algo;
    return &cryptography_if_struct;
}

static int32_t cryptography_config(void)
{
    return CRYPTO_LIB_SUCCESS;
}

static int32_t cryptography_init(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    
    // Initialize WolfSSL
    memset(&enc, 0, sizeof(Aes));
    status = wc_AesInit(&enc, NULL, -2);
    if (status < 0)
    {
        status = CRYPTOGRAPHY_LIBRARY_INITIALIZIATION_ERROR;
        printf(KRED "ERROR: wolfssl initialization failed\n" RESET);
    }

    return status;
}

static int32_t cryptography_shutdown(void)
{ 
    wc_AesFree(&enc);    
    return CRYPTO_LIB_SUCCESS; 
}

static int32_t cryptography_authenticate(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr, // For key index or key references (when key not passed in explicitly via key param)
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs, char* cam_cookies)
{ 
    int32_t status = CRYPTO_LIB_SUCCESS;
    //int32_t tmp;
    Hmac hmac;

    // Unused in this implementation
    cam_cookies = cam_cookies;
    ecs = ecs;
    iv = iv;
    iv_len = iv_len;
    len_data_out = len_data_out;
    mac_size = mac_size;
    sa_ptr = sa_ptr;

    // Need to copy the data over, since authentication won't change/move the data directly
    if(data_out != NULL)
    {
        memcpy(data_out, data_in, len_data_in);
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }

    switch (acs)
    {
        // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CMAC.html
        case CRYPTO_MAC_CMAC_AES256:
            /*
            Cmac cmac;
            status = wc_InitCmac(&cmac, key, len_key, WC_CMAC_AES, NULL);
            if (status == 0)
            {
                status = wc_CmacUpdate(&cmac, aad, aad_len);
            }
            if (status == 0)
            {
                status = wc_CmacUpdate(&cmac, data_in, len_data_in);
            }
            if (status == 0)
            {
                status = wc_CmacFinal(&cmac, mac, &tmp);
            }
            */
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
            break;

        // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__HMAC.html
        case CRYPTO_MAC_HMAC_SHA256:
            status = wc_HmacSetKey(&hmac, WC_SHA256, key, len_key);
            if (status == 0)
            {
                status = wc_HmacUpdate(&hmac, aad, aad_len);
            }
            if (status == 0)
            {
                status = wc_HmacUpdate(&hmac, data_in, len_data_in);
            }
            if (status == 0)
            {
                status = wc_HmacFinal(&hmac, mac);
            }
            break;

        case CRYPTO_MAC_HMAC_SHA512:
            status = wc_HmacSetKey(&hmac, WC_SHA512, key, len_key);
            if (status == 0)
            {
                status = wc_HmacUpdate(&hmac, aad, aad_len);
            }
            if (status == 0)
            {
                status = wc_HmacUpdate(&hmac, data_in, len_data_in);
            }
            if (status == 0)
            {
                status = wc_HmacFinal(&hmac, mac);
            }
            break;

        default:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
    }

    return status; 
}

static int32_t cryptography_validate_authentication(uint8_t* data_out, size_t len_data_out,
                                                    const uint8_t* data_in, const size_t len_data_in,
                                                    uint8_t* key, uint32_t len_key,
                                                    SecurityAssociation_t* sa_ptr,
                                                    const uint8_t* iv, uint32_t iv_len,
                                                    const uint8_t* mac, uint32_t mac_size,
                                                    const uint8_t* aad, uint32_t aad_len,
                                                    uint8_t ecs, uint8_t acs, char* cam_cookies)
{ 
    int32_t status = CRYPTO_LIB_SUCCESS;
    Hmac hmac;
    uint8_t calc_mac[mac_size];


    // Unused in this implementation
    cam_cookies = cam_cookies;
    ecs = ecs;
    iv = iv;
    iv_len = iv_len;
    sa_ptr = sa_ptr;

    // Need to copy the data over, since authentication won't change/move the data directly
    // If you don't want data out, don't set a data out length
    if(data_out != NULL)
    {
        memcpy(data_out, data_in, len_data_out);
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }

    switch (acs)
    {
        // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CMAC.html
        case CRYPTO_MAC_CMAC_AES256:
            /*
            Cmac cmac[1];
            status = wc_InitCmac(cmac, key, len_key, WC_CMAC_AES, NULL);
            if (status == 0)
            {
                status = wc_CmacUpdate(cmac, aad, aad_len);
            }
            if (status == 0)
            {
                status = wc_CmacUpdate(cmac, data_in, len_data_in);
            }
            if (status == 0)
            {
                status = wc_CmacFinal(cmac, calc_mac, &tmp);
            }
            */
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
            break;

        // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__HMAC.html
        case CRYPTO_MAC_HMAC_SHA256:
            status = wc_HmacSetKey(&hmac, WC_SHA256, key, len_key);
            if (status == 0)
            {
                status = wc_HmacUpdate(&hmac, aad, aad_len);
            }
            if (status == 0)
            {
                status = wc_HmacUpdate(&hmac, data_in, len_data_in);
            }
            if (status == 0)
            {
                status = wc_HmacFinal(&hmac, calc_mac);
            }
            break;

        case CRYPTO_MAC_HMAC_SHA512:
            status = wc_HmacSetKey(&hmac, WC_SHA512, key, len_key);
            if (status == 0)
            {
                status = wc_HmacUpdate(&hmac, aad, aad_len);
            }
            if (status == 0)
            {
                status = wc_HmacUpdate(&hmac, data_in, len_data_in);
            }
            if (status == 0)
            {
                status = wc_HmacFinal(&hmac, calc_mac);
            }
            break;

        default:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
    }

    // Compare calculated MAC to provided
    if (status == 0)
    {
        for(uint32_t i = 0; i < mac_size; i++)
        {
            if(calc_mac[i] != mac[i])
            {
                status = CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR;
            }
        }
    }

    return status; 
}

static int32_t cryptography_encrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,uint8_t* ecs, uint8_t padding, char* cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Unused in this implementation
    cam_cookies = cam_cookies;
    data_out = data_out;
    len_data_out = len_data_out;
    iv = iv;
    iv_len = iv_len;
    padding = padding;
    sa_ptr = sa_ptr;

    // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html
    switch (*ecs)
    {
        case CRYPTO_CIPHER_AES256_CBC:
            status = wc_AesSetKey(&enc, key, len_key, iv, AES_ENCRYPTION);
            if (status == 0)
            {
                status = wc_AesSetIV(&enc, iv);
            }
            if (status == 0)
            {
                status = wc_AesCbcEncrypt(&enc, data_out, data_in, len_data_in);
            }
            break;

        default:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
            break;
    }

    return status;
}

static int32_t cryptography_aead_encrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr, // For key index or key references (when key not passed in explicitly via key param)
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t* ecs, uint8_t* acs, char* cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Unused in this implementation
    acs = acs;
    cam_cookies = cam_cookies;
    len_data_out = len_data_out;
    aad = aad;
    aad_len = aad_len;
    encrypt_bool = encrypt_bool;
    authenticate_bool = authenticate_bool;
    aad_bool = aad_bool;
    sa_ptr = sa_ptr;

    // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html
    switch (*ecs)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            status = wc_AesGcmSetKey(&enc, key, len_key);
            if (status == 0)
            {
                status = wc_AesGcmEncrypt(&enc, data_out, data_in, len_data_in, iv, iv_len, mac, mac_size, aad, aad_len);
            }
            break;

        case CRYPTO_CIPHER_AES256_CCM:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
            break;

        default:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
            break;
    }

    return status;
}

static int32_t cryptography_decrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr, 
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* ecs, uint8_t* acs, char* cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    
    // Unused in this implementation
    acs = acs;
    cam_cookies = cam_cookies;
    len_data_out = len_data_out;
    iv_len = iv_len;
    sa_ptr = sa_ptr;

    // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html
    switch (*ecs)
    {
        case CRYPTO_CIPHER_AES256_CBC:
            status = wc_AesSetKey(&enc, key, len_key, iv, AES_DECRYPTION);
            if (status == 0)
            {
                status = wc_AesSetIV(&enc, iv);
            }
            if (status == 0)
            {
                status = wc_AesCbcDecrypt(&enc, data_out, data_in, len_data_in);
            }
            break;

        default:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
            break;
    }

    return status;
}

static int32_t cryptography_aead_decrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t* ecs, uint8_t* acs, char* cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    
    // Fix warnings
    acs = acs;
    cam_cookies = cam_cookies;
    len_data_out = len_data_out;
    aad = aad;
    aad_len = aad_len;
    decrypt_bool = decrypt_bool;
    authenticate_bool = authenticate_bool;
    aad_bool = aad_bool;
    sa_ptr = sa_ptr;

    // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html
    switch (*ecs)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            status = wc_AesGcmSetKey(&enc, key, len_key);
            if (status == 0)
            {
                status = wc_AesGcmDecrypt(&enc, data_out, data_in, len_data_in, iv, iv_len, mac, mac_size, NULL, 0);
            }
            break;

        case CRYPTO_CIPHER_AES256_CCM:
            // Intentional fall through to unsupported

        default:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
            break;
    }

    return status;
}

/**
 * @brief Function: cryptography_get_acs_algo
 * @param algo_enum
 **/
int32_t cryptography_get_acs_algo(int8_t algo_enum)
{
    int32_t algo = CRYPTO_LIB_ERR_UNSUPPORTED_ACS; 

    // Unused by WolfSSL, simply leverage same CryptoLib enums
    switch (algo_enum)
    {
        case CRYPTO_MAC_CMAC_AES256:
            algo = CRYPTO_MAC_CMAC_AES256;
            break;
        case CRYPTO_MAC_HMAC_SHA256:
            algo = CRYPTO_MAC_HMAC_SHA256;
            break;
        case CRYPTO_MAC_HMAC_SHA512:
            algo = CRYPTO_MAC_HMAC_SHA512;
            break;

        default:
#ifdef DEBUG
            printf("ACS Algo Enum not supported\n");
#endif
            break;
    }

    return (int)algo;
}

/**
 * @brief Function: cryptography_get_ecs_algo
 * @param algo_enum
 **/
int32_t cryptography_get_ecs_algo(int8_t algo_enum)
{
    int32_t algo = CRYPTO_LIB_ERR_UNSUPPORTED_ECS; 

    // Unused by WolfSSL, simply leverage same CryptoLib enums
    switch (algo_enum)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            algo = CRYPTO_CIPHER_AES256_GCM;
            break;
        case CRYPTO_CIPHER_AES256_CBC:
            algo = CRYPTO_CIPHER_AES256_CBC;
            break;
        case CRYPTO_CIPHER_AES256_CCM:
            algo = CRYPTO_CIPHER_AES256_CCM;
            break;

        default:
#ifdef DEBUG
            printf("Algo Enum not supported\n");
#endif
            break;
    }

    return (int)algo;
}
