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
#include <wolfssl/ssl.h>
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
    if (LIBWOLFSSL_VERSION_HEX != wolfSSL_lib_version_hex())
    {
        status = CRYPTOGRAPHY_LIBRARY_INITIALIZIATION_ERROR;
        printf(KRED "ERROR: wolfssl version mismatch!\n" RESET);
    }

    return status;
}

static int32_t cryptography_shutdown(void)
{ 
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
    Cmac cmac;
    Hmac hmac;
    uint8_t calc_mac[64];

    // Unused in this implementation
    cam_cookies = cam_cookies;
    ecs = ecs;
    iv = iv;
    iv_len = iv_len;
    len_data_out = len_data_out;
    mac_size = mac_size;
    sa_ptr = sa_ptr;

    #ifdef DEBUG
        printf("cryptography_authenticate \n");
    #endif

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
            status = wc_InitCmac(&cmac, key, len_key, WC_CMAC_AES, NULL);
            if (status == 0)
            {
                status = wc_CmacUpdate(&cmac, aad, aad_len);
            }
            // Commented out for now while assessing unit tests
            //if (status == 0)
            //{
            //    status = wc_CmacUpdate(&cmac, data_in, len_data_in);
            //}
            if (status == 0)
            {
                status = wc_CmacFinal(&cmac, mac, &mac_size);
            }
            break;

        // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__HMAC.html
        case CRYPTO_MAC_HMAC_SHA256:
            status = wc_HmacSetKey(&hmac, WC_SHA256, key, len_key);
            if (status == 0)
            {
                status = wc_HmacUpdate(&hmac, aad, aad_len);
            }
            // Commented out for now while assessing unit tests
            //if (status == 0)
            //{
            //    status = wc_HmacUpdate(&hmac, data_in, len_data_in);
            //}
            if (status == 0)
            {
                status = wc_HmacFinal(&hmac, calc_mac);
            }
            if (status == 0)
            {
                memcpy(mac, calc_mac, mac_size);
            }
            break;

        case CRYPTO_MAC_HMAC_SHA512:
            status = wc_HmacSetKey(&hmac, WC_SHA512, key, len_key);
            if (status == 0)
            {
                status = wc_HmacUpdate(&hmac, aad, aad_len);
            }
            // Commented out for now while assessing unit tests
            //if (status == 0)
            //{
            //    status = wc_HmacUpdate(&hmac, data_in, len_data_in);
            //}
            if (status == 0)
            {
                status = wc_HmacFinal(&hmac, calc_mac);
            }
            if (status == 0)
            {
                memcpy(mac, calc_mac, mac_size);
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
    Cmac cmac;
    Hmac hmac;
    uint8_t calc_mac[64];

    // Unused in this implementation
    size_t len_in = len_data_in;
    len_in = len_in;
    cam_cookies = cam_cookies;
    ecs = ecs;
    iv = iv;
    iv_len = iv_len;
    sa_ptr = sa_ptr;

    #ifdef DEBUG
        printf("cryptography_validate_authentication \n");
    #endif

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
            status = wc_InitCmac(&cmac, key, len_key, WC_CMAC_AES, NULL);
            if (status == 0)
            {
                if (aad_len > 0)
                {
                    status = wc_CmacUpdate(&cmac, aad, aad_len);
                }
            }
            // Commented out for now while assessing unit tests
            //if (status == 0)
            //{
            //    status = wc_CmacUpdate(&cmac, data_in, len_data_in);
            //    printf("    wc_CmacUpdate(data_in) returned %d \n", status);
            //}
            if (status == 0)
            {
                status = wc_CmacFinal(&cmac, calc_mac, &mac_size);
            }
            break;

        // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__HMAC.html
        case CRYPTO_MAC_HMAC_SHA256:
            status = wc_HmacSetKey(&hmac, WC_SHA256, key, len_key);
            if (status == 0)
            {  
                if (aad_len > 0)
                {
                    status = wc_HmacUpdate(&hmac, aad, aad_len);
                }
            }
            // Commented out for now while assessing unit tests
            //if (status == 0)
            //{
            //    status = wc_HmacUpdate(&hmac, data_in, len_data_in);
            //}
            if (status == 0)
            {
                status = wc_HmacFinal(&hmac, calc_mac);
            }
            break;

        case CRYPTO_MAC_HMAC_SHA512:
            status = wc_HmacSetKey(&hmac, WC_SHA512, key, len_key);
            if (status == 0)
            {
                if (aad_len > 0)
                {
                    status = wc_HmacUpdate(&hmac, aad, aad_len);
                }
            }
            // Commented out for now while assessing unit tests
            //if (status == 0)
            //{
            //    status = wc_HmacUpdate(&hmac, data_in, len_data_in);
            //}
            if (status == 0)
            {
                status = wc_HmacFinal(&hmac, calc_mac);
            }
            break;

        default:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
    }

    #ifdef MAC_DEBUG
        printf("Calculated Mac Size: %d\n", mac_size);
        printf("Calculated MAC:\n\t");
        for (uint32_t i = 0; i < mac_size; i ++)
        {
            printf("%02X", calc_mac[i]);
        }
        printf("\n");
        printf("Received MAC:\n\t");
        for (uint32_t i = 0; i < mac_size; i ++)
        {
            printf("%02X", mac[i]);
        }
        printf("\n");   
    #endif

    // Compare calculated MAC to provided
    if (status == 0)
    {
        for(uint32_t i = 0; i < mac_size; i++)
        {
            if(calc_mac[i] != mac[i])
            {
                status = CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR;
                break;
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
    Aes enc;

    // Unused in this implementation
    cam_cookies = cam_cookies;
    data_out = data_out;
    len_data_out = len_data_out;
    iv = iv;
    iv_len = iv_len;
    padding = padding;
    sa_ptr = sa_ptr;

    #ifdef DEBUG
        printf("cryptography_encrypt \n");
        size_t j;
        printf("Input payload length is %ld\n", (long int) len_data_in);
        printf(KYEL "Printing Frame Data prior to encryption:\n\t");
        for (j = 0; j < len_data_in; j++)
        {
            printf("%02X", *(data_in + j));
        }
        printf("\n");
    #endif

    // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html
    switch (*ecs)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            status = wc_AesGcmSetKey(&enc, key, len_key);
            if (status == 0)
            {
                status = wc_AesGcmEncrypt(&enc, data_out, data_in, len_data_in, iv, iv_len, NULL, 16, NULL, 0);
                if (status == -180)
                {   // Special error case as Wolf will not accept a zero value for MAC size
                    status = CRYPTO_LIB_SUCCESS;
                }
            }
            break;

        // TODO: Confirm same process as above for SIV
        // case CRYPTO_CIPHER_AES256_GCM_SIV:
        //     status = wc_AesGcmSetKey(&enc, key, len_key);
        //     if (status == 0)
        //     {
        //         //status = wc_AesGcmEncrypt(&enc, data_out, data_in, len_data_in, iv, iv_len, NULL, 16, NULL, 0);
        //         status = wc_AesSivEncrypt(key, len_key, NULL, 0, )
        //         if (status == -180)
        //         {   // Special error case as Wolf will not accept a zero value for MAC size
        //             status = CRYPTO_LIB_SUCCESS;
        //         }
        //     }
        //     break;

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

    #ifdef DEBUG
        printf("Output payload length is %ld\n", (long int) len_data_out);
        printf(KYEL "Printing Frame Data after encryption:\n\t");
        for (j = 0; j < len_data_out; j++)
        {
            printf("%02X", *(data_out + j));
        }
        printf("\n");
    #endif

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
    Aes enc;

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

    #ifdef DEBUG
        size_t j;
        printf("cryptography_aead_encrypt \n");
        printf("Input payload length is %ld\n", (long int) len_data_in);
        printf(KYEL "Printing Frame Data prior to encryption:\n\t");
        for (j = 0; j < len_data_in; j++)
        {
            printf("%02X", *(data_in + j));
        }
        printf("\n");
    #endif

    // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html
    switch (*ecs)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            status = wc_AesGcmSetKey(&enc, key, len_key);
            if (status == 0)
            {
                if ((encrypt_bool == CRYPTO_TRUE) && (authenticate_bool == CRYPTO_TRUE))
                {
                    status = wc_AesGcmEncrypt(&enc, data_out, data_in, len_data_in, iv, iv_len, mac, mac_size, aad, aad_len);
                }
                else if (encrypt_bool == CRYPTO_TRUE)
                {
                    status = wc_AesGcmEncrypt(&enc, data_out, data_in, len_data_in, iv, iv_len, mac, 16, aad, aad_len);
                    if (status == -180)
                    {   // Special error case as Wolf will not accept a zero value for MAC size
                        status = CRYPTO_LIB_SUCCESS;
                    }
                }
                else if (authenticate_bool == CRYPTO_TRUE)
                {
                    status = wc_AesGcmEncrypt(&enc, data_out, data_in, 0, iv, iv_len, mac, mac_size, aad, aad_len);
                }
            }
            break;

        // TODO: Confirm same process will be used
        case CRYPTO_CIPHER_AES256_GCM_SIV:
            status = wc_AesGcmSetKey(&enc, key, len_key);
            if (status == 0)
            {
                if ((encrypt_bool == CRYPTO_TRUE) && (authenticate_bool == CRYPTO_TRUE))
                {
                    status = wc_AesGcmEncrypt(&enc, data_out, data_in, len_data_in, iv, iv_len, mac, mac_size, aad, aad_len);
                }
                else if (encrypt_bool == CRYPTO_TRUE)
                {
                    status = wc_AesGcmEncrypt(&enc, data_out, data_in, len_data_in, iv, iv_len, mac, 16, aad, aad_len);
                    if (status == -180)
                    {   // Special error case as Wolf will not accept a zero value for MAC size
                        status = CRYPTO_LIB_SUCCESS;
                    }
                }
                else if (authenticate_bool == CRYPTO_TRUE)
                {
                    status = wc_AesGcmEncrypt(&enc, data_out, data_in, 0, iv, iv_len, mac, mac_size, aad, aad_len);
                }
            }
            break;

        case CRYPTO_CIPHER_AES256_CCM:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
            break;

        default:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
            break;
    }

    #ifdef DEBUG
        printf("Output payload length is %ld\n", (long int) len_data_out);
        printf(KYEL "Printing Frame Data after encryption:\n\t");
        for (j = 0; j < len_data_out; j++)
        {
            printf("%02X", *(data_out + j));
        }
        printf("\n");
    #endif

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
    Aes dec;
    uint8_t calc_mac[16];
    
    // Unused in this implementation
    acs = acs;
    cam_cookies = cam_cookies;
    len_data_out = len_data_out;
    iv_len = iv_len;
    sa_ptr = sa_ptr;

    #ifdef DEBUG
        printf("cryptography_decrypt \n");
    #endif

    // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html
    switch (*ecs)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            status = wc_AesGcmSetKey(&dec, key, len_key);
            if (status == 0)
            {
                status = wc_AesGcmDecrypt(&dec, data_out, data_in, len_data_in, iv, iv_len, calc_mac, 16, NULL, 0);
                if (status == -180)
                {   // Special error case as Wolf will not accept a zero value for MAC size
                    status = CRYPTO_LIB_SUCCESS;
                }
            }
            break;

        case CRYPTO_CIPHER_AES256_GCM_SIV:
            status = wc_AesGcmSetKey(&dec, key, len_key);
            if (status == 0)
            {
                status = wc_AesGcmDecrypt(&dec, data_out, data_in, len_data_in, iv, iv_len, calc_mac, 16, NULL, 0);
                if (status == -180)
                {   // Special error case as Wolf will not accept a zero value for MAC size
                    status = CRYPTO_LIB_SUCCESS;
                }
            }
            break;

        case CRYPTO_CIPHER_AES256_CBC:
            status = wc_AesSetKey(&dec, key, len_key, iv, AES_DECRYPTION);
            if (status == 0)
            {
                status = wc_AesSetIV(&dec, iv);
            }
            if (status == 0)
            {
                status = wc_AesCbcDecrypt(&dec, data_out, data_in, len_data_in);
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
    Aes dec;
    
    // Fix warnings
    acs = acs;
    cam_cookies = cam_cookies;
    len_data_out = len_data_out;
    decrypt_bool = decrypt_bool;
    authenticate_bool = authenticate_bool;
    aad_bool = aad_bool;
    sa_ptr = sa_ptr;

    #ifdef DEBUG
        printf("cryptography_aead_decrypt \n");
    #endif

    // Reference: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html
    switch (*ecs)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            status = wc_AesGcmSetKey(&dec, key, len_key);
            if (status == 0)
            {
                if ((decrypt_bool == CRYPTO_TRUE) && (authenticate_bool == CRYPTO_TRUE))
                {
                    // Added for now while assessing unit tests and requirements
                    if (mac_size > 0)
                    {
                        status = wc_AesGcmDecrypt(&dec, data_out, data_in, len_data_in, iv, iv_len, mac, mac_size, aad, aad_len);
                    }
                    else
                    {
                        status = wc_AesGcmDecrypt(&dec, data_out, data_in, len_data_in, iv, iv_len, mac, 16, aad, aad_len);
                        if (status == -180)
                        {   // Special error case as Wolf will not accept a zero value for MAC size
                            status = CRYPTO_LIB_SUCCESS;
                        }
                    }
                }
                else if (decrypt_bool == CRYPTO_TRUE)
                {
                    status = wc_AesGcmDecrypt(&dec, data_out, data_in, len_data_in, iv, iv_len, mac, 16, aad, aad_len);
                    if (status == -180)
                    {   // Special error case as Wolf will not accept a zero value for MAC size
                        status = CRYPTO_LIB_SUCCESS;
                    }
                }
                else if (authenticate_bool == CRYPTO_TRUE)
                {
                    status = wc_AesGcmDecrypt(&dec, data_out, data_in, len_data_in, iv, iv_len, mac, mac_size, aad, aad_len);
                    // If authentication only, don't decrypt the data. Just pass the data PDU through.
                    memcpy(data_out, data_in, len_data_in);
                }
            }
            break;

        case CRYPTO_CIPHER_AES256_GCM_SIV:
            status = wc_AesGcmSetKey(&dec, key, len_key);
            if (status == 0)
            {
                if ((decrypt_bool == CRYPTO_TRUE) && (authenticate_bool == CRYPTO_TRUE))
                {
                    // Added for now while assessing unit tests and requirements
                    if (mac_size > 0)
                    {
                        status = wc_AesGcmDecrypt(&dec, data_out, data_in, len_data_in, iv, iv_len, mac, mac_size, aad, aad_len);
                    }
                    else
                    {
                        status = wc_AesGcmDecrypt(&dec, data_out, data_in, len_data_in, iv, iv_len, mac, 16, aad, aad_len);
                        if (status == -180)
                        {   // Special error case as Wolf will not accept a zero value for MAC size
                            status = CRYPTO_LIB_SUCCESS;
                        }
                    }
                }
                else if (decrypt_bool == CRYPTO_TRUE)
                {
                    status = wc_AesGcmDecrypt(&dec, data_out, data_in, len_data_in, iv, iv_len, mac, 16, aad, aad_len);
                    if (status == -180)
                    {   // Special error case as Wolf will not accept a zero value for MAC size
                        status = CRYPTO_LIB_SUCCESS;
                    }
                }
                else if (authenticate_bool == CRYPTO_TRUE)
                {
                    status = wc_AesGcmDecrypt(&dec, data_out, data_in, len_data_in, iv, iv_len, mac, mac_size, aad, aad_len);
                    // If authentication only, don't decrypt the data. Just pass the data PDU through.
                    memcpy(data_out, data_in, len_data_in);
                }
            }
            break;

        case CRYPTO_CIPHER_AES256_CCM:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
            break;

        default:
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
            break;
    }

    // Translate WolfSSL errors to CryptoLib
    if (status == -180)
    {
        status = CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR;
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
        case CRYPTO_CIPHER_AES256_GCM_SIV:
            algo = CRYPTO_CIPHER_AES256_GCM_SIV;
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
