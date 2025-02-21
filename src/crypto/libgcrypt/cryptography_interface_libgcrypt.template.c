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

#include <gcrypt.h>

#include "crypto.h"
#include "crypto_error.h"
#include "cryptography_interface.h"

// Cryptography Interface Initialization & Management Functions
static int32_t cryptography_config(void);
static int32_t cryptography_init(void);
static int32_t cryptography_shutdown(void);
// Cryptography Interface Functions
static int32_t cryptography_encrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                    uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                    uint32_t iv_len, uint8_t *ecs, uint8_t padding, char *cam_cookies);
static int32_t cryptography_decrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                    uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                    uint32_t iv_len, uint8_t *ecs, uint8_t *acs, char *cam_cookies);
static int32_t cryptography_authenticate(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                         uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                         uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad,
                                         uint32_t aad_len, uint8_t ecs, uint8_t acs, char *cam_cookies);
static int32_t cryptography_validate_authentication(uint8_t *data_out, size_t len_data_out, const uint8_t *data_in,
                                                    const size_t len_data_in, uint8_t *key, uint32_t len_key,
                                                    SecurityAssociation_t *sa_ptr, const uint8_t *iv, uint32_t iv_len,
                                                    const uint8_t *mac, uint32_t mac_size, const uint8_t *aad,
                                                    uint32_t aad_len, uint8_t ecs, uint8_t acs, char *cam_cookies);
static int32_t cryptography_aead_encrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                         uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                         uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad,
                                         uint32_t aad_len, uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t *ecs, uint8_t *acs, char *cam_cookies);
static int32_t cryptography_aead_decrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                         uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                         uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad,
                                         uint32_t aad_len, uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t *ecs, uint8_t *acs, char *cam_cookies);
static int32_t cryptography_get_acs_algo(int8_t algo_enum);
static int32_t cryptography_get_ecs_algo(int8_t algo_enum);
static int32_t cryptography_get_ecs_mode(int8_t algo_enum);

/*
** Module Variables
*/
// Cryptography Interface
static CryptographyInterfaceStruct cryptography_if_struct;

CryptographyInterface get_cryptography_interface_libgcrypt(void)
{
    cryptography_if_struct.cryptography_config                  = cryptography_config;
    cryptography_if_struct.cryptography_init                    = cryptography_init;
    cryptography_if_struct.cryptography_shutdown                = cryptography_shutdown;
    cryptography_if_struct.cryptography_encrypt                 = cryptography_encrypt;
    cryptography_if_struct.cryptography_decrypt                 = cryptography_decrypt;
    cryptography_if_struct.cryptography_authenticate            = cryptography_authenticate;
    cryptography_if_struct.cryptography_validate_authentication = cryptography_validate_authentication;
    cryptography_if_struct.cryptography_aead_encrypt            = cryptography_aead_encrypt;
    cryptography_if_struct.cryptography_aead_decrypt            = cryptography_aead_decrypt;
    cryptography_if_struct.cryptography_get_acs_algo            = cryptography_get_acs_algo;
    cryptography_if_struct.cryptography_get_ecs_algo            = cryptography_get_ecs_algo;
    return &cryptography_if_struct;
}

static int32_t cryptography_config(void)
{
    return CRYPTO_LIB_SUCCESS;
}

static int32_t cryptography_init(void)
{
#ifdef DEBUG
    printf(KYEL "Initializing Libgcrypt...\n" RESET);
#endif
    int32_t status = CRYPTO_LIB_SUCCESS;
    // Initialize libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION))
    {
        fprintf(stderr, "Gcrypt Version: %s", GCRYPT_VERSION);
        printf(KRED "\tERROR: gcrypt version mismatch! \n" RESET);
    }
    if (gcry_control(GCRYCTL_SELFTEST) != GPG_ERR_NO_ERROR)
    {
        status = CRYPTOGRAPHY_LIBRARY_INITIALIZIATION_ERROR;
        printf(KRED "ERROR: gcrypt self test failed\n" RESET);
    }
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    return status;
}
static int32_t cryptography_shutdown(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    gvcid_counter = 0;

    if (key_if != NULL)
    {
        key_if = NULL;
    }

    if (mc_if != NULL)
    {
        mc_if = NULL;
    }

    if (sa_if != NULL)
    {
        sa_if = NULL;
    }

    if (cryptography_if != NULL)
    {
        cryptography_if = NULL;
    }

    return status;
}

static int32_t cryptography_authenticate(
    uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in, uint8_t *key, uint32_t len_key,
    SecurityAssociation_t *sa_ptr, // For key index or key references (when key not passed in explicitly via key param)
    uint8_t *iv, uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad, uint32_t aad_len, uint8_t ecs,
    uint8_t acs, char *cam_cookies)
{
    gcry_error_t  gcry_error = GPG_ERR_NO_ERROR;
    gcry_mac_hd_t tmp_mac_hd;
    int32_t       status  = CRYPTO_LIB_SUCCESS;
    uint8_t      *key_ptr = key;

    sa_ptr = sa_ptr; // Unused in this implementation

    // Need to copy the data over, since authentication won't change/move the data directly
    if (data_out != NULL)
    {
        memcpy(data_out, data_in, len_data_in);
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }
    // Using to fix warning
    len_data_out = len_data_out;
    ecs          = ecs;
    cam_cookies  = cam_cookies;

    // Select correct libgcrypt acs enum
    int32_t algo = cryptography_get_acs_algo(acs);
    if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ACS)
    {
        return CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
    }

    gcry_error = gcry_mac_open(&(tmp_mac_hd), algo, GCRY_MAC_FLAG_SECURE, NULL);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_mac_setkey(tmp_mac_hd, key_ptr, len_key);

#ifdef SA_DEBUG
    uint32_t i;
    printf(KYEL "Auth MAC Printing Key:\n\t");
    for (i = 0; i < len_key; i++)
    {
        printf("%02X", *(key_ptr + i));
    }
    printf("\n");
#endif
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        gcry_mac_close(tmp_mac_hd);
        return status;
    }

    // If MAC needs IV, set it (only for certain ciphers)
    if (iv_len > 0)
    {
        gcry_error = gcry_mac_setiv(tmp_mac_hd, iv, iv_len);
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_mac_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERROR;
            gcry_mac_close(tmp_mac_hd);
            return status;
        }
    }

    gcry_error = gcry_mac_write(tmp_mac_hd,
                                aad,    // additional authenticated data
                                aad_len // length of AAD
    );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_write error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERROR;
        gcry_mac_close(tmp_mac_hd);
        return status;
    }

    uint32_t *tmac_size = &mac_size;
    gcry_error          = gcry_mac_read(tmp_mac_hd,
                                        mac,                // tag output
                                        (size_t *)tmac_size // tag size
             );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_read error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR;
        gcry_mac_close(tmp_mac_hd);
        return status;
    }

    // Zeroise any sensitive information
    gcry_mac_close(tmp_mac_hd);
    return status;
}
static int32_t cryptography_validate_authentication(uint8_t *data_out, size_t len_data_out, const uint8_t *data_in,
                                                    const size_t len_data_in, uint8_t *key, uint32_t len_key,
                                                    SecurityAssociation_t *sa_ptr, const uint8_t *iv, uint32_t iv_len,
                                                    const uint8_t *mac, uint32_t mac_size, const uint8_t *aad,
                                                    uint32_t aad_len, uint8_t ecs, uint8_t acs, char *cam_cookies)
{
    gcry_error_t  gcry_error = GPG_ERR_NO_ERROR;
    gcry_mac_hd_t tmp_mac_hd;
    int32_t       status  = CRYPTO_LIB_SUCCESS;
    uint8_t      *key_ptr = key;
    size_t        len_in  = len_data_in; // Unused
    len_in                = len_in;

    sa_ptr = sa_ptr; // Unused in this implementation

    // Need to copy the data over, since authentication won't change/move the data directly
    // If you don't want data out, don't set a data out length

    if (data_out != NULL)
    {
        memcpy(data_out, data_in, len_data_out);
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }
    // Using to fix warning
    ecs         = ecs;
    cam_cookies = cam_cookies;

    // Select correct libgcrypt acs enum
    int32_t algo = cryptography_get_acs_algo(acs);
    if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ACS)
    {
        return CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
    }

    gcry_error = gcry_mac_open(&(tmp_mac_hd), algo, GCRY_MAC_FLAG_SECURE, NULL);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n" RESET, gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }

    gcry_error = gcry_mac_setkey(tmp_mac_hd, key_ptr, len_key);
#ifdef SA_DEBUG
    uint32_t i;
    printf(KYEL "Validate MAC Printing Key:\n\t");
    for (i = 0; i < len_key; i++)
    {
        printf("%02X", *(key_ptr + i));
    }
    printf("\n" RESET);
#endif
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n" RESET, gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_mac_close(tmp_mac_hd);
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    // If MAC needs IV, set it (only for certain ciphers)
    if (iv_len > 0)
    {
        gcry_error = gcry_mac_setiv(tmp_mac_hd, iv, iv_len);
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_mac_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n" RESET, gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            gcry_mac_close(tmp_mac_hd);
            status = CRYPTO_LIB_ERROR;
            return status;
        }
    }
    gcry_error = gcry_mac_write(tmp_mac_hd,
                                aad,    // additional authenticated data
                                aad_len // length of AAD
    );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_write error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n" RESET, gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_mac_close(tmp_mac_hd);
        status = CRYPTO_LIB_ERROR;
        return status;
    }

#ifdef MAC_DEBUG
    uint32_t *tmac_size = &mac_size;
    uint8_t  *tmac      = calloc(1, *tmac_size);
    gcry_error          = gcry_mac_read(tmp_mac_hd,
                                        tmac,               // tag output
                                        (size_t *)tmac_size // tag size
             );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_read error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        status = CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR;
        return status;
    }

    printf("Calculated Mac Size: %d\n", *tmac_size);
    printf("Calculated MAC (full length):\n\t");
    for (uint32_t i = 0; i < *tmac_size; i++)
    {
        printf("%02X", tmac[i]);
    }
    printf("\nCalculated MAC (truncated to sa_ptr->stmacf_len):\n\t");
    for (uint32_t i = 0; i < mac_size; i++)
    {
        printf("%02X", tmac[i]);
    }
    printf("\n");
    if (!tmac)
        free(tmac);

    printf("Received MAC:\n\t");
    for (uint32_t i = 0; i < mac_size; i++)
    {
        printf("%02X", mac[i]);
    }
    printf("\n");
#endif

    // Compare computed mac with MAC in frame
    gcry_error = gcry_mac_verify(tmp_mac_hd,
                                 mac,             // original mac
                                 (size_t)mac_size // tag size
    );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_verify error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n" RESET, gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_mac_close(tmp_mac_hd);
        status = CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR;
        return status;
    }
#ifdef DEBUG
    else
    {
        printf("Mac verified!\n");
    }
#endif
    // Zeroise any sensitive information
    gcry_mac_reset(tmp_mac_hd);
    gcry_mac_close(tmp_mac_hd);
    return status;
}

static int32_t cryptography_encrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                    uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                    uint32_t iv_len, uint8_t *ecs, uint8_t padding, char *cam_cookies)
{
    gcry_error_t     gcry_error = GPG_ERR_NO_ERROR;
    gcry_cipher_hd_t tmp_hd;
    int32_t          status  = CRYPTO_LIB_SUCCESS;
    uint8_t         *key_ptr = key;

    data_out     = data_out; // TODO:  Look into tailoring these out, as they're not used or needed.
    len_data_out = len_data_out;
    padding      = padding;
    cam_cookies  = cam_cookies;

    sa_ptr = sa_ptr; // Unused in this implementation

    // Select correct libgcrypt algorith enum
    int32_t algo = -1;
    if (ecs != NULL)
    {
        algo = cryptography_get_ecs_algo(*ecs);
        if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_MODE)
        {
            return CRYPTO_LIB_ERR_UNSUPPORTED_MODE;
        }
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_MODE_PTR;
    }

    // Verify the mode to accompany the algorithm enum
    int32_t mode = -1;
    mode         = cryptography_get_ecs_mode(*ecs);
    if (mode == CRYPTO_LIB_ERR_UNSUPPORTED_MODE)
    {
        return CRYPTO_LIB_ERR_UNSUPPORTED_MODE;
    }

    gcry_error = gcry_cipher_open(&(tmp_hd), algo, mode, GCRY_CIPHER_NONE);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setkey(tmp_hd, key_ptr, len_key);

#ifdef SA_DEBUG
    uint32_t i;
    printf(KYEL "Printing Key:\n\t");
    for (i = 0; i < len_key; i++)
    {
        printf("%02X", *(key_ptr + i));
    }
    printf("\n");
#endif

    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        gcry_cipher_close(tmp_hd);
        return status;
    }
    gcry_error = gcry_cipher_setiv(tmp_hd, iv, iv_len);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        gcry_cipher_close(tmp_hd);
        return status;
    }

#ifdef TC_DEBUG
    size_t j;
    printf("Input payload length is %ld\n", (long int)len_data_in);
    printf(KYEL "Printing Frame Data prior to encryption:\n\t");
    for (j = 0; j < len_data_in; j++)
    {
        printf("%02X", *(data_in + j));
    }
    printf("\n" RESET);
#endif

    gcry_error = gcry_cipher_encrypt(tmp_hd, data_in, len_data_in, NULL, 0);
    // TODO:  Add PKCS#7 padding to data_in, and increment len_data_in to match necessary block size
    // TODO:  Remember to remove the padding.
    // TODO:  Does this interfere with max frame size?  Does that need to be taken into account?
    // gcry_error = gcry_cipher_encrypt(tmp_hd,
    //                                     data_out,              // ciphertext output
    //                                     len_data_out,                // length of data
    //                                     data_in, // plaintext input
    //                                     len_data_in                 // in data length
    // );

    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_encrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_ENCRYPTION_ERROR;
        gcry_cipher_close(tmp_hd);
        return status;
    }

#ifdef TC_DEBUG
    printf("Output payload length is %ld\n", (long int)len_data_out);
    printf(KYEL "Printing Frame Data after encryption:\n\t");
    for (j = 0; j < len_data_out; j++)
    {
        printf("%02X", *(data_out + j));
    }
    printf("\n" RESET);
#endif

    gcry_cipher_close(tmp_hd);
    return status;
}

int32_t cryptography_verify_ecs_enum_algo(uint8_t *ecs, int32_t *algo, int32_t *mode)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (ecs != NULL)
    {
        *algo = cryptography_get_ecs_algo(*ecs);
        if (*algo == CRYPTO_LIB_ERR_UNSUPPORTED_ECS)
        {
            status = CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
            return status;
        }
    }
    else
    {
        status = CRYPTO_LIB_ERR_NULL_ECS_PTR;
        return status;
    }

    // Verify the mode to accompany the ecs enum
    *mode = cryptography_get_ecs_mode(*ecs);
    if (*mode == CRYPTO_LIB_ERR_UNSUPPORTED_ECS_MODE)
    {
        status = CRYPTO_LIB_ERR_UNSUPPORTED_ECS_MODE;
        return status;
    }
    return status;
}

int32_t cryptography_gcry_setup(int32_t mode, int32_t algo, gcry_cipher_hd_t *tmp_hd, uint8_t *key_ptr,
                                uint32_t len_key, uint8_t *iv, uint32_t iv_len, gcry_error_t *gcry_error)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (mode == CRYPTO_CIPHER_AES256_CBC_MAC)
    {
        *gcry_error = gcry_cipher_open(tmp_hd, algo, mode, GCRY_CIPHER_CBC_MAC);
    }
    else
    {
        *gcry_error = gcry_cipher_open(tmp_hd, algo, mode, GCRY_CIPHER_NONE);
    }
    if ((*gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, *gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(*gcry_error), gcry_strerror(*gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    *gcry_error = gcry_cipher_setkey(*tmp_hd, key_ptr, len_key);
#ifdef SA_DEBUG
    uint32_t i;
    printf(KYEL "AEAD MAC: Printing Key:\n\t");
    for (i = 0; i < len_key; i++)
    {
        printf("%02X", *(key_ptr + i));
    }
    printf("\n" RESET);
#endif

    if ((*gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, *gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(*gcry_error), gcry_strerror(*gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        gcry_cipher_close(*tmp_hd);
        return status;
    }
    *gcry_error = gcry_cipher_setiv(*tmp_hd, iv, iv_len);
    if ((*gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, *gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(*gcry_error), gcry_strerror(*gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        gcry_cipher_close(*tmp_hd);
        return status;
    }
    return status;
}

static int32_t cryptography_aead_encrypt(
    uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in, uint8_t *key, uint32_t len_key,
    SecurityAssociation_t *sa_ptr, // For key index or key references (when key not passed in explicitly via key param)
    uint8_t *iv, uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad, uint32_t aad_len, uint8_t encrypt_bool,
    uint8_t authenticate_bool, uint8_t aad_bool, uint8_t *ecs, uint8_t *acs, char *cam_cookies)
{
    gcry_error_t     gcry_error = GPG_ERR_NO_ERROR;
    gcry_cipher_hd_t tmp_hd     = 0;
    int32_t          status     = CRYPTO_LIB_SUCCESS;
    uint8_t         *key_ptr    = key;

    // Fix warning
    acs         = acs;
    cam_cookies = cam_cookies;

    sa_ptr = sa_ptr; // Unused in this implementation

    // Select correct libgcrypt ecs enum
    int32_t algo = -1;
    int32_t mode = -1;
    status       = cryptography_verify_ecs_enum_algo(ecs, &algo, &mode);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
        return status;
    }

    // TODO: Get Flag Functionality
    status = cryptography_gcry_setup(mode, algo, &tmp_hd, key_ptr, len_key, iv, iv_len, &gcry_error);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
        return status;
    }

#ifdef DEBUG
    size_t j;
    printf("Input payload length is %ld\n", (long int)len_data_in);
    printf(KYEL "Printing Frame Data prior to encryption:\n\t");
    for (j = 0; j < len_data_in; j++)
    {
        printf("%02X", *(data_in + j));
    }
    printf("\n" RESET);
#endif

    if (aad_bool == CRYPTO_TRUE) // Authenticate with AAD!
    {
        gcry_error = gcry_cipher_authenticate(tmp_hd,
                                              aad,    // additional authenticated data
                                              aad_len // length of AAD
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_authenticate error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERR_AUTHENTICATION_ERROR;
            gcry_cipher_close(tmp_hd);
            return status;
        }
    }

    if (encrypt_bool == CRYPTO_TRUE)
    {
        // TODO:  Add PKCS#7 padding to data_in, and increment len_data_in to match necessary block size
        // TODO:  Remember to remove the padding.
        // TODO:  Does this interfere with max frame size?  Does that need to be taken into account?
        gcry_error = gcry_cipher_encrypt(tmp_hd,
                                         data_out,     // ciphertext output
                                         len_data_out, // length of data
                                         data_in,      // plaintext input
                                         len_data_in   // in data length
        );
    }
    else // AEAD authenticate only
    {
        gcry_error = gcry_cipher_encrypt(tmp_hd,
                                         NULL, // ciphertext output
                                         0,    // length of data
                                         NULL, // plaintext input
                                         0     // in data length
        );
    }
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_encrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_ENCRYPTION_ERROR;
        gcry_cipher_close(tmp_hd);
        return status;
    }

#ifdef TC_DEBUG
    printf("Output payload length is %ld\n", (long int)len_data_out);
    printf(KYEL "Printing Frame Data after encryption:\n\t");
    for (j = 0; j < len_data_out; j++)
    {
        printf("%02X", *(data_out + j));
    }
    printf("\n" RESET);
#endif

    if (authenticate_bool == CRYPTO_TRUE)
    {
        gcry_error = gcry_cipher_gettag(tmp_hd,
                                        mac,     // tag output
                                        mac_size // tag size
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR;
            gcry_cipher_close(tmp_hd);
            return status;
        }

#ifdef MAC_DEBUG
        uint32_t i = 0;
        printf("MAC = 0x");
        for (i = 0; i < mac_size; i++)
        {
            printf("%02x", (uint8_t)mac[i]);
        }
        printf("\n");
#endif
    }

    gcry_cipher_close(tmp_hd);
    return status;
}

static int32_t cryptography_decrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                    uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                    uint32_t iv_len, uint8_t *ecs, uint8_t *acs, char *cam_cookies)
{
    gcry_cipher_hd_t tmp_hd;
    gcry_error_t     gcry_error = GPG_ERR_NO_ERROR;
    int32_t          status     = CRYPTO_LIB_SUCCESS;
    uint8_t         *key_ptr    = key;

    // Fix warnings
    acs         = acs;
    cam_cookies = cam_cookies;

    sa_ptr = sa_ptr; // Unused in this implementation

    // Select correct libgcrypt ecs enum
    int32_t algo = -1;
    if (ecs != NULL)
    {
        algo = cryptography_get_ecs_algo(*ecs);
        if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ECS)
        {
            return CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
        }
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_ECS_PTR;
    }

    // Verify the mode to accompany the algorithm enum
    int32_t mode = -1;
    mode         = cryptography_get_ecs_mode(*ecs);
    if (mode == CRYPTO_LIB_ERR_UNSUPPORTED_MODE)
    {
        return CRYPTO_LIB_ERR_UNSUPPORTED_MODE;
    }

    gcry_error = gcry_cipher_open(&(tmp_hd), algo, mode, GCRY_CIPHER_NONE);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setkey(tmp_hd, key_ptr, len_key);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_cipher_close(tmp_hd);
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }

    gcry_error = gcry_cipher_setiv(tmp_hd, iv, iv_len);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_cipher_close(tmp_hd);
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }

    gcry_error = gcry_cipher_decrypt(tmp_hd,
                                     data_out,     // plaintext output
                                     len_data_out, // length of data
                                     data_in,      // in place decryption
                                     len_data_in   // in data length
    );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_decrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        gcry_cipher_close(tmp_hd);
        status = CRYPTO_LIB_ERR_DECRYPT_ERROR;
        return status;
    }

    gcry_cipher_close(tmp_hd);
    return status;
}

static int32_t cryptography_aead_decrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                         uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                         uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad,
                                         uint32_t aad_len, uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t *ecs, uint8_t *acs, char *cam_cookies)
{
    gcry_cipher_hd_t tmp_hd;
    gcry_error_t     gcry_error = GPG_ERR_NO_ERROR;
    int32_t          status     = CRYPTO_LIB_SUCCESS;
    uint8_t         *key_ptr    = key;

    // Fix warnings
    acs         = acs;
    cam_cookies = cam_cookies;

    sa_ptr = sa_ptr; // Unused in this implementation

    // Select correct libgcrypt ecs enum
    int32_t algo = -1;
    int32_t mode = -1;
    if (ecs != NULL)
    {
        algo = cryptography_get_ecs_algo(*ecs);
        if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ECS)
        {
            return CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
        }
        mode = cryptography_get_ecs_mode(*ecs);
        if (mode == CRYPTO_LIB_ERR_UNSUPPORTED_ECS)
        {
            return CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
        }
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_ECS_PTR;
    }

    // Sanity check for future developers
    if (algo != GCRY_CIPHER_AES256)
    {
        printf(KRED "Warning - only  AES256 supported for AEAD decrypt - exiting!\n" RESET);
        status = CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
        return status;
    }

    gcry_error = gcry_cipher_open(&(tmp_hd), GCRY_CIPHER_AES256, mode, GCRY_CIPHER_NONE);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setkey(tmp_hd, key_ptr, len_key);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_cipher_close(tmp_hd);
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setiv(tmp_hd, iv, iv_len);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_cipher_close(tmp_hd);
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }

    if (aad_bool == CRYPTO_TRUE)
    {
        gcry_error = gcry_cipher_authenticate(tmp_hd,
                                              aad,    // additional authenticated data
                                              aad_len // length of AAD
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_authenticate error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            gcry_cipher_close(tmp_hd);
            status = CRYPTO_LIB_ERR_AUTHENTICATION_ERROR;
            return status;
        }
    }

    if (decrypt_bool == CRYPTO_TRUE)
    {
        if (mode == GCRY_CIPHER_MODE_GCM_SIV || mode == GCRY_CIPHER_MODE_SIV)
        {
            gcry_cipher_set_decryption_tag(tmp_hd, mac, mac_size);
        }
        gcry_error = gcry_cipher_decrypt(tmp_hd,
                                         data_out,     // plaintext output
                                         len_data_out, // length of data
                                         data_in,      // in place decryption
                                         len_data_in   // in data length
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_decrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            gcry_cipher_close(tmp_hd);
            status = CRYPTO_LIB_ERR_DECRYPT_ERROR;
            return status;
        }
    }
    else // Authentication only
    {
        // Authenticate only! No input data passed into decryption function, only AAD.
        gcry_error = gcry_cipher_decrypt(tmp_hd, NULL, 0, NULL, 0);
        // If authentication only, don't decrypt the data. Just pass the data PDU through.
        memcpy(data_out, data_in, len_data_in);

        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_decrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            gcry_cipher_close(tmp_hd);
            status = CRYPTO_LIB_ERR_DECRYPT_ERROR;
            return status;
        }
    }

    if (authenticate_bool == CRYPTO_TRUE)
    {
        /*
        ** *** !!!WARNING!!!
        ** *** This Debug block cannot be enabled during normal use, gettag fundamentally changes the
        ** *** gettag output
        */
        // #ifdef MAC_DEBUG
        //         printf("Received MAC is: \n\t0x:");
        //         for (uint32_t i =0; i<mac_size; i++)
        //         {
        //             printf("%02X", mac[i]);
        //         }
        // #endif
        //         gcry_error = gcry_cipher_gettag(tmp_hd,
        //                                 mac,  // tag output
        //                                 mac_size // tag size
        //         );
        // #ifdef MAC_DEBUG
        //         printf("\nCalculated MAC is: \n\t0x:");
        //         for (uint32_t i =0; i<mac_size; i++)
        //         {
        //             printf("%02X", mac[i]);
        //         }
        // #endif
        /*
        ** *** End debug block
        */
        gcry_error = gcry_cipher_checktag(tmp_hd,
                                          mac,     // tag input
                                          mac_size // tag size
        );

        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            gcry_cipher_close(tmp_hd);
            status = CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR;
            return status;
        }
    }

    gcry_cipher_close(tmp_hd);
    return status;
}

/**
 * @brief Function: cryptography_get_acs_algo. Maps Cryptolib ACS enums to libgcrypt enums
 * It is possible for supported algos to vary between crypto libraries
 * @param algo_enum
 **/
int32_t cryptography_get_acs_algo(int8_t algo_enum)
{
    int32_t algo = CRYPTO_LIB_ERR_UNSUPPORTED_ACS; // All valid algos will be positive
    switch (algo_enum)
    {
        case CRYPTO_MAC_CMAC_AES256:
            algo = GCRY_MAC_CMAC_AES;
            break;
        case CRYPTO_MAC_HMAC_SHA256:
            algo = GCRY_MAC_HMAC_SHA256;
            break;
        case CRYPTO_MAC_HMAC_SHA512:
            algo = GCRY_MAC_HMAC_SHA512;
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
 * @brief Function: cryptography_get_ecs_algo. Maps Cryptolib ECS enums to libgcrypt enums
 * It is possible for supported algos to vary between crypto libraries
 * @param algo_enum
 **/
int32_t cryptography_get_ecs_algo(int8_t algo_enum)
{
    int32_t algo = CRYPTO_LIB_ERR_UNSUPPORTED_ECS; // All valid algos will be positive
    switch (algo_enum)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            algo = GCRY_CIPHER_AES256;
            break;
        case CRYPTO_CIPHER_AES256_GCM_SIV:
            algo = GCRY_CIPHER_AES256;
            break;
        case CRYPTO_CIPHER_AES256_CBC:
            algo = GCRY_CIPHER_AES256;
            break;
        case CRYPTO_CIPHER_AES256_CCM:
            algo = GCRY_CIPHER_AES256;
            break;

        default:
#ifdef DEBUG
            printf("Algo Enum not supported\n");
#endif
            break;
    }

    return (int)algo;
}

/**
 * @brief Function: cryptography_get_ecs_mode. Maps Cryptolib ECS enums to libgcrypt enums
 * It is possible for supported algos to vary between crypto libraries
 * @param algo_enum
 **/
int32_t cryptography_get_ecs_mode(int8_t algo_enum)
{
    int32_t mode = CRYPTO_LIB_ERR_UNSUPPORTED_ECS_MODE; // All valid algos will be positive
    switch (algo_enum)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            mode = GCRY_CIPHER_MODE_GCM;
            break;
        case CRYPTO_CIPHER_AES256_GCM_SIV:
            mode = GCRY_CIPHER_MODE_GCM_SIV;
            break;
        case CRYPTO_CIPHER_AES256_CBC:
            mode = GCRY_CIPHER_MODE_CBC;
            break;
        case CRYPTO_CIPHER_AES256_CBC_MAC:
            mode = GCRY_CIPHER_MODE_CBC;
            break;
        case CRYPTO_CIPHER_AES256_CCM:
            mode = GCRY_CIPHER_MODE_CCM;
            break;

        default:
#ifdef DEBUG
            printf("ECS Mode Enum not supported\n");
#endif
            break;
    }

    return (int)mode;
}
