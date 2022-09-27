/* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration.
   All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory,
   including, but not limited to, any warranty that the software will conform to specifications, any implied warranties
   of merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty that the
   documentation will conform to the program, or any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
   consequential damages, arising out of, resulting from, or in any way connected with the software or its
   documentation, whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was sustained
   from, or arose out of the results of, or use of, the software, documentation or services provided hereunder.

   ITC Team
   NASA IV&V
   jstar-development-team@mail.nasa.gov
*/

#include "crypto_error.h"
#include "crypto.h"

char *crypto_enum_errlist_core[] =
{
        "CRYPTO_LIB_SUCCESS"
        ,"CRYPTO_LIB_ERROR"
        ,"CRYPTO_LIB_ERR_NO_INIT"
        ,"CRYPTO_LIB_ERR_INVALID_TFVN"
        ,"CRYPTO_LIB_ERR_INVALID_SCID"
        ,"CRYPTO_LIB_ERR_INVALID_VCID"
        ,"CRYPTO_LIB_ERR_INVALID_MAPID"
        ,"CRYPTO_LIB_ERR_INVALID_CC_FLAG"
        ,"CRYPTO_LIB_ERR_NO_OPERATIONAL_SA"
        ,"CRYPTO_LIB_ERR_NULL_BUFFER"
        ,"CRYPTO_LIB_ERR_UT_BYTE_MISMATCH"
        ,"CRYPTO_LIB_ERR_NO_CONFIG"
        ,"CRYPTO_LIB_ERR_INVALID_FECF"
        ,"CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW"
        ,"CRYPTO_LIB_ERR_LIBGCRYPT_ERROR"
        ,"CRYPTO_LIB_ERR_AUTHENTICATION_ERROR"
        ,"CRYPTO_LIB_ERR_NULL_IV"
        ,"CRYPTO_LIB_ERR_NULL_ABM"
        ,"CRYPTO_LIB_ERR_DECRYPT_ERROR"
        ,"CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD"
        ,"CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR"
        ,"CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR"
        ,"CRYPTO_LIB_ERR_INVALID_HEADER"
        ,"CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW"
        ,"CRYPTO_LIB_ERR_NULL_ARSN"
        ,"CRYPTO_LIB_ERR_NULL_SA"
        ,"CRYPTO_LIB_ERR_UNSUPPORTED_ACS"
        ,"CRYPTO_LIB_ERR_ENCRYPTION_ERROR"
        ,"CRYPTO_LIB_ERR_INVALID_SA_CONFIGURATION"
        ,"CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_MANAGED_PARAM_MAX_LIMIT"
        ,"CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_SPEC_LIMIT"
        ,"CRYPTO_LIB_ERR_UNSUPPORTED_ECS"
        ,"CRYPTO_LIB_ERR_KEY_LENGTH_ERROR"
        ,"CRYPTO_LIB_ERR_NULL_ECS_PTR"
        ,"CRYPTO_LIB_ERR_IV_NOT_SUPPORTED_FOR_ACS_ALGO"
        ,"CRYPTO_LIB_ERR_NULL_CIPHERS"
        ,"CRYPTO_LIB_ERR_NO_ECS_SET_FOR_ENCRYPTION_MODE"
        ,"CRYPTO_LIB_ERR_IV_LEN_SHORTER_THAN_SEC_HEADER_LENGTH"
        ,"CRYPTO_LIB_ERR_ARSN_LEN_SHORTER_THAN_SEC_HEADER_LENGTH"
        ,"CRYPTO_LIB_ERR_FRAME_COUNTER_DOESNT_MATCH_SA"
        ,"CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TC_STANDARD"
        ,"CRYPTO_LIB_ERR_INPUT_FRAME_LENGTH_SHORTER_THAN_FRAME_HEADERS_LENGTH"
        ,"CRYPTO_LIB_ERR_UNSUPPORTED_ECS_MODE"
        ,"CRYPTO_LIB_ERR_NULL_MODE_PTR"
        ,"CRYPTO_LIB_ERR_UNSUPPORTED_MODE"
};

char *crypto_enum_errlist_config[] =
{
        "CRYPTO_CONFIGURATION_NOT_COMPLETE"
        ,"CRYPTO_MANAGED_PARAM_CONFIGURATION_NOT_COMPLETE"
        ,"CRYPTO_MARIADB_CONFIGURATION_NOT_COMPLETE"
        ,"MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND"
};

char *crypto_enum_errlist_sadb_if[] =
{
        "SADB_INVALID_SADB_TYPE"
        ,"SADB_NULL_SA_USED"
};
char *crypto_enum_errlist_sadb_mariadb[] =
{
        "SADB_MARIADB_CONNECTION_FAILED"
        ,"SADB_QUERY_FAILED"
        ,"SADB_QUERY_EMPTY_RESULTS"
        ,"SADB_INSERT_FAILED"
};
char *crypto_enum_errlist_crypto_if[] =
{
        "CRYPTOGRAPHY_INVALID_CRYPTO_INTERFACE_TYPE"
        ,"CRYPTOGRAPHY_UNSUPPORTED_OPERATION_FOR_KEY_RING"
        ,"CRYPTOGRAPHY_LIBRARY_INITIALIZIATION_ERROR"
};
char *crypto_enum_errlist_crypto_kmc[] =
{
        "CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIGURATION_NOT_COMPLETE"
        ,"CRYPTOGRAPHY_KMC_CURL_INITIALIZATION_FAILURE"
        ,"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_CONNECTION_ERROR"
        ,"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AEAD_ENCRYPT_ERROR"
        ,"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AEAD_DECRYPT_ERROR"
        ,"CRYPTOGRAHPY_KMC_CRYPTO_JSON_PARSE_ERROR"
        ,"CRYPTOGRAHPY_KMC_CIPHER_TEXT_NOT_FOUND_IN_JSON_RESPONSE"
        ,"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE"
        ,"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AUTHENTICATION_ERROR"
        ,"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_MAC_VALIDATION_ERROR"
        ,"CRYPTOGRAHPY_KMC_ICV_NOT_FOUND_IN_JSON_RESPONSE"
        ,"CRYPTOGRAHPY_KMC_NULL_ENCRYPTION_KEY_REFERENCE_IN_SA"
        ,"CRYPTOGRAHPY_KMC_NULL_AUTHENTICATION_KEY_REFERENCE_IN_SA"
        ,"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_EMPTY_RESPONSE"
        ,"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_DECRYPT_ERROR"
        ,"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_ENCRYPT_ERROR"
};

char *crypto_enum_errlist_crypto_cam[] =
{
        "CAM_CONFIG_NOT_SUPPORTED_ERROR"
        ,"CAM_INVALID_COOKIE_FILE_CONFIGURATION_NULL"
        ,"CAM_AUTHENTICATION_FAILURE_REDIRECT"
        ,"CAM_AUTHENTICATION_REQUIRED"
        ,"CAM_GET_SSO_TOKEN_FAILURE"
        ,"CAM_INVALID_CONFIGURATION_ACCESS_MANAGER_URI_NULL"
        ,"CAM_INVALID_CONFIGURATION_KEYTAB_FILE_PATH_NULL"
        ,"CAM_INVALID_CONFIGURATION_KEYTAB_FILE_USERNAME_NULL"
        ,"CAM_KEYTAB_FILE_KINIT_FAILURE"
};

/*
** @brief: For a given crypto error code, return the associated error code enum string
** @param: int32_t
 * @return: char*
*/
char* Crypto_Get_Error_Code_Enum_String(int32_t crypto_error_code)
{
    if(crypto_error_code >= 600) // CAM Error Codes
    {
        if(crypto_error_code > 610)
        {
            return CRYPTO_UNDEFINED_ERROR;
        }
        else
        {
            return crypto_enum_errlist_crypto_cam[crypto_error_code % 600];
        }

    }
    else if(crypto_error_code >= 500) // KMC Error Codes
    {
        if(crypto_error_code > 515)
        {
            return CRYPTO_UNDEFINED_ERROR;
        }
        else
        {
            return crypto_enum_errlist_crypto_kmc[crypto_error_code % 500];
        }
    }
    else if(crypto_error_code >= 400) // Crypto Interface Error Codes
    {
        if(crypto_error_code > 402)
        {
            return CRYPTO_UNDEFINED_ERROR;
        }
        else
        {
            return crypto_enum_errlist_crypto_if[crypto_error_code % 400];
        }

    }
    else if(crypto_error_code >= 300) // SADB MariadDB Error Codes
    {
        if(crypto_error_code > 303)
        {
            return CRYPTO_UNDEFINED_ERROR;
        }
        else
        {
            return crypto_enum_errlist_sadb_mariadb[crypto_error_code % 300];
        }

    }
    else if(crypto_error_code >= 200) // SADB Interface Error Codes
    {
        if(crypto_error_code > 201)
        {
            return CRYPTO_UNDEFINED_ERROR;
        }
        else
        {
            return crypto_enum_errlist_sadb_if[crypto_error_code % 200];
        }
    }
    else if(crypto_error_code >= 100) // Configuration Error Codes
    {
        if(crypto_error_code > 103)
        {
            return CRYPTO_UNDEFINED_ERROR;
        }
        else
        {
            return crypto_enum_errlist_config[crypto_error_code % 100];
        }
    }
    else if(crypto_error_code > 0) // Unused Error Codes 1-100
    {
        return CRYPTO_UNDEFINED_ERROR;
    }
    else if(crypto_error_code <= 0) // Cryptolib Core Error Codes
    {
        if(crypto_error_code < -44)
        {
            return CRYPTO_UNDEFINED_ERROR;
        }
        else
        {
            return crypto_enum_errlist_core[(crypto_error_code * (-1))];
        }
    }
    else
    {
        return CRYPTO_UNDEFINED_ERROR;
    }
}