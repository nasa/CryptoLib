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

#define CRYPTO_UNDEFINED_ERROR (char *)"CRYPTO_UNDEFINED_ERROR_CODE"

char *crypto_enum_errlist_core[] = {(char *)"CRYPTO_LIB_SUCCESS",
                                    (char *)"CRYPTO_LIB_ERROR",
                                    (char *)"CRYPTO_LIB_ERR_NO_INIT",
                                    (char *)"CRYPTO_LIB_ERR_INVALID_TFVN",
                                    (char *)"CRYPTO_LIB_ERR_INVALID_SCID",
                                    (char *)"CRYPTO_LIB_ERR_INVALID_VCID",
                                    (char *)"CRYPTO_LIB_ERR_INVALID_MAPID",
                                    (char *)"CRYPTO_LIB_ERR_INVALID_CC_FLAG",
                                    (char *)"CRYPTO_LIB_ERR_NO_OPERATIONAL_SA",
                                    (char *)"CRYPTO_LIB_ERR_NULL_BUFFER",
                                    (char *)"CRYPTO_LIB_ERR_UT_BYTE_MISMATCH",
                                    (char *)"CRYPTO_LIB_ERR_NO_CONFIG",
                                    (char *)"CRYPTO_LIB_ERR_INVALID_FECF",
                                    (char *)"CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW",
                                    (char *)"CRYPTO_LIB_ERR_LIBGCRYPT_ERROR",
                                    (char *)"CRYPTO_LIB_ERR_AUTHENTICATION_ERROR",
                                    (char *)"CRYPTO_LIB_ERR_NULL_IV",
                                    (char *)"CRYPTO_LIB_ERR_NULL_ABM",
                                    (char *)"CRYPTO_LIB_ERR_DECRYPT_ERROR",
                                    (char *)"CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD",
                                    (char *)"CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR",
                                    (char *)"CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR",
                                    (char *)"CRYPTO_LIB_ERR_INVALID_HEADER",
                                    (char *)"CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW",
                                    (char *)"CRYPTO_LIB_ERR_NULL_ARSN",
                                    (char *)"CRYPTO_LIB_ERR_NULL_SA",
                                    (char *)"CRYPTO_LIB_ERR_UNSUPPORTED_ACS",
                                    (char *)"CRYPTO_LIB_ERR_ENCRYPTION_ERROR",
                                    (char *)"CRYPTO_LIB_ERR_INVALID_SA_CONFIGURATION",
                                    (char *)"CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_MANAGED_PARAM_MAX_LIMIT",
                                    (char *)"CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_SPEC_LIMIT",
                                    (char *)"CRYPTO_LIB_ERR_UNSUPPORTED_ECS",
                                    (char *)"CRYPTO_LIB_ERR_KEY_LENGTH_ERROR",
                                    (char *)"CRYPTO_LIB_ERR_NULL_ECS_PTR",
                                    (char *)"CRYPTO_LIB_ERR_IV_NOT_SUPPORTED_FOR_ACS_ALGO",
                                    (char *)"CRYPTO_LIB_ERR_NULL_CIPHERS",
                                    (char *)"CRYPTO_LIB_ERR_NO_ECS_SET_FOR_ENCRYPTION_MODE",
                                    (char *)"CRYPTO_LIB_ERR_IV_LEN_SHORTER_THAN_SEC_HEADER_LENGTH",
                                    (char *)"CRYPTO_LIB_ERR_ARSN_LEN_SHORTER_THAN_SEC_HEADER_LENGTH",
                                    (char *)"CRYPTO_LIB_ERR_FRAME_COUNTER_DOESNT_MATCH_SA",
                                    (char *)"CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TC_STANDARD",
                                    (char *)"CRYPTO_LIB_ERR_INPUT_FRAME_LENGTH_SHORTER_THAN_FRAME_HEADERS_LENGTH",
                                    (char *)"CRYPTO_LIB_ERR_UNSUPPORTED_ECS_MODE",
                                    (char *)"CRYPTO_LIB_ERR_NULL_MODE_PTR",
                                    (char *)"CRYPTO_LIB_ERR_UNSUPPORTED_MODE",
                                    (char *)"CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TM_STANDARD",
                                    (char *)"CRYPTO_LIB_ERR_TC_ENUM_USED_FOR_TM_CONFIG",
                                    (char *)"CRYPTO_LIB_ERR_KEY_ID_ERROR",
                                    (char *)"CRYPTO_LIB_ERR_MC_INIT",
                                    (char *)"CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_AOS_STANDARD",
                                    (char *)"CRYPTO_LIB_ERR_TC_ENUM_USED_FOR_AOS_CONFIG",
                                    (char *)"CRYPTO_LIB_ERR_INVALID_SA_SERVICE_TYPE",
                                    (char *)"CRYPTO_LIB_ERR_FAIL_SA_SAVE",
                                    (char *)"CRYPTO_LIB_ERR_FAIL_SA_LOAD",
                                    (char *)"CRYPTO_LIB_ERR_EXCEEDS_MANAGED_PARAMETER_MAX_LIMIT",
                                    (char *)"CRYPTO_LIB_ERR_KEY_VALIDATION",
                                    (char *)"CRYPTO_LIB_ERR_SPI_INDEX_OOB",
                                    (char *)"CRYPTO_LIB_ERR_SA_NOT_OPERATIONAL",
                                    (char *)"CRYPTO_LIB_ERR_IV_GREATER_THAN_MAX_LENGTH",
                                    (char *)"CRYPTO_LIB_ERR_KEY_STATE_TRANSITION_ERROR",
                                    (char *)"CRYPTO_LIB_ERR_SPI_INDEX_MISMATCH",
                                    (char *)"CRYPTO_LIB_ERR_KEY_STATE_INVALID",
                                    (char *)"CRYPTO_LIB_ERR_SDLS_EP_WRONG_SPI",
                                    (char *)"CRYPTO_LIB_ERR_SDLS_EP_NOT_BUILT"};

char *crypto_enum_errlist_config[] = {
    (char *)"CRYPTO_CONFIGURATION_NOT_COMPLETE",
    (char *)"CRYPTO_MANAGED_PARAM_CONFIGURATION_NOT_COMPLETE",
    (char *)"CRYPTO_MARIADB_CONFIGURATION_NOT_COMPLETE",
    (char *)"MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND",
};

char *crypto_enum_errlist_sa_if[] = {
    (char *)"SADB_INVALID_SADB_TYPE",
    (char *)"SADB_NULL_SA_USED",
};
char *crypto_enum_errlist_sa_mariadb[] = {
    (char *)"SADB_MARIADB_CONNECTION_FAILED",
    (char *)"SADB_QUERY_FAILED",
    (char *)"SADB_QUERY_EMPTY_RESULTS",
    (char *)"SADB_INSERT_FAILED",
};
char *crypto_enum_errlist_crypto_if[] = {
    (char *)"CRYPTOGRAPHY_INVALID_CRYPTO_INTERFACE_TYPE",
    (char *)"CRYPTOGRAPHY_UNSUPPORTED_OPERATION_FOR_KEY_RING",
    (char *)"CRYPTOGRAPHY_LIBRARY_INITIALIZIATION_ERROR",
};
char *crypto_enum_errlist_crypto_kmc[] = {
    (char *)"CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIGURATION_NOT_COMPLETE",
    (char *)"CRYPTOGRAPHY_KMC_CURL_INITIALIZATION_FAILURE",
    (char *)"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_CONNECTION_ERROR",
    (char *)"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AEAD_ENCRYPT_ERROR",
    (char *)"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AEAD_DECRYPT_ERROR",
    (char *)"CRYPTOGRAHPY_KMC_CRYPTO_JSON_PARSE_ERROR",
    (char *)"CRYPTOGRAHPY_KMC_CIPHER_TEXT_NOT_FOUND_IN_JSON_RESPONSE",
    (char *)"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE",
    (char *)"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AUTHENTICATION_ERROR",
    (char *)"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_MAC_VALIDATION_ERROR",
    (char *)"CRYPTOGRAHPY_KMC_ICV_NOT_FOUND_IN_JSON_RESPONSE",
    (char *)"CRYPTOGRAHPY_KMC_NULL_ENCRYPTION_KEY_REFERENCE_IN_SA",
    (char *)"CRYPTOGRAHPY_KMC_NULL_AUTHENTICATION_KEY_REFERENCE_IN_SA",
    (char *)"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_EMPTY_RESPONSE",
    (char *)"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_DECRYPT_ERROR",
    (char *)"CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_ENCRYPT_ERROR",
};

char *crypto_enum_errlist_crypto_cam[] = {
    (char *)"CAM_CONFIG_NOT_SUPPORTED_ERROR",
    (char *)"CAM_INVALID_COOKIE_FILE_CONFIGURATION_NULL",
    (char *)"CAM_AUTHENTICATION_FAILURE_REDIRECT",
    (char *)"CAM_AUTHENTICATION_REQUIRED",
    (char *)"CAM_GET_SSO_TOKEN_FAILURE",
    (char *)"CAM_INVALID_CONFIGURATION_ACCESS_MANAGER_URI_NULL",
    (char *)"CAM_INVALID_CONFIGURATION_KEYTAB_FILE_PATH_NULL",
    (char *)"CAM_INVALID_CONFIGURATION_KEYTAB_FILE_USERNAME_NULL",
    (char *)"CAM_KEYTAB_FILE_KINIT_FAILURE",
    (char *)"CAM_KERBEROS_REQUEST_TIME_OUT",
    (char *)"CAM_MAX_AUTH_RETRIES_REACHED",
};

/*
** @brief: Helper Function. Get specific error code, given code, allowable max, and valid string expansion
** @param: int32_t, int32_t, char*
* @return: char*
*/
char *Crypto_Get_Crypto_Error_Code_String(int32_t crypto_error_code, int32_t crypto_error_code_max,
                                          char *valid_output_string)
{
    if (crypto_error_code < crypto_error_code_max)
    {
        return CRYPTO_UNDEFINED_ERROR;
    }
    return valid_output_string;
}

/*
** @brief: Helper Function. Get specific error code, given code, allowable max, and valid string expansion
** @param: int32_t, int32_t, char*
* @return: char*
*/
char *Crypto_Get_Error_Code_String(int32_t crypto_error_code, int32_t crypto_error_code_max, char *valid_output_string)
{
    if (crypto_error_code > crypto_error_code_max)
    {
        return CRYPTO_UNDEFINED_ERROR;
    }
    return valid_output_string;
}

/*
** @brief: For a given crypto error code, return the associated error code enum string
** @param: int32_t
* @return: char*
*/
char *Crypto_Get_Error_Code_Enum_String(int32_t crypto_error_code)
{
    char *return_string = CRYPTO_UNDEFINED_ERROR;
    if (crypto_error_code >= CAM_ERROR_CODES) // CAM Error Codes
    {
        return_string =
            Crypto_Get_Error_Code_String(crypto_error_code, CAM_ERROR_CODES_MAX,
                                         crypto_enum_errlist_crypto_cam[crypto_error_code - CAM_ERROR_CODES]);
    }
    else if (crypto_error_code >= KMC_ERROR_CODES) // KMC Error Codes
    {
        return_string =
            Crypto_Get_Error_Code_String(crypto_error_code, KMC_ERROR_CODES_MAX,
                                         crypto_enum_errlist_crypto_kmc[crypto_error_code - KMC_ERROR_CODES]);
    }
    else if (crypto_error_code >= CRYPTO_INTERFACE_ERROR_CODES) // Crypto Interface Error Codes
    {
        return_string = Crypto_Get_Error_Code_String(
            crypto_error_code, CRYPTO_INTERFACE_ERROR_CODES_MAX,
            crypto_enum_errlist_crypto_if[crypto_error_code - CRYPTO_INTERFACE_ERROR_CODES]);
    }
    else if (crypto_error_code >= SADB_ERROR_CODES) // SADB MariadDB Error Codes
    {
        return_string =
            Crypto_Get_Error_Code_String(crypto_error_code, SADB_ERROR_CODES_MAX,
                                         crypto_enum_errlist_sa_mariadb[crypto_error_code - SADB_ERROR_CODES]);
    }
    else if (crypto_error_code >= SADB_ERROR_CODES) // SADB Interface Error Codes
    {
        return_string = Crypto_Get_Error_Code_String(crypto_error_code, SADB_INTERFACE_ERROR_CODES_MAX,
                                                     crypto_enum_errlist_sa_if[crypto_error_code - SADB_ERROR_CODES]);
    }
    else if (crypto_error_code >= CONFIGURATION_ERROR_CODES) // Configuration Error Codes
    {
        return_string =
            Crypto_Get_Error_Code_String(crypto_error_code, CONFIGURATION_ERROR_CODES_MAX,
                                         crypto_enum_errlist_config[crypto_error_code - CONFIGURATION_ERROR_CODES]);
    }
    else if (crypto_error_code <= 0) // Cryptolib Core Error Codes
    {
        return_string = Crypto_Get_Crypto_Error_Code_String(
            crypto_error_code, CRYPTO_CORE_ERROR_CODES_MAX,
            crypto_enum_errlist_core[(crypto_error_code * (-1))]); // Cryptolib uses negative error return codes.
    }
    return return_string;
}