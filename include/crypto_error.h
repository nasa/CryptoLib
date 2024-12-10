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
#ifndef CRYPTO_ERROR_H
#define CRYPTO_ERROR_H

/*
 *  *** IMPORTANT READ ***
 *  If error codes are added to this header file, their enum string must be added to the error lists (in crypto_error.c)
 *  AND the appropriate _ERROR_CODE_MAX must be updated below!
 */

#define CRYPTO_CONFIGURATION_NOT_COMPLETE               100
#define CRYPTO_MANAGED_PARAM_CONFIGURATION_NOT_COMPLETE 101
#define CRYPTO_MARIADB_CONFIGURATION_NOT_COMPLETE       102
#define MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND          103

#define SADB_INVALID_SADB_TYPE 200
#define SADB_NULL_SA_USED      201

#define SADB_MARIADB_CONNECTION_FAILED 300
#define SADB_QUERY_FAILED              301
#define SADB_QUERY_EMPTY_RESULTS       302
#define SADB_INSERT_FAILED             303

#define CRYPTOGRAPHY_INVALID_CRYPTO_INTERFACE_TYPE      400
#define CRYPTOGRAPHY_UNSUPPORTED_OPERATION_FOR_KEY_RING 401
#define CRYPTOGRAPHY_LIBRARY_INITIALIZIATION_ERROR      402

#define CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIGURATION_NOT_COMPLETE 500
#define CRYPTOGRAPHY_KMC_CURL_INITIALIZATION_FAILURE               501
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_CONNECTION_ERROR           502
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AEAD_ENCRYPT_ERROR         503
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AEAD_DECRYPT_ERROR         504
#define CRYPTOGRAHPY_KMC_CRYPTO_JSON_PARSE_ERROR                   505
#define CRYPTOGRAHPY_KMC_CIPHER_TEXT_NOT_FOUND_IN_JSON_RESPONSE    506
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE            507
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AUTHENTICATION_ERROR       508
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_MAC_VALIDATION_ERROR       509
#define CRYPTOGRAHPY_KMC_ICV_NOT_FOUND_IN_JSON_RESPONSE            510
#define CRYPTOGRAHPY_KMC_NULL_ENCRYPTION_KEY_REFERENCE_IN_SA       511
#define CRYPTOGRAHPY_KMC_NULL_AUTHENTICATION_KEY_REFERENCE_IN_SA   512
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_EMPTY_RESPONSE             513
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_DECRYPT_ERROR              514
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_ENCRYPT_ERROR              515

#define CAM_CONFIG_NOT_SUPPORTED_ERROR                      600
#define CAM_INVALID_COOKIE_FILE_CONFIGURATION_NULL          601
#define CAM_AUTHENTICATION_FAILURE_REDIRECT                 602
#define CAM_AUTHENTICATION_REQUIRED                         603
#define CAM_GET_SSO_TOKEN_FAILURE                           604
#define CAM_INVALID_CONFIGURATION_ACCESS_MANAGER_URI_NULL   605
#define CAM_INVALID_CONFIGURATION_KEYTAB_FILE_PATH_NULL     606
#define CAM_INVALID_CONFIGURATION_KEYTAB_FILE_USERNAME_NULL 607
#define CAM_KEYTAB_FILE_KINIT_FAILURE                       608
#define CAM_KERBEROS_REQUEST_TIME_OUT                       609
#define CAM_MAX_AUTH_RETRIES_REACHED                        610

#define CRYPTO_LIB_SUCCESS                                                  (0)
#define CRYPTO_LIB_ERROR                                                    (-1)
#define CRYPTO_LIB_ERR_NO_INIT                                              (-2)
#define CRYPTO_LIB_ERR_INVALID_TFVN                                         (-3)
#define CRYPTO_LIB_ERR_INVALID_SCID                                         (-4)
#define CRYPTO_LIB_ERR_INVALID_VCID                                         (-5)
#define CRYPTO_LIB_ERR_INVALID_MAPID                                        (-6)
#define CRYPTO_LIB_ERR_INVALID_CC_FLAG                                      (-7)
#define CRYPTO_LIB_ERR_NO_OPERATIONAL_SA                                    (-8)
#define CRYPTO_LIB_ERR_NULL_BUFFER                                          (-9)
#define CRYPTO_LIB_ERR_UT_BYTE_MISMATCH                                     (-10)
#define CRYPTO_LIB_ERR_NO_CONFIG                                            (-11)
#define CRYPTO_LIB_ERR_INVALID_FECF                                         (-12)
#define CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW                                  (-13)
#define CRYPTO_LIB_ERR_LIBGCRYPT_ERROR                                      (-14)
#define CRYPTO_LIB_ERR_AUTHENTICATION_ERROR                                 (-15)
#define CRYPTO_LIB_ERR_NULL_IV                                              (-16)
#define CRYPTO_LIB_ERR_NULL_ABM                                             (-17)
#define CRYPTO_LIB_ERR_DECRYPT_ERROR                                        (-18)
#define CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD                                (-19)
#define CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR                                  (-20)
#define CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR                                 (-21)
#define CRYPTO_LIB_ERR_INVALID_HEADER                                       (-22)
#define CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW                                    (-23)
#define CRYPTO_LIB_ERR_NULL_ARSN                                            (-24)
#define CRYPTO_LIB_ERR_NULL_SA                                              (-25)
#define CRYPTO_LIB_ERR_UNSUPPORTED_ACS                                      (-26)
#define CRYPTO_LIB_ERR_ENCRYPTION_ERROR                                     (-27)
#define CRYPTO_LIB_ERR_INVALID_SA_CONFIGURATION                             (-28)
#define CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_MANAGED_PARAM_MAX_LIMIT        (-29)
#define CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_SPEC_LIMIT                     (-30)
#define CRYPTO_LIB_ERR_UNSUPPORTED_ECS                                      (-31)
#define CRYPTO_LIB_ERR_KEY_LENGTH_ERROR                                     (-32)
#define CRYPTO_LIB_ERR_NULL_ECS_PTR                                         (-33)
#define CRYPTO_LIB_ERR_IV_NOT_SUPPORTED_FOR_ACS_ALGO                        (-34)
#define CRYPTO_LIB_ERR_NULL_CIPHERS                                         (-35)
#define CRYPTO_LIB_ERR_NO_ECS_SET_FOR_ENCRYPTION_MODE                       (-36)
#define CRYPTO_LIB_ERR_IV_LEN_SHORTER_THAN_SEC_HEADER_LENGTH                (-37)
#define CRYPTO_LIB_ERR_ARSN_LEN_SHORTER_THAN_SEC_HEADER_LENGTH              (-38)
#define CRYPTO_LIB_ERR_FRAME_COUNTER_DOESNT_MATCH_SA                        (-39)
#define CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TC_STANDARD                (-40)
#define CRYPTO_LIB_ERR_INPUT_FRAME_LENGTH_SHORTER_THAN_FRAME_HEADERS_LENGTH (-41)
#define CRYPTO_LIB_ERR_UNSUPPORTED_ECS_MODE                                 (-42)
#define CRYPTO_LIB_ERR_NULL_MODE_PTR                                        (-43)
#define CRYPTO_LIB_ERR_UNSUPPORTED_MODE                                     (-44)
#define CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TM_STANDARD                (-45)
#define CRYPTO_LIB_ERR_TC_ENUM_USED_FOR_TM_CONFIG                           (-46)
#define CRYPTO_LIB_ERR_KEY_ID_ERROR                                         (-47)
#define CRYPTO_LIB_ERR_MC_INIT                                              (-48)
#define CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_AOS_STANDARD               (-49)
#define CRYPTO_LIB_ERR_TC_ENUM_USED_FOR_AOS_CONFIG                          (-50)
#define CRYPTO_LIB_ERR_INVALID_SA_SERVICE_TYPE                              (-51)
#define CRYPTO_LIB_ERR_FAIL_SA_SAVE                                         (-52)
#define CRYPTO_LIB_ERR_FAIL_SA_LOAD                                         (-53)
#define CRYPTO_LIB_ERR_EXCEEDS_MANAGED_PARAMETER_MAX_LIMIT                  (-54)
#define CRYPTO_LIB_ERR_KEY_VALIDATION                                       (-55)
#define CRYPTO_LIB_ERR_SPI_INDEX_OOB                                        (-56)
#define CRYPTO_LIB_ERR_SA_NOT_OPERATIONAL                                   (-57)
#define CRYPTO_LIB_ERR_IV_GREATER_THAN_MAX_LENGTH                           (-58)
#define CRYPTO_LIB_ERR_KEY_STATE_TRANSITION_ERROR                           (-59)
#define CRYPTO_LIB_ERR_SPI_INDEX_MISMATCH                                   (-60)
#define CRYPTO_LIB_ERR_KEY_STATE_INVALID                                    (-61)
#define CRYPTO_LIB_ERR_SDLS_EP_WRONG_SPI                                    (-62)
#define CRYPTO_LIB_ERR_SDLS_EP_NOT_BUILT                                    (-63)

#define CRYPTO_CORE_ERROR_CODES_MAX -63

// Define codes for returning MDB Strings, and determining error based on strings
#define CAM_ERROR_CODES     600
#define CAM_ERROR_CODES_MAX 610

#define KMC_ERROR_CODES     500
#define KMC_ERROR_CODES_MAX 515

#define CRYPTO_INTERFACE_ERROR_CODES     400
#define CRYPTO_INTERFACE_ERROR_CODES_MAX 402

#define SADB_ERROR_CODES     300
#define SADB_ERROR_CODES_MAX 303

#define SADB_INTERFACE_ERROR_CODES     200
#define SADB_INTERFACE_ERROR_CODES_MAX 201

#define CONFIGURATION_ERROR_CODES     100
#define CONFIGURATION_ERROR_CODES_MAX 103

extern char *crypto_enum_errlist_core[];
extern char *crypto_enum_errlist_config[];
extern char *crypto_enum_errlist_sa_if[];
extern char *crypto_enum_errlist_sa_mariadb[];
extern char *crypto_enum_errlist_crypto_if[];
extern char *crypto_enum_errlist_crypto_kmc[];
extern char *crypto_enum_errlist_crypto_cam[];

#endif // CRYPTO_ERROR_H