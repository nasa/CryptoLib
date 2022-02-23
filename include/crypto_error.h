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
#ifndef _crypto_error_h_
#define _crypto_error_h_

#define SADB_INVALID_SADB_TYPE 201
#define SADB_NULL_SA_USED 202
#define CRYPTO_CONFIGURATION_NOT_COMPLETE 101
#define CRYPTO_MANAGED_PARAM_CONFIGURATION_NOT_COMPLETE 102
#define CRYPTO_MARIADB_CONFIGURATION_NOT_COMPLETE 103
#define MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND 104

#define SADB_MARIADB_CONNECTION_FAILED 300
#define SADB_QUERY_FAILED 301
#define SADB_QUERY_EMPTY_RESULTS 302
#define SADB_INSERT_FAILED 303

#define CRYPTOGRAPHY_INVALID_CRYPTO_INTERFACE_TYPE  400
#define CRYPTOGRAPHY_UNSUPPORTED_OPERATION_FOR_KEY_RING 401
#define CRYPTOGRAPHY_LIBRARY_INITIALIZIATION_ERROR 402

#define CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIGURATION_NOT_COMPLETE 501
#define CRYPTOGRAPHY_KMC_CURL_INITIALIZATION_FAILURE 502
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_CONNECTION_ERROR 503
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AEAD_ENCRYPT_ERROR 504
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AEAD_DECRYPT_ERROR 505
#define CRYPTOGRAHPY_KMC_CRYPTO_JSON_PARSE_ERROR 506
#define CRYPTOGRAHPY_KMC_CIPHER_TEXT_NOT_FOUND_IN_JSON_RESPONSE 507
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE 508
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_AUTHENTICATION_ERROR 509
#define CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_MAC_VALIDATION_ERROR 510
#define CRYPTOGRAHPY_KMC_ICV_NOT_FOUND_IN_JSON_RESPONSE 511



#define CRYPTO_LIB_SUCCESS (0)
#define CRYPTO_LIB_ERROR (-1)
#define CRYPTO_LIB_ERR_NO_INIT (-2)
#define CRYPTO_LIB_ERR_INVALID_TFVN (-3)
#define CRYPTO_LIB_ERR_INVALID_SCID (-4)
#define CRYPTO_LIB_ERR_INVALID_VCID (-5)
#define CRYPTO_LIB_ERR_INVALID_MAPID (-6)
#define CRYPTO_LIB_ERR_INVALID_CC_FLAG (-7)
#define CRYPTO_LIB_ERR_NO_OPERATIONAL_SA (-8)
#define CRYPTO_LIB_ERR_NULL_BUFFER (-9)
#define CRYPTO_LIB_ERR_UT_BYTE_MISMATCH (-10)
#define CRYPTO_LIB_ERR_NO_CONFIG (-11)
#define CRYPTO_LIB_ERR_INVALID_FECF (-12)
#define CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW (-13)
#define CRYPTO_LIB_ERR_LIBGCRYPT_ERROR (-14)
#define CRYPTO_LIB_ERR_AUTHENTICATION_ERROR (-15)
#define CRYPTO_LIB_ERR_NULL_IV (-16)
#define CRYPTO_LIB_ERR_NULL_ABM (-17)
#define CRYPTO_LIB_ERR_DECRYPT_ERROR (-18)
#define CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD (-19)
#define CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR (-20)
#define CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR (-21)
#define CRYPTO_LIB_ERR_INVALID_HEADER (-22)
#define CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW (-23)
#define CRYPTO_LIB_ERR_NULL_ARSN (-24)

#endif //_crypto_error_h_
