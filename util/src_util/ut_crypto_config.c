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

/**
 *  Unit Tests that macke use of CRYPTO_CONFIG functionality on the data.
 **/
#include "ut_crypto_config.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

/**
 * @brief Unit Test: Crypto Init with incomplete configuration
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_WITH_INCOMPLETE_CONFIG)
{
    // Make use of Crypto_Init_With_Configs
    int32_t status = CRYPTO_LIB_ERROR;
    CryptoConfig_t* crypto_config_p = NULL;
    GvcidManagedParameters_t* gvcid_managed_paramenters_p = NULL;
    SadbMariaDBConfig_t* sadb_mariadb_config_p = NULL;
    CryptographyKmcCryptoServiceConfig_t* cryptography_kmc_crypto_config_p = NULL;

    status = Crypto_Init_With_Configs(crypto_config_p, gvcid_managed_paramenters_p, sadb_mariadb_config_p, cryptography_kmc_crypto_config_p);
    ASSERT_EQ(CRYPTO_CONFIGURATION_NOT_COMPLETE, status);
}

/**
 * @brief Unit Test: Crypto Init with no managed parameters configuration
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_NO_MANAGED_PARAM_CONFIG)
{
    int32_t status = CRYPTO_LIB_ERROR;
    CryptoConfig_t* crypto_config_p = malloc(sizeof(CryptoConfig_t) * sizeof(uint8_t));
    GvcidManagedParameters_t* gvcid_managed_paramenters_p = NULL;
    SadbMariaDBConfig_t* sadb_mariadb_config_p = NULL;
    CryptographyKmcCryptoServiceConfig_t* cryptography_kmc_crypto_config_p = NULL;
    status = Crypto_Init_With_Configs(crypto_config_p, gvcid_managed_paramenters_p, sadb_mariadb_config_p, cryptography_kmc_crypto_config_p);
    free(crypto_config_p);
    ASSERT_EQ(CRYPTO_MANAGED_PARAM_CONFIGURATION_NOT_COMPLETE, status);
}

/**
 * @brief Unit Test: Crypto Init with NULL Maria DB
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_MARIADB_NULL)
{
    int32_t status = CRYPTO_LIB_ERROR;
    CryptoConfig_t* crypto_config_p = malloc(sizeof(CryptoConfig_t) * sizeof(uint8_t));
    GvcidManagedParameters_t* gvcid_managed_paramenters_p = malloc(sizeof(GvcidManagedParameters_t));
    gvcid_managed_paramenters_p->next = NULL;
    SadbMariaDBConfig_t* sadb_mariadb_config_p = NULL;
    CryptographyKmcCryptoServiceConfig_t* cryptography_kmc_crypto_config_p = NULL;

    crypto_config->sadb_type = SADB_TYPE_MARIADB;
    status = Crypto_Init_With_Configs(crypto_config_p, gvcid_managed_paramenters_p, sadb_mariadb_config_p, cryptography_kmc_crypto_config_p);
 
    free(crypto_config_p);
    free(gvcid_managed_paramenters_p);
    ASSERT_EQ(CRYPTO_MARIADB_CONFIGURATION_NOT_COMPLETE, status);
}

/**
 * @brief Unit Test: Crypto Init with NULL KMC Crypto configuration
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_KMCCRYPTO_NULL)
{
    int32_t status = CRYPTO_LIB_ERROR;
    CryptoConfig_t* crypto_config_p = malloc(sizeof(CryptoConfig_t) * sizeof(uint8_t));
    GvcidManagedParameters_t* gvcid_managed_paramenters_p = malloc(sizeof(GvcidManagedParameters_t));
    gvcid_managed_paramenters_p->next = NULL;
    SadbMariaDBConfig_t* sadb_mariadb_config_p = malloc(sizeof(SadbMariaDBConfig_t) * sizeof(uint8_t));
    CryptographyKmcCryptoServiceConfig_t* cryptography_kmc_crypto_config_p = NULL;

    crypto_config->sadb_type = SADB_TYPE_MARIADB;
    crypto_config->cryptography_type = CRYPTOGRAPHY_TYPE_KMCCRYPTO;

    status = Crypto_Init_With_Configs(crypto_config_p, gvcid_managed_paramenters_p, sadb_mariadb_config_p, cryptography_kmc_crypto_config_p);
    free(crypto_config_p);
    free(gvcid_managed_paramenters_p);
    free(sadb_mariadb_config_p);
    ASSERT_EQ(CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIGURATION_NOT_COMPLETE, status);
}

/**
 * @brief Unit Test: Crypto Init with Invalid Interface
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_INVALID_INTERFACE)
{
    int32_t status = CRYPTO_LIB_ERROR;
    CryptoConfig_t* crypto_config_p = malloc(sizeof(CryptoConfig_t) * sizeof(uint8_t));
    GvcidManagedParameters_t* gvcid_managed_paramenters_p = malloc(sizeof(GvcidManagedParameters_t));
    gvcid_managed_paramenters_p->next = NULL;
    SadbMariaDBConfig_t* sadb_mariadb_config_p = malloc(sizeof(SadbMariaDBConfig_t) * sizeof(uint8_t));
    CryptographyKmcCryptoServiceConfig_t* cryptography_kmc_crypto_config_p = NULL;

    crypto_config->sadb_type = SADB_TYPE_MARIADB;
    crypto_config->cryptography_type = 2; // Currently an invalid ENUM

    status = Crypto_Init_With_Configs(crypto_config_p, gvcid_managed_paramenters_p, sadb_mariadb_config_p, cryptography_kmc_crypto_config_p);
    free(crypto_config_p);
    free(gvcid_managed_paramenters_p);
    free(sadb_mariadb_config_p);
    ASSERT_EQ(CRYPTOGRAPHY_INVALID_CRYPTO_INTERFACE_TYPE, status);
}

/**
 * @brief Unit Test: Crypto Init with invalid SADB
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_INVALID_SADB)
{
    int32_t status = CRYPTO_LIB_ERROR;
    CryptoConfig_t* crypto_config_p = malloc(sizeof(CryptoConfig_t) * sizeof(uint8_t));
    GvcidManagedParameters_t* gvcid_managed_paramenters_p = malloc(sizeof(GvcidManagedParameters_t) * sizeof(uint8_t));
    gvcid_managed_paramenters_p->next = NULL;
    SadbMariaDBConfig_t* sadb_mariadb_config_p = malloc(sizeof(SadbMariaDBConfig_t) * sizeof(uint8_t));
    CryptographyKmcCryptoServiceConfig_t* cryptography_kmc_crypto_config_p = NULL;

    crypto_config->sadb_type = 2; // Currently an invalid ENUM
    crypto_config->cryptography_type = 2; // Currently an invalid ENUM

    status = Crypto_Init_With_Configs(crypto_config_p, gvcid_managed_paramenters_p, sadb_mariadb_config_p, cryptography_kmc_crypto_config_p);
    free(crypto_config_p);
    free(gvcid_managed_paramenters_p);
    free(sadb_mariadb_config_p);
    ASSERT_EQ(SADB_INVALID_SADB_TYPE, status);
}

/**
 * @brief Unit Test: Crypto Init with incomplete configuration
 * @note TODO: Not able to force the Crypto_Lib_Error ATM
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_CONFIG_MDB)
{
    int32_t status = CRYPTO_LIB_ERROR;
    char* mysql_username = "ITC_JPL";
    char* mysql_password = "ITC_JPL";
    char* mysql_hostname = "ITC_JPL";
    char* mysql_database = "ITC_JPL";
    uint16_t mysql_port = 9999;
    char* ssl_cert = "NONE";
    char* ssl_key = "NONE";
    char* ssl_ca = "NONE";
    char* ssl_capath = "NONE";
    uint8_t verify_server = 0; 
    char* client_key_password = NULL;
    status = Crypto_Config_MariaDB(mysql_hostname, mysql_database, mysql_port, CRYPTO_FALSE, verify_server, ssl_ca,
                                   ssl_capath, ssl_cert, ssl_key, client_key_password, mysql_username, mysql_password);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Crypto KMC Configuration
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_CONFIG_KMC)
{
    int32_t status = CRYPTO_LIB_ERROR;
    char* protocol = "https";
    char* hostname = "ITC_JPL";
    int16_t port = 9999;

    char* kmc_crypto_app_uri = "crypto-service";
    char* mtls_client_cert_path = "/dev/null";
    char* mtls_client_cert_type = "PEM";
    char* mtls_client_key_path = "/dev/null";
    char* mtls_client_key_pass = "12345";
    char* mtls_ca_bundle = "/dev/null";
    char* mtls_ca_path = "/dev/null";
    char* mtls_issuer_cert = "/dev/null";
    uint8_t ignore_ssl_hostname_validation = CRYPTO_TRUE;

    status = Crypto_Config_Kmc_Crypto_Service(protocol, hostname, port, kmc_crypto_app_uri, mtls_ca_bundle,
                                              mtls_ca_path, ignore_ssl_hostname_validation, mtls_client_cert_path,
                                              mtls_client_cert_type, mtls_client_key_path,
                                              mtls_client_key_pass, mtls_issuer_cert);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

#ifdef TODO_NEEDSWORK
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_KMC_OK)
{
    int32_t status = CRYPTO_LIB_ERROR;
    CryptoConfig_t* crypto_config_p = malloc(sizeof(CryptoConfig_t) * sizeof(uint8_t));
    GvcidManagedParameters_t* gvcid_managed_paramenters_p = malloc(sizeof(GvcidManagedParameters_t) * sizeof(uint8_t));
    SadbMariaDBConfig_t* sadb_mariadb_config_p = malloc(sizeof(SadbMariaDBConfig_t) * sizeof(uint8_t));
    CryptographyKmcCryptoServiceConfig_t* cryptography_kmc_crypto_config_p = malloc(sizeof(CryptographyKmcCryptoServiceConfig_t) * sizeof(uint8_t));

    crypto_config->sadb_type = SADB_TYPE_MARIADB;
    crypto_config->cryptography_type = CRYPTOGRAPHY_TYPE_KMCCRYPTO;

    status = Crypto_Init_With_Configs(crypto_config_p, gvcid_managed_paramenters_p, sadb_mariadb_config_p, cryptography_kmc_crypto_config_p);
    free(crypto_config_p);
    free(gvcid_managed_paramenters_p);
    free(sadb_mariadb_config_p);
    free(cryptography_kmc_crypto_config_p);
    ASSERT_EQ(CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIGURATION_NOT_COMPLETE, status);
}
#endif

UTEST_MAIN();