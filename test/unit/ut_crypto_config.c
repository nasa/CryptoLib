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
#include "sa_interface.h"
#include "utest.h"

/**
 * @brief Unit Test: Crypto Init with incomplete configuration
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_WITH_INCOMPLETE_CONFIG)
{
    remove("sa_save_file.bin");
    int32_t status = CRYPTO_LIB_ERROR;
    status         = Crypto_Init();
    ASSERT_EQ(CRYPTO_CONFIGURATION_NOT_COMPLETE, status);
}

/**
 * @brief Unit Test: Crypto Init with no managed parameters configuration
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_NO_MANAGED_PARAM_CONFIG)
{
    remove("sa_save_file.bin");
    int32_t                               status                           = CRYPTO_LIB_ERROR;
    CryptoConfigGlobal_t                 *crypto_config_p                  = malloc(CRYPTO_GLOBAL_CONFIG_SIZE);
    TCGvcidManagedParameters_t            gvcid_managed_paramenters_p      = {0, 0, 0, 0, 0, 0, 0};
    SadbMariaDBConfig_t                  *sa_mariadb_config_p              = NULL;
    CryptographyKmcCryptoServiceConfig_t *cryptography_kmc_crypto_config_p = NULL;
    status = Crypto_Init_With_Configs(crypto_config_p, &gvcid_managed_paramenters_p, sa_mariadb_config_p,
                                      cryptography_kmc_crypto_config_p);
    free(crypto_config_p);
    ASSERT_EQ(CRYPTO_MANAGED_PARAM_CONFIGURATION_NOT_COMPLETE, status);
}

/**
 * @brief Unit Test: Crypto Init with NULL Maria DB
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_MARIADB_NULL)
{
    remove("sa_save_file.bin");
    int32_t               status                           = CRYPTO_LIB_ERROR;
    CryptoConfigGlobal_t *crypto_config_p                  = malloc(CRYPTO_GLOBAL_CONFIG_SIZE);
    crypto_config_p->key_type                              = KEY_TYPE_INTERNAL;
    crypto_config_p->mc_type                               = MC_TYPE_INTERNAL;

    TCGvcidManagedParameters_t TC_UT_Managed_Parameters = {0, 0x0000, 0, TC_NO_FECF, TC_NO_SEGMENT_HDRS, 0, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);

    SadbMariaDBConfig_t                  *sa_mariadb_config_p              = NULL;
    CryptographyKmcCryptoServiceConfig_t *cryptography_kmc_crypto_config_p = NULL;

    crypto_config_p->sa_type = SA_TYPE_MARIADB;
    status = Crypto_Init_With_Configs(crypto_config_p, &tc_gvcid_managed_parameters_array[0], sa_mariadb_config_p,
                                      cryptography_kmc_crypto_config_p);

    free(crypto_config_p);
    ASSERT_EQ(CRYPTO_MARIADB_CONFIGURATION_NOT_COMPLETE, status);
    Crypto_Shutdown();
}

/**
 * @brief Unit Test: Crypto Init with invalid SADB
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_INIT_INVALID_SADB)
{
    remove("sa_save_file.bin");
    int32_t               status                           = CRYPTO_LIB_ERROR;
    CryptoConfigGlobal_t *crypto_config_p                  = malloc(CRYPTO_GLOBAL_CONFIG_SIZE);
    crypto_config_p->key_type                              = KEY_TYPE_INTERNAL;
    crypto_config_p->mc_type                               = MC_TYPE_INTERNAL;
    TCGvcidManagedParameters_t gvcid_managed_paramenters_p = {0, 0, 0, 0, 0, 0, 1}; 
    tc_gvcid_counter++;

    SadbMariaDBConfig_t                  *sa_mariadb_config_p = malloc(sizeof(SadbMariaDBConfig_t) * sizeof(uint8_t));
    CryptographyKmcCryptoServiceConfig_t *cryptography_kmc_crypto_config_p = NULL;

    crypto_config_p->sa_type           = 99; // Currently an invalid ENUM
    crypto_config_p->cryptography_type = 99; // Currently an invalid ENUM

    status = Crypto_Init_With_Configs(crypto_config_p, &gvcid_managed_paramenters_p, sa_mariadb_config_p,
                                      cryptography_kmc_crypto_config_p);
    free(crypto_config_p);
    free(sa_mariadb_config_p);
    ASSERT_EQ(SADB_INVALID_SADB_TYPE, status);
}

/**
 * @brief Unit Test: Crypto Init with incomplete configuration
 * @note TODO: Not able to force the Crypto_Lib_Error ATM
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_CONFIG_MDB)
{
    remove("sa_save_file.bin");
    int32_t  status              = CRYPTO_LIB_ERROR;
    char    *mysql_username      = "ITC_JPL";
    char    *mysql_password      = "ITC_JPL";
    char    *mysql_hostname      = "ITC_JPL";
    char    *mysql_database      = "ITC_JPL";
    uint16_t mysql_port          = 9999;
    char    *ssl_cert            = "NONE";
    char    *ssl_key             = "NONE";
    char    *ssl_ca              = "NONE";
    char    *ssl_capath          = "NONE";
    uint8_t  verify_server       = 0;
    char    *client_key_password = NULL;
    status = Crypto_Config_MariaDB(mysql_hostname, mysql_database, mysql_port, CRYPTO_FALSE, verify_server, ssl_ca,
                                   ssl_capath, ssl_cert, ssl_key, client_key_password, mysql_username, mysql_password);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Crypto KMC Configuration
 **/
UTEST(CRYPTO_CONFIG, CRYPTO_CONFIG_KMC)
{
    remove("sa_save_file.bin");
    int32_t status   = CRYPTO_LIB_ERROR;
    char   *protocol = "https";
    char   *hostname = "ITC_JPL";
    int16_t port     = 9999;

    char   *kmc_crypto_app_uri             = "crypto-service";
    char   *mtls_client_cert_path          = "/dev/null";
    char   *mtls_client_cert_type          = "PEM";
    char   *mtls_client_key_path           = "/dev/null";
    char   *mtls_client_key_pass           = "12345";
    char   *mtls_ca_bundle                 = "/dev/null";
    char   *mtls_ca_path                   = "/dev/null";
    char   *mtls_issuer_cert               = "/dev/null";
    uint8_t ignore_ssl_hostname_validation = CRYPTO_TRUE;

    status = Crypto_Config_Kmc_Crypto_Service(
        protocol, hostname, port, kmc_crypto_app_uri, mtls_ca_bundle, mtls_ca_path, ignore_ssl_hostname_validation,
        mtls_client_cert_path, mtls_client_cert_type, mtls_client_key_path, mtls_client_key_pass, mtls_issuer_cert);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST_MAIN();