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
 *  Unit Tests that make use of TC Functionality with KMC Service.
 **/

#include "ut_tc_apply.h"
#include "ut_tc_process.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

#include <mysql/mysql.h>
#include <stdlib.h>

#ifdef KMC_MDB_RH
    #define CLIENT_CERTIFICATE "/certs/redhat-cert.pem"
    #define CLIENT_CERTIFICATE_KEY "/certs/redhat-key.pem"
#else
    /* KMC_MDB_DB */
    #define CLIENT_CERTIFICATE "/certs/debian-cert.pem"
    #define CLIENT_CERTIFICATE_KEY "/certs/debian-key.pem"
#endif

/**
 * @brief Error Function for MDB_DB_RESET
 * 
 * @param con 
 */
void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  mysql_close(con);
  exit(1);
}

/**
 * @brief MariaDB: Table Cleanup for Unit Tests
 * Be sure to use only after initialization
 * TODO: Move to shared function for all Unit Tests
 */
void MDB_DB_RESET()
{
    MYSQL *con = mysql_init(NULL);
    if(sadb_mariadb_config->mysql_mtls_key != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_KEY, sadb_mariadb_config->mysql_mtls_key);
            }
            if(sadb_mariadb_config->mysql_mtls_cert != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_CERT, sadb_mariadb_config->mysql_mtls_cert);
            }
            if(sadb_mariadb_config->mysql_mtls_ca != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_CA, sadb_mariadb_config->mysql_mtls_ca);
            }
            if(sadb_mariadb_config->mysql_mtls_capath != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_CAPATH, sadb_mariadb_config->mysql_mtls_capath);
            }
            if (sadb_mariadb_config->mysql_tls_verify_server != CRYPTO_FALSE)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &(sadb_mariadb_config->mysql_tls_verify_server));
            }
            if (sadb_mariadb_config->mysql_mtls_client_key_password != NULL)
            {
                mysql_optionsv(con, MARIADB_OPT_TLS_PASSPHRASE, sadb_mariadb_config->mysql_mtls_client_key_password);
            }
            if (sadb_mariadb_config->mysql_require_secure_transport == CRYPTO_TRUE)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_ENFORCE,&(sadb_mariadb_config->mysql_require_secure_transport));
            }
            //if encrypted connection (TLS) connection. No need for SSL Key
            if (mysql_real_connect(con, sadb_mariadb_config->mysql_hostname,
                    sadb_mariadb_config->mysql_username,
                    sadb_mariadb_config->mysql_password,
                    sadb_mariadb_config->mysql_database,
                    sadb_mariadb_config->mysql_port, NULL, 0) == NULL)
            {
                //0,NULL,0 are port number, unix socket, client flag
                finish_with_error(con);
            }

    printf("Truncating Tables\n");
    char* query = "TRUNCATE TABLE security_associations\n";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to Truncate Table\n");
        finish_with_error(con);
    }
    query = "INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid,ecs_len, shplf_len) VALUES (11,'kmc/test/key130',3,X'02',1,0,16,16,0,X'00000000000000000000000000000001',1024,X'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',5,0,0,3,0,0,1,1)";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 11\n");
        finish_with_error(con);
    }
}


/**
 * @brief Unit Test: Nominal Encryption CBC KMC
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_ENC_CBC_KMC)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t* test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;
    test_association->ast = 0;
    test_association->stmacf_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    char* truth_data_h = "2003002A0000000B00000000000000000000000000000000025364F9BC3344AF359DA06CA886746F59A0AB";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    //printf("Encrypted Frame:\n");
    for(int i = 0; i < enc_frame_len; i++)
    {
        //printf("%02x -> %02x ", ptr_enc_frame[i], truth_data_b[i]);
        ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }
    //printf("\n");

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Encryption CBC KMC 1 Byte of padding
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_KMC_1BP)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "20030016000080d2c70008197f0b0031000000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t* test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 0;
    test_association->arsn_len = 0;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    char* truth_data_h = "2003002A0000000B00000000000000000000000000000000011C1741A95DE7EF6FCF2B20B6F09E9FD29988";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    //printf("Encrypted Frame:\n");
    for(int i = 0; i < enc_frame_len; i++)
    {
        //printf("%02x -> %02x ", ptr_enc_frame[i], truth_data_b[i]);
        ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }
    //printf("\n");

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Encryption CBC KMC 16 Bytes of padding
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_KMC_16BP)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "20030017000080d2c70008197f0b003100000000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t* test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 0;
    test_association->arsn_len = 0;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    char* truth_data_h = "2003003A0000000B00000000000000000000000000000000103970EAE4C05ACD1B0C348FDA174DF73EF0E2D603996C4B78B992CD60918729D3A47A";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    //printf("Encrypted Frame:\n");
    for(int i = 0; i < enc_frame_len; i++)
    {
        //printf("%02x -> %02x ", ptr_enc_frame[i], truth_data_b[i]);
        ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }
    printf("\n");

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Nominal Encryption CBC KMC
 *                      Frame is max size for this test.  Any encrypted data of length greater than 1007 bytes, 
 *                      will cause frame length exception.
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_KMC_FRAME_MAX)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "200303E6000080d2c70008197f0b00310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b1fed255";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t* test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 0;
    test_association->arsn_len = 0;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Encryption CBC KMC
 *                      Frame is 1 byte too large for this test.  Any encrypted data of length greater than 1007 bytes, 
 *                      will cause frame length exception.
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_KMC_FRAME_TOO_BIG)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "200303F7000080d2c70008197f0b0031000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b1fed255";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t* test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 0;
    test_association->arsn_len = 0;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_SPEC_LIMIT, return_val);
}

/**
 * @brief Unit Test: Nominal Encryption CBC KMC, with no supplied IV
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_KMC_NULL_IV)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    
    char* raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t* test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 0;
    test_association->est = 1;
    test_association->stmacf_len = 0;
    *test_association->ecs = CRYPTO_CIPHER_AES256_CBC;
    test_association->acs_len = 1;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = 0;
    test_association->arsn_len = 0;
    test_association->iv = NULL;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
}

/**
 * @brief Unit Test: Nominal Encryption CBC KMC, with no supplied IV
 **/
UTEST(TC_APPLY_SECURITY, ENC_GCM_KMC_NULL_IV)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    // // 200300230000000B000000000000000000000000852DDEFF8FCD93567F271E192C07F126
    char* raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t* test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 1;
    test_association->est = 1;
    test_association->stmacf_len = 16;
    test_association->shplf_len = 0;
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    test_association->acs_len = 1;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = 0;
    test_association->arsn_len = 0;
    test_association->iv_len = 12;
    test_association->shivf_len = 12;
    test_association->ecs[0] = 0x01;
    test_association->iv = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
}

//********************************* Encryption Tests MDB + KMC *******************************************************************//
/**
 * @brief Unit Test: Nominal Encryption CBC MDB KMC
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_ENC_CBC_MDB_KMC)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);

    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 6, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "20031815000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    //SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    
    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
}

/**
 * @brief Unit Test: Encryption CBC MDB KMC 1 Byte of padding
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_MDB_KMC_1BP)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 6, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "20031816000080d2c70008197f0b0031000000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* truth_data_h = "2003182A0000001200000000000000000000000000000002011D90CE80C259660B229B6C1783C80E898D52";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    printf("Encrypted Frame:\n");
    for(int i = 0; i < enc_frame_len; i++)
    {
        printf("%02x -> %02x ", ptr_enc_frame[i], truth_data_b[i]);
        ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }
    printf("\n");

    Crypto_Shutdown();
    //free(raw_tc_sdls_ping_b);
    //free(ptr_enc_frame);
}

/**
 * @brief Unit Test: Encryption CBC MDB KMC 16 Bytes of padding
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_MDB_KMC_16BP)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 6, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "20031817000080d2c70008197f0b003100000000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    char* truth_data_h = "2003183A000000120000000000000000000000000000000310CA8B21BCB5AFB1A306CDC96C80C9208D00EB961E3F61D355E30F01CFDCCC7D026D56";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    //printf("Encrypted Frame:\n");
    for(int i = 0; i < enc_frame_len; i++)
    {
        //printf("%02x -> %02x ", ptr_enc_frame[i], truth_data_b[i]);
        ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }
    printf("\n");

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Nominal Encryption CBC MDB KMC
 *                      Frame is max size for this test.  Any encrypted data of length greater than 1007 bytes, 
 *                      will cause frame length exception.
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_MDB_KMC_FRAME_MAX)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 6, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "20031BE0000080d2c70008197f0b003100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b1fed255";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t* test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 0;
    test_association->arsn_len = 0;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Encryption CBC MDB KMC
 *                      Frame is 1 byte too large for this test.  Any encrypted data of length greater than 1007 bytes, 
 *                      will cause frame length exception.
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_MDB_KMC_FRAME_TOO_BIG)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "200303F2000080d2c70008197f0b003100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b1fed255";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t* test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 0;
    test_association->arsn_len = 0;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_MANAGED_PARAM_MAX_LIMIT, return_val);
}

/**
 * @brief Unit Test: Nominal Encryption CBC MDB KMC, Null IV
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_MDB_KMC_NULL_IV)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);

    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 4, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "20031015000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);


    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}


//******************************************************* Decryption Tests *******************************************************//

/**
 * @brief Unit Test: Nominal Decryption CBC KMC
 **/
UTEST(TC_PROCESS, HAPPY_PATH_DECRYPT_CBC_KMC)
{
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));
    char* test_frame_pt_h = "2003002A0000000B00000000000000000000000000000000025364F9BC3344AF359DA06CA886746F59A0AB";
    //char* test_frame_pt_h = "2003001A0000000B025364F9BC3344AF359DA06CA886746F591C8E";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;
    test_association->ast = 0;
    test_association->stmacf_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char**) &test_frame_pt_b, &test_frame_pt_len);
    
    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);
    
    char* truth_data_h = "80d2c70008197f0b00310000b1fe";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char**) &truth_data_b, &truth_data_l);
    //printf("Decrypted Frame:\n");
    for(int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        //printf("%02x -> %02x ", tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
        ASSERT_EQ(tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    }
    //printf("\n");

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    free(test_frame_pt_b);
    Crypto_Shutdown();       
}

/**
 * @brief Unit Test: Decryption CBC KMC with 1 Byte of padding
 **/
UTEST(TC_PROCESS, DECRYPT_CBC_KMC_1B)
{
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003002A0000000B00000000000000000000000000000000011C1741A95DE7EF6FCF2B20B6F09E9FD29988";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;
    test_association->ast = 0;
    test_association->stmacf_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char**) &test_frame_pt_b, &test_frame_pt_len);
    
    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);
    
    char* truth_data_h = "80d2c70008197f0b0031000000b1fe";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char**) &truth_data_b, &truth_data_l);
    //printf("Decrypted Frame:\n");
    for(int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        //printf("%02x -> %02x ", tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
        ASSERT_EQ(tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    }
    //printf("\n");

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    free(test_frame_pt_b);
    Crypto_Shutdown();       
}

/**
 * @brief Unit Test: Decryption CBC KMC with 16 Bytes of padding
 **/
UTEST(TC_PROCESS, DECRYPT_CBC_KMC_16B)
{
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003003A0000000B00000000000000000000000000000000103970EAE4C05ACD1B0C348FDA174DF73EF0E2D603996C4B78B992CD60918729D3A47A";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;
    test_association->ast = 0;
    test_association->stmacf_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char**) &test_frame_pt_b, &test_frame_pt_len);
    
    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);
    
    char* truth_data_h = "80d2c70008197f0b003100000000b1fe";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char**) &truth_data_b, &truth_data_l);
    //printf("Decrypted Frame:\n");
    for(int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        //printf("%02x -> %02x ", tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
        ASSERT_EQ(tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    }
    //printf("\n");

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    free(test_frame_pt_b);
    Crypto_Shutdown();       
}

/**
 * @brief Unit Test: Nominal Decryption CBC KMC, Null IV
 **/
UTEST(TC_PROCESS, DECRYPT_CBC_KMC_NULL_IV)
{
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003002A0000000B22BA7A6B53C17DD9405B599FB04222A7026AC591A28602BF97D3E7D9CE6BC52D4382EB";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->iv = NULL;
    test_association->ast = 0;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char**) &test_frame_pt_b, &test_frame_pt_len);
    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);
    

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    free(test_frame_pt_b);
    Crypto_Shutdown();       
}

/**
 * @brief Unit Test: Nominal Encryption CBC KMC, with no supplied IV
 **/
UTEST(TC_PROCESS, DECRYPT_GCM_KMC_NULL_IV)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* raw_tc_sdls_ping_h = "200300330000000B5C7D0E687B4ACC8978CEB8F9F1713AC7E65FAA6845BF9607A6D2B89B7AF55C4463B9068F344242AAFAEBE298";
    uint8_t* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, (char **) &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    SecurityAssociation_t* test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 1;
    test_association->est = 1;
    test_association->stmacf_len = 16;
    test_association->shplf_len = 0;
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    test_association->acs_len = 1;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = 0;
    test_association->arsn_len = 0;
    test_association->iv_len = 12;
    test_association->shivf_len = 12;
    test_association->iv = NULL;
    return_val = Crypto_TC_ProcessSecurity(raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len, tc_sdls_processed_frame);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
}

// *************************************** Decryption + MDB ***********************************************//
/**
 * @brief Unit Test: Nominal Decryption CBC MDB KMC
 **/
UTEST(TC_PROCESS, HAPPY_PATH_DECRYPT_CBC_MDB_KMC)
{
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 6, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003182A000000120000000000000000000000000000000102FCFCF53E77DDCFD92993273B6C449B76CA1E";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char**) &test_frame_pt_b, &test_frame_pt_len);
    
    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    char* truth_data_h = "80d2c70008197f0b00310000b1fe";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char**) &truth_data_b, &truth_data_l);
    //printf("Decrypted Frame:\n");
    for(int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        //printf("%02x -> %02x ", tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
        ASSERT_EQ(tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    }
    //printf("\n");

    
    free(test_frame_pt_b);
    Crypto_Shutdown();       
}

/**
 * @brief Unit Test: Decryption CBC MDB KMC with 1 Byte of padding
 **/
UTEST(TC_PROCESS, DECRYPT_CBC_MDB_KMC_1B)
{
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 6, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003182A0000001200000000000000000000000000000002011D90CE80C259660B229B6C1783C80E898D52";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char**) &test_frame_pt_b, &test_frame_pt_len);
    
    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    char* truth_data_h = "80d2c70008197f0b0031000000b1fe";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char**) &truth_data_b, &truth_data_l);
    //printf("Decrypted Frame:\n");
    for(int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        printf("%02x -> %02x ", tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
        ASSERT_EQ(tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    }
    //printf("\n");

    
    free(test_frame_pt_b);
    Crypto_Shutdown();       
}

/**
 * @brief Unit Test: Decryption CBC MDB KMC with 16 Bytes of padding
 **/
UTEST(TC_PROCESS, DECRYPT_CBC_MDB_KMC_16B)
{
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 6, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003183A000000120000000000000000000000000000000310CA8B21BCB5AFB1A306CDC96C80C9208D00EB961E3F61D355E30F01CFDCCC7D026D56";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char**) &test_frame_pt_b, &test_frame_pt_len);
    
    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    char* truth_data_h = "80d2c70008197f0b003100000000b1fe";
    uint8_t* truth_data_b = NULL;
    int truth_data_l = 0;

    hex_conversion(truth_data_h, (char**) &truth_data_b, &truth_data_l);
    //printf("Decrypted Frame:\n");
    for(int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        printf("%02x -> %02x ", tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
        //ASSERT_EQ(tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    }
    printf("\n");

    
    free(test_frame_pt_b);
    Crypto_Shutdown();       
}

/**
 * @brief Unit Test: Nominal Decryption CBC MDB KMC, NULL IV
 **/
UTEST(TC_PROCESS, DECRYPT_CBC_MDB_KMC_NULL_IV)
{
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 4, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));
                           //2003102E00000006DDB12ADB9F880659AD5703EF6D45BD4A0001EF2BD095982BC3AC58B8AB92484662E000000026F3
    char* test_frame_pt_h = "2003102C00000006703809AED191A8041A6DCEB4C030894400120218AB4508A560430D644DE39E35011E454755";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;
    test_association->iv = NULL;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char**) &test_frame_pt_b, &test_frame_pt_len);
    
    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);
    
    // char* truth_data_h = "80d2c70008197f0b00310000b1fe";
    // uint8_t* truth_data_b = NULL;
    // int truth_data_l = 0;

    // hex_conversion(truth_data_h, (char**) &truth_data_b, &truth_data_l);
    // //printf("Decrypted Frame:\n");
    // for(int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    // {
    //     //printf("%02x -> %02x ", tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    //     ASSERT_EQ(tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    // }
    // //printf("\n");

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    free(test_frame_pt_b);
    Crypto_Shutdown();       
}

UTEST_MAIN();