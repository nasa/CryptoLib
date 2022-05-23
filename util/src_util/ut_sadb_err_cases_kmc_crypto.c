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
 *  Unit Tests that make use of TC_ApplySecurity/TC_ProcessSecurity function on the data with KMC Crypto Service/MariaDB Functionality Enabled.
 **/
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

#include "crypto.h"
#include "shared_util.h"
#include <stdio.h>

/**
 * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
 **/
UTEST(KMC_CRYPTO, ONLY_KEYED_SA_AVAILABLE_FOR_GVCID)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sadb_user",
                          "sadb_password");
    Crypto_Config_Kmc_Crypto_Service("https", "asec-cmdenc-srv1.jpl.nasa.gov", 8443, "crypto-service",
                                     "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt", NULL,
                                     CRYPTO_FALSE,
                                     "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
                                     "PEM", "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
                                     NULL, NULL);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 33, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c8408000169e2df";
    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    printf("Frame before encryption:\n");
    for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len);
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
    ASSERT_EQ(SADB_QUERY_EMPTY_RESULTS, status);
    printf("Frame after encryption:\n");
    for (int i=0; i<enc_frame_len; i++)
    {
        printf("%02x ", ptr_enc_frame[i]);
    }
    printf("\n");


    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
}

UTEST(KMC_CRYPTO, ONLY_UNKEYED_SA_AVAILABLE_FOR_GVCID)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sadb_user",
                          "sadb_password");
    Crypto_Config_Kmc_Crypto_Service("https", "asec-cmdenc-srv1.jpl.nasa.gov", 8443, "crypto-service",
                                     "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt", NULL,
                                     CRYPTO_FALSE,
                                     "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
                                     "PEM", "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
                                     NULL, NULL);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 32, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c8008000169e2df";
    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    printf("Frame before encryption:\n");
    for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len);
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
    ASSERT_EQ(SADB_QUERY_EMPTY_RESULTS, status);
    printf("Frame after encryption:\n");
    for (int i=0; i<enc_frame_len; i++)
    {
        printf("%02x ", ptr_enc_frame[i]);
    }
    printf("\n");


    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
}

UTEST(KMC_CRYPTO, NULL_EKID_BLANK_ECS_ERROR)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sadb_user",
                          "sadb_password");
    Crypto_Config_Kmc_Crypto_Service("https", "asec-cmdenc-srv1.jpl.nasa.gov", 8443, "crypto-service",
                                     "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt", NULL,
                                     CRYPTO_FALSE,
                                     "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
                                     "PEM", "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
                                     NULL, NULL);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 34, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c8808000169e2df";
    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    printf("Frame before encryption:\n");
    for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len);
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
    ASSERT_EQ(CRYPTO_LIB_ERR_NO_ECS_SET_FOR_ENCRYPTION_MODE, status);
    printf("Frame after encryption:\n");
    for (int i=0; i<enc_frame_len; i++)
    {
        printf("%02x ", ptr_enc_frame[i]);
    }
    printf("\n");


    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
}

UTEST(KMC_CRYPTO, INVALID_ABM_LENGTH_FOR_FRAME_WITH_SEG_HEADERS)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sadb_user",
                          "sadb_password");
    Crypto_Config_Kmc_Crypto_Service("https", "asec-cmdenc-srv1.jpl.nasa.gov", 8443, "crypto-service",
                                     "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt", NULL,
                                     CRYPTO_FALSE,
                                     "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
                                     "PEM", "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
                                     NULL, NULL);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 28, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c7008000169e2df";
    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    printf("Frame before encryption:\n");
    for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len);
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
    ASSERT_EQ(CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD, status);
    printf("Frame after encryption:\n");
//    for (int i=0; i<enc_frame_len; i++)
//    {
//        printf("%02x ", ptr_enc_frame[i]);
//    }
//    printf("\n");


    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
}


UTEST_MAIN();
