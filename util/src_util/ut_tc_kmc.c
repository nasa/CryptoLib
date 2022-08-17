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
 *  Unit Tests that macke use of TC Functionality with KMC Service.
 **/

#include "ut_tc_apply.h"
#include "ut_tc_process.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

/**
 * @brief Unit Test: Nominal Encryption CBC KMC
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_ENC_CBC_KMC)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
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
    test_association->arsn_len = 0;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    char* truth_data_h = "2003001A0000000B025364F9BC3344AF359DA06CA886746F591C8E";
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
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
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

    char* truth_data_h = "2003001A0000000B011C1741A95DE7EF6FCF2B20B6F09E9FD225AD";
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
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
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

    char* truth_data_h = "2003002A0000000B103970EAE4C05ACD1B0C348FDA174DF73EF0E2D603996C4B78B992CD60918729D34FE2";
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
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "200303F6000080d2c70008197f0b00310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b1fed255";
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
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
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

//********************************* Encryption Tests MDB + KMC *******************************************************************//
/**
 * @brief Unit Test: Nominal Encryption CBC MDB KMC
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_ENC_CBC_MDB_KMC)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
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
    test_association->arsn_len = 0;
    sadb_routine->sadb_get_sa_from_spi(11, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    char* truth_data_h = "2003001A0000000B025364F9BC3344AF359DA06CA886746F591C8E";
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
 * @brief Unit Test: Encryption CBC MDB KMC 1 Byte of padding
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_MDB_KMC_1BP)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
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

    char* truth_data_h = "2003001A0000000B011C1741A95DE7EF6FCF2B20B6F09E9FD225AD";
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
 * @brief Unit Test: Encryption CBC MDB KMC 16 Bytes of padding
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_MDB_KMC_16BP)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
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

    char* truth_data_h = "2003002A0000000B103970EAE4C05ACD1B0C348FDA174DF73EF0E2D603996C4B78B992CD60918729D34FE2";
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
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char* raw_tc_sdls_ping_h = "200303F6000080d2c70008197f0b00310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b1fed255";
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
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
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


//******************************************************* Decryption Tests *******************************************************//

/**
 * @brief Unit Test: Nominal Decryption CBC KMC
 **/
UTEST(TC_PROCESS, HAPPY_PATH_DECRYPT_CBC_KMC)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003001A0000000B025364F9BC3344AF359DA06CA886746F591C8E";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;

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
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003001A0000000B011C1741A95DE7EF6FCF2B20B6F09E9FD225AD";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;

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
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003002A0000000B103970EAE4C05ACD1B0C348FDA174DF73EF0E2D603996C4B78B992CD60918729D34FE2";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;

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

// *************************************** Decryption + MDB ***********************************************//
/**
 * @brief Unit Test: Nominal Decryption CBC MDB KMC
 **/
UTEST(TC_PROCESS, HAPPY_PATH_DECRYPT_CBC_MDB_KMC)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003001A0000000B025364F9BC3344AF359DA06CA886746F591C8E";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;

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
 * @brief Unit Test: Decryption CBC MDB KMC with 1 Byte of padding
 **/
UTEST(TC_PROCESS, DECRYPT_CBC_MDB_KMC_1B)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003001A0000000B011C1741A95DE7EF6FCF2B20B6F09E9FD225AD";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;

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
 * @brief Unit Test: Decryption CBC MDB KMC with 16 Bytes of padding
 **/
UTEST(TC_PROCESS, DECRYPT_CBC_MDB_KMC_16B)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char* test_frame_pt_h = "2003002A0000000B103970EAE4C05ACD1B0C348FDA174DF73EF0E2D603996C4B78B992CD60918729D34FE2";
    uint8_t *test_frame_pt_b = NULL;
    int test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->arsn_len = 0;
    test_association->shsnf_len = 0;

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

UTEST_MAIN();