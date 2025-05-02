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
 *  Unit Tests that make use of TC_ApplySecurity/TC_ProcessSecurity function on the data with KMC Crypto Service/MariaDB
 *Functionality Enabled.
 **/
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"

#include "crypto.h"
#include "shared_util.h"
#include <stdio.h>
#include <mysql/mysql.h>

// #ifdef KMC_MDB_RH
//     #define CLIENT_CERTIFICATE "/certs/redhat-cert.pem"
//     #define CLIENT_CERTIFICATE_KEY "/certs/redhat-key.pem"
// #else
//     /* KMC_MDB_DB */
//     #define CLIENT_CERTIFICATE "/certs/debian-cert.pem"
//     #define CLIENT_CERTIFICATE_KEY "/certs/debian-key.pem"
// #endif

// /**
//  * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
//  **/
// UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_CMAC_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE, MC_TYPE, SA_TYPE, CRYPTO_TYPE,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt",
//     NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL); Crypto_Config_Kmc_Crypto_Service("https",
//     "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE,
//     "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 7, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* raw_tc_jpl_mmt_scid44_vcid1= "202c1c08000001bb40";

//     char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//     int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect,
//     &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;
//     uint16_t enc_frame_len = 0;

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     printf("Frame before encryption:\n");
//     for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect,
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//     printf("Frame after encryption:\n");
//     for (int i=0; i<enc_frame_len; i++)
//     {
//         printf("%02x ", ptr_enc_frame[i]);
//     }
//     printf("\n");

//     Crypto_Shutdown();
//     free(raw_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
// }
// /**
//  * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
//  * This doesn't work -- Apply Security Auth Only doesn't return the proper tag.
//  **/
// UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_CMAC_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE, MC_TYPE, SA_TYPE, CRYPTO_TYPE,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt",
//     NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL); Crypto_Config_Kmc_Crypto_Service("https",
//     "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE,
//     "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 7, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1A0000050001C50827915AEB423F054402D5DC3C67566986"; // Returns
//     CRYPTO_LIB_ERR_INVALID_HEADER since SN/ARC missing from header
//     // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1E000005000000050001C7BA93010000000000000000000000007ACC";  //
//     Invalid MAC, should fail with error 510 char* enc_tc_jpl_mmt_scid44_vcid1=
//     "202C1C1E00000B0000000300018090C73F5D6A53ACEAFA86EB1DF66ED92F46"; char* enc_tc_jpl_mmt_scid44_vcid1_expect =
//     NULL; int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     // Data=0001

//     TC_t* tc_processed_frame;
//     tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

//     hex_conversion(enc_tc_jpl_mmt_scid44_vcid1, &enc_tc_jpl_mmt_scid44_vcid1_expect,
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     printf("Encrypted Frame Before Processing:\n");
//     for (int i=0; i<enc_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)enc_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ProcessSecurity((uint8_t* )enc_tc_jpl_mmt_scid44_vcid1_expect,
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame);

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//     printf("Processed PDU:\n");
//     for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
//     {
//         printf("%02x ", tc_processed_frame->tc_pdu[i]);
//     }
//     printf("\n");

//     ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
//     ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);

//     Crypto_Shutdown();
//     free(enc_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
// }

// /**
//  * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
//  **/
// UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_CMAC_LARGE_FRM_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE, MC_TYPE, SA_TYPE, CRYPTO_TYPE,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt",
//     NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL); Crypto_Config_Kmc_Crypto_Service("https",
//     "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE,
//     "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 7, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* raw_tc_jpl_mmt_scid44_vcid1=
//     "202c1f0700a6ec42999902579daaac3a5af6aabe93288e18d5d4046e24cc5df1f8fa06bac515206d5b0dfcc9861db694f3207175b725bfa6e987fadc1e1e417bff0c30a90b143ca737f2fcf02525c6080c38fde4d4da229387339f363ccdabf42a1defa29f711926c8e0a7479e082ec00b495ae53c8e33b5dc001833aa1d909b4b3aecd60bc6b0af62e8febb58fa15979a5d1e37b9ba48d6d1bf4b9d669306375d7f93942908e410492d6535c91245abbb98a0584aa764815bfdcab44d8c0aeff3a2e2c712649497f95e9440bb1b562cb6fa70a5ff5e5fdbcad40a97fa3bf48f0560bc9c7125b758f25a27678996e5ee3a82a5b864672b80888c2d469fe690aca0501d0de3bec247825f3fbd7f51184f8099dd2ffeb140c9aad86ae8ade912eadbcbef0bb821e684366a084f8d65bd9d0acccfae5fb130d8bf27ff855cea8de4a4e249e5bc8ef9732c06d6d578574b9f936ae1837a61369a7871612337df2dc091dadc8386e53aba816f3a162b71c268e07583a0378805a1f435bf437c0e27193cee4b653273d965fc0b42cfd3c094e2ff89f276153d452814ff016bfcc1b5ec313667de1aaddeb2d31dcaa75f88e4ac758556c7a632374089c53852601385c89aa668b70fd735e9053473538614408241ac47f6ef12aff10c2bce36df6afe7610a5a06997680b579953888684543b7cdefc7cc5987459a9255d187c8790284ad1f2ca38a3a3d56d909a03af87f3788e00d1b9887296ea5ff4087306569c2a3581189a70892e01279812151fdb9f8ec71786edd9cddd8652558503aac1904cf542aeebf269b08c5f648145b498be842080ccbdfe14c8cad1f371e706c0c4ed27d963e2e645224510e7d43ddf50daf8225f484ec841c9e642e489bd70fdbc925c532ab988d0f3999e3e1bdc88d5b0dd61e2b8d72a4a994f3efdc19382cdffdb96ea55ee5a389b003fc91ebc493c0949f56dc7b4b6d69d10dbc937f3757fb36b9000bf67d049c9c768a586b14b5166bffb41fc29c1d5613f2aaa2868fd974a95a3461b0c1c0f1ca87eccf7624fd1ffbe2f45463505b649a0b32410182731dfbe23813e88c3b6bdec7e";

//     char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//     int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect,
//     &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;
//     uint16_t enc_frame_len = 0;

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     printf("Frame before encryption:\n");
//     for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect,
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//     printf("Frame after encryption:\n");
//     for (int i=0; i<enc_frame_len; i++)
//     {
//         printf("%02x ", ptr_enc_frame[i]);
//     }
//     printf("\n");

//     Crypto_Shutdown();
//     free(raw_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
// }

// UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_HMAC256_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE, MC_TYPE, SA_TYPE, CRYPTO_TYPE,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt",
//     NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL); Crypto_Config_Kmc_Crypto_Service("https",
//     "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE,
//     "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 8, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* raw_tc_jpl_mmt_scid44_vcid1= "202c2008000001bb40";

//     char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//     int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect,
//     &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;
//     uint16_t enc_frame_len = 0;

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     printf("Frame before encryption:\n");
//     for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect,
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//     printf("Frame after encryption:\n");
//     for (int i=0; i<enc_frame_len; i++)
//     {
//         printf("%02x ", ptr_enc_frame[i]);
//     }
//     printf("\n");

//     Crypto_Shutdown();
//     free(raw_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
// }

// /**
//  * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
//  * This doesn't work -- Apply Security Auth Only doesn't return the proper tag.
//  **/
// UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_HMAC256_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE, MC_TYPE, SA_TYPE, CRYPTO_TYPE,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt",
//     NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL); Crypto_Config_Kmc_Crypto_Service("https",
//     "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE,
//     "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 8, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* enc_tc_jpl_mmt_scid44_vcid1=
//     "202C202E00000D000000020001482F52BA9B9411B46C8ABD6F5DF9FC63A2CE8EB3FC7D83EE488DA7A88D49FDFC4264"; char*
//     enc_tc_jpl_mmt_scid44_vcid1_expect = NULL; int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     // Data=0001

//     TC_t* tc_processed_frame;
//     tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

//     hex_conversion(enc_tc_jpl_mmt_scid44_vcid1, &enc_tc_jpl_mmt_scid44_vcid1_expect,
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     printf("Encrypted Frame Before Processing:\n");
//     for (int i=0; i<enc_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)enc_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ProcessSecurity((uint8_t* )enc_tc_jpl_mmt_scid44_vcid1_expect,
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame);

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//     printf("Processed PDU:\n");
//     for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
//     {
//         printf("%02x ", tc_processed_frame->tc_pdu[i]);
//     }
//     printf("\n");

//     ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
//     ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);

//     Crypto_Shutdown();
//     free(enc_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
// }

// /**
//  * @brief Unit Test: See test name for description of whats being exercised!
//  **/
// UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_HMAC512_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE, MC_TYPE, SA_TYPE, CRYPTO_TYPE,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt",
//     NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL); Crypto_Config_Kmc_Crypto_Service("https",
//     "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE,
//     "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 9, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* raw_tc_jpl_mmt_scid44_vcid1= "202c2408000001bb40";

//     char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//     int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect,
//     &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;
//     uint16_t enc_frame_len = 0;

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     printf("Frame before encryption:\n");
//     for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect,
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//     printf("Frame after encryption:\n");
//     for (int i=0; i<enc_frame_len; i++)
//     {
//         printf("%02x ", ptr_enc_frame[i]);
//     }
//     printf("\n");

//     Crypto_Shutdown();
//     free(raw_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
// }

// /**
//  * @brief Unit Test: HAPPY_PATH_PROCESS_SEC_HMAC512_AUTH_ONLY
//  **/
// UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_HMAC512_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE, MC_TYPE, SA_TYPE, CRYPTO_TYPE,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt",
//     NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL); Crypto_Config_Kmc_Crypto_Service("https",
//     "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE,
//     "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 9, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1A0000050001C50827915AEB423F054402D5DC3C67566986"; // Returns
//     CRYPTO_LIB_ERR_INVALID_HEADER since SN/ARC missing from header
//     // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1E000005000000050001C7BA93010000000000000000000000007ACC";  //
//     Invalid MAC, should fail with error 510 char* enc_tc_jpl_mmt_scid44_vcid1=
//     "202C244E00000E000000010001113F476FA33E4AF40C9E8D4A013FCB6AADA140B2CA5CA3FA18897C5D3084188ED127CCFAB7B5F063700AB3976E18A9713694922C11F0DB5F97277107C0712DC76557";
//     char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//     int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     // Data=0001

//     TC_t* tc_processed_frame;
//     tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

//     hex_conversion(enc_tc_jpl_mmt_scid44_vcid1, &enc_tc_jpl_mmt_scid44_vcid1_expect,
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     printf("Encrypted Frame Before Processing:\n");
//     for (int i=0; i<enc_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)enc_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ProcessSecurity((uint8_t* )enc_tc_jpl_mmt_scid44_vcid1_expect,
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame);

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//     printf("Processed PDU:\n");
//     for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
//     {
//         printf("%02x ", tc_processed_frame->tc_pdu[i]);
//     }
//     printf("\n");

//     ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
//     ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);

//     Crypto_Shutdown();
//     free(enc_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
// }
// /**
//  * @brief Unit Test: HAPPY_PATH_APPLY_SEC_HMAC512_TRUNCATED_16BYTE_MAC_AUTH_ONLY
//  **/
// UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_HMAC512_TRUNCATED_16BYTE_MAC_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE, MC_TYPE, SA_TYPE, CRYPTO_TYPE,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt",
//     NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL); Crypto_Config_Kmc_Crypto_Service("https",
//     "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE,
//     "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 10, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* raw_tc_jpl_mmt_scid44_vcid1= "202c2808000001bb40";

//     char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//     int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect,
//     &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;
//     uint16_t enc_frame_len = 0;

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     printf("Frame before encryption:\n");
//     for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect,
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//     printf("Frame after encryption:\n");
//     for (int i=0; i<enc_frame_len; i++)
//     {
//         printf("%02x ", ptr_enc_frame[i]);
//     }
//     printf("\n");

//     Crypto_Shutdown();
//     free(raw_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
// }

// /**
//  * @brief Unit Test: HAPPY_PATH_PROCESS_SEC_HMAC512_TRUNCATED_16BYTE_MAC_AUTH_ONLY
//  **/
// UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_HMAC512_TRUNCATED_16BYTE_MAC_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE, MC_TYPE, SA_TYPE, CRYPTO_TYPE,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt",
//     NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL); Crypto_Config_Kmc_Crypto_Service("https",
//     "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE,
//     "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 10, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1A0000050001C50827915AEB423F054402D5DC3C67566986"; // Returns
//     CRYPTO_LIB_ERR_INVALID_HEADER since SN/ARC missing from header
//     // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1E000005000000050001C7BA93010000000000000000000000007ACC";  //
//     Invalid MAC, should fail with error 510 char* enc_tc_jpl_mmt_scid44_vcid1=
//     "202C281E00000F0000000200011100B088C804DFA2B04AAF8780553E3C9615"; char* enc_tc_jpl_mmt_scid44_vcid1_expect =
//     NULL; int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     // Data=0001

//     TC_t* tc_processed_frame;
//     tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

//     hex_conversion(enc_tc_jpl_mmt_scid44_vcid1, &enc_tc_jpl_mmt_scid44_vcid1_expect,
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;

//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     printf("Encrypted Frame Before Processing:\n");
//     for (int i=0; i<enc_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)enc_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ProcessSecurity((uint8_t* )enc_tc_jpl_mmt_scid44_vcid1_expect,
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame); ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     printf("Processed PDU:\n");
//     for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
//     {
//         printf("%02x ", tc_processed_frame->tc_pdu[i]);
//     }
//     printf("\n");

//     ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
//     ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);

//     Crypto_Shutdown();
//     free(enc_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
//     // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
// }

UTEST_MAIN();
