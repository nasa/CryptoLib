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

#include "shared_util.h"
#include <stdio.h>

// /**
//  * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
//  **/
// UTEST(KMC_CRYPTO_CAM, HAPPY_PATH_APPLY_SEC_ENC_AND_AUTH_KERBEROS_KEYTAB_FILE)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sa_user",
//                           "sa_password");
//     Crypto_Config_Kmc_Crypto_Service("https", "asec-dev-vm18.jpl.nasa.gov", 8443, "crypto-service",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",
//                                      NULL, CRYPTO_FALSE,
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
//                                      "PEM",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
//                                      NULL, NULL);
// //
// Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_NONE,"https://asec-dev-vm10.jpl.nasa.gov:443",
// NULL, NULL);
//     Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file","/home/isaleh/secret/testuser3300.kt",CAM_LOGIN_KEYTAB_FILE,"https://asec-dev-vm10.jpl.nasa.gov:443",
//     "testuser3300", NULL);
// //
// Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_KERBEROS,"https://asec-dev-vm10.jpl.nasa.gov:443",
// NULL, NULL);
//     Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA,
//     AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024,
//     AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3,
//     TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     char* raw_tc_jpl_mmt_scid44_vcid1= "202c0408000001bd37";
//     char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//     int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect,
//     &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;
//     uint16_t enc_frame_len = 0;

//     printf("Frame before encryption:\n");
//     for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect,
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); if(status != CRYPTO_LIB_SUCCESS)
//     {
//         Crypto_Shutdown();
//     }
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
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
// UTEST(KMC_CRYPTO_CAM, HAPPY_PATH_APPLY_SEC_ENC_AND_AUTH_KERBEROS)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sa_user",
//                           "sa_password");
//     Crypto_Config_Kmc_Crypto_Service("https", "asec-dev-vm18.jpl.nasa.gov", 8443, "crypto-service",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",
//                                      NULL, CRYPTO_FALSE,
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
//                                      "PEM",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
//                                      NULL, NULL);
// //
// Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_NONE,"https://asec-dev-vm10.jpl.nasa.gov:443",
// NULL, NULL);
// //
// Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file","/home/isaleh/secret/testuser3300.kt",CAM_LOGIN_KEYTAB_FILE,"https://asec-dev-vm10.jpl.nasa.gov:443",
// "testuser3300", NULL);
//     Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_KERBEROS,"https://asec-dev-vm10.jpl.nasa.gov:443",
//     NULL, NULL); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024,
//     AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2,
//     TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0,
//     0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

//     char* raw_tc_jpl_mmt_scid44_vcid1= "202c0408000001bd37";
//     char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//     int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect,
//     &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

//     uint8_t* ptr_enc_frame = NULL;
//     uint16_t enc_frame_len = 0;

//     printf("Frame before encryption:\n");
//     for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//     {
//         printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
//     }
//     printf("\n");

//     status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect,
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); if(status != CRYPTO_LIB_SUCCESS)
//     {
//         Crypto_Shutdown();
//     }
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
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
//  **/
// UTEST(KMC_CRYPTO_CAM, HAPPY_PATH_APPLY_SEC_ENC_AND_AUTH)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sa_user",
//                           "sa_password");
//     Crypto_Config_Kmc_Crypto_Service("https", "asec-dev-vm18.jpl.nasa.gov", 8443, "crypto-service",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",
//                                      NULL, CRYPTO_FALSE,
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
//                                      "PEM",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
//                                      NULL, NULL);
//     Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_NONE,NULL, NULL, NULL);
//     Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA,
//     AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024,
//     AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3,
//     TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* raw_tc_jpl_mmt_scid44_vcid1= "202c0408000001bd37";
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
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); if(status != CRYPTO_LIB_SUCCESS)
//     {
//         Crypto_Shutdown();
//     }
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
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
//  **/
// UTEST(KMC_CRYPTO_CAM, HAPPY_PATH_APPLY_SEC_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sa_user",
//                           "sa_password");
//     Crypto_Config_Kmc_Crypto_Service("https", "asec-dev-vm18.jpl.nasa.gov", 8443, "crypto-service",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",
//                                      NULL, CRYPTO_FALSE,
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
//                                      "PEM",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
//                                      NULL, NULL);
//     Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_NONE,NULL, NULL, NULL);
//     Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA,
//     AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024,
//     AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3,
//     TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* raw_tc_jpl_mmt_scid44_vcid1= "202c0C08000001bf1a";
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
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); if(status != CRYPTO_LIB_SUCCESS)
//     {
//         Crypto_Shutdown();
//     }
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
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
//  **/
// UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_ENC_AND_AUTH)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sa_user",
//                           "sa_password");
//     Crypto_Config_Kmc_Crypto_Service("https", "asec-dev-vm18.jpl.nasa.gov", 8443, "crypto-service",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",
//                                      NULL, CRYPTO_FALSE,
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
//                                      "PEM",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
//                                      NULL, NULL);
//     Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_NONE,NULL, NULL, NULL);
//     Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA,
//     AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024,
//     AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3,
//     TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* enc_tc_jpl_mmt_scid44_vcid1=
//     "202C0426000002000000000000000000000001669C5639DCCFEA8C6CE33230EE2E7065496367CC"; char*
//     enc_tc_jpl_mmt_scid44_vcid1_expect = NULL; int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     // Data=0001
//     // IV=000000000000000000000001
//     // AAD=00000000000000000000000000000000000000

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
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame); if(status != CRYPTO_LIB_SUCCESS)
//     {
//         Crypto_Shutdown();
//     }
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
//  * This doesn't work -- Apply Security Auth Only doesn't return the proper tag.
//  **/
// UTEST(KMC_CRYPTO_CAM, HAPPY_PATH_PROCESS_SEC_AUTH_ONLY)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sa_user",
//                           "sa_password");
//     Crypto_Config_Kmc_Crypto_Service("https", "asec-dev-vm18.jpl.nasa.gov", 8443, "crypto-service",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",
//                                      NULL, CRYPTO_FALSE,
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
//                                      "PEM",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
//                                      NULL, NULL);
//     Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_NONE,NULL, NULL, NULL);
//     Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA,
//     AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024,
//     AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF,
//     TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3,
//     TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* enc_tc_jpl_mmt_scid44_vcid1=
//     "202C0C2600000400000000000000000000000100016E2051F96CAB186BCE364A65AF599AE52F38"; char*
//     enc_tc_jpl_mmt_scid44_vcid1_expect = NULL; int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     // Data=0001
//     // IV=000000000000000000000001
//     // AAD=00000000000000000000000000000000000000

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

//     if(status != CRYPTO_LIB_SUCCESS)
//     {
//         Crypto_Shutdown();
//     }
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//     // Expected to fail -- KMC doesn't support 0 cipher text input for decrypt function.
//     // ASSERT_EQ(CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE, status);
//     printf("Processed PDU:\n");
//     for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
//     {
//         printf("%02x ", tc_processed_frame->tc_pdu[i]);
//     }
//     printf("\n");

//     // ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
//     // ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);

//     Crypto_Shutdown();
//     free(enc_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
//     // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
// }

// UTEST(KMC_CRYPTO_CAM, HAPPY_PATH_APPLY_SEC_ENC_AND_AUTH_AESGCM_8BYTE_MAC)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sa_user",
//                           "sa_password");
//     Crypto_Config_Kmc_Crypto_Service("https", "asec-dev-vm18.jpl.nasa.gov", 8443, "crypto-service",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",
//                                      NULL, CRYPTO_FALSE,
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
//                                      "PEM",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
//                                      NULL, NULL);
//     Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_NONE,NULL, NULL, NULL);
//     Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 11, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA,
//     AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* raw_tc_jpl_mmt_scid44_vcid1= "202c2c08000001bd37";
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
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); if(status != CRYPTO_LIB_SUCCESS)
//     {
//         Crypto_Shutdown();
//     }
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
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

// UTEST(KMC_CRYPTO_CAM, HAPPY_PATH_PROCESS_SEC_ENC_AND_AUTH_AESGCM_8BYTE_MAC)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sa_user",
//                           "sa_password");
//     Crypto_Config_Kmc_Crypto_Service("https", "asec-dev-vm18.jpl.nasa.gov", 8443, "crypto-service",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",
//                                      NULL, CRYPTO_FALSE,
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
//                                      "PEM",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
//                                      NULL, NULL);
//     Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_NONE,NULL, NULL, NULL);
//     Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 11, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA,
//     AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* enc_tc_jpl_mmt_scid44_vcid1= "202C2C1E000009000000000000000000000001669C5639DCCFEA8C6CE3AA71";
//     char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//     int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     // Data=0001
//     // IV=000000000000000000000001
//     // AAD=00000000000000000000000000000000000000

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
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame); if(status != CRYPTO_LIB_SUCCESS)
//     {
//         Crypto_Shutdown();
//     }
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

// UTEST(KMC_CRYPTO_CAM, UNHAPPY_PATH_INVALID_MAC_PROCESS_SEC_ENC_AND_AUTH_AESGCM_8BYTE_MAC)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sa_user",
//                           "sa_password");
//     Crypto_Config_Kmc_Crypto_Service("https", "asec-dev-vm18.jpl.nasa.gov", 8443, "crypto-service",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",
//                                      NULL, CRYPTO_FALSE,
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
//                                      "PEM",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
//                                      NULL, NULL);
//     Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_NONE,NULL, NULL, NULL);
//     Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 11, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA,
//     AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* enc_tc_jpl_mmt_scid44_vcid1= "202C2C1E000009000000000000000000000001669C5639DCCDEA8C6CE3EEF2";
//     char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//     int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

//     // Data=0001
//     // IV=000000000000000000000001
//     // AAD=00000000000000000000000000000000000000

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
//     &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame); if(status != CRYPTO_LIB_SUCCESS)
//     {
//         Crypto_Shutdown();
//     }
//     ASSERT_EQ(CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE, status);

//     Crypto_Shutdown();
//     free(enc_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
// }

// //16 bytes is max for AES GCM so this is an error test
// UTEST(KMC_CRYPTO_CAM, UNHAPPY_PATH_APPLY_SEC_ENC_AND_AUTH_AESGCM_32BYTE_MAC)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
//                             IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                             TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                             TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//     Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sa_user",
//                           "sa_password");
//     Crypto_Config_Kmc_Crypto_Service("https", "asec-dev-vm18.jpl.nasa.gov", 8443, "crypto-service",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",
//                                      NULL, CRYPTO_FALSE,
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem",
//                                      "PEM",
//                                      "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",
//                                      NULL, NULL);
//     Crypto_Config_Cam(CAM_ENABLED_TRUE,"/home/isaleh/.cam_cookie_file",NULL,CAM_LOGIN_NONE,NULL, NULL, NULL);
//     Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 12, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024, AOS_FHEC_NA,
//     AOS_IZ_NA, 0); int32_t status = Crypto_Init();

//     char* raw_tc_jpl_mmt_scid44_vcid1= "202c3008000001bd37";
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
//     raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len); if(status != CRYPTO_LIB_SUCCESS)
//     {
//         Crypto_Shutdown();
//     }
//     // we expect an InvalidAlgorithmParameterException for macLength of that size.
//     ASSERT_EQ(CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE, status);

//     Crypto_Shutdown();
//     free(raw_tc_jpl_mmt_scid44_vcid1_expect);
//     free(ptr_enc_frame);
// }

UTEST_MAIN();
