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
 *  Unit Tests that make use of TC_ProcessSecurity function on the data.
 **/
#include "ut_tc_process.h"
#include "crypto.h"
#include "crypto_error.h"
#include "crypto_print.h"
#include "sa_interface.h"
#include "utest.h"

/**
 * @brief Exercise the IV window checking logic
 * Test Cases: Replay, outside of window
 **/
UTEST(TC_PROCESS, EXERCISE_IV)
{
    remove("sa_save_file.bin");
    uint8_t *ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);

    Crypto_Init();
    SaInterface   sa_if  = get_sa_interface_inmemory();
    crypto_key_t *ekp    = NULL;
    int           status = 0;

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "ef9f9284cf599eac3b119905a7d18851e7e374cf63aea04358586b0f757670f8";
    char *buffer_nist_iv_h  = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    char *buffer_replay_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374B1224DFEFB72A20D49E09256908874979DFC1"; // IV is one less than library
                                                                                        // expects
    char *buffer_outside_window_h =
        "2003002500FF0009B6AC8E4963F49207FFD6375C1224DFEFB72A20D49E09256908874979B36E"; // IV is outside the positive
                                                                                        // window
    char *buffer_good_iv_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374C1224DFEFB72A20D49E09256908874979AD6F"; // IV is the next one expected
    char *buffer_good_iv_with_gap_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374F1224DFEFB72A20D49E092569088749799C49"; // IV is valid, but not next one
                                                                                        // expected
    uint8_t *buffer_replay_b, *buffer_outside_window_b, *buffer_good_iv_b, *buffer_good_iv_with_gap_b,
        *buffer_nist_iv_b, *buffer_nist_key_b = NULL;
    int buffer_replay_len, buffer_outside_window_len, buffer_good_iv_len, buffer_good_iv_with_gap_len,
        buffer_nist_iv_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;
    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->est       = 1;
    test_association->ast       = 0;
    test_association->ekid      = 136;
    test_association->shivf_len = 12;
    test_association->iv_len    = 12;
    test_association->ecs_len   = 1;
    test_association->shplf_len = 1;
    test_association->arsnw_len = 1;
    test_association->arsnw     = 5;
    test_association->arsn_len  = 0;
    test_association->shsnf_len = 0;
    test_association->abm_len   = ABM_SIZE;
    test_association->ecs       = CRYPTO_CIPHER_AES256_GCM;
    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);
    ekp->key_state = KEY_ACTIVE;

    // Convert frames that will be processed
    hex_conversion(buffer_replay_h, (char **)&buffer_replay_b, &buffer_replay_len);
    hex_conversion(buffer_outside_window_h, (char **)&buffer_outside_window_b, &buffer_outside_window_len);
    hex_conversion(buffer_good_iv_h, (char **)&buffer_good_iv_b, &buffer_good_iv_len);
    hex_conversion(buffer_good_iv_with_gap_h, (char **)&buffer_good_iv_with_gap_b, &buffer_good_iv_with_gap_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char **)&buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);

    // Expect to fail on replay
    printf(KGRN "Checking replay - using previous received IV...\n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_replay_b, &buffer_replay_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW, status);

    // Expect to fail on counter being too high
    printf(KGRN "Checking replay - using IV outside the window...\n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_outside_window_b, &buffer_outside_window_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW, status);

    // Expect success on valid IV
    printf(KGRN "Checking valid IV... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_good_iv_b, &buffer_good_iv_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Expect success on valid IV within window, but has a gap
    printf(KGRN "Checking valid IV within window... should be able to receive it... \n" RESET);
    status =
        Crypto_TC_ProcessSecurity(buffer_good_iv_with_gap_b, &buffer_good_iv_with_gap_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Validate that the SA IV is updated to the most recently received IV
    // IV length in this testing is 12 bytes
    printf(KGRN "Verifying IV updated correctly...\n" RESET);
    printf("SA IV is now:\t");
    for (int i = 0; i < test_association->shivf_len; i++)
    {
        ASSERT_EQ(*(test_association->iv + i), *(buffer_good_iv_with_gap_b + 8 + i)); // 8 is IV offset into packet
        printf("%02X", *(test_association->iv + i));
    }
    printf("\n");
    Crypto_Shutdown();
    free(buffer_replay_b);
    free(buffer_outside_window_b);
    free(buffer_good_iv_b);
    free(buffer_good_iv_with_gap_b);
    free(ptr_enc_frame);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(tc_nist_processed_frame);
}

/**
 * @brief Exercise the ARSN window checking logic using AES CMAC
 * Test Cases: Replay, outside of window
 **/
UTEST(TC_PROCESS, EXERCISE_ARSN)
{
    remove("sa_save_file.bin");
    uint8_t *ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF,
    // TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    Crypto_Init();
    SaInterface   sa_if  = get_sa_interface_inmemory();
    crypto_key_t *akp    = NULL;
    int           status = 0;

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "ef9f9284cf599eac3b119905a7d18851e7e374cf63aea04358586b0f757670f8";
    char *buffer_arsn_h     = "0123"; // The last valid ARSN that was seen by the SA
    // For reference:        | Header  |SH SPI SN| Payload                       | MAC                           |FECF
    char *buffer_replay_h =
        "2003002B00FF000901231224DFEFB72A20D49E09256908874979fd56ca1ffc2697a700dbe6292c10e9ef1B49"; // ARSN is one less
                                                                                                    // than library
                                                                                                    // expects
    char *buffer_outside_window_h =
        "2003002B00FF000904441224DFEFB72A20D49E09256908874979fd56ca1ffc2697a700dbe6292c10e9ef9C5C"; // ARSN is outside
                                                                                                    // the positive
                                                                                                    // window
    char *buffer_good_arsn_h =
        "2003002B00FF000901241224DFEFB72A20D49E09256908874979fd56ca1ffc2697a700dbe6292c10e9ef8A3E"; // ARSN is the next
                                                                                                    // one expected
    char *buffer_good_arsn_with_gap_h =
        "2003002B00FF000901291224DFEFB72A20D49E09256908874979fd56ca1ffc2697a700dbe6292c10e9ef3EB4"; // ARSN is valid,
                                                                                                    // but not next one
                                                                                                    // expected
    uint8_t *buffer_replay_b, *buffer_outside_window_b, *buffer_good_arsn_b, *buffer_good_arsn_with_gap_b,
        *buffer_arsn_b, *buffer_nist_key_b = NULL;
    int buffer_replay_len, buffer_outside_window_len, buffer_good_arsn_len, buffer_good_arsn_with_gap_len,
        buffer_arsn_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;
    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->ecs_len   = 1;
    test_association->ecs       = CRYPTO_CIPHER_NONE;
    test_association->acs_len   = 1;
    test_association->acs       = CRYPTO_MAC_CMAC_AES256;
    test_association->est       = 0;
    test_association->ast       = 1;
    test_association->shivf_len = 0;
    test_association->iv_len    = 0;
    test_association->shsnf_len = 2;
    test_association->arsn_len  = 2;
    test_association->arsnw     = 5;
    test_association->abm_len   = 1024;
    test_association->akid      = 136;
    test_association->ekid      = 0;
    // memset(test_association->abm, 0x00, (test_association->abm_len * sizeof(uint8_t)));
    test_association->stmacf_len = 16;
    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    akp = key_if->get_key(test_association->akid);
    memcpy(akp->value, buffer_nist_key_b, buffer_nist_key_len);
    akp->key_state = KEY_ACTIVE;
    // Convert frames that will be processed
    hex_conversion(buffer_replay_h, (char **)&buffer_replay_b, &buffer_replay_len);
    hex_conversion(buffer_outside_window_h, (char **)&buffer_outside_window_b, &buffer_outside_window_len);
    hex_conversion(buffer_good_arsn_h, (char **)&buffer_good_arsn_b, &buffer_good_arsn_len);
    hex_conversion(buffer_good_arsn_with_gap_h, (char **)&buffer_good_arsn_with_gap_b, &buffer_good_arsn_with_gap_len);
    // Convert/Set input ARSN
    hex_conversion(buffer_arsn_h, (char **)&buffer_arsn_b, &buffer_arsn_len);
    memcpy(test_association->arsn, buffer_arsn_b, buffer_arsn_len);
    // Expect to fail on replay
    printf(KGRN "Checking replay - using previous received ARSN...\n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_replay_b, &buffer_replay_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW, status);
    // Expect to fail on counter being too high
    printf(KGRN "Checking replay - using ARSN outside the window...\n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_outside_window_b, &buffer_outside_window_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW, status);

    // Expect success on valid ARSN
    printf(KGRN "Checking next valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_good_arsn_b, &buffer_good_arsn_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Expect success on valid ARSN within window, but has a gap
    printf(KGRN "Checking valid ARSN within window... should be able to receive it... \n" RESET);
    status =
        Crypto_TC_ProcessSecurity(buffer_good_arsn_with_gap_b, &buffer_good_arsn_with_gap_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Validate that the SA ARSN is updated to the most recently received ARSN
    // ARSN length in this testing is 2 bytes
    printf(KGRN "Verifying ARSN updated correctly...\n" RESET);
    printf("SA ARSN is now:\t");
    for (int i = 0; i < test_association->shsnf_len; i++)
    {
        printf("%02X", *(test_association->arsn + i));
        ASSERT_EQ(*(test_association->arsn + i),
                  *(buffer_good_arsn_with_gap_b + 8 + i)); // 8 is ARSN offset into packet
    }
    printf("\n");
    Crypto_Shutdown();
    free(tc_nist_processed_frame);
    free(ptr_enc_frame);
    free(buffer_nist_key_b);
    free(buffer_replay_b);
    free(buffer_outside_window_b);
    free(buffer_good_arsn_b);
    free(buffer_good_arsn_with_gap_b);
    free(buffer_arsn_b);
}

UTEST(TC_PROCESS, HAPPY_PATH_PROCESS_STATIC_IV_ROLLOVER)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF,
    // TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();

    char *dec_test_fe_h =
        "2003002D00000004FFFFFFFFFFFE610B082EA91C8AA93F08EAA642EA3189128D87159B2354AA753248F050022FD9";
    char *dec_test_ff_h =
        "2003002D00000004FFFFFFFFFFFFCECBA30A6E0B54ACE0D5F92D1360084822CFA46240C0CD7D6830A6A7771ECFEC";
    char *dec_test_00_h =
        "2003002D0000000400000000000064DB31BBC4656F072A8E4A706F9508C440A003496E8A71FD47621297DDCC393C";

    uint8_t *dec_test_fe_b, *dec_test_ff_b, *dec_test_00_b     = NULL;
    int      dec_test_fe_len, dec_test_ff_len, dec_test_00_len = 0;

    hex_conversion(dec_test_fe_h, (char **)&dec_test_fe_b, &dec_test_fe_len);
    hex_conversion(dec_test_ff_h, (char **)&dec_test_ff_b, &dec_test_ff_len);
    hex_conversion(dec_test_00_h, (char **)&dec_test_00_b, &dec_test_00_len);

    SecurityAssociation_t *test_association;

    int32_t return_val = -1;

    TC_t tc_sdls_processed_frame;
    memset(&tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    // Default SA
    // Expose SA 1 for testing
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->ecs_len = 1;
    test_association->ecs     = CRYPTO_CIPHER_NONE;

    // Deactive SA 1
    test_association->sa_state = SA_NONE;

    // Expose SA 4 for testing
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.vcid = 0;
    test_association->shivf_len      = 6;
    test_association->iv_len         = 12;
    test_association->ekid           = 130;
    // IV = "000000000000FFFFFFFFFFFE"
    test_association->iv[0]    = 0x00;
    test_association->iv[1]    = 0x00;
    test_association->iv[2]    = 0x00;
    test_association->iv[3]    = 0x00;
    test_association->iv[4]    = 0x00;
    test_association->iv[5]    = 0x00;
    test_association->iv[6]    = 0xFF;
    test_association->iv[7]    = 0xFF;
    test_association->iv[8]    = 0xFF;
    test_association->iv[9]    = 0xFF;
    test_association->iv[10]   = 0xFF;
    test_association->iv[11]   = 0xFD;
    test_association->ast      = 1;
    test_association->est      = 1;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs      = CRYPTO_CIPHER_AES256_GCM;

    Crypto_saPrint(test_association);
    return_val = Crypto_TC_ProcessSecurity(dec_test_fe_b, &dec_test_fe_len, &tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    ASSERT_EQ(test_association->iv[11], 0xFE);

    return_val = Crypto_TC_ProcessSecurity(dec_test_ff_b, &dec_test_ff_len, &tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    ASSERT_EQ(test_association->iv[11], 0xFF);

    return_val = Crypto_TC_ProcessSecurity(dec_test_00_b, &dec_test_00_len, &tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    for (int i = 0; i < test_association->iv_len; i++)
    {
        ASSERT_EQ(test_association->iv[i], 0x00);
    }
    Crypto_saPrint(test_association);

    Crypto_Shutdown();
    free(dec_test_fe_b);
    free(dec_test_ff_b);
    free(dec_test_00_b);
}

UTEST(TC_PROCESS, HAPPY_PATH_PROCESS_NONTRANSMITTED_INCREMENTING_IV_ROLLOVER)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF,
    // TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();

    char *dec_test_fe_h =
        "2003002D00000004FFFFFFFFFFFE610B082EA91C8AA93F08EAA642EA3189128D87159B2354AA753248F050022FD9";
    char *dec_test_ff_h =
        "2003002D00000004FFFFFFFFFFFFCECBA30A6E0B54ACE0D5F92D1360084822CFA46240C0CD7D6830A6A7771ECFEC";
    char *dec_test_00_h =
        "2003002D00000004000000000000CEB2378F0F335664496406AC4F3A2ABFFD8678CB76DD009D7FE5B425BB96F567";

    uint8_t *dec_test_fe_b, *dec_test_ff_b, *dec_test_00_b     = NULL;
    int      dec_test_fe_len, dec_test_ff_len, dec_test_00_len = 0;

    hex_conversion(dec_test_fe_h, (char **)&dec_test_fe_b, &dec_test_fe_len);
    hex_conversion(dec_test_ff_h, (char **)&dec_test_ff_b, &dec_test_ff_len);
    hex_conversion(dec_test_00_h, (char **)&dec_test_00_b, &dec_test_00_len);

    SecurityAssociation_t *test_association;

    int32_t return_val = -1;

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    // Default SA
    // Expose SA 1 for testing
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->ecs_len = 1;
    test_association->ecs     = CRYPTO_CIPHER_NONE;

    // Deactive SA 1
    test_association->sa_state = SA_NONE;

    // Expose SA 4 for testing
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.vcid = 0;
    test_association->shivf_len      = 6;
    test_association->iv_len         = 12;
    test_association->ekid           = 130;
    // IV = "000000000000FFFFFFFFFFFE"
    test_association->iv[0]    = 0x00;
    test_association->iv[1]    = 0x00;
    test_association->iv[2]    = 0x00;
    test_association->iv[3]    = 0x00;
    test_association->iv[4]    = 0x00;
    test_association->iv[5]    = 0x00;
    test_association->iv[6]    = 0xFF;
    test_association->iv[7]    = 0xFF;
    test_association->iv[8]    = 0xFF;
    test_association->iv[9]    = 0xFF;
    test_association->iv[10]   = 0xFF;
    test_association->iv[11]   = 0xFD;
    test_association->ast      = 1;
    test_association->est      = 1;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs      = CRYPTO_CIPHER_AES256_GCM;

    Crypto_saPrint(test_association);
    return_val = Crypto_TC_ProcessSecurity(dec_test_fe_b, &dec_test_fe_len, tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    ASSERT_EQ(test_association->iv[11], 0xFE);
    return_val = Crypto_TC_ProcessSecurity(dec_test_ff_b, &dec_test_ff_len, tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    ASSERT_EQ(test_association->iv[11], 0xFF);
    // test_association->iv[5] = 0x01;
    return_val = Crypto_TC_ProcessSecurity(dec_test_00_b, &dec_test_00_len, tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    ASSERT_EQ(test_association->iv[0], 0x00);
    ASSERT_EQ(test_association->iv[1], 0x00);
    ASSERT_EQ(test_association->iv[2], 0x00);
    ASSERT_EQ(test_association->iv[3], 0x00);
    ASSERT_EQ(test_association->iv[4], 0x00);
    ASSERT_EQ(test_association->iv[5], 0x01);
    ASSERT_EQ(test_association->iv[6], 0x00);
    ASSERT_EQ(test_association->iv[7], 0x00);
    ASSERT_EQ(test_association->iv[8], 0x00);
    ASSERT_EQ(test_association->iv[9], 0x00);
    ASSERT_EQ(test_association->iv[10], 0x00);
    ASSERT_EQ(test_association->iv[11], 0x00);

    Crypto_saPrint(test_association);

    Crypto_Shutdown();

    free(dec_test_fe_b);
    free(dec_test_ff_b);
    free(dec_test_00_b);
    free(tc_sdls_processed_frame);
}

UTEST(TC_PROCESS, HAPPY_PATH_PROCESS_NONTRANSMITTED_INCREMENTING_ARSN_ROLLOVER)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF,
    // TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    Crypto_Init();

    SaInterface sa_if = get_sa_interface_inmemory();

    char *dec_test_fe_h = "2003002900000004FFFE80D2C70008197F0B00310000B1FE7F97816F523951BAF0445DB078B502760741";
    char *dec_test_ff_h = "2003002900000004FFFF80D2C70008197F0B00310000B1FE7F97816F523951BAF0445DB078B502768968";
    char *dec_test_00_h = "2003002900000004000080D2C70008197F0B00310000B1FE7F97816F523951BAF0445DB078B50276E797";

    uint8_t *dec_test_fe_b, *dec_test_ff_b, *dec_test_00_b     = NULL;
    int      dec_test_fe_len, dec_test_ff_len, dec_test_00_len = 0;

    hex_conversion(dec_test_fe_h, (char **)&dec_test_fe_b, &dec_test_fe_len);
    hex_conversion(dec_test_ff_h, (char **)&dec_test_ff_b, &dec_test_ff_len);
    hex_conversion(dec_test_00_h, (char **)&dec_test_00_b, &dec_test_00_len);

    SecurityAssociation_t *test_association;

    int32_t return_val = -1;

    TC_t tc_sdls_processed_frame;
    memset(&tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    // Default SA
    // Expose SA 1 for testing
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->ecs_len = 1;
    test_association->ecs     = CRYPTO_CIPHER_NONE;

    // Deactive SA 1
    test_association->sa_state = SA_NONE;

    // Expose SA 4 for testing
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->shivf_len = 0;
    test_association->iv_len    = 0;
    test_association->est       = 0;
    test_association->ast       = 1;
    test_association->ecs_len   = 1;
    test_association->ecs       = CRYPTO_CIPHER_NONE;
    test_association->acs_len   = 1;
    test_association->acs       = CRYPTO_MAC_CMAC_AES256;
    test_association->arsn_len  = 3;
    test_association->shsnf_len = 2;
    // ARSN = "05FFFD"
    test_association->arsn[0] = 0x05;
    test_association->arsn[1] = 0xFF;
    test_association->arsn[2] = 0xFD;

    // This TA was originally setup for AESGCM, need to specify an akid so we can use it for a MAC
    test_association->akid = 130;

    Crypto_saPrint(test_association);
    return_val = Crypto_TC_ProcessSecurity(dec_test_fe_b, &dec_test_fe_len, &tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    ASSERT_EQ(test_association->arsn[2], 0xFE);

    return_val = Crypto_TC_ProcessSecurity(dec_test_ff_b, &dec_test_ff_len, &tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    ASSERT_EQ(test_association->arsn[2], 0xFF);

    // test_association->iv[5] = 0x01;
    return_val = Crypto_TC_ProcessSecurity(dec_test_00_b, &dec_test_00_len, &tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    ASSERT_EQ(test_association->arsn[0], 0x06);
    ASSERT_EQ(test_association->arsn[1], 0x00);
    ASSERT_EQ(test_association->arsn[2], 0x00);

    Crypto_saPrint(test_association);

    Crypto_Shutdown();

    free(dec_test_fe_b);
    free(dec_test_ff_b);
    free(dec_test_00_b);
}

UTEST(TC_PROCESS, ERROR_TC_INPUT_FRAME_TOO_SHORT_FOR_SPEC)
{
    remove("sa_save_file.bin");
    int32_t status = CRYPTO_LIB_SUCCESS;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 4,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char    *test_frame_pt_h   = "2003001c";
    uint8_t *test_frame_pt_b   = NULL;
    int      test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->arsn_len  = 0;
    test_association->shsnf_len = 0;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char **)&test_frame_pt_b, &test_frame_pt_len);
    // Should fail, as frame length violates the managed parameter
    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TC_STANDARD, status);

    Crypto_Shutdown();
    free(tc_sdls_processed_frame);
    free(test_frame_pt_b);
}

UTEST(TC_PROCESS, ERROR_TC_INPUT_FRAME_TOO_SHORT_FOR_SPECIFIED_FRAME_LENGTH_HEADER)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 4,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char    *test_frame_pt_h   = "200304260000020000000000000000000000309e09deeaa375487983a89f3ed7519a230baf22";
    uint8_t *test_frame_pt_b   = NULL;
    int      test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->arsn_len  = 0;
    test_association->shsnf_len = 0;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char **)&test_frame_pt_b, &test_frame_pt_len);
    // Should fail, as frame length violates the managed parameter
    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_INPUT_FRAME_LENGTH_SHORTER_THAN_FRAME_HEADERS_LENGTH, status);

    Crypto_Shutdown();
    free(test_frame_pt_b);
    free(tc_sdls_processed_frame);
}

UTEST(TC_PROCESS, HAPPY_PATH_DECRYPT_CBC)
{
    remove("sa_save_file.bin");
    int32_t status = CRYPTO_LIB_SUCCESS;
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char    *test_frame_pt_h = "2003002A0000000B00000000000000000000000000000000025364F9BC3344AF359DA06CA886746F59A0AB";
    uint8_t *test_frame_pt_b = NULL;
    int      test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;
    sa_if->sa_get_from_spi(11, &test_association);
    test_association->arsn_len   = 0;
    test_association->shsnf_len  = 0;
    test_association->ast        = 0;
    test_association->stmacf_len = 0;
    test_association->ekid       = 130;
    test_association->sa_state   = SA_OPERATIONAL;

    crypto_key_t *ekp    = NULL;
    ekp = key_if->get_key(test_association->ekid);
    ekp->key_state = KEY_ACTIVE;

    crypto_key_t *akp    = NULL;
    akp = key_if->get_key(test_association->akid);
    akp->key_state = KEY_ACTIVE;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char **)&test_frame_pt_b, &test_frame_pt_len);

    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);

    char    *truth_data_h = "80d2c70008197f0b00310000b1fe";
    uint8_t *truth_data_b = NULL;
    int      truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    // printf("Decrypted Frame:\n");
    for (int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        // printf("%02x -> %02x ", tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
        ASSERT_EQ(tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    }
    // printf("\n");

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    free(tc_sdls_processed_frame);
    free(test_frame_pt_b);
    free(truth_data_b);
    Crypto_Shutdown();
}

/**
 * @brief Unit Test: Decryption CBC with 1 Byte of padding
 **/
UTEST(TC_PROCESS, DECRYPT_CBC_1B)
{
    remove("sa_save_file.bin");
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF,
    // TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0,
    // 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);

    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 2;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 3;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char    *test_frame_pt_h = "2003002A0000000B00000000000000000000000000000000011C1741A95DE7EF6FCF2B20B6F09E9FD29988";
    uint8_t *test_frame_pt_b = NULL;
    int      test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;
    sa_if->sa_get_from_spi(11, &test_association);
    test_association->arsn_len   = 0;
    test_association->shsnf_len  = 0;
    test_association->ast        = 0;
    test_association->stmacf_len = 0;
    test_association->ekid       = 130;
    test_association->sa_state   = SA_OPERATIONAL;

    crypto_key_t *ekp    = NULL;
    ekp = key_if->get_key(test_association->ekid);
    ekp->key_state = KEY_ACTIVE;

    crypto_key_t *akp    = NULL;
    akp = key_if->get_key(test_association->akid);
    akp->key_state = KEY_ACTIVE;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char **)&test_frame_pt_b, &test_frame_pt_len);

    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);

    char    *truth_data_h = "80d2c70008197f0b0031000000b1fe";
    uint8_t *truth_data_b = NULL;
    int      truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    // printf("Decrypted Frame:\n");
    for (int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        // printf("%02x -> %02x ", tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
        ASSERT_EQ(tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    }
    // printf("\n");

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    free(test_frame_pt_b);
    free(tc_sdls_processed_frame);
    free(truth_data_b);
    Crypto_Shutdown();
}

/**
 * @brief Unit Test: Decryption CBC with 16 Bytes of padding
 **/
UTEST(TC_PROCESS, DECRYPT_CBC_16B)
{
    remove("sa_save_file.bin");
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF,
    // TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0,
    // 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);

    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 2;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 3;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    int32_t status = Crypto_Init();

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    char *test_frame_pt_h = "2003003A0000000B00000000000000000000000000000000103970EAE4C05ACD1B0C348FDA174DF73EF0E2D603"
                            "996C4B78B992CD60918729D3A47A";
    uint8_t *test_frame_pt_b   = NULL;
    int      test_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;
    sa_if->sa_get_from_spi(11, &test_association);
    test_association->arsn_len   = 0;
    test_association->shsnf_len  = 0;
    test_association->ast        = 0;
    test_association->stmacf_len = 0;
    test_association->sa_state   = SA_OPERATIONAL;
    test_association->ekid       = 130;

    crypto_key_t *ekp    = NULL;
    ekp = key_if->get_key(test_association->ekid);
    ekp->key_state = KEY_ACTIVE;

    crypto_key_t *akp    = NULL;
    akp = key_if->get_key(test_association->akid);
    akp->key_state = KEY_ACTIVE;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char **)&test_frame_pt_b, &test_frame_pt_len);

    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);

    char    *truth_data_h = "80d2c70008197f0b003100000000b1fe";
    uint8_t *truth_data_b = NULL;
    int      truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    // printf("Decrypted Frame:\n");
    for (int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        printf("%02x -> %02x ", tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
        ASSERT_EQ(tc_sdls_processed_frame->tc_pdu[i], truth_data_b[i]);
    }
    // printf("\n");

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    free(test_frame_pt_b);
    free(tc_sdls_processed_frame);
    free(truth_data_b);
    Crypto_Shutdown();
}

/**
 * @brief GCM window checking should be able to check IV and ARSN counters
 * Test Cases: Replay, outside of window
 **/
UTEST(TC_PROCESS, GCM_IV_AND_ARSN)
{
    remove("sa_save_file.bin");
    uint8_t *ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF,
    // TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);

    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 2;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 3;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    Crypto_Init();
    SaInterface   sa_if  = get_sa_interface_inmemory();
    crypto_key_t *ekp    = NULL;
    int           status = 0;

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_arsn_h     = "0123"; // The last valid ARSN that was seen by the SA
    char *buffer_nist_key_h = "ef9f9284cf599eac3b119905a7d18851e7e374cf63aea04358586b0f757670f8";
    char *buffer_nist_iv_h  = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    char *buffer_replay_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374B1224DFEFB72A20D49E09256908874979DFC1"; // IV is one less than library
                                                                                        // expects
    char *buffer_outside_window_h =
        "2003002500FF0009B6AC8E4963F49207FFD6375C1224DFEFB72A20D49E09256908874979B36E"; // IV is outside the positive
                                                                                        // window
    char *buffer_bad_iv_bad_arsn_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374C01231224DFEFB72A20D49E09256908874979"; // IV isa replay, ARSN is a
                                                                                        // replay
    char *buffer_good_iv_bad_arsn_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374C01231224DFEFB72A20D49E09256908874979"; // IV is the next one expected,
                                                                                        // ARSN is a replay
    char *buffer_bad_iv_good_arsn_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374B01241224DFEFB72A20D49E09256908874979"; // IV is a replay, ARSN is next
                                                                                        // expected
    char *buffer_good_iv_with_gap_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374F1224DFEFB72A20D49E092569088749799C49"; // IV is valid, but not next one
                                                                                        // expected
    char *buffer_high_iv_good_arsn_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374B01241224DFEFB72A20D49E09256908874979"; // IV is outside upper bounds,
                                                                                        // ARSN is next expected
    char *buffer_good_iv_high_arsn_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374BFFFE1224DFEFB72A20D49E09256908874979"; // IV is next expected, ARSN is
                                                                                        // outside upper bounds
    char *buffer_good_iv_good_arsn_h =
        "2003002500FF0009B6AC8E4963F49207FFD6374C01241224DFEFB72A20D49E09256908874979"; // IV is next expected, ARSN is
                                                                                        // next expected
    char *buffer_good_iv_gap_good_arsn_gap_h =
        "2003002500FF0009B6AC8E4963F49207FFD6375101291224DFEFB72A20D49E09256908874979"; // IV is next expected, ARSN is
                                                                                        // next expected

    uint8_t *buffer_replay_b, *buffer_outside_window_b, *buffer_bad_iv_bad_arsn_b, *buffer_good_iv_bad_arsn_b,
        *buffer_bad_iv_good_arsn_b, *buffer_good_iv_with_gap_b, *buffer_high_iv_good_arsn_b,
        *buffer_good_iv_high_arsn_b, *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_good_iv_good_arsn_b,
        *buffer_good_iv_gap_good_arsn_gap_b, *buffer_arsn_b = NULL;
    int buffer_replay_len, buffer_outside_window_len, buffer_bad_iv_bad_arsn_len, buffer_good_iv_bad_arsn_len,
        buffer_bad_iv_good_arsn_len, buffer_good_iv_with_gap_len, buffer_high_iv_good_arsn_len,
        buffer_good_iv_high_arsn_len, buffer_nist_iv_len, buffer_nist_key_len, buffer_good_iv_good_arsn_len,
        buffer_good_iv_gap_good_arsn_gap_len, buffer_arsn_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;
    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->sa_state   = SA_OPERATIONAL;
    test_association->ecs_len    = 1;
    test_association->ecs        = CRYPTO_CIPHER_AES256_GCM;
    test_association->acs        = 0;
    test_association->shsnf_len  = 2;
    test_association->arsn_len   = 2;
    test_association->arsnw      = 5;
    test_association->est        = 1;
    test_association->ast        = 0;
    test_association->ekid       = 136;
    test_association->akid       = 0;
    test_association->shivf_len  = 12;
    test_association->iv_len     = 12;
    test_association->shplf_len  = 1;
    test_association->arsnw_len  = 1;
    test_association->stmacf_len = 0;
    test_association->abm_len    = 1024;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);

    ekp->key_state = KEY_ACTIVE;

    // Convert frames that will be processed
    hex_conversion(buffer_replay_h, (char **)&buffer_replay_b, &buffer_replay_len);
    hex_conversion(buffer_outside_window_h, (char **)&buffer_outside_window_b, &buffer_outside_window_len);
    hex_conversion(buffer_bad_iv_bad_arsn_h, (char **)&buffer_bad_iv_bad_arsn_b, &buffer_bad_iv_bad_arsn_len);
    hex_conversion(buffer_good_iv_bad_arsn_h, (char **)&buffer_good_iv_bad_arsn_b, &buffer_good_iv_bad_arsn_len);
    hex_conversion(buffer_bad_iv_good_arsn_h, (char **)&buffer_bad_iv_good_arsn_b, &buffer_bad_iv_good_arsn_len);
    hex_conversion(buffer_good_iv_with_gap_h, (char **)&buffer_good_iv_with_gap_b, &buffer_good_iv_with_gap_len);
    hex_conversion(buffer_high_iv_good_arsn_h, (char **)&buffer_high_iv_good_arsn_b, &buffer_high_iv_good_arsn_len);
    hex_conversion(buffer_good_iv_high_arsn_h, (char **)&buffer_good_iv_high_arsn_b, &buffer_good_iv_high_arsn_len);
    hex_conversion(buffer_good_iv_good_arsn_h, (char **)&buffer_good_iv_good_arsn_b, &buffer_good_iv_good_arsn_len);
    hex_conversion(buffer_good_iv_gap_good_arsn_gap_h, (char **)&buffer_good_iv_gap_good_arsn_gap_b,
                   &buffer_good_iv_gap_good_arsn_gap_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char **)&buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert/Set input ARSN
    hex_conversion(buffer_arsn_h, (char **)&buffer_arsn_b, &buffer_arsn_len);
    memcpy(test_association->arsn, buffer_arsn_b, buffer_arsn_len);

    // Expect to fail on ARSN (Bad IV, bad ARSN)
    printf(KGRN "Checking replay - using previous received ARSN and previous IV...\n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_bad_iv_bad_arsn_b, &buffer_bad_iv_bad_arsn_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW, status);

    // Expect to fail on ARSN (Good IV, bad ARSN)
    printf(KGRN "Checking replay - using previous received ARSN...\n" RESET);
    status =
        Crypto_TC_ProcessSecurity(buffer_good_iv_bad_arsn_b, &buffer_good_iv_bad_arsn_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW, status);
    // Verify IV did not increment since ARSN was bad
    for (int i = 0; i < test_association->iv_len; i++)
    {
        ASSERT_EQ(test_association->iv[i], buffer_nist_iv_b[i]);
    }

    // Expect to fail on IV (Bad IV, Good ARSN)
    printf(KGRN "Checking replay - using previous received IV...\n" RESET);
    status =
        Crypto_TC_ProcessSecurity(buffer_bad_iv_good_arsn_b, &buffer_bad_iv_good_arsn_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW, status);
    // Verify ARSN did not increment since IV was bad
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(test_association->arsn[i], buffer_arsn_b[i]);
    }

    // Expect to fail on IV counter being too high
    // Check w/ Mike
    printf(KGRN "Checking replay - using IV outside (above) the window...\n" RESET);
    status =
        Crypto_TC_ProcessSecurity(buffer_high_iv_good_arsn_b, &buffer_high_iv_good_arsn_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW, status);

    // Expect to fail on ARSN counter being too high
    // Check w/ Mike
    printf(KGRN "Checking replay - using ARSN outside (above) the window...\n" RESET);
    status =
        Crypto_TC_ProcessSecurity(buffer_good_iv_high_arsn_b, &buffer_good_iv_high_arsn_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW, status);

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking  next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status =
        Crypto_TC_ProcessSecurity(buffer_good_iv_good_arsn_b, &buffer_good_iv_good_arsn_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    // Verify IV LSB incremented
    ASSERT_EQ(test_association->iv[test_association->iv_len - 1], 0x4C);
    // Verify ARSN LSB incremented
    ASSERT_EQ(test_association->arsn[test_association->arsn_len - 1], 0x24);

    // Expect success on valid IV and ARSNs within window, but have a gap
    printf(KGRN "Checking valid IV and ARSN within window... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_good_iv_gap_good_arsn_gap_b, &buffer_good_iv_gap_good_arsn_gap_len,
                                       tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Validate that the SA IV is updated to the most recently received IV
    // IV length in this testing is 12 bytes
    printf(KGRN "Verifying IV updated correctly...\n" RESET);
    printf("SA IV is now:\t");
    for (int i = 0; i < test_association->shivf_len; i++)
    {
        ASSERT_EQ(*(test_association->iv + i),
                  *(buffer_good_iv_gap_good_arsn_gap_b + 8 + i)); // 8 is IV offset into packet
        printf("%02X", *(test_association->iv + i));
    }
    printf("\n");
    // Validate that the SA ARSN is updated to the most recently received IV
    // ARSN length in this testing is 2 bytes
    printf(KGRN "Verifying ARSN updated correctly...\n" RESET);
    printf("SA ARSN is now:\t");
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(*(test_association->arsn + i),
                  *(buffer_good_iv_gap_good_arsn_gap_b + 8 + test_association->shivf_len +
                    i)); // 8 + shivf is IV offset into packet
        printf("%02X", *(test_association->arsn + i));
    }
    printf("\n");
    Crypto_Shutdown();
    free(buffer_replay_b);
    free(buffer_outside_window_b);
    free(buffer_good_iv_bad_arsn_b);
    free(buffer_good_iv_with_gap_b);
    free(ptr_enc_frame);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(tc_nist_processed_frame);
}

UTEST(TC_PROCESS, TC_SA_SEGFAULT_TEST)
{
    remove("sa_save_file.bin");
    // Local Variables
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Configure Parameters
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // AOS Tests
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t AOS_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(AOS_Managed_Parameters);

    status = Crypto_Init();

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    // Test frame setup
    char    *test_frame_pt_h = "2003002A000000FF00000000000000000000000000000000025364F9BC3344AF359DA06CA886748F59A0AB";
    uint8_t *test_frame_pt_b = NULL;
    int      test_frame_pt_len = 0;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char **)&test_frame_pt_b, &test_frame_pt_len);

    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);

    ASSERT_EQ(CRYPTO_LIB_ERR_SPI_INDEX_OOB, status);
    free(test_frame_pt_b);
    free(tc_sdls_processed_frame);
    Crypto_Shutdown();
}

UTEST(TC_PROCESS, TC_SA_NOT_OPERATIONAL)
{
    remove("sa_save_file.bin");
    // Local Variables
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Configure Parameters
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // AOS Tests
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t AOS_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(AOS_Managed_Parameters);

    status = Crypto_Init();

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    // Test frame setup
    char    *test_frame_pt_h   = "2003000C00002C414243444546";
    uint8_t *test_frame_pt_b   = NULL;
    int      test_frame_pt_len = 0;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char **)&test_frame_pt_b, &test_frame_pt_len);

    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);

    ASSERT_EQ(CRYPTO_LIB_ERR_SA_NOT_OPERATIONAL, status);
    free(test_frame_pt_b);
    free(tc_sdls_processed_frame);
    Crypto_Shutdown();
}

UTEST(TC_PROCESS, TC_KEY_STATE_TEST)
{
    remove("sa_save_file.bin");
    // Local Variables
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Configure Parameters
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // AOS Tests
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t AOS_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(AOS_Managed_Parameters);

    status = Crypto_Init();

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    // Test frame setup
    char    *test_frame_pt_h = "2003002A0000000100000000000000000000000000000000025364F9BC3344AF359DA06CA886748F59A0AB";
    uint8_t *test_frame_pt_b = NULL;
    int      test_frame_pt_len = 0;

    SecurityAssociation_t *test_association;
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->est = 1;

    crypto_key_t *ekp    = NULL;
    ekp = key_if->get_key(test_association->ekid);
    ekp->key_state = KEY_DEACTIVATED;

    crypto_key_t *akp    = NULL;
    akp = key_if->get_key(test_association->akid);
    akp->key_state = KEY_DEACTIVATED;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char **)&test_frame_pt_b, &test_frame_pt_len);

    status = Crypto_TC_ProcessSecurity(test_frame_pt_b, &test_frame_pt_len, tc_sdls_processed_frame);

    ASSERT_EQ(CRYPTO_LIB_ERR_KEY_STATE_INVALID, status);
    free(test_frame_pt_b);
    free(tc_sdls_processed_frame);
    Crypto_Shutdown();
}

UTEST_MAIN();
