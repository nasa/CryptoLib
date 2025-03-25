// /* Copyright (C) 2009 - 2022 National Aeronautics and Space Admirfcration.
//    All Foreign Rights are Reserved to the U.S. Government.

//    This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory,
//    including, but not limited to, any warranty that the software will conform to specifications, any implied
//    warranties of merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty
//    that the documentation will conform to the program, or any warranty that the software will be error free.

//    In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
//    consequential damages, arising out of, resulting from, or in any way connected with the software or its
//    documentation, whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was
//    sustained from, or arose out of the results of, or use of, the software, documentation or services provided
//    hereunder.

//    ITC Team
//    NASA IV&V
//    jstar-development-team@mail.nasa.gov
// */

#include "ut_aes_gcm_siv.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"

/**
 * @brief Unit Test: Crypto ECS Get Algorithm key length response for AES-GCM-SIV
 **/
UTEST(AES_GCM_SIV, GET_ECS_ALGO_KEY_LEN_SIV)
{
    remove("sa_save_file.bin");
    int32_t algo_keylen = -1;
    uint8_t crypto_algo = CRYPTO_CIPHER_AES256_GCM_SIV;
    algo_keylen         = Crypto_Get_ECS_Algo_Keylen(crypto_algo);
    ASSERT_EQ(algo_keylen, 32);
    Crypto_Shutdown();
}

/**
 * @brief Unit Test: Crypto ECS Get Algorithm response for AES-GCM-SIV
 **/
UTEST(AES_GCM_SIV, GET_ECS_ALGO_SIV)
{
    remove("sa_save_file.bin");
    Crypto_Init_TC_Unit_Test();
    int32_t libgcrypt_algo = -1;
    int8_t  crypto_algo    = CRYPTO_CIPHER_AES256_GCM_SIV;

    libgcrypt_algo = cryptography_if->cryptography_get_ecs_algo(crypto_algo);
    ASSERT_EQ(libgcrypt_algo, 9);
    Crypto_Shutdown();
}

/**
 * @brief Validation Test: AEAD_AES_256_GCM_SIV Test Vectors
 * Reference:
 * https://datatracker.ietf.org/doc/rfc8452/?include_text=1 C.2. Second Example
 * Recreated test vectors with https://github.com/line/aes-gcm-siv/tree/master, then input CryptoLib test vectors to
 *generate truth data.
 **/
UTEST(AES_GCM_SIV, AES_GCM_SIV_256_KEY_32_PT_8_ENC_TEST_1)
{
    remove("sa_save_file.bin");
    int status = CRYPTO_LIB_SUCCESS;
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface   sa_if = get_sa_interface_inmemory();
    crypto_key_t *ekp   = NULL;

    // RFC supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char    *buffer_rfc_pt_h    = "2003000c000100000000000000";
    char    *buffer_rfc_aad_h   = "";
    char    *buffer_rfc_key_h   = "0100000000000000000000000000000000000000000000000000000000000000";
    char    *buffer_rfc_nonce_h = "030000000000000000000000";
    char    *buffer_rfc_ct_h    = "4fa7a4cb7d3434f8a2855b40016daccb62a454551878fc26";
    uint8_t *buffer_rfc_pt_b, *buffer_rfc_aad_b, *buffer_rfc_key_b, *buffer_rfc_nonce_b, *buffer_rfc_ct_b       = NULL;
    int      buffer_rfc_pt_len, buffer_rfc_aad_len, buffer_rfc_key_len, buffer_rfc_nonce_len, buffer_rfc_ct_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association                        = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->arsn_len       = 0;
    test_association->shsnf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->ast            = 1;
    test_association->est            = 1;
    test_association->ecs_len        = 1;
    test_association->ecs            = CRYPTO_CIPHER_AES256_GCM_SIV;
    test_association->acs_len        = 1;
    test_association->acs            = CRYPTO_MAC_CMAC_AES256;
    test_association->stmacf_len     = 16;
    test_association->gvcid_blk.tfvn = 0;
    test_association->abm_len        = 1024;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_rfc_key_h, (char **)&buffer_rfc_key_b, &buffer_rfc_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_rfc_key_b, buffer_rfc_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_rfc_pt_h, (char **)&buffer_rfc_pt_b, &buffer_rfc_pt_len);
    // Convert/Set input AAD
    hex_conversion(buffer_rfc_aad_h, (char **)&buffer_rfc_aad_b, &buffer_rfc_aad_len);
    memcpy(test_association->abm, buffer_rfc_aad_b + 5, buffer_rfc_aad_len);
    hex_conversion(buffer_rfc_nonce_h, (char **)&buffer_rfc_nonce_b, &buffer_rfc_nonce_len);
    memcpy(test_association->iv, buffer_rfc_nonce_b, buffer_rfc_nonce_len);
    // Convert input ciphertext
    hex_conversion(buffer_rfc_ct_h, (char **)&buffer_rfc_ct_b, &buffer_rfc_ct_len);

    Crypto_TC_ApplySecurity(buffer_rfc_pt_b, buffer_rfc_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_rfc_ct_len;
    Crypto_Shutdown();
    for (int i = 0; i < buffer_rfc_pt_len - 7; i++)
    {
        printf("[%d]: %02x -> %02x \n", i, *(ptr_enc_frame + enc_data_idx), buffer_rfc_ct_b[i]);
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_rfc_ct_b[i]);
        enc_data_idx++;
    }
    // ASSERT_EQ(1,0);
    free(ptr_enc_frame);
    free(buffer_rfc_pt_b);
    free(buffer_rfc_aad_b);
    free(buffer_rfc_nonce_b);
    free(buffer_rfc_ct_b);
    free(buffer_rfc_key_b);
}

/**
 * @brief Validation Test: AEAD_AES_256_GCM_SIV Test Vectors
 * Reference:
 * https://datatracker.ietf.org/doc/rfc8452/?include_text=1 C.2. Second Example
 * Recreated test vectors with https://github.com/line/aes-gcm-siv/tree/master, then input CryptoLib test vectors to
 *generate truth data.
 **/
UTEST(AES_GCM_SIV, AES_GCM_SIV_256_KEY_32_PT_8_DEC_TEST_1)
{
    remove("sa_save_file.bin");
    uint8_t *ptr_enc_frame = NULL;

    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface   sa_if = get_sa_interface_inmemory();
    crypto_key_t *ekp   = NULL;

    // rfc supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char    *buffer_rfc_key_h   = "0100000000000000000000000000000000000000000000000000000000000000";
    char    *buffer_rfc_pt_h    = "2003000c000100000000000000";
    char    *buffer_rfc_aad_h   = "";
    char    *buffer_rfc_nonce_h = "030000000000000000000000";
    char    *buffer_rfc_et_h = "2003002a0000090300000000000000000000004fa7a4cb7d3434f8a2855b40016daccb62a454551878fc26";
    uint8_t *buffer_rfc_pt_b, *buffer_rfc_nonce_b, *buffer_rfc_et_b, *buffer_rfc_key_b, *buffer_rfc_aad_b       = NULL;
    int      buffer_rfc_pt_len, buffer_rfc_nonce_len, buffer_rfc_et_len, buffer_rfc_key_len, buffer_rfc_aad_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_rfc_processed_frame;
    tc_rfc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association                        = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->arsn_len       = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->ast            = 1;
    test_association->est            = 1;
    test_association->ecs_len        = 1;
    test_association->ecs            = CRYPTO_CIPHER_AES256_GCM_SIV;
    test_association->stmacf_len     = 16;
    test_association->shsnf_len      = 0;
    test_association->gvcid_blk.tfvn = 0;
    test_association->abm_len        = 1024;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_rfc_key_h, (char **)&buffer_rfc_key_b, &buffer_rfc_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_rfc_key_b, buffer_rfc_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_rfc_pt_h, (char **)&buffer_rfc_pt_b, &buffer_rfc_pt_len);
    // Convert/Set input nonce
    hex_conversion(buffer_rfc_nonce_h, (char **)&buffer_rfc_nonce_b, &buffer_rfc_nonce_len);
    memcpy(test_association->iv, buffer_rfc_nonce_b, buffer_rfc_nonce_len);
    hex_conversion(buffer_rfc_aad_h, (char **)&buffer_rfc_aad_b, &buffer_rfc_aad_len);
    // Convert input encryptedtext
    hex_conversion(buffer_rfc_et_h, (char **)&buffer_rfc_et_b, &buffer_rfc_et_len);

    ASSERT_EQ(0, Crypto_TC_ProcessSecurity(buffer_rfc_et_b, &buffer_rfc_et_len, tc_rfc_processed_frame));

    for (int i = 0; i < tc_rfc_processed_frame->tc_pdu_len; i++)
    {

        if (buffer_rfc_pt_b[i + 5] != tc_rfc_processed_frame->tc_pdu[i])
        {
            printf("[%d]: %02x -> %02x \n", i, buffer_rfc_pt_b[i + 5], tc_rfc_processed_frame->tc_pdu[i]);
        }
        ASSERT_EQ(buffer_rfc_pt_b[i + 5], tc_rfc_processed_frame->tc_pdu[i]);
    }
    Crypto_Shutdown();
    free(ptr_enc_frame);
    free(buffer_rfc_pt_b);
    free(buffer_rfc_nonce_b);
    free(buffer_rfc_aad_b);
    free(buffer_rfc_et_b);
    free(buffer_rfc_key_b);
}

/**
 * @brief Validation Test: AEAD_AES_256_GCM_SIV Test Vectors
 * Reference:
 * https://datatracker.ietf.org/doc/rfc8452/?include_text=1 C.2.
 * Recreated test vectors with https://github.com/line/aes-gcm-siv/tree/master, then input CryptoLib test vectors to
 *generate truth data.
 **/
UTEST(AES_GCM_SIV, AES_GCM_SIV_256_KEY_32_PT_8_ENC_TEST_2)
{
    remove("sa_save_file.bin");
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface   sa_if = get_sa_interface_inmemory();
    crypto_key_t *ekp   = NULL;

    // RFC supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char    *buffer_rfc_pt_h    = "2003001000010000000000000000000000";
    char    *buffer_rfc_aad_h   = "";
    char    *buffer_rfc_key_h   = "0100000000000000000000000000000000000000000000000000000000000000";
    char    *buffer_rfc_nonce_h = "030000000000000000000000";
    char    *buffer_rfc_ct_h    = "08fbd140589f067e2772b4a1480eefe49f5ec5c2e65c135e1ad51c58";
    uint8_t *buffer_rfc_pt_b, *buffer_rfc_aad_b, *buffer_rfc_key_b, *buffer_rfc_nonce_b, *buffer_rfc_ct_b       = NULL;
    int      buffer_rfc_pt_len, buffer_rfc_aad_len, buffer_rfc_key_len, buffer_rfc_nonce_len, buffer_rfc_ct_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association                        = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->arsn_len       = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->ast            = 1;
    test_association->est            = 1;
    test_association->ecs_len        = 1;
    test_association->ecs            = CRYPTO_CIPHER_AES256_GCM_SIV;
    test_association->acs_len        = 1;
    test_association->acs            = CRYPTO_MAC_CMAC_AES256;
    test_association->stmacf_len     = 16;
    test_association->shsnf_len      = 0;
    test_association->gvcid_blk.tfvn = 0;
    test_association->abm_len        = 1024;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_rfc_key_h, (char **)&buffer_rfc_key_b, &buffer_rfc_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_rfc_key_b, buffer_rfc_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_rfc_pt_h, (char **)&buffer_rfc_pt_b, &buffer_rfc_pt_len);
    // Convert/Set input AAD
    hex_conversion(buffer_rfc_aad_h, (char **)&buffer_rfc_aad_b, &buffer_rfc_aad_len);
    memcpy(test_association->abm, buffer_rfc_aad_b + 5, buffer_rfc_aad_len);
    hex_conversion(buffer_rfc_nonce_h, (char **)&buffer_rfc_nonce_b, &buffer_rfc_nonce_len);
    memcpy(test_association->iv, buffer_rfc_nonce_b, buffer_rfc_nonce_len);
    // Convert input ciphertext
    hex_conversion(buffer_rfc_ct_h, (char **)&buffer_rfc_ct_b, &buffer_rfc_ct_len);

    Crypto_TC_ApplySecurity(buffer_rfc_pt_b, buffer_rfc_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_rfc_ct_len;
    Crypto_Shutdown();
    for (int i = 0; i < buffer_rfc_pt_len - 7; i++)
    {
        printf("[%d]: %02x -> %02x \n", i, *(ptr_enc_frame + enc_data_idx), buffer_rfc_ct_b[i]);
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_rfc_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_rfc_pt_b);
    free(buffer_rfc_aad_b);
    free(buffer_rfc_nonce_b);
    free(buffer_rfc_ct_b);
    free(buffer_rfc_key_b);
}

/**
 * @brief Validation Test: AEAD_AES_256_GCM_SIV Test Vectors
 * Reference:
 * https://datatracker.ietf.org/doc/rfc8452/?include_text=1 C.2.
 * Recreated test vectors with https://github.com/line/aes-gcm-siv/tree/master, then input CryptoLib test vectors to
 *generate truth data.
 **/
UTEST(AES_GCM_SIV, AES_GCM_SIV_256_KEY_32_PT_20_WITH_AAD_ENC_TEST_1)
{
    remove("sa_save_file.bin");
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    // Crypto_Init_TC_Unit_Test();
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_FALSE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface   sa_if = get_sa_interface_inmemory();
    crypto_key_t *ekp   = NULL;

    // RFC8452 supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char    *buffer_rfc_pt_h    = "20030018000300000000000000000000000000000004000000";
    char    *buffer_rfc_aad_h   = "010000000000000000000000000000000200";
    char    *buffer_rfc_key_h   = "0100000000000000000000000000000000000000000000000000000000000000";
    char    *buffer_rfc_nonce_h = "030000000000000000000000";
    char    *buffer_rfc_ct_h    = "e6e883db43a9ef98fa6271cb7d4834139acf479e3b910775e769286f3f59d2e588f69b06";
    uint8_t *buffer_rfc_pt_b, *buffer_rfc_aad_b, *buffer_rfc_key_b, *buffer_rfc_nonce_b, *buffer_rfc_ct_b       = NULL;
    int      buffer_rfc_pt_len, buffer_rfc_aad_len, buffer_rfc_key_len, buffer_rfc_nonce_len, buffer_rfc_ct_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association                        = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->arsn_len       = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->ast            = 1;
    test_association->est            = 1;
    test_association->ecs_len        = 1;
    test_association->ecs            = CRYPTO_CIPHER_AES256_GCM_SIV;
    test_association->acs_len        = 1;
    test_association->acs            = CRYPTO_MAC_CMAC_AES256;
    test_association->stmacf_len     = 16;
    test_association->shsnf_len      = 0;
    test_association->gvcid_blk.tfvn = 0;
    test_association->abm_len        = 1024;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_rfc_key_h, (char **)&buffer_rfc_key_b, &buffer_rfc_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_rfc_key_b, buffer_rfc_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_rfc_pt_h, (char **)&buffer_rfc_pt_b, &buffer_rfc_pt_len);
    // Convert/Set input AAD
    hex_conversion(buffer_rfc_aad_h, (char **)&buffer_rfc_aad_b, &buffer_rfc_aad_len);
    memcpy(test_association->abm, buffer_rfc_aad_b, buffer_rfc_aad_len);
    hex_conversion(buffer_rfc_nonce_h, (char **)&buffer_rfc_nonce_b, &buffer_rfc_nonce_len);
    memcpy(test_association->iv, buffer_rfc_nonce_b, buffer_rfc_nonce_len);
    // Convert input ciphertext
    hex_conversion(buffer_rfc_ct_h, (char **)&buffer_rfc_ct_b, &buffer_rfc_ct_len);

    Crypto_TC_ApplySecurity(buffer_rfc_pt_b, buffer_rfc_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_rfc_ct_len;
    Crypto_Shutdown();
    for (int i = 0; i < buffer_rfc_pt_len - 7; i++)
    {
        printf("[%d]: %02x -> %02x \n", i, *(ptr_enc_frame + enc_data_idx), buffer_rfc_ct_b[i]);
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_rfc_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_rfc_pt_b);
    free(buffer_rfc_aad_b);
    free(buffer_rfc_nonce_b);
    free(buffer_rfc_ct_b);
    free(buffer_rfc_key_b);
}

/**
 * @brief Validation Test: AEAD_AES_256_GCM_SIV Test Vectors
 * Reference:
 * https://datatracker.ietf.org/doc/rfc8452/?include_text=1 C.2. Second Example
 * Recreated test vectors with https://github.com/line/aes-gcm-siv/tree/master, then input CryptoLib test vectors to
 *generate truth data.
 **/
UTEST(AES_GCM_SIV, AES_GCM_SIV_256_KEY_32_PT_20_WITH_AAD_DEC_TEST_1)
{
    remove("sa_save_file.bin");
    uint8_t *ptr_enc_frame = NULL;

    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface   sa_if = get_sa_interface_inmemory();
    crypto_key_t *ekp   = NULL;

    // rfc supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_rfc_pt_h  = "20030018000300000000000000000000000000000004000000";
    char *buffer_rfc_key_h = "0100000000000000000000000000000000000000000000000000000000000000";
    char *buffer_rfc_et_h = "20030036000009030000000000000000000000e6e883db43a9ef98fa6271cb7d4834139acf479e3b910775e769"
                            "286f3f59d2e588f69b06";
    uint8_t *buffer_rfc_pt_b, *buffer_rfc_et_b, *buffer_rfc_key_b     = NULL;
    int      buffer_rfc_pt_len, buffer_rfc_et_len, buffer_rfc_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_rfc_processed_frame;
    tc_rfc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association                        = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->arsn_len       = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->ast            = 1;
    test_association->est            = 1;
    test_association->ecs_len        = 1;
    test_association->ecs            = CRYPTO_CIPHER_AES256_GCM_SIV;
    test_association->stmacf_len     = 16;
    test_association->shsnf_len      = 0;
    test_association->gvcid_blk.tfvn = 0;
    test_association->abm_len        = 1024;
    // Insert key into keyring of SA 9
    hex_conversion(buffer_rfc_key_h, (char **)&buffer_rfc_key_b, &buffer_rfc_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_rfc_key_b, buffer_rfc_key_len);

    // Convert input plaintext
    hex_conversion(buffer_rfc_pt_h, (char **)&buffer_rfc_pt_b, &buffer_rfc_pt_len);
    // Convert input encryptedtext
    hex_conversion(buffer_rfc_et_h, (char **)&buffer_rfc_et_b, &buffer_rfc_et_len);

    Crypto_TC_ProcessSecurity(buffer_rfc_et_b, &buffer_rfc_et_len, tc_rfc_processed_frame);

    for (int i = 0; i < tc_rfc_processed_frame->tc_pdu_len; i++)
    {
        if (buffer_rfc_pt_b[i + 5] != tc_rfc_processed_frame->tc_pdu[i])
        {
            printf("[%d]: %02x -> %02x \n", i, buffer_rfc_pt_b[i + 5], tc_rfc_processed_frame->tc_pdu[i]);
        }
        ASSERT_EQ(buffer_rfc_pt_b[i + 5], tc_rfc_processed_frame->tc_pdu[i]);
    }

    Crypto_Shutdown();
    free(ptr_enc_frame);
    free(buffer_rfc_pt_b);
    free(buffer_rfc_et_b);
    free(buffer_rfc_key_b);
}

UTEST_MAIN();