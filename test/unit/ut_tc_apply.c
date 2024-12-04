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
 *  Unit Tests that make use of TC_ApplySecurity function on the data.
 **/
#include "ut_tc_apply.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"

/**
 * @brief Unit Test: No Crypto_Init()
 *
 * TC_ApplySecurity should reject functionality if the Crypto_Init() function has not been called.
 **/
UTEST(TC_APPLY_SECURITY, NO_CRYPTO_INIT)
{
    remove("sa_save_file.bin");
    // No Crypto_Init(), but we still Configure It;
    char *raw_tc_sdls_ping_h   = "20030015001880d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b   = NULL;
    int   raw_tc_sdls_ping_len = 0;

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t  return_val    = CRYPTO_LIB_ERROR;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_ERR_NO_CONFIG, return_val);

    char *error_enum = Crypto_Get_Error_Code_Enum_String(return_val);
    ASSERT_STREQ("CRYPTO_LIB_ERR_NO_CONFIG", error_enum);
    free(raw_tc_sdls_ping_b);
    Crypto_Shutdown();
}

/**
 * @brief Unit Test: No Set Configuration
 **/
UTEST(TC_APPLY_SECURITY, NO_CONFIG)
{
    remove("sa_save_file.bin");
    // No Crypto_Init(), but we still Configure It;
    char *raw_tc_sdls_ping_h   = "20030015001880d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b   = NULL;
    int   raw_tc_sdls_ping_len = 0;

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t  return_val    = CRYPTO_LIB_ERROR;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_ERR_NO_CONFIG, return_val);

    char *error_enum = Crypto_Get_Error_Code_Enum_String(return_val);
    ASSERT_STREQ("CRYPTO_LIB_ERR_NO_CONFIG", error_enum);

    free(raw_tc_sdls_ping_b);
    Crypto_Shutdown();
}

/**
 * @brief Unit Test:  Nominal Case
 * This should read a raw_tc_sdls_ping and continue down the "happy Path", finally returning CRYPTO_LIB_SUCCESS
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_CLEAR)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char *raw_tc_sdls_ping_h   = "20030015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b   = NULL;
    int   raw_tc_sdls_ping_len = 0;

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Nominal Encryption
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_ENC)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char       *raw_tc_sdls_ping_h   = "20030015000080d2c70008197f0b00310000b1fe3128";
    char       *raw_tc_sdls_ping_b   = NULL;
    int         raw_tc_sdls_ping_len = 0;
    SaInterface sa_if                = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    // Set the Key
    test_association->ekid           = 130;
    test_association->gvcid_blk.vcid = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->ast            = 0;
    test_association->arsn_len       = 0;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Nominal Encryption
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_ENC_BAD_SPI)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char       *raw_tc_sdls_ping_h   = "20030015000080d2c70008197f0b00310000b1fe3128";
    char       *raw_tc_sdls_ping_b   = NULL;
    int         raw_tc_sdls_ping_len = 0;
    SaInterface sa_if                = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    // Set the Key
    test_association->ekid           = 130;
    test_association->gvcid_blk.vcid = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->ast            = 0;
    test_association->arsn_len       = 0;
    test_association->spi            = 5;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_SPI_INDEX_MISMATCH, return_val);
}

/**
 * @brief Unit Test: Nominal Encryption CBC
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_ENC_CBC)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char       *raw_tc_sdls_ping_h   = "20030015000080d2c70008197f0b00310000b1fe3128";
    char       *raw_tc_sdls_ping_b   = NULL;
    int         raw_tc_sdls_ping_len = 0;
    SaInterface sa_if                = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(2, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast      = 0;
    test_association->arsn_len = 0;
    // Set the Key
    test_association->ekid = 130;
    sa_if->sa_get_from_spi(2, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}
/**
 * @brief Unit Test: Nominal Authorized Encryption
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_AUTH_ENC)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char       *raw_tc_sdls_ping_h   = "20030015000080d2c70008197f0b00310000b1fe3128";
    char       *raw_tc_sdls_ping_b   = NULL;
    int         raw_tc_sdls_ping_len = 0;
    SaInterface sa_if                = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->gvcid_blk.vcid = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->arsn_len       = 0;
    // Set the Key
    test_association->ekid = 130;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Nominal Authorized Encryption With Partial IV Rollover, increment static IV
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_APPLY_NONTRANSMITTED_INCREMENTING_IV_ROLLOVER)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char *raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b = NULL;

    char *new_iv_h = "FFFFFFFFFFFC";
    char *new_iv_b = NULL;

    char *expected_iv_h = "000000000001000000000001";
    char *expected_iv_b = NULL;

    int raw_tc_sdls_ping_len = 0;
    int new_iv_len           = 0;
    int expected_iv_len      = 0;

    SaInterface sa_if = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    hex_conversion(new_iv_h, &new_iv_b, &new_iv_len);
    hex_conversion(expected_iv_h, &expected_iv_b, &expected_iv_len);
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->gvcid_blk.vcid = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->ekid           = 130;
    test_association->shivf_len      = 6;
    test_association->iv_len         = 12;
    test_association->arsn_len       = 0;
    memcpy(test_association->iv + (test_association->iv_len - test_association->shivf_len), new_iv_b, new_iv_len);

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    for (int i = 0; i < test_association->iv_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", i, expected_iv_b[i], *(test_association->iv + i));
        ASSERT_EQ(expected_iv_b[i], *(test_association->iv + i));
    }

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    free(new_iv_b);
    free(expected_iv_b);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Nominal Authorized Encryption With Partial IV Rollover, Static IV
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_APPLY_STATIC_IV_ROLLOVER)
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
    char *raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b = NULL;

    char *new_iv_h = "FFFFFFFFFFFC";
    char *new_iv_b = NULL;

    char *expected_iv_h = "000000000000000000000001";
    char *expected_iv_b = NULL;

    int raw_tc_sdls_ping_len = 0;
    int new_iv_len           = 0;
    int expected_iv_len      = 0;

    SaInterface sa_if = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    hex_conversion(new_iv_h, &new_iv_b, &new_iv_len);
    hex_conversion(expected_iv_h, &expected_iv_b, &expected_iv_len);
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->gvcid_blk.vcid = 0;
    test_association->ekid           = 130;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->shivf_len      = 6;
    test_association->iv_len         = 12;
    test_association->arsn_len       = 0;
    printf("TEST ASSOCIATION IV_LEN: %d\n", test_association->iv_len);
    sa_if->sa_get_from_spi(4, &test_association);
    memcpy(test_association->iv + (test_association->iv_len - test_association->shivf_len), new_iv_b, new_iv_len);
    printf("IV:\n");
    for (int i = 0; i < test_association->iv_len; i++)
    {
        printf("%02x ", *(test_association->iv + i));
    }
    printf("\n");

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    for (int i = 0; i < test_association->iv_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", i, expected_iv_b[i], *(test_association->iv + i));
        ASSERT_EQ(expected_iv_b[i], *(test_association->iv + i));
    }

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    free(new_iv_b);
    free(expected_iv_b);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Nominal Authorized Encryption With Partial ARSN Rollover, increment static ARSN
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_APPLY_NONTRANSMITTED_INCREMENTING_ARSN_ROLLOVER)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char *raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b = NULL;

    char *new_arsn_h = "05FFFC";
    char *new_arsn_b = NULL;

    char *expected_arsn_h = "060001";
    char *expected_arsn_b = NULL;

    int raw_tc_sdls_ping_len = 0;
    int new_arsn_len         = 0;
    int expected_arsn_len    = 0;

    SaInterface sa_if = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    hex_conversion(new_arsn_h, &new_arsn_b, &new_arsn_len);
    hex_conversion(expected_arsn_h, &expected_arsn_b, &expected_arsn_len);
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->gvcid_blk.vcid = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->shivf_len      = 0;
    test_association->iv_len         = 0;
    test_association->est            = 0;
    test_association->ast            = 1;
    test_association->ecs_len        = 1;
    test_association->ecs            = CRYPTO_CIPHER_NONE;
    test_association->acs_len        = 1;
    test_association->acs            = CRYPTO_MAC_CMAC_AES256;
    test_association->arsn_len       = 3;
    test_association->shsnf_len      = 2;
    memcpy(test_association->arsn, (uint8_t *)new_arsn_b, new_arsn_len);
    // This TA was originally setup for AESGCM, need to specify an akid so we can use it for a MAC
    test_association->akid = 130;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    printf("Expected ARSN:\n");
    Crypto_hexprint(expected_arsn_b, expected_arsn_len);
    printf("Actual SA ARSN:\n");
    Crypto_hexprint(test_association->arsn, test_association->arsn_len);

    for (int i = 0; i < test_association->arsn_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", i, expected_arsn_b[i], *(test_association->arsn + i));
        ASSERT_EQ(expected_arsn_b[i], *(test_association->arsn + i));
    }
    // Must shutdown after checking test_association ARSN since that will get freed!
    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    free(new_arsn_b);
    free(expected_arsn_b);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Bad Spacecraft ID
 * This should pass the flawed hex string, and return CRYPTO_LIB_ERR_INVALID_SCID
 * Bad Space Craft ID.  This should pass the flawed .dat file, and return MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND
 **/
UTEST(TC_APPLY_SECURITY, BAD_SPACE_CRAFT_ID)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char *raw_tc_sdls_ping_bad_scid_h   = "20010015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_bad_scid_b   = NULL;
    int   raw_tc_sdls_ping_bad_scid_len = 0;

    hex_conversion(raw_tc_sdls_ping_bad_scid_h, &raw_tc_sdls_ping_bad_scid_b, &raw_tc_sdls_ping_bad_scid_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_bad_scid_b, raw_tc_sdls_ping_bad_scid_len,
                                                 &ptr_enc_frame, &enc_frame_len);
    free(raw_tc_sdls_ping_bad_scid_b);
    free(ptr_enc_frame);
    Crypto_Shutdown();
    ASSERT_EQ(MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND, return_val);
}

/**
 * @brief Unit Test: Bad Virtual Channel ID
 * This will be passed a flawed hex string with an invalid virtual channel ID.  CRYPTO_LIB_ERR_INVALID_VCID should be
 *returned.
 **/
UTEST(TC_APPLY_SECURITY, BAD_VIRTUAL_CHANNEL_ID)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char *raw_tc_sdls_ping_bad_vcid_h   = "20032015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_bad_vcid_b   = NULL;
    int   raw_tc_sdls_ping_bad_vcid_len = 0;

    hex_conversion(raw_tc_sdls_ping_bad_vcid_h, &raw_tc_sdls_ping_bad_vcid_b, &raw_tc_sdls_ping_bad_vcid_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t  return_val    = CRYPTO_LIB_ERROR;

    return_val = Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_bad_vcid_b, raw_tc_sdls_ping_bad_vcid_len,
                                         &ptr_enc_frame, &enc_frame_len);
    free(raw_tc_sdls_ping_bad_vcid_b);
    free(ptr_enc_frame);
    Crypto_Shutdown();
    ASSERT_EQ(MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND, return_val);
}

/**
 * @brief Unit Test: Null Buffer -> TC_ApplySecurity
 * Tests how ApplySecurity function handles a null buffer.  Should reject functionality, and return
 *CRYPTO_LIB_ERR_NULL_BUFFER
 **/
UTEST(TC_APPLY_SECURITY, NULL_BUFFER)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    long     buffer_size   = 0;
    uint8_t *buffer        = NULL;
    uint16_t buffer_size_i = (uint16_t)buffer_size;

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t  return_val    = -1;

    return_val = Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len);

    Crypto_Shutdown();
    ASSERT_EQ(CRYPTO_LIB_ERR_NULL_BUFFER, return_val);
}

// TODO:
/*  What should be returned if something goes wrong with Control Command Flag?
    Should a NULL pointer be returned....The original pointer?
    We need to decide on this functionality and write a test for this
*/

/*
 * @brief Unit Test: Test that frame sizes violate the spec max and the managed parameter max
 **/
UTEST(TC_APPLY_SECURITY, INVALID_FRAME_SIZE)
{
    remove("sa_save_file.bin");
    int32_t  status        = CRYPTO_LIB_ERROR;
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 4,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 0, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    Crypto_Init();

    char *test_frame_pt_h = "2003001c00ff000100001880d03e000a197f0b000300020093d4ba21c4";
    char *long_frame_pt_h =
        "200307FF00ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000021c4";
    uint8_t *test_frame_pt_b, *long_frame_pt_b    = NULL;
    int      test_frame_pt_len, long_frame_pt_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->arsn_len  = 0;
    test_association->shsnf_len = 0;

    // Convert input test frame
    hex_conversion(test_frame_pt_h, (char **)&test_frame_pt_b, &test_frame_pt_len);
    // Should fail, as frame length violates the managed parameter
    status = Crypto_TC_ApplySecurity(test_frame_pt_b, test_frame_pt_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_MANAGED_PARAM_MAX_LIMIT, status);

    // Expose/setup SAs for testing
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->arsn_len       = 0;
    test_association->shsnf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->ekid           = 130;
    test_association->gvcid_blk.vcid = 1;
    // Reset Managed Parameters for this channel to  an invalid maximum
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 2047,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters_Reset = {
        0, 0x0003, 1, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 2047, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters_Reset);
    // Convert input test frame
    hex_conversion(long_frame_pt_h, (char **)&long_frame_pt_b, &long_frame_pt_len);
    // Should fail, as frame length violates the spec max
    status = Crypto_TC_ApplySecurity(long_frame_pt_b, long_frame_pt_len, &ptr_enc_frame, &enc_frame_len);
    free(test_frame_pt_b);
    free(long_frame_pt_b);
    Crypto_Shutdown();
    ASSERT_EQ(CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_SPEC_LIMIT, status);
}

UTEST(TC_APPLY_SECURITY, ERROR_TC_INPUT_FRAME_TOO_SHORT_FOR_SPEC)
{
    remove("sa_save_file.bin");
    int32_t  status        = CRYPTO_LIB_SUCCESS;
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 4,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 4, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

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
    status = Crypto_TC_ApplySecurity(test_frame_pt_b, test_frame_pt_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TC_STANDARD, status);
    free(test_frame_pt_b);
    Crypto_Shutdown();
}

UTEST(TC_APPLY_SECURITY, ERROR_TC_INPUT_FRAME_TOO_SHORT_FOR_SPECIFIED_FRAME_LENGTH_HEADER)
{
    remove("sa_save_file.bin");
    int32_t  status        = CRYPTO_LIB_SUCCESS;
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 4,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 4, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    char    *test_frame_pt_h   = "2003001c00000002ff";
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
    status = Crypto_TC_ApplySecurity(test_frame_pt_b, test_frame_pt_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_ERR_INPUT_FRAME_LENGTH_SHORTER_THAN_FRAME_HEADERS_LENGTH, status);
    free(test_frame_pt_b);
    Crypto_Shutdown();
}

/**
 * @brief Unit Test: Encryption CBC 1 Byte of padding
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_1BP)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
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
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char       *raw_tc_sdls_ping_h   = "20030016000080d2c70008197f0b0031000000b1fe3128";
    char       *raw_tc_sdls_ping_b   = NULL;
    int         raw_tc_sdls_ping_len = 0;
    SaInterface sa_if                = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state   = SA_OPERATIONAL;
    test_association->ekid       = 1;
    test_association->shivf_len  = 16;
    test_association->iv_len     = 16;
    test_association->arsn_len   = 0;
    test_association->ast        = 0;
    test_association->stmacf_len = 0;
    test_association->shplf_len  = 1;
    test_association->ecs        = CRYPTO_CIPHER_AES256_CBC;
    sa_if->sa_get_from_spi(4, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    char    *truth_data_h = "2003002a000000040000000000000000000000000000000001956b3e423390b3c3756c626f8b30812b6c0e";
    uint8_t *truth_data_b = NULL;
    int      truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    // printf("Encrypted Frame:\n");
    for (int i = 0; i < enc_frame_len; i++)
    {
        printf("%02x", ptr_enc_frame[i]);
        ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }
    // printf("\n");

    Crypto_Shutdown();
    free(truth_data_b);
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Encryption CBC 16 Bytes of padding
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_16BP)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
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

    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char       *raw_tc_sdls_ping_h   = "20030017000080d2c70008197f0b003100000000b1fe3128";
    char       *raw_tc_sdls_ping_b   = NULL;
    int         raw_tc_sdls_ping_len = 0;
    SaInterface sa_if                = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state   = SA_OPERATIONAL;
    test_association->ast        = 0;
    test_association->iv_len     = 16;
    test_association->shplf_len  = 1;
    test_association->ecs        = CRYPTO_CIPHER_AES256_CBC;
    test_association->ekid       = 130;
    test_association->stmacf_len = 0;
    test_association->arsn_len   = 0;
    sa_if->sa_get_from_spi(4, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    char *truth_data_h = "2003003600000004000000000000000000000000103970eae4c05acd1b0c348fda174df73ef0e2d603996c4b78b99"
                         "2cd60918729d3b8c0";
    uint8_t *truth_data_b = NULL;
    int      truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    for (int i = 0; i < enc_frame_len; i++)
    {
        ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }
    printf("\n");

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    free(truth_data_b);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Nominal Encryption CBC
 *                      Frame is max size for this test.  Any encrypted data of length greater than 1007 bytes,
 *                      will cause frame length exception.
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_FRAME_MAX)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
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

    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char *raw_tc_sdls_ping_h =
        "200303E3000080d2c70008197f0b0031000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000b1fed255";
    char       *raw_tc_sdls_ping_b   = NULL;
    int         raw_tc_sdls_ping_len = 0;
    SaInterface sa_if                = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->ekid       = 130;
    test_association->shivf_len  = 16;
    test_association->iv_len     = 16;
    test_association->shplf_len  = 1;
    test_association->ecs        = CRYPTO_CIPHER_AES256_CBC;
    test_association->sa_state   = SA_OPERATIONAL;
    test_association->ast        = 0;
    test_association->arsn_len   = 0;
    test_association->stmacf_len = 0;
    sa_if->sa_get_from_spi(4, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Encryption CBC
 *                      Frame is 1 byte too large for this test.  Any encrypted data of length greater than 1007 bytes,
 *                      will cause frame length exception.
 **/
UTEST(TC_APPLY_SECURITY, ENC_CBC_FRAME_TOO_BIG)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
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
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char *raw_tc_sdls_ping_h =
        "200303F7000080d2c70008197f0b0031000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000b1fed255";
    char       *raw_tc_sdls_ping_b   = NULL;
    int         raw_tc_sdls_ping_len = 0;
    SaInterface sa_if                = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->ekid       = 130;
    test_association->shivf_len  = 16;
    test_association->iv_len     = 16;
    test_association->shplf_len  = 1;
    test_association->ecs        = CRYPTO_CIPHER_AES256_CBC;
    test_association->sa_state   = SA_OPERATIONAL;
    test_association->ast        = 0;
    test_association->arsn_len   = 0;
    test_association->stmacf_len = 0;
    sa_if->sa_get_from_spi(4, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_SPEC_LIMIT, return_val);
}

// Verify Payload against truth data, not just return val of methods
UTEST(TC_APPLY_SECURITY, ENC_CBC_1BP_1)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
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
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char *raw_tc_sdls_ping_h   = "20030016000080d2c70008197f0b0031000000b1fe3128";
    char *raw_tc_sdls_ping_b   = NULL;
    int   raw_tc_sdls_ping_len = 0;

    char *new_iv_h = "FFEEDDCCBBAA";
    char *new_iv_b = NULL;

    // char* expected_iv_h = "000000000001000000000001";
    // char* expected_iv_b = NULL;

    int new_iv_len = 12;
    // int expected_iv_len = 0;
    SaInterface sa_if = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    hex_conversion(new_iv_h, &new_iv_b, &new_iv_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->ekid      = 130;
    test_association->ecs       = CRYPTO_CIPHER_AES256_CBC;
    test_association->ast       = 0;
    test_association->arsn_len  = 0;
    test_association->iv_len    = 12;
    test_association->shivf_len = 12;
    memcpy(test_association->iv + (test_association->iv_len - test_association->shivf_len), new_iv_b, new_iv_len);
    sa_if->sa_get_from_spi(4, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    char    *truth_data_h = "200300260000000BFFEEDDCCBBAA00000000000001BD8722C9D22E0CB109AC402748F672067D37";
    uint8_t *truth_data_b = NULL;
    int      truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    // printf("Encrypted Frame:\n");
    for (int i = 0; i < enc_frame_len; i++)
    {
        printf("%02x", ptr_enc_frame[i]);
        // ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }
    printf("\n");

    Crypto_Shutdown();
    free(truth_data_b);
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

// If using CBC, libgcrypt, in memory SA,
// expect CBC to fail if NULL IV
UTEST(TC_APPLY_SECURITY, ENC_CBC_NULL_IV)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_CRYPTO_MODULE, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
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
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char *raw_tc_sdls_ping_h   = "20030016000080d2c70008197f0b0031000000b1fe3128";
    char *raw_tc_sdls_ping_b   = NULL;
    int   raw_tc_sdls_ping_len = 0;

    char *new_iv_h = "FFEEDDCCBBAA";
    char *new_iv_b = NULL;

    // char* expected_iv_h = "000000000001000000000001";
    // char* expected_iv_b = NULL;

    int new_iv_len = 12;
    // int expected_iv_len = 0;
    SaInterface sa_if = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    hex_conversion(new_iv_h, &new_iv_b, &new_iv_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->ast       = 0;
    test_association->arsn_len  = 0;
    test_association->iv_len    = 0;
    test_association->shivf_len = 0;
    test_association->ecs       = CRYPTO_CIPHER_AES256_CBC;
    test_association->shplf_len = 1;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    char    *truth_data_h = "200300260000000BFFEEDDCCBBAA00000000000001BD8722C9D22E0CB109AC402748F672067D37";
    uint8_t *truth_data_b = NULL;
    int      truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    // printf("Encrypted Frame:\n");
    for (int i = 0; i < enc_frame_len; i++)
    {
        printf("%02x -> %02x \n", ptr_enc_frame[i], truth_data_b[i]);
        ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }
    // printf("\n");

    Crypto_Shutdown();
    free(truth_data_b);
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_NULL_IV, return_val);
}

// IV not NULL, but SHIVF len>0
UTEST(TC_APPLY_SECURITY, CBC_NULL_IV_W_IVH)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_CRYPTO_MODULE, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
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
    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char *raw_tc_sdls_ping_h   = "20030016000080d2c70008197f0b0031000000b1fe3128";
    char *raw_tc_sdls_ping_b   = NULL;
    int   raw_tc_sdls_ping_len = 0;

    char *new_iv_h = "FFEEDDCCBBAA";
    char *new_iv_b = NULL;

    // char* expected_iv_h = "000000000001000000000001";
    // char* expected_iv_b = NULL;

    int new_iv_len = 12;
    // int expected_iv_len = 0;
    SaInterface sa_if = get_sa_interface_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    hex_conversion(new_iv_h, &new_iv_b, &new_iv_len);

    uint8_t  enc_frame[2048];
    uint8_t *ptr_enc_frame = &enc_frame[0];
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t *test_association;
    // Expose the SADB Security Association for test edits.
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    printf("SPI: %d\n", test_association->spi);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->ast       = 0;
    test_association->ekid      = 130;
    test_association->shplf_len = 1;
    test_association->ecs       = CRYPTO_CIPHER_AES256_CBC;
    test_association->arsn_len  = 0;
    test_association->iv_len    = 16;
    test_association->shivf_len = 16;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    ASSERT_EQ(CRYPTO_LIB_ERR_NULL_IV, return_val);

    char    *truth_data_h = "200300260000000BFFEEDDCCBBAA00000000000001BD8722C9D22E0CB109AC402748F672067D37";
    uint8_t *truth_data_b = NULL;
    int      truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);

    printf("Received Encrypted Frame of length %d bytes:\n\t", enc_frame_len);
    for (int i = 0; i < enc_frame_len; i++)
    {
        printf("%02x -> %02x ", ptr_enc_frame[i], truth_data_b[i]);
        ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }
    printf("\n");

    Crypto_Shutdown();
    free(truth_data_b);
    free(raw_tc_sdls_ping_b);
}

/*
 * @brief: Unit Test: Verify plaintext with an ARSN places bytes appropriately.
 * Use a full length verification of all bytes. Exists due to found bug.
 */
UTEST(TC_APPLY_SECURITY, PLAINTEXT_W_ARSN)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    Crypto_Init();
    // Test string
    char *raw_tc_sdls_ping_h   = "2003001F00000100011880D2C9000E197F0B001B0004000400003040D95E0000";
    char *raw_tc_sdls_ping_b   = NULL;
    int   raw_tc_sdls_ping_len = 0;

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t  return_val    = CRYPTO_LIB_ERROR;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    // 200300230000010000000100011880D2C9000E197F0B001B0004000400003040D95E85F3
    char *truth_data_h =
        "2003002f0000010000000000000000000000000000000100011880d2c9000e197f0b001b0004000400003040d95e5ba0";
    uint8_t *truth_data_b = NULL;
    int      truth_data_l = 0;

    hex_conversion(truth_data_h, (char **)&truth_data_b, &truth_data_l);
    // printf("Encrypted Frame:\n");
    for (int i = 0; i < enc_frame_len; i++)
    {
        // printf("%02x -> %02x ", ptr_enc_frame[i], truth_data_b[i]);
        ASSERT_EQ(ptr_enc_frame[i], truth_data_b[i]);
    }

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

UTEST(TC_APPLY_SECURITY, TC_KEY_STATE_TEST)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    Crypto_Init();
    // Test string
    char *raw_tc_sdls_ping_h   = "20030015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b   = NULL;
    int   raw_tc_sdls_ping_len = 0;

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t  return_val    = CRYPTO_LIB_ERROR;

    SecurityAssociation_t *test_association;
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_KEYED;
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ekid = 130;

    crypto_key_t *ekp    = NULL;
    ekp = key_if->get_key(test_association->ekid);
    ekp->key_state = KEY_DEACTIVATED;

    crypto_key_t *akp    = NULL;
    akp = key_if->get_key(test_association->akid);
    akp->key_state = KEY_DEACTIVATED;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);

    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    ASSERT_EQ(CRYPTO_LIB_ERR_KEY_STATE_INVALID, return_val);
}

UTEST_MAIN();
