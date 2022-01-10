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
 *  Unit Tests that macke use of TC_ApplySecurity function on the data.
 **/
#include "ut_tc_apply.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

/**
 * @brief Unit Test: No Crypto_Init()
 *
 * TC_ApplySecurity should reject functionality if the Crypto_Init() function has not been called.
 **/
UTEST(TC_APPLY_SECURITY, NO_CRYPTO_INIT)
{
    // No Crypto_Init(), but we still Configure It;
    char *raw_tc_sdls_ping_h = "20030015001880d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                            TC_CHECK_FECF_TRUE, 0x3F);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t return_val = CRYPTO_LIB_ERROR;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_ERR_NO_INIT, return_val);
    free(raw_tc_sdls_ping_b);
    Crypto_Shutdown();
}

/**
 * @brief Unit Test:  Nominal Case
 * This should read a raw_tc_sdls_ping and continue down the "happy Path", finally returning CRYPTO_LIB_SUCCESS
 **/
UTEST(TC_APPLY_SECURITY, HAPPY_PATH_CLEAR)
{
    // Setup & Initialize CryptoLib
    Crypto_Init_Unit_Test();
    char *raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;

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
    // Setup & Initialize CryptoLib
    Crypto_Init_Unit_Test();
    char *raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t *test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(4, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 0;
    test_association->arc_len = 0;

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
    // Setup & Initialize CryptoLib
    Crypto_Init_Unit_Test();
    char *raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t *test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(4, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->arc_len = 0;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

/**
 * @brief Unit Test: Bad Spacecraft ID
 * This should pass the flawed hex string, and return CRYPTO_LIB_ERR_INVALID_SCID
 * Bad Space Craft ID.  This should pass the flawed .dat file, and return MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND
 **/
UTEST(TC_APPLY_SECURITY, BAD_SPACE_CRAFT_ID)
{
    // Setup & Initialize CryptoLib
    Crypto_Init_Unit_Test();
    char *raw_tc_sdls_ping_bad_scid_h = "20010015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_bad_scid_b = NULL;
    int raw_tc_sdls_ping_bad_scid_len = 0;

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
    // Setup & Initialize CryptoLib
    Crypto_Init_Unit_Test();
    char *raw_tc_sdls_ping_bad_vcid_h = "20032015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_bad_vcid_b = NULL;
    int raw_tc_sdls_ping_bad_vcid_len = 0;

    hex_conversion(raw_tc_sdls_ping_bad_vcid_h, &raw_tc_sdls_ping_bad_vcid_b, &raw_tc_sdls_ping_bad_vcid_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t return_val = CRYPTO_LIB_ERROR;

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
    // Setup & Initialize CryptoLib
    Crypto_Init_Unit_Test();
    long buffer_size = 0;
    uint8_t *buffer = NULL;
    uint16_t buffer_size_i = (uint16_t)buffer_size;

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t return_val = -1;

    return_val = Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len);

    Crypto_Shutdown();
    ASSERT_EQ(CRYPTO_LIB_ERR_NULL_BUFFER, return_val);
}

// TODO:
/*  What should be returned if something goes wrong with Control Command Flag?
    Should a NULL pointer be returned....The original pointer?
    We need to decide on this functionality and write a test for this
*/

UTEST_MAIN();
