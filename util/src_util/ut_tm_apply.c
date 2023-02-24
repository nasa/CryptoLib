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
 *  Unit Tests that macke use of TM_ApplySecurity function on the data.
 **/
#include "ut_tm_apply.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

/**
 * @brief Unit Test: No Crypto_Init()
 *
 * TM_ApplySecurity should reject functionality if the Crypto_Init() function has not been called.
 **/
UTEST(TM_APPLY_SECURITY, NO_CRYPTO_INIT)
{
    // No Crypto_Init(), but we still Configure It;
    char* raw_tm_sdls_ping_h = "20030015001880d2c70008197f0b00310000b1fe3128";
    char* raw_tm_sdls_ping_b = NULL;
    int raw_tm_sdls_ping_len = 0;

    hex_conversion(raw_tm_sdls_ping_h, &raw_tm_sdls_ping_b, &raw_tm_sdls_ping_len);
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0000, 0, TM_HAS_FECF, TM_HAS_SEGMENT_HDRS, 1024);

    // uint8_t* ptr_enc_frame = NULL;
    // uint16_t enc_frame_len = 0;
    int32_t return_val = CRYPTO_LIB_ERROR;

    return_val = Crypto_TM_ApplySecurity((uint8_t* )raw_tm_sdls_ping_b, &raw_tm_sdls_ping_len);
    ASSERT_EQ(CRYPTO_LIB_ERR_NO_INIT, return_val);

    char* error_enum = Crypto_Get_Error_Code_Enum_String(return_val);
    ASSERT_STREQ("CRYPTO_LIB_ERR_NO_INIT",error_enum);
    free(raw_tm_sdls_ping_b);
    Crypto_Shutdown();
}

/**
 * @brief Unit Test: No Set Configuration
 **/
// UTEST(TM_APPLY_SECURITY, NO_CONFIG)
// {
//     // No Crypto_Init(), but we still Configure It;
//     char* raw_tm_sdls_ping_h = "20030015001880d2c70008197f0b00310000b1fe3128";
//     char* raw_tm_sdls_ping_b = NULL;
//     int raw_tm_sdls_ping_len = 0;

//     hex_conversion(raw_tm_sdls_ping_h, &raw_tm_sdls_ping_b, &raw_tm_sdls_ping_len);

//     // uint8_t* ptr_enc_frame = NULL;
//     // uint16_t enc_frame_len = 0;
//     int32_t return_val = CRYPTO_LIB_ERROR;

//     return_val = Crypto_TM_ApplySecurity((uint8_t* )raw_tm_sdls_ping_b, &raw_tm_sdls_ping_len);
//     ASSERT_EQ(CRYPTO_LIB_ERR_NO_CONFIG, return_val);

//     char* error_enum = Crypto_Get_Error_Code_Enum_String(return_val);
//     ASSERT_STREQ("CRYPTO_LIB_ERR_NO_CONFIG",error_enum);

//     free(raw_tm_sdls_ping_b);
//     Crypto_Shutdown();
// }

/**
 * @brief Unit Test:  Nominal Case
 * This should read a raw_tm_sdls_ping and continue down the "happy Path", finally returning CRYPTO_LIB_SUCCESS
 **/
// UTEST(TM_APPLY_SECURITY, HAPPY_PATH_CLEAR)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Init_Unit_Test();
//     char* raw_tm_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
//     char* raw_tm_sdls_ping_b = NULL;
//     int raw_tm_sdls_ping_len = 0;

//     hex_conversion(raw_tm_sdls_ping_h, &raw_tm_sdls_ping_b, &raw_tm_sdls_ping_len);

//     uint8_t* ptr_enc_frame = NULL;
//     // uint16_t enc_frame_len = 0;

//     int32_t return_val = CRYPTO_LIB_ERROR;

//     return_val =
//         Crypto_TM_ApplySecurity((uint8_t* )raw_tm_sdls_ping_b, &raw_tm_sdls_ping_len);
//     Crypto_Shutdown();
//     free(raw_tm_sdls_ping_b);
//     free(ptr_enc_frame);
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
// }

// /**
//  * @brief Unit Test: Nominal Encryption
//  **/
// UTEST(TM_APPLY_SECURITY, HAPPY_PATH_ENC)
// {
//     // Setup & Initialize CryptoLib
//     Crypto_Init_Unit_Test();
//     char* raw_tm_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
//     char* raw_tm_sdls_ping_b = NULL;
//     int raw_tm_sdls_ping_len = 0;
//     SadbRoutine sadb_routine = get_sadb_routine_inmemory();

//     hex_conversion(raw_tm_sdls_ping_h, &raw_tm_sdls_ping_b, &raw_tm_sdls_ping_len);

//     uint8_t* ptr_enc_frame = NULL;
//     // uint16_t enc_frame_len = 0;

//     int32_t return_val = CRYPTO_LIB_ERROR;

//     SecurityAssociation_t* test_association;
//     // Expose the SADB Security Association for test edits.
//     sadb_routine->sadb_get_sa_from_spi(1, &test_association);
//     test_association->sa_state = SA_NONE;
//     sadb_routine->sadb_get_sa_from_spi(4, &test_association);
//     test_association->sa_state = SA_OPERATIONAL;
//     test_association->ast = 0;
//     test_association->arsn_len = 0;

//     return_val =
//         Crypto_TM_ApplySecurity((uint8_t* )raw_tm_sdls_ping_b, &raw_tm_sdls_ping_len);
//     Crypto_Shutdown();
//     free(raw_tm_sdls_ping_b);
//     free(ptr_enc_frame);
//     ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
// }

UTEST_MAIN();
