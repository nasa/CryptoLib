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
 * NOTE:  ALL OF THESE TESTS ARE MEANT TO BE RUN SEQUENTIALLY!!
 *
 * ERRONEOUS BEHAVIOR OTHERWISE
 *
 * NOTE:  AS Security associations change, this tese will need to be updated for validation
 */

/**
 *  Unit Tests that macke use of CRYPTO_CONFIG functionality on the data.
 **/
#include "ut_sa_save.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"

UTEST(SA_SAVE, VERIFY_INTERNAL)
{
    remove("sa_save_file.bin");
    Crypto_Init_TC_Unit_Test();

    SaInterface            sa_if = get_sa_interface_inmemory();
    SecurityAssociation_t *test_association;

    sa_if->sa_get_from_spi(4, &test_association);

    ASSERT_EQ(test_association->spi, 4);
    ASSERT_EQ(test_association->ekid, 4);
    ASSERT_EQ(test_association->akid, 4);
    int str_cmp_output = 0;
    str_cmp_output     = strcmp(test_association->ek_ref, "");
    ASSERT_EQ(0, str_cmp_output);
    str_cmp_output = strcmp(test_association->ak_ref, "");
    ASSERT_EQ(0, str_cmp_output);
    ASSERT_EQ(test_association->sa_state, SA_KEYED);
    ASSERT_EQ(test_association->gvcid_blk.tfvn, 0);
    ASSERT_EQ(test_association->gvcid_blk.scid, (SCID & 0x3FF));
    ASSERT_EQ(test_association->gvcid_blk.vcid, 0);
    ASSERT_EQ(test_association->gvcid_blk.mapid, TYPE_TC);
    ASSERT_EQ(test_association->est, 1);
    ASSERT_EQ(test_association->ast, 1);
    ASSERT_EQ(test_association->shivf_len, 12);
    ASSERT_EQ(test_association->shsnf_len, 0);
    ASSERT_EQ(test_association->shplf_len, 0);
    ASSERT_EQ(test_association->stmacf_len, 16);
    ASSERT_EQ(test_association->ecs, 0x01);
    ASSERT_EQ(test_association->ecs_len, 1);
    for (int i = 0; i < test_association->iv_len; i++)
    {
        ASSERT_EQ(test_association->iv[i], 0x00);
    }
    ASSERT_EQ(test_association->iv_len, 12);
    ASSERT_EQ(test_association->acs_len, 0);
    ASSERT_EQ(test_association->acs, 0x00);
    ASSERT_EQ(test_association->abm_len, 1786);
    for (int i = 0; i < test_association->abm_len; i++)
    {
        ASSERT_EQ(test_association->abm[i], 0x00);
    }
    // sa[location].abm[0] = sa_ptr->abm;
    ASSERT_EQ(test_association->arsn_len, 11);
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(test_association->arsn[i], 0);
    }
    // sa[location].arsn[0] = sa_ptr->arsn;
    ASSERT_EQ(test_association->arsnw_len, 1);
    ASSERT_EQ(test_association->arsnw, 5);
}

UTEST(SA_SAVE, INTERNAL_DEFAULT_PASS_1)
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
    test_association->shivf_len      = 6;
    test_association->iv_len         = 12;
    test_association->arsn_len       = 0;
    strcpy(test_association->ek_ref, "TEST_EK_REF");
    strcpy(test_association->ak_ref, "TEST_AK_REF");
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

UTEST(SA_SAVE, VERIFY_DEFAULT_PASS_1_SAVE)
{
    Crypto_Init_TC_Unit_Test();

    SaInterface            sa_if = get_sa_interface_inmemory();
    SecurityAssociation_t *test_association;

    sa_if->sa_get_from_spi(4, &test_association);

    ASSERT_EQ(test_association->spi, 4);
    ASSERT_EQ(test_association->ekid, 4);
    ASSERT_EQ(test_association->akid, 4);
    int str_cmp_output = 0;
    str_cmp_output     = strcmp(test_association->ek_ref, "TEST_EK_REF");
    ASSERT_EQ(0, str_cmp_output);
    str_cmp_output = strcmp(test_association->ek_ref, "TEST_EK_REF_BAD");
    ASSERT_NE(0, str_cmp_output);
    str_cmp_output = strcmp(test_association->ak_ref, "TEST_AK_REF");
    ASSERT_EQ(0, str_cmp_output);
    str_cmp_output = strcmp(test_association->ak_ref, "TEST_AK_REF_BAD");
    ASSERT_NE(0, str_cmp_output);

    ASSERT_EQ(test_association->sa_state, SA_OPERATIONAL);
    ASSERT_EQ(test_association->gvcid_blk.tfvn, 0);
    ASSERT_EQ(test_association->gvcid_blk.scid, (SCID & 0x3FF));
    ASSERT_EQ(test_association->gvcid_blk.vcid, 0);
    ASSERT_EQ(test_association->gvcid_blk.mapid, TYPE_TC);
    ASSERT_EQ(test_association->est, 1);
    ASSERT_EQ(test_association->ast, 1);
    ASSERT_EQ(test_association->shivf_len, 6);
    ASSERT_EQ(test_association->shsnf_len, 0);
    ASSERT_EQ(test_association->shplf_len, 0);
    ASSERT_EQ(test_association->stmacf_len, 16);
    ASSERT_EQ(test_association->ecs, 0x01);
    ASSERT_EQ(test_association->ecs_len, 1);

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
    ASSERT_EQ(test_association->iv[11], 0x01);

    ASSERT_EQ(test_association->iv_len, 12);
    ASSERT_EQ(test_association->acs_len, 0);
    ASSERT_EQ(test_association->acs, 0x00);
    ASSERT_EQ(test_association->abm_len, 1786);
    for (int i = 0; i < test_association->abm_len; i++)
    {
        ASSERT_EQ(test_association->abm[i], 0x00);
    }
    // sa[location].abm[0] = sa_ptr->abm;
    ASSERT_EQ(test_association->arsn_len, 0);
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(test_association->arsn[i], 0);
    }
    // sa[location].arsn[0] = sa_ptr->arsn;
    ASSERT_EQ(test_association->arsnw_len, 1);
    ASSERT_EQ(test_association->arsnw, 5);
}

UTEST(SA_SAVE, SAVE_PASS_1)
{
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char *raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b = NULL;

    char *new_iv_h = "FFFFFFFFFFFC";
    char *new_iv_b = NULL;

    char *expected_iv_h = "000000000002000000000001";
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
    test_association->shivf_len      = 6;
    test_association->iv_len         = 12;
    test_association->arsn_len       = 0;
    clean_akref(test_association);
    clean_ekref(test_association);
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

UTEST(SA_SAVE, VERIFY_SAVE_PASS_1_SAVE)
{
    Crypto_Init_TC_Unit_Test();

    SaInterface            sa_if = get_sa_interface_inmemory();
    SecurityAssociation_t *test_association;

    sa_if->sa_get_from_spi(4, &test_association);

    ASSERT_EQ(test_association->spi, 4);
    ASSERT_EQ(test_association->ekid, 4);
    ASSERT_EQ(test_association->akid, 4);
    int str_cmp_output = 0;
    str_cmp_output     = strcmp(test_association->ek_ref, "");
    ASSERT_EQ(0, str_cmp_output);
    str_cmp_output = strcmp(test_association->ek_ref, "TEST_EK_REF_BAD");
    ASSERT_NE(0, str_cmp_output);
    str_cmp_output = strcmp(test_association->ak_ref, "");
    ASSERT_EQ(0, str_cmp_output);
    str_cmp_output = strcmp(test_association->ak_ref, "TEST_AK_REF_BAD");
    ASSERT_NE(0, str_cmp_output);
    ASSERT_EQ(test_association->sa_state, SA_OPERATIONAL);
    ASSERT_EQ(test_association->gvcid_blk.tfvn, 0);
    ASSERT_EQ(test_association->gvcid_blk.scid, (SCID & 0x3FF));
    ASSERT_EQ(test_association->gvcid_blk.vcid, 0);
    ASSERT_EQ(test_association->gvcid_blk.mapid, TYPE_TC);
    ASSERT_EQ(test_association->est, 1);
    ASSERT_EQ(test_association->ast, 1);
    ASSERT_EQ(test_association->shivf_len, 6);
    ASSERT_EQ(test_association->shsnf_len, 0);
    ASSERT_EQ(test_association->shplf_len, 0);
    ASSERT_EQ(test_association->stmacf_len, 16);
    ASSERT_EQ(test_association->ecs, 0x01);
    ASSERT_EQ(test_association->ecs_len, 1);

    ASSERT_EQ(test_association->iv[0], 0x00);
    ASSERT_EQ(test_association->iv[1], 0x00);
    ASSERT_EQ(test_association->iv[2], 0x00);
    ASSERT_EQ(test_association->iv[3], 0x00);
    ASSERT_EQ(test_association->iv[4], 0x00);
    ASSERT_EQ(test_association->iv[5], 0x02);
    ASSERT_EQ(test_association->iv[6], 0x00);
    ASSERT_EQ(test_association->iv[7], 0x00);
    ASSERT_EQ(test_association->iv[8], 0x00);
    ASSERT_EQ(test_association->iv[9], 0x00);
    ASSERT_EQ(test_association->iv[10], 0x00);
    ASSERT_EQ(test_association->iv[11], 0x01);

    ASSERT_EQ(test_association->iv_len, 12);
    ASSERT_EQ(test_association->acs_len, 0);
    ASSERT_EQ(test_association->acs, 0x00);
    ASSERT_EQ(test_association->abm_len, 1786);
    for (int i = 0; i < test_association->abm_len; i++)
    {
        ASSERT_EQ(test_association->abm[i], 0x00);
    }
    // sa[location].abm[0] = sa_ptr->abm;
    ASSERT_EQ(test_association->arsn_len, 0);
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(test_association->arsn[i], 0);
    }
    // sa[location].arsn[0] = sa_ptr->arsn;
    ASSERT_EQ(test_association->arsnw_len, 1);
    ASSERT_EQ(test_association->arsnw, 5);
}

UTEST(SA_SAVE, SAVE_PASS_2)
{
    // Setup & Initialize CryptoLib
    Crypto_Init_TC_Unit_Test();
    char *raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char *raw_tc_sdls_ping_b = NULL;

    char *new_iv_h = "FFFFFFFFFFFC";
    char *new_iv_b = NULL;

    char *expected_iv_h = "000000000003000000000001";
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

UTEST(SA_SAVE, VERIFY_SAVE_PASS_2_SAVE)
{
    Crypto_Init_TC_Unit_Test();

    SaInterface            sa_if = get_sa_interface_inmemory();
    SecurityAssociation_t *test_association;

    sa_if->sa_get_from_spi(4, &test_association);

    ASSERT_EQ(test_association->spi, 4);
    ASSERT_EQ(test_association->ekid, 4);
    ASSERT_EQ(test_association->akid, 4);
    // test_association->ek_ref = sa_ptr->ek_ref;
    // test_association->ak_ref = sa_ptr->ak_ref;
    ASSERT_EQ(test_association->sa_state, SA_OPERATIONAL);
    ASSERT_EQ(test_association->gvcid_blk.tfvn, 0);
    ASSERT_EQ(test_association->gvcid_blk.scid, (SCID & 0x3FF));
    ASSERT_EQ(test_association->gvcid_blk.vcid, 0);
    ASSERT_EQ(test_association->gvcid_blk.mapid, TYPE_TC);
    ASSERT_EQ(test_association->est, 1);
    ASSERT_EQ(test_association->ast, 1);
    ASSERT_EQ(test_association->shivf_len, 6);
    ASSERT_EQ(test_association->shsnf_len, 0);
    ASSERT_EQ(test_association->shplf_len, 0);
    ASSERT_EQ(test_association->stmacf_len, 16);
    ASSERT_EQ(test_association->ecs, 0x01);
    ASSERT_EQ(test_association->ecs_len, 1);

    ASSERT_EQ(test_association->iv[0], 0x00);
    ASSERT_EQ(test_association->iv[1], 0x00);
    ASSERT_EQ(test_association->iv[2], 0x00);
    ASSERT_EQ(test_association->iv[3], 0x00);
    ASSERT_EQ(test_association->iv[4], 0x00);
    ASSERT_EQ(test_association->iv[5], 0x03);
    ASSERT_EQ(test_association->iv[6], 0x00);
    ASSERT_EQ(test_association->iv[7], 0x00);
    ASSERT_EQ(test_association->iv[8], 0x00);
    ASSERT_EQ(test_association->iv[9], 0x00);
    ASSERT_EQ(test_association->iv[10], 0x00);
    ASSERT_EQ(test_association->iv[11], 0x01);

    ASSERT_EQ(test_association->iv_len, 12);
    ASSERT_EQ(test_association->acs_len, 0);
    ASSERT_EQ(test_association->acs, 0x00);
    ASSERT_EQ(test_association->abm_len, 1786);
    for (int i = 0; i < test_association->abm_len; i++)
    {
        ASSERT_EQ(test_association->abm[i], 0x00);
    }
    // sa[location].abm[0] = sa_ptr->abm;
    ASSERT_EQ(test_association->arsn_len, 0);
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(test_association->arsn[i], 0);
    }
    // sa[location].arsn[0] = sa_ptr->arsn;
    ASSERT_EQ(test_association->arsnw_len, 1);
    ASSERT_EQ(test_association->arsnw, 5);
}

UTEST(SA_SAVE, VERIFY_SAVE_ADJACENT)
{
    Crypto_Init_TC_Unit_Test();

    SaInterface            sa_if = get_sa_interface_inmemory();
    SecurityAssociation_t *test_association;

    // VERIFY SA 4
    sa_if->sa_get_from_spi(4, &test_association);
    ASSERT_EQ(test_association->spi, 4);
    ASSERT_EQ(test_association->ekid, 4);
    ASSERT_EQ(test_association->akid, 4);
    // test_association->ek_ref = sa_ptr->ek_ref;
    // test_association->ak_ref = sa_ptr->ak_ref;
    ASSERT_EQ(test_association->sa_state, SA_OPERATIONAL);
    ASSERT_EQ(test_association->gvcid_blk.tfvn, 0);
    ASSERT_EQ(test_association->gvcid_blk.scid, (SCID & 0x3FF));
    ASSERT_EQ(test_association->gvcid_blk.vcid, 0);
    ASSERT_EQ(test_association->gvcid_blk.mapid, TYPE_TC);
    ASSERT_EQ(test_association->est, 1);
    ASSERT_EQ(test_association->ast, 1);
    ASSERT_EQ(test_association->shivf_len, 6);
    ASSERT_EQ(test_association->shsnf_len, 0);
    ASSERT_EQ(test_association->shplf_len, 0);
    ASSERT_EQ(test_association->stmacf_len, 16);
    ASSERT_EQ(test_association->ecs, 0x01);
    ASSERT_EQ(test_association->ecs_len, 1);

    ASSERT_EQ(test_association->iv[0], 0x00);
    ASSERT_EQ(test_association->iv[1], 0x00);
    ASSERT_EQ(test_association->iv[2], 0x00);
    ASSERT_EQ(test_association->iv[3], 0x00);
    ASSERT_EQ(test_association->iv[4], 0x00);
    ASSERT_EQ(test_association->iv[5], 0x03);
    ASSERT_EQ(test_association->iv[6], 0x00);
    ASSERT_EQ(test_association->iv[7], 0x00);
    ASSERT_EQ(test_association->iv[8], 0x00);
    ASSERT_EQ(test_association->iv[9], 0x00);
    ASSERT_EQ(test_association->iv[10], 0x00);
    ASSERT_EQ(test_association->iv[11], 0x01);

    ASSERT_EQ(test_association->iv_len, 12);
    ASSERT_EQ(test_association->acs_len, 0);
    ASSERT_EQ(test_association->acs, 0x00);
    ASSERT_EQ(test_association->abm_len, 1786);
    for (int i = 0; i < test_association->abm_len; i++)
    {
        ASSERT_EQ(test_association->abm[i], 0x00);
    }
    // sa[location].abm[0] = sa_ptr->abm;
    ASSERT_EQ(test_association->arsn_len, 0);
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(test_association->arsn[i], 0);
    }
    // sa[location].arsn[0] = sa_ptr->arsn;
    ASSERT_EQ(test_association->arsnw_len, 1);
    ASSERT_EQ(test_association->arsnw, 5);

    // VERIFY SA 3
    sa_if->sa_get_from_spi(3, &test_association);
    ASSERT_EQ(test_association->spi, 3);
    ASSERT_EQ(test_association->ekid, 3);
    ASSERT_EQ(test_association->akid, 3);
    // test_association->ek_ref = sa_ptr->ek_ref;
    // test_association->ak_ref = sa_ptr->ak_ref;
    ASSERT_EQ(test_association->sa_state, SA_KEYED);
    ASSERT_EQ(test_association->gvcid_blk.tfvn, 0);
    ASSERT_EQ(test_association->gvcid_blk.scid, 3);
    ASSERT_EQ(test_association->gvcid_blk.vcid, 0);
    ASSERT_EQ(test_association->gvcid_blk.mapid, TYPE_TC);
    ASSERT_EQ(test_association->est, 0);
    ASSERT_EQ(test_association->ast, 1);
    ASSERT_EQ(test_association->shivf_len, 12);
    ASSERT_EQ(test_association->shsnf_len, 2);
    ASSERT_EQ(test_association->shplf_len, 0);
    ASSERT_EQ(test_association->stmacf_len, 16);
    ASSERT_EQ(test_association->ecs, 0);
    ASSERT_EQ(test_association->ecs_len, 0);

    ASSERT_EQ(test_association->iv[0], 0x00);
    ASSERT_EQ(test_association->iv[1], 0x00);
    ASSERT_EQ(test_association->iv[2], 0x00);
    ASSERT_EQ(test_association->iv[3], 0x00);
    ASSERT_EQ(test_association->iv[4], 0x00);
    ASSERT_EQ(test_association->iv[5], 0x00);
    ASSERT_EQ(test_association->iv[6], 0x00);
    ASSERT_EQ(test_association->iv[7], 0x00);
    ASSERT_EQ(test_association->iv[8], 0x00);
    ASSERT_EQ(test_association->iv[9], 0x00);
    ASSERT_EQ(test_association->iv[10], 0x00);
    ASSERT_EQ(test_association->iv[11], 0x00);

    ASSERT_EQ(test_association->iv_len, 12);
    ASSERT_EQ(test_association->acs_len, 1);
    ASSERT_EQ(test_association->acs, 3);
    ASSERT_EQ(test_association->abm_len, 0);
    for (int i = 0; i < test_association->abm_len; i++)
    {
        ASSERT_EQ(test_association->abm[i], 0x00);
    }
    // sa[location].abm[0] = sa_ptr->abm;
    ASSERT_EQ(test_association->arsn_len, 2);
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(test_association->arsn[i], 0);
    }
    // sa[location].arsn[0] = sa_ptr->arsn;
    ASSERT_EQ(test_association->arsnw_len, 1);
    ASSERT_EQ(test_association->arsnw, 5);

    // VERIFY SA 5
    sa_if->sa_get_from_spi(5, &test_association);
    ASSERT_EQ(test_association->spi, 5);
    ASSERT_EQ(test_association->ekid, 5);
    ASSERT_EQ(test_association->akid, 5);
    // test_association->ek_ref = sa_ptr->ek_ref;
    // test_association->ak_ref = sa_ptr->ak_ref;
    ASSERT_EQ(test_association->sa_state, SA_KEYED);
    ASSERT_EQ(test_association->gvcid_blk.tfvn, 0);
    ASSERT_EQ(test_association->gvcid_blk.scid, 3);
    ASSERT_EQ(test_association->gvcid_blk.vcid, 1);
    ASSERT_EQ(test_association->gvcid_blk.mapid, 2);
    ASSERT_EQ(test_association->est, 0);
    ASSERT_EQ(test_association->ast, 0);
    ASSERT_EQ(test_association->shivf_len, 12);
    ASSERT_EQ(test_association->shsnf_len, 2);
    ASSERT_EQ(test_association->shplf_len, 0);
    ASSERT_EQ(test_association->stmacf_len, 0);
    ASSERT_EQ(test_association->ecs, 0);
    ASSERT_EQ(test_association->ecs_len, 0);

    ASSERT_EQ(test_association->iv[0], 0x00);
    ASSERT_EQ(test_association->iv[1], 0x00);
    ASSERT_EQ(test_association->iv[2], 0x00);
    ASSERT_EQ(test_association->iv[3], 0x00);
    ASSERT_EQ(test_association->iv[4], 0x00);
    ASSERT_EQ(test_association->iv[5], 0x00);
    ASSERT_EQ(test_association->iv[6], 0x00);
    ASSERT_EQ(test_association->iv[7], 0x00);
    ASSERT_EQ(test_association->iv[8], 0x00);
    ASSERT_EQ(test_association->iv[9], 0x00);
    ASSERT_EQ(test_association->iv[10], 0x00);
    ASSERT_EQ(test_association->iv[11], 0x00);

    ASSERT_EQ(test_association->iv_len, 12);
    ASSERT_EQ(test_association->acs_len, 0);
    ASSERT_EQ(test_association->acs, 0x00);
    ASSERT_EQ(test_association->abm_len, 0);
    for (int i = 0; i < test_association->abm_len; i++)
    {
        ASSERT_EQ(test_association->abm[i], 0x00);
    }
    // sa[location].abm[0] = sa_ptr->abm;
    ASSERT_EQ(test_association->arsn_len, 2);
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(test_association->arsn[i], 0);
    }
    // sa[location].arsn[0] = sa_ptr->arsn;
    ASSERT_EQ(test_association->arsnw_len, 1);
    ASSERT_EQ(test_association->arsnw, 5);
}

UTEST(SA_SAVE, VERIFY_SAVE_EDGES)
{
    Crypto_Init_TC_Unit_Test();

    SaInterface            sa_if = get_sa_interface_inmemory();
    SecurityAssociation_t *test_association;

    // VERIFY SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    ASSERT_EQ(test_association->spi, 1);
    ASSERT_EQ(test_association->ekid, 1);
    ASSERT_EQ(test_association->akid, 1);
    // test_association->ek_ref = sa_ptr->ek_ref;
    // test_association->ak_ref = sa_ptr->ak_ref;
    ASSERT_EQ(test_association->sa_state, SA_NONE);
    ASSERT_EQ(test_association->gvcid_blk.tfvn, 0);
    ASSERT_EQ(test_association->gvcid_blk.scid, (SCID & 0x3FF));
    ASSERT_EQ(test_association->gvcid_blk.vcid, 0);
    ASSERT_EQ(test_association->gvcid_blk.mapid, TYPE_TC);
    ASSERT_EQ(test_association->est, 0);
    ASSERT_EQ(test_association->ast, 0);
    ASSERT_EQ(test_association->shivf_len, 12);
    ASSERT_EQ(test_association->shsnf_len, 2);
    ASSERT_EQ(test_association->shplf_len, 0);
    ASSERT_EQ(test_association->stmacf_len, 0);
    ASSERT_EQ(test_association->ecs, 0x00);
    ASSERT_EQ(test_association->ecs_len, 0);

    ASSERT_EQ(test_association->iv[0], 0x00);
    ASSERT_EQ(test_association->iv[1], 0x00);
    ASSERT_EQ(test_association->iv[2], 0x00);
    ASSERT_EQ(test_association->iv[3], 0x00);
    ASSERT_EQ(test_association->iv[4], 0x00);
    ASSERT_EQ(test_association->iv[5], 0x00);
    ASSERT_EQ(test_association->iv[6], 0x00);
    ASSERT_EQ(test_association->iv[7], 0x00);
    ASSERT_EQ(test_association->iv[8], 0x00);
    ASSERT_EQ(test_association->iv[9], 0x00);
    ASSERT_EQ(test_association->iv[10], 0x00);
    ASSERT_EQ(test_association->iv[11], 0x00);

    ASSERT_EQ(test_association->iv_len, 12);
    ASSERT_EQ(test_association->acs_len, 0);
    ASSERT_EQ(test_association->acs, 0x00);
    ASSERT_EQ(test_association->abm_len, 0);
    for (int i = 0; i < test_association->abm_len; i++)
    {
        ASSERT_EQ(test_association->abm[i], 0x00);
    }
    // sa[location].abm[0] = sa_ptr->abm;
    ASSERT_EQ(test_association->arsn_len, 2);
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(test_association->arsn[i], 0);
    }
    // sa[location].arsn[0] = sa_ptr->arsn;
    ASSERT_EQ(test_association->arsnw_len, 1);
    ASSERT_EQ(test_association->arsnw, 5);

    // VERIFY SA 17
    sa_if->sa_get_from_spi(17, &test_association);
    ASSERT_EQ(test_association->spi, 17);
    ASSERT_EQ(test_association->ekid, 17);
    ASSERT_EQ(test_association->akid, 17);
    // test_association->ek_ref = sa_ptr->ek_ref;
    // test_association->ak_ref = sa_ptr->ak_ref;
    ASSERT_EQ(test_association->sa_state, SA_NONE);
    ASSERT_EQ(test_association->gvcid_blk.tfvn, 0);
    ASSERT_EQ(test_association->gvcid_blk.scid, 0);
    ASSERT_EQ(test_association->gvcid_blk.vcid, 0);
    ASSERT_EQ(test_association->gvcid_blk.mapid, TYPE_TC);
    ASSERT_EQ(test_association->est, 0);
    ASSERT_EQ(test_association->ast, 0);
    ASSERT_EQ(test_association->shivf_len, 0);
    ASSERT_EQ(test_association->shsnf_len, 0);
    ASSERT_EQ(test_association->shplf_len, 0);
    ASSERT_EQ(test_association->stmacf_len, 0);
    ASSERT_EQ(test_association->ecs, 0);
    ASSERT_EQ(test_association->ecs_len, 0);

    ASSERT_EQ(test_association->iv[0], 0x00);
    ASSERT_EQ(test_association->iv[1], 0x00);
    ASSERT_EQ(test_association->iv[2], 0x00);
    ASSERT_EQ(test_association->iv[3], 0x00);
    ASSERT_EQ(test_association->iv[4], 0x00);
    ASSERT_EQ(test_association->iv[5], 0x00);
    ASSERT_EQ(test_association->iv[6], 0x00);
    ASSERT_EQ(test_association->iv[7], 0x00);
    ASSERT_EQ(test_association->iv[8], 0x00);
    ASSERT_EQ(test_association->iv[9], 0x00);
    ASSERT_EQ(test_association->iv[10], 0x00);
    ASSERT_EQ(test_association->iv[11], 0x00);

    ASSERT_EQ(test_association->iv_len, 0);
    ASSERT_EQ(test_association->acs_len, 0);
    ASSERT_EQ(test_association->acs, 0x00);
    ASSERT_EQ(test_association->abm_len, 0);
    for (int i = 0; i < test_association->abm_len; i++)
    {
        ASSERT_EQ(test_association->abm[i], 0xff);
    }
    // sa[location].abm[0] = sa_ptr->abm;
    ASSERT_EQ(test_association->arsn_len, 0);
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        ASSERT_EQ(test_association->arsn[i], 0);
    }
    // sa[location].arsn[0] = sa_ptr->arsn;
    ASSERT_EQ(test_association->arsnw_len, 0);
    ASSERT_EQ(test_association->arsnw, 0);
}

UTEST_MAIN();