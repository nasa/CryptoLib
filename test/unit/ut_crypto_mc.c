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
 *  Unit Tests that macke use of CRYPTO_MC functionality on the data.
 **/
#include "ut_crypto_mc.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"


/**
 * @brief Unit Test: Crypto MC Status test
 **/
UTEST(CRYPTO_MC, STATUS)
{
    remove("sa_save_file.bin");
    int status = CRYPTO_LIB_SUCCESS;
    int count = 0;
    uint8_t ingest[1024] = {0};

    status = Crypto_MC_status(ingest, &count);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Crypto MC Dump test
 **/
UTEST(CRYPTO_MC, DUMP)
{
    remove("sa_save_file.bin");
    int status = CRYPTO_LIB_SUCCESS;
    int count = 0;
    uint8_t ingest[1024] = {0};

    status = Crypto_MC_dump(ingest, &count);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Crypto MC Erase Test
 **/
UTEST(CRYPTO_MC, ERASE)
{
    remove("sa_save_file.bin");
    int status = CRYPTO_LIB_SUCCESS;
    int count = 0;
    uint8_t ingest[1024] = {0};

    status = Crypto_MC_erase(ingest, &count);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Crypto MC SelfTest Test
 **/
UTEST(CRYPTO_MC, SELFTEST)
{
    remove("sa_save_file.bin");
    int status = CRYPTO_LIB_SUCCESS;
    int count = 0;
    uint8_t ingest[1024] = {0};

    status = Crypto_MC_selftest(ingest, &count);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Crypto MC ReadARSN Test
 **/
UTEST(CRYPTO_MC, READARSN)
{
    remove("sa_save_file.bin");
    int count = 0;
    int* temp_count = &count;
    int32_t status = CRYPTO_LIB_ERROR;
    uint8_t ingest[1024] = {0};
    Crypto_Init_TC_Unit_Test();
    SaInterface sa_if = get_sa_interface_inmemory();
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));

    sa_if->sa_get_from_spi(1, &test_association);
    status = Crypto_SA_readARSN(ingest, temp_count);
    sa_if = sa_if;
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Crypto MC Process Security Test
 **/
UTEST(CRYPTO_MC, PROCESS)
{
    remove("sa_save_file.bin");
    uint8_t ingest[1024] = {0};
    uint16_t len_ingest = 1024;
    int32_t status = CRYPTO_LIB_ERROR;
    uint8_t* tm_sdls_processed_frame = NULL;
    uint16_t dec_frame_length;

    status = Crypto_TM_ProcessSecurity((uint8_t *)&ingest, len_ingest, &tm_sdls_processed_frame, &dec_frame_length);
    ASSERT_EQ(103, status);
}

/**
 * @brief Unit Test: Crypto Get TM Length Test
 **/
UTEST(CRYPTO_MC, TMLENGTH)
{
    remove("sa_save_file.bin");
    int length = 0;

    length = Crypto_Get_tmLength(length);
    ASSERT_EQ(1145, length);
}

UTEST_MAIN();