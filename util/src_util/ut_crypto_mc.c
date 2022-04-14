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
#include "sadb_routine.h"
#include "utest.h"


/**
 * @brief Unit Test: Crypto MC Status test
 **/
UTEST(CRYPTO_MC, STATUS)
{
    int count = 0;
    uint8_t ingest[1024] = {0};

    count = Crypto_MC_status(ingest);
    ASSERT_EQ(11, count);
}

/**
 * @brief Unit Test: Crypto MC Dump test
 **/
UTEST(CRYPTO_MC, DUMP)
{
    int count = 0;
    uint8_t ingest[1024] = {0};

    count = Crypto_MC_dump(ingest);
    ASSERT_EQ(((log_count * 4) + (log_count * 2) + 9), count);
}

/**
 * @brief Unit Test: Crypto MC Erase Test
 **/
UTEST(CRYPTO_MC, ERASE)
{
    int count = 0;
    uint8_t ingest[1024] = {0};

    count = Crypto_MC_erase(ingest);
    ASSERT_EQ(11, count);
}

/**
 * @brief Unit Test: Crypto MC SelfTest Test
 **/
UTEST(CRYPTO_MC, SELFTEST)
{
    int count = 0;
    uint8_t ingest[1024] = {0};

    count = Crypto_MC_selftest(ingest);
    ASSERT_EQ(10, count);
}

/**
 * @brief Unit Test: Crypto MC ReadARSN Test
 **/
UTEST(CRYPTO_MC, READARSN)
{
    int count = 0;
    uint8_t ingest[1024] = {0};
    Crypto_Init_Unit_Test();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));

    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    count = Crypto_SA_readARSN(ingest);
    sadb_routine = sadb_routine;
    ASSERT_EQ(11, count); // Future me's problem... why?
}

/**
 * @brief Unit Test: Crypto MC Process Security Test
 **/
UTEST(CRYPTO_MC, PROCESS)
{
    uint8_t ingest[1024] = {0};
    int len_ingest = 0;
    int32_t status = CRYPTO_LIB_ERROR;

    status = Crypto_TM_ProcessSecurity(ingest, &len_ingest);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Crypto Get TM Length Test
 **/
UTEST(CRYPTO_MC, TMLENGTH)
{
    int length = 0;

    length = Crypto_Get_tmLength(length);
    ASSERT_EQ(1145, length);
}

UTEST_MAIN();