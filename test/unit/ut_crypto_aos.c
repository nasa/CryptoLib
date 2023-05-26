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
 *  Unit Tests that macke use of CRYPTO_AOS functionality on the data.
 **/
#include "ut_crypto_aos.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

/**
 * @brief Unit Test: Crypto Init with invalid SADB
 * @note: TODO:  This test will need to be reworked when this functionality exists.
 **/
UTEST(CRYPTO_AOS, APPLY_SECURITY)
{
    int32_t status = CRYPTO_LIB_ERROR;
    uint8_t ingest[1024] = {0};
    int len_ingest = 0;

    status = Crypto_AOS_ApplySecurity(&ingest[0], &len_ingest);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Crypto AOS Process Security
 **/
UTEST(CRYPTO_AOS, PROCESS_SECURITY)
{
    int32_t status = CRYPTO_LIB_ERROR;
    uint8_t ingest[1024] = {0};
    int len_ingest = 0;

    status = Crypto_AOS_ProcessSecurity(&ingest[0], &len_ingest);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST_MAIN();