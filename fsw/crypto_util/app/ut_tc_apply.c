/* Copyright (C) 2009 - 2017 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
   limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
   any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
   arising out of, resulting from, or in any way connected with the software or its documentation.  Whether or not based upon warranty,
   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
   documentation or services provided hereunder

   ITC Team
   NASA IV&V
   ivv-itc@lists.nasa.gov
*/

/*
 *  Simple apply security program that reads a file into memory and calls the Crypto_TC_ApplySecurity function on the data.
 */
#include "ut_tc_apply.h"
#include "utest.h"

// Initilization header?

UTEST(HAPPY_PATH, TC_APPLY_SECURITY)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();
    long buffer_size;
    char *buffer = c_read_file("../../fsw/crypto_tests/data/raw_tc_sdls_ping.dat", &buffer_size);
    uint32 buffer_size_i = (uint32) buffer_size;

    uint8 *ptr_enc_frame = NULL;
    uint32 enc_frame_len;

    ASSERT_TRUE(Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len) == 0);
}

UTEST(BAD_SPACE_CRAFT_ID, TC_APPLY_SECURITY)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();
    long buffer_size;
    char *buffer = c_read_file("../../fsw/crypto_tests/data/raw_tc_sdls_ping_bad_scid.dat", &buffer_size);
    uint32 buffer_size_i = (uint32) buffer_size;

    uint8 *ptr_enc_frame = NULL;
    uint32 enc_frame_len;

    ASSERT_FALSE(Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len) == 0);
}

UTEST(BAD_VIRTUAL_CHANNEL_ID, TC_APPLY_SECURITY)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();
    long buffer_size;
    char *buffer = c_read_file("../../fsw/crypto_tests/data/raw_tc_sdls_ping_bad_vcid.dat", &buffer_size);
    uint32 buffer_size_i = (uint32) buffer_size;

    uint8 *ptr_enc_frame = NULL;
    uint32 enc_frame_len;

    ASSERT_FALSE(Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len) == 0);
}

UTEST(NULL_BUFFER, TC_APPLY_SECURITY)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();
    long buffer_size;
    char *buffer = NULL;
    uint32 buffer_size_i = (uint32) buffer_size;

    uint8 *ptr_enc_frame = NULL;
    uint32 enc_frame_len;

    ASSERT_FALSE(Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len) == 0);
}



UTEST_MAIN();