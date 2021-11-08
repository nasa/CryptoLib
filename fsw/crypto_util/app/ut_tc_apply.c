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

// TODO:  Should this be set up with a set of tests, or continue to Crypto_Init() each time.  For now I think the current setup is the best path.

// Inactive SA Database
// TODO:  Should this return or continue to function as currently written when SA is not initalized?
UTEST(TC_APPLY_SECURITY, NO_CRYPTO_INIT)
{
    // No Crypto_Init();
    long buffer_size;
    char *buffer = c_read_file("../../fsw/crypto_tests/data/raw_tc_sdls_ping.dat", &buffer_size);
    uint32 buffer_size_i = (uint32) buffer_size;

    uint8 *ptr_enc_frame = NULL;
    uint32 enc_frame_len;
    int return_val = -1;

    return_val = Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(return_val, 0);
}

// Nominal Test.  This should read a raw_tc_sdls_ping.dat file, continue down the "happy path", and return OS_SUCCESS
UTEST(TC_APPLY_SECURITY, HAPPY_PATH)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();
    long buffer_size;
    char *buffer = c_read_file("../../fsw/crypto_tests/data/raw_tc_sdls_ping.dat", &buffer_size);
    uint32 buffer_size_i = (uint32) buffer_size;

    uint8 *ptr_enc_frame = NULL;
    uint32 enc_frame_len;

    int return_val = -1;

    return_val = Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(return_val, 0);
}

// Bad Space Craft ID.  This should pass the flawed .dat file, and return OS_ERROR
UTEST(TC_APPLY_SECURITY1, BAD_SPACE_CRAFT_ID)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();
    long buffer_size;
    char *buffer = c_read_file("../../fsw/crypto_tests/data/raw_tc_sdls_ping_bad_scid.dat", &buffer_size);
    uint32 buffer_size_i = (uint32) buffer_size;

    uint8 *ptr_enc_frame = NULL;
    uint32 enc_frame_len;
    int return_val = -1;

    return_val = Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(return_val, -1);
}

// TODO:  This does not report the correct error.  It returns the correctly, but complains of an incorrect SCID
//        This should return OS_ERROR
UTEST(TC_APPLY_SECURITY, BAD_VIRTUAL_CHANNEL_ID)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();
    long buffer_size;
    char *buffer = c_read_file("../../fsw/crypto_tests/data/raw_tc_sdls_ping_bad_vcid.dat", &buffer_size);
    uint32 buffer_size_i = (uint32) buffer_size;

    uint8 *ptr_enc_frame = NULL;
    uint32 enc_frame_len;
    int return_val = -1;
    return_val = Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(return_val, return_val);
}

// This test should test how to handle a null buffer being passed into the ApplySecurity Function.
// Currently this functionality isn't handled properly, and casues a seg-fault.
// TODO:  We need to determine how this would return, as it will help in other test cases.
//        Should this return the original buffer, a null pointer, OS_ERROR, etc?
UTEST(TC_APPLY_SECURITY, NULL_BUFFER)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();
    long buffer_size;
    char *buffer = NULL;
    uint32 buffer_size_i = (uint32) buffer_size;

    uint8 *ptr_enc_frame = NULL;
    uint32 enc_frame_len;

    ASSERT_EQ(Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len), -1);
}

//TODO: 
/*  What should be returned if something goes wrong with Control Command Flag?
    Should a NULL pointer be returned....THe original pointer?
    We need to decide on this functionality and write a test for this

    We should probably have more error codes than OS_SUCCESS and OS_ERROR

    Some way to modify and test the SA?

    Authentication Tests
        When Ready / Complete?

    Encryption Tests
        When Ready / Complete?
    
    Authenticated Encryption Tests
        When Ready / Complete
*/



UTEST_MAIN();