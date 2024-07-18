// /* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration.
//    All Foreign Rights are Reserved to the U.S. Government.

//    This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory,
//    including, but not limited to, any warranty that the software will conform to specifications, any implied warranties
//    of merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty that the
//    documentation will conform to the program, or any warranty that the software will be error free.

//    In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
//    consequential damages, arising out of, resulting from, or in any way connected with the software or its
//    documentation, whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was sustained
//    from, or arose out of the results of, or use of, the software, documentation or services provided hereunder.

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
 * @brief Unit Test: Crypto ECS Get Algorithm response for AES-GCM-SIV
 **/
UTEST(AES_GCM_SIV, GET_ECS_ALGO_SIV)
{
    remove("sa_save_file.bin");
    int32_t libgcrypt_algo = -1;
    int8_t crypto_algo = CRYPTO_CIPHER_AES256_GCM_SIV;
    
    // Convert CRYPTOAES enum to GCRY_CIPHER_AES256
    //libgcrypt_algo = cryptography_if->cryptography_get_ecs_algo(crypto_algo);
    //ASSERT_EQ(libgcrypt_algo, GCRY_CIPHER_AES256);

    libgcrypt_algo = cryptography_if->cryptography_get_ecs_algo(crypto_algo);
    ASSERT_EQ(libgcrypt_algo, 9);
}

/**
 * @brief Unit Test: Crypto ECS Get Algorithm key length response for AES-GCM-SIV
 **/
UTEST(AES_GCM_SIV, GET_ECS_ALGO_KEY_LEN_SIV)
{
    remove("sa_save_file.bin");
    int32_t algo_keylen = -1;
    uint8_t crypto_algo = CRYPTO_CIPHER_AES256_GCM_SIV;
    algo_keylen = Crypto_Get_ACS_Algo_Keylen(crypto_algo);
    ASSERT_EQ(algo_keylen, 32);
}