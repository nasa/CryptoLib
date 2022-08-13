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
 *  Unit Tests that make use of TC_ApplySecurity/TC_ProcessSecurity function on the data with KMC Crypto Service/MariaDB Functionality Enabled.
 *  BE SURE TO HAVE APPROPRIATE SA's READY FOR EACH SET OF TESTS
 **/

#include "utest.h"

#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>

#include <time.h>
#include <unistd.h>

#include "crypto.h"
#include "crypto_error.h"

#include "shared_util.h"

void random_big_buffer(char* buffer, int32_t buffer_len)
{
    const char* hex_digits = "ABCDEF0123456789";
    for(int i = 0; i < buffer_len; i++)
    {
        srand(clock());
        int j = (rand() % 16);
        //printf("J: %d\n", j);
        buffer[i] = hex_digits[j];
    }
}

UTEST(PERFORMANCE, GCRY_BASE)
{
    int32_t status = Crypto_Init_Unit_Test();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    int32_t big_buffer_len = 1024; 
    int num_loops = 1000;
    int32_t len_data_out = 1024;

    struct timespec begin, end;
    double total_time = 0.0;

    for(int i = 0; i < num_loops; i++)
    {
        char* big_buffer = calloc(1, big_buffer_len * 2 * sizeof(char));
        uint8_t* big_buffer_b = NULL;
        int32_t big_buffer_b_len = 0;
        //clock_gettime(CLOCK_REALTIME, &begin);
        random_big_buffer(big_buffer, (big_buffer_len * 2));
        hex_conversion((char *)big_buffer, (char **)&big_buffer_b, &big_buffer_b_len);
        printf("\n");
         for (int i = 0; i < (big_buffer_b_len); i++)
        {
            printf("%02x", big_buffer_b[i] & 0xff);
        }
        printf("\nLength: %d\n", big_buffer_b_len);

        gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
        gcry_cipher_hd_t tmp_hd;
        
        char* key_ptr_h = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210";
        char* key_ptr = NULL;
        int32_t key_ptr_len = 32;

        hex_conversion(key_ptr_h, &key_ptr, &key_ptr_len);
        printf("\nKEY: ");
        for (int i = 0; i < key_ptr_len; i++)
        {
            printf("%02x", (uint8_t)key_ptr[i]);
        }
        printf("\n");

        uint8_t* iv = (uint8_t* )calloc(1, 12 * sizeof(uint8_t));
        int32_t iv_len = 16;
        printf("IV: ");
        for(int i = 0; i < iv_len; i++)
        {
            printf("%02x ", iv[i]);
        }
        printf("\n");

        char* aad_h = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345";
        uint8_t* aad = NULL;
        int32_t aad_len = 30;
        hex_conversion(aad_h, (char **) &aad, &aad_len);
        printf("\nAAD: ");
        for (int i = 0; i < aad_len; i++)
        {
            printf("%02x", (uint8_t)aad[i]);
        }
        printf("\n");

        uint8_t* data_out = calloc(1, len_data_out * sizeof(uint8_t));
        
        clock_gettime(CLOCK_REALTIME, &begin);
        gcry_error = gcry_cipher_open(&(tmp_hd), GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, GCRY_CIPHER_NONE);
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
            total_time = -1.0;
            ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
        }

        gcry_error = gcry_cipher_setkey(tmp_hd, key_ptr, key_ptr_len);
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
            gcry_cipher_close(tmp_hd);
            total_time = -1.0;
            ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
        }

        gcry_error = gcry_cipher_setiv(tmp_hd, iv, iv_len);
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
            gcry_cipher_close(tmp_hd);
            total_time = -1.0;
            ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
        }

        gcry_error = gcry_cipher_authenticate(tmp_hd,
                                                aad,      // additional authenticated data
                                                aad_len   // length of AAD
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_authenticate error code %d\n" RESET,
                    gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERR_AUTHENTICATION_ERROR;
            gcry_cipher_close(tmp_hd);
            total_time = -1.0;
            ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
        }
        
        
        
        printf("BIG BUFFER LENGTH: %d\n", big_buffer_len);
        gcry_error = gcry_cipher_encrypt(tmp_hd,
                                            data_out,          // ciphertext output
                                            len_data_out,      // length of data
                                            big_buffer_b,      // plaintext input
                                            big_buffer_b_len   // in data length
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_encrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERR_ENCRYPTION_ERROR;
            gcry_cipher_close(tmp_hd);
            total_time = -1.0;
            ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
        }

        clock_gettime(CLOCK_REALTIME, &end);
        long seconds = end.tv_sec - begin.tv_sec;
        long nanoseconds = end.tv_nsec - begin.tv_nsec;
        double elapsed = seconds + nanoseconds*1e-9;

        total_time += elapsed;

        printf("Output payload length is %d\n", len_data_out);
        printf(KYEL "Printing TC Frame Data after encryption:\n\t");
        for (int j = 0; j < len_data_out; j++)
        {
            printf("%02x", *(data_out + j));
        }
        printf("\n");
        free(big_buffer_b);
        free(iv);
        free(data_out);
    }
    printf("Total Frames: %d\n", num_loops);
    printf("Bytes per Frame: %d\n", len_data_out);
    printf("Total Time: %f\n", total_time);
    printf("Mbps: %f\n", (((len_data_out * 8 * num_loops)/total_time)/1024/1024));

}

UTEST_MAIN();