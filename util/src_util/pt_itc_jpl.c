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
 **/
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

#include "crypto.h"
#include "shared_util.h"
#include <stdio.h>

#include <time.h>

double Apply_Security_Loop(uint8_t *frame, int frame_length, uint8_t *enc_frame, uint16_t *enc_frame_len, int num_loops)
{
    struct timespec begin, end;
    double avg_time, total_time;
    avg_time = 0.0;
    total_time = 0.0;

    frame = frame;
    frame_length = frame_length;
    enc_frame_len = enc_frame_len;

    int32_t status = CRYPTO_LIB_SUCCESS;

    for(int i = 0; i < num_loops; i++)
    {
        printf("LOOP NUMBER: %d\n", i+1);
        clock_gettime(CLOCK_REALTIME, &begin);
        status = Crypto_TC_ApplySecurity(frame, frame_length, &enc_frame, enc_frame_len);
        // sleep(1);
        clock_gettime(CLOCK_REALTIME, &end);
        free(enc_frame);

        long seconds = end.tv_sec - begin.tv_sec;
        long nanoseconds = end.tv_nsec - begin.tv_nsec;
        double elapsed = seconds + nanoseconds*1e-9;

        if (status != CRYPTO_LIB_SUCCESS)
        {
            avg_time = -1.0;
            break;
        }

        total_time += elapsed;

        if( i == 0 )
        {
            avg_time = elapsed;
        }
        else
        {
            avg_time = (avg_time + elapsed)/2.0;
        }
    }
    printf("Total Time: %.20f\n",total_time);
    return total_time;
}

/**
 * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
 **/
UTEST(PERFORMANCE, AS_MDB_KMC)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
    TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
    TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("localhost", "sadb", 3306, CRYPTO_FALSE, 0, NULL, NULL, NULL, NULL, NULL, "sadb_user",
                          "sadb_password");
    Crypto_Config_Kmc_Crypto_Service("https", "asec-cmdenc-srv1.jpl.nasa.gov", 8443, "crypto-service","/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem", "PEM","/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    char* raw_tc_jpl_mmt_scid44_vcid1_long = "202C07E100CDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01E41B";
    //char* raw_tc_jpl_mmt_scid44_vcid1_long = "202c0408000001bd37";
    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;
    float ttl_time_mdb_kmc_100 = 0.0;
    //double avg_time_mdb_kmc_1000 = 0.0;

    int num_frames = 100;
    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1_long, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);


    ttl_time_mdb_kmc_100 = Apply_Security_Loop((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, ptr_enc_frame, &enc_frame_len, num_frames);
    //avg_time_mdb_kmc_1000 = Apply_Security_Loop((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len, 1);

    printf("\nMDB+KMC Apply Security");
    printf("\tLoops: 1\n");
    printf("\t\tData Sent: %d\n", raw_tc_jpl_mmt_scid44_vcid1_expect_len);
    printf("\t\tData Received: %d\n", enc_frame_len);
    printf("\t\tTotal Time: %f\n", ttl_time_mdb_kmc_100);
    printf("\tMbps: %f\n", (((enc_frame_len * 8 * num_frames)/ttl_time_mdb_kmc_100)/1024/1024));
    printf("\n");
   
    // printf("\nMDB+KMC Apply Security");
    // printf("\tLoops: 1000\n");
    // printf("\t\tData Sent (Bytes): %d\n", raw_tc_jpl_mmt_scid44_vcid1_expect_len);
    // printf("\t\tData Received (Bytes): %d\n", enc_frame_len);
    // printf("\t\tAverage Time: %f\n", avg_time_mdb_kmc_1000);
    // printf("\tMbps: %f\n", ((enc_frame_len * 8)/avg_time_mdb_kmc_1000));
    // printf("\n");


    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST_MAIN();