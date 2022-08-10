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
#include <unistd.h>

int num_frames_1K = 1000;
int num_frames_100 = 100;

void Write_To_File(uint16_t enc_frame_len, float total_time, char* test_name, int num_frames, int reset)
{
    if(reset == 1)
    {
        if(access("PERFORMANCE_RESULTS_AEPS.csv", F_OK) == 0)
        {
            int deleted = remove("PERFORMANCE_RESULTS.csv");
            if(deleted){printf("ERROR Deleting File");}
        }
    }

    FILE *fp = NULL;
    fp = fopen("PERFORMANCE_RESULTS_AEPS.csv", "a");
    if (fp != NULL)
    {   
        if(reset ==1) fprintf(fp, "Name of Test,Frames Sent,Bytes per Frame,Total Time,Mbps\n");
        fprintf(fp, "%s,%d,%d,%f,%f\n", test_name, num_frames, enc_frame_len, total_time, (((enc_frame_len * 8 * num_frames)/total_time)/1024/1024));
    }
    fclose(fp);
    
}

double Process_Security_Loop(SecurityAssociation_t* test_association, char *data_b, int* data_l, TC_t* processed_frame, int num_loops)
{
    struct timespec begin, end;
    double total_time;
    total_time = 0.0;


    int32_t status = CRYPTO_LIB_SUCCESS;

    for(int i = 0; i < num_loops; i++)
    {
        printf("LOOP NUMBER: %d\n", i+1);
        test_association->iv[11] = 0x62;
        clock_gettime(CLOCK_REALTIME, &begin);
        status = Crypto_TC_ProcessSecurity((uint8_t*) data_b, data_l, processed_frame);
        clock_gettime(CLOCK_REALTIME, &end);
        //free(enc_frame);

        long seconds = end.tv_sec - begin.tv_sec;
        long nanoseconds = end.tv_nsec - begin.tv_nsec;
        double elapsed = seconds + nanoseconds*1e-9;

        if (status != CRYPTO_LIB_SUCCESS)
        {
            total_time = -1.0;
            printf("ERROR: %d\n", status);
            break;
        }

        total_time += elapsed;
    }
    return total_time;
}

UTEST(PERFORMANCE, LSA_LIBG_SHORT_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);

    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C047F00000A00000000000000000000006367CCB04793EECE4ECFAE6926856AB15F27C747E4F00F0314AC3174263FCC8ABEEE245A705DF168E7AF81057111A8776502606B698CA119FFDAEE33FD3027358EC40BC2C166D6E5312BF6A813D97864A037D8E3696EFBF2052228DFB63A4245482C24985171000B61A0C7F0386C";
    int32_t status = Crypto_Init_Unit_Test();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(test_association, data_b, &data_l, processed_frame, num_frames_100);
    ttl_time_lsa_libg_100 = ttl_time_lsa_libg_100;
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST_MAIN();