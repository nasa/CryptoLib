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
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

#include "crypto.h"
#include "shared_util.h"
#include <stdio.h>

#include <time.h>
#include <unistd.h>

int num_frames_1K = 1;
int num_frames_100 = 1;

void Write_To_File(uint16_t enc_frame_len, float total_time, char* test_name, int num_frames, int reset)
{
    if(reset == 1)
    {
        if(access("PERFORMANCE_RESULTS_AEPS.csv", F_OK) == 0)
        {
            int deleted = remove("PERFORMANCE_RESULTS_AEPS.csv");
            if(deleted){printf("ERROR Deleting File!\n");}
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

double Process_Security_Loop(char *data_b, int* data_l, TC_t* processed_frame, int num_loops)
{
    struct timespec begin, end;
    double total_time;
    total_time = 0.0;


    int32_t status = CRYPTO_LIB_SUCCESS;

    for(int i = 0; i < num_loops; i++)
    {
        printf("LOOP NUMBER: %d\n", i+1);
        clock_gettime(CLOCK_REALTIME, &begin);
        status = Crypto_TC_ProcessSecurity((uint8_t*) data_b, data_l, processed_frame);
        clock_gettime(CLOCK_REALTIME, &end);
        free(processed_frame->tc_sec_header.iv);
        free(processed_frame->tc_sec_header.sn);
        free(processed_frame->tc_sec_header.pad);
        free(processed_frame->tc_sec_trailer.mac);

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
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);

    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C047F00000A00000000000000000000006367CCB04793EECE4ECFAE6926856AB15F27C747E4F00F0314AC3174263FCC8ABEEE245A705DF168E7AF81057111A8776502606B698CA119FFDAEE33FD3027358EC40BC2C166D6E5312BF6A813D97864A037D8E3696EFBF2052228DFB63A4245482C24985171000B61A0C7F0386C";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nLSA+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tBytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_lsa_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_libg_100, "LSA+LIBG Process Security SHORT", num_frames_100, 1);

    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_LIBG_SHORT_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C047F0000020000000000000000000070E304CDF655C3FE953D03F0C9322A30FC1E9E93A753017B3B7890A0FF7DECFFE57CBBE804F7CB184436CD7F21D92E01586D243D128E195834F3070365D9CE59D7F71F7F71C4E60FA424ADE3C3976200268804BB9CD6027F9BCFA3BF13F126C5565AF370736625F4A32B1B390B11D3";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_mdb_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nMDB+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_mdb_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_mdb_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_mdb_libg_100, "MDB+LIBG Process Security SHORT", num_frames_100, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, LSA_KMC_SHORT_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C047F00000A00000000000000000000006367CCB04793EECE4ECFAE6926856AB15F27C747E4F00F0314AC3174263FCC8ABEEE245A705DF168E7AF81057111A8776502606B698CA119FFDAEE33FD3027358EC40BC2C166D6E5312BF6A813D97864A037D8E3696EFBF2052228DFB63A4245482C24985171000B61A0C7F0386C";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nLSA+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_lsa_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_kmc_100, "LSA+KMC Process Security SHORT", num_frames_100, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_KMC_SHORT_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C047F0000020000000000000000000071B20E13F2B09519E820E696F04588AACE79E1827D42E5EA66F450E2C4893674185EC19C970BE7CABD06AB8768B04F5A29A1AA58FC539A3010EB674B2FC821441BA36AF225474E8E0998513417C525336E858704588E4F3083EC3EA4245D3C6F1CA5312A20DC3AADC47A0310C7FB09";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_mdb_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nMDB+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_mdb_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_mdb_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_mdb_kmc_100, "MDB+KMC Process Security SHORT", num_frames_100, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

// MEDIUM TESTS

UTEST(PERFORMANCE, LSA_LIBG_MED_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);

    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C05FF00000A000000000000000000000063CC818D81B0A3B0B8CFAE6926856AB15F27C747E4F00F0314AC3174263FCC8ABEEE245A705DF168E7AF81057111A8776502606B698CA119FFDAEE33FD3027358EC40BC2C166D6E5312BF6A813D97864A037D8E3696EFBF2052228DF90F3545628E3182AADD4E7084E423A4CCA88F7C0BAE07A50169E687A1D6232EA056F02AD1F8362D9168A239CDF20EA0615E2FF9B3FC9E02852DD335F0ABCEBBC45A037E073A09B3300B3A2275A646209F4F5BF9C95A9D2A20881273A269B5DB614572D1E117CB73587832D3D63ACD4AD8C9C73AE9A0E521A8C85E19D20F9D670E709924849C46D578D91C0790EF998663E03DE0B830360B2C8E14DF8FA33BC0AC0120CCCA5823543E999C48064B140D8034EBB299E238E526B0443C239EE1CBA826BDAA8705DF421B073A08706D38E11DBD988E08EF9A38C4E4E726326FF54DC43AA76B0EAF004973BCDD51265B306D68EF393E6389AE35858D1B619A3B7D6A3656C3F8EA9512FA6685A3F2710A5A6274FCA0B69275339BC09F3349700E4214A275B9362EE08D2E1E6BBFE0D038007470DD17D8133451B027D1C73AA491256489F6FA2B1964BBA4A6746544ABF98C20C9511E5EFF08678A4B04BFBDFDF401D092FEF153DAB01DB3EBBF0C1879758A6485342DF30D84F46059846F2B910AC279437195F7B80DB14495CA46D9BC075A94CEE7F";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nLSA+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tBytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_lsa_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_libg_100, "LSA+LIBG Process Security MED", num_frames_100, 0);

    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_LIBG_MED_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C05FF000002000000000000000000007147C4888DE20936C8FFF8772894382BC0EADCFDA9B684BC64250309930E745CB9B300EA84D6C694C8688DCFA9007C276FDC33CDFE2CA12415C359FEDED084549487AA3FD876D04BC947B2EDA171983D7FEE5E627D93ADEF5EA9D9790203E1683B6454AD33614D47903A9D2BD46620FCB1A20DA9138B7A42DDA9F4E5207E3A1A15ECE4C917903B0CACEEED9EC8391AC0010F5BBD309EE3FDD5337BFE51F70DC07EB006B646967269CE93073402CCFB547577AA45CAC5823C35F6F76496F1621252491306EE70089F7DFAE6C1A9E515409E1603F61ADDD12C3BDFF98B2E8595B2CCC0F8339D081380EBBDC295DF274F8C4A02BBE1FC7E405CD54CF11FFA4FF6983A2AD6EAF2EB98EE3418191AE5CFCEBB8653091E4605D017C382990B18E2569A64DE56152CBF5B76D23614E60B449CE24924D549325A0447B88D931C8A0580DD167F5FD1B670A36D965FD3411005C4809F1CF1245C1DA008F1003B7334F933C89DDBF21BC556F8E5F244464A77FFB4320C64DBCD9DF82B3D720A8C9796C3BB8677355A7FF0BDC43D48D8990DC8EA34DA3B796AB0515341522D67FF629C283EA8B71CF261BD2F758443E880A3BEB61C5A839BD702D6D35F7B783B3752D59A1D4A4909A677F88572B84665184AE5149E9492728DA5BBDEA36B6B27E2E6F8194136604C98497056815197F871B8C36B51";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nMDB+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tBytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_lsa_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_libg_100, "MDB+LIBG Process Security MED", num_frames_100, 0);

    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, LSA_KMC_MED_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C05FF00000A000000000000000000000010B7D5264AA13C588EBCE851BB4CF923A94BDCB9E04ABB6688055EE94074AEFF78139C195EFB6D26F9D5DF2A002D4D26F6C1420F623D9EC8AC1B47EF469314F30D2466B5A1F8E4DC1ED2FFDA3B82C6BF6A8CC93B220C9B15A7FDCC1C3D86AEAA7EC2158D603F5FA4E102AE14917E5CF9B4A5EDC23E4EC5E42368C0D8FB1CF9FBCEE6ADC4790ACDE3B91BA41907416B949B7852DBFF244752242405E58A2C9B48D26E428DC89168A7AD434D3800B60192016F7925A27E12EE8F6C58BFC4D5297C39139B4871A2A37A1B5E4669F753A95003569BDD6CA8DB454CB25677D9227D9744EC09391F56A22970580AF34E5743918CF87387918596155B153CC913B588D07E96D765B11703B2D6C5910BFF92042C5ABD4FC474A0E050DACA184FCE4CAF82903F5C2BE659BD8551D1CA66BBA61B3611D4E9DA7E3060400A80F7F9504867F0943BCAC62EA2D07DD1BEE2FBD52439FA45A5F1AB8041D724E6B73A3803AA0B701BA7821B797C30C71C3B3BAF0CFA3C76DBC8323FFB22FF8507C995B5C552883141054E8B0B01594BCA4E6741E6D5DCC5CCA0D5D8A0F07E4771607513AEC948157966E0D0A8B0C8F8AC3D114F1095781B6F29B37655484F8C7C700D41F7B231D2A4637B10EAFDEFA26D133ECE3FDECF73E379BE93E3488F91F82C01031839E851EB324969EA367D98965AC0FA351B";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nLSA+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_lsa_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_kmc_100, "LSA+KMC Process Security MED", num_frames_100, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_KMC_MED_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C05FF0000020000000000000000000071B8A9140EDCF90BEB2E84643FB928463D5E7CA5A2CA190B13DFCCBD7C150FC57FCAE7812FD90A672132370F05C11740089A0A263DE28CCF66901393AD69E63E71BF7795929B3F1ECB93D8C73168C84150835C3942C6DE5C015FEEC35DF5227FC068098CFB6307D7D1D9888B81688DFED4D6A16915A636DD6D93C46DE65C869A9E08985D238D5898B07760EAC9DEF46E9F3A38BDF6A28B9185350DB8C0AD33CDA11E6DF84EB849E7288138CEA52F8E9BACB6C461D6E30E365E89697D1FEE1D484452207403A988B643779A07D56A91CFC0C7C197DDC0C68AD837D0FF248AFE3D0F5A46FEB4380EEF796C46D1A279A4D1E12103107FDF84BB1A4FCCF7E56460CEC85F99580597966B5214BBFE22E84E078EFB664D79A98A850F1FC2DDCCD43A92E25D5732C4700F86D2D342A67EBD2363032F7B2E1C1F2D7C003D0590FD4ABD064AE5C8FCFCD656A2AF510223345CC9F2F8837F3060A66F6DAF811E93600D9CB9BC3B3B66EFC395B86DF065C66C9C8A86192092AED70AC44A1D33D219ABE453E47764B78B5ED8689E06FA40A1276874E99560BA983B01B4268C1FD6B7CAA90B5148D2B39E2026C2E6AD56A9071894A7F6FD0BBE91F75519A0ACC72196F3CD72ACACD0820DA674215E80D63D3C9AFE59FFE547AB2F5F7EE16FFF9328EF6473BD7D3121116AD14868BDA4EA305636D744";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_mdb_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nMDB+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_mdb_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_mdb_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_mdb_kmc_100, "MDB+KMC Process Security MED", num_frames_100, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

// LONG TESTS

UTEST(PERFORMANCE, LSA_LIBG_LONG_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);

    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C07FF00000A000000000000000000000063CC818D81B0A3B0B8CFAE6926856AB15F27C747E4F00F0314AC3174263FCC8ABEEE245A705DF168E7AF81057111A8776502606B698CA119FFDAEE33FD3027358EC40BC2C166D6E5312BF6A813D97864A037D8E3696EFBF2052228DF90F3545628E3182AADD4E7084E423A4CCA88F7C0BAE07A50169E687A1D6232EA056F02AD1F8362D9168A239CDF20EA0615E2FF9B3FC9E02852DD335F0ABCEBBC45A037E073A09B3300B3A2275A646209F4F5BF9C95A9D2A20881273A269B5DB614572D1E117CB73587832D3D63ACD4AD8C9C73AE9A0E521A8C85E19D20F9D670E709924849C46D578D91C0790EF998663E03DE0B830360B2C8E14DF8FA33BC0AC0120CCCA5823543E999C48064B140D8034EBB299E238E526B0443C239EE1CBA826BDAA8705DF421B073A08706D38E11DBD988E08EF9A38C4E4E726326FF54DC43AA76B0EAF004973BCDD51265B306D68EF393E6389AE35858D1B619A3B7D6A3656C3F8EA9512FA6685A3F2710A5A6274FCA0B69275339BC09F3349700E4214A275B9362EE08D2E1E6BBFE0D038007470DD17D8133451B027D1C73AA491256489F6FA2B1964BBA4A6746544ABF98C20C9511E5EFF08678A4B04BFBDFDF401D092FEF153DAB01DB3EBBF0C1879758A6485342DF30D84F46059846F2B9100CEA4A31F68604E41C4448D56A4174B38CF4BA1B365904A442ABCAE1773DBD4007470E674DD5422C5F6DE74EBB068C1C0EEBB68378BB1CFFBC8893DB94136AA501D30C7AEA14135C95C7FA017A893681DF3696448D7F4523102B0A93D183097560B75145754158C7A77B8CE69A7BC7625E28B59FCAD104FDB619B2BB9D5BA7C621697EBC87F80A7FD43480A46828E433314522B9146FCA62CB2105D1EB22D19F55FAE320ED16D54F150FD20081F1336572D128F6D2803A09E8E35456ECB1D6AE0A3A8ECCE231C4602893171538BF40E5AD79003B2CEFA33FDD83D5A79E0BCF26A25754D1E91B279222393F8BDB7A07A0B5BD15458FAB9FB6138192D43A294A9FDE48F660A497305C49726BB3AF29521F8EB686441C34E2DF0BB5EE4E7B0FA14E0A56879A44D252BDA7939B777B6D283C85522F77202A574C0BA9049A3B9BBD059B2CE6CEAEE88B7C979FCB4333BB39AF5F14CFF8B8E8F477C15F11FC6A89365DD8CD258339AB6B748EAB34F93D007805E904A532E7BB5C90AE88209E6170A6656AFCBA6C9F6F5902A8117694C28BF9CF396648E993F5C59D5C60C5C175EEE70E2EA72EA67E2E6535E56E4F95B03B3B077572C6A021D1F1E54EA83DA804E84CD4EE2368917D367552B102B80A5DA8203F65FA9C1BDB5992C0A75F9FF4B9052CD1A59D1AFFC4F31397702C795E36FD31DB437F2376F0E5C9D451777AF0BF88CFE466EE9F4BF2B7929689EDFB2A529ECF8DAFF177E382";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nLSA+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tBytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_lsa_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_libg_100, "LSA+LIBG Process Security LONG", num_frames_100, 0);

    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_LIBG_LONG_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C07FF000002000000000000000000007217E059763EF5ADFC613DFAC3D96B906BE1361B1652B72637738C5731EDEF6C0C8EF2A5915169F1C6BBF7755B2D96BEE2F6DBC490A432A1515A89F4164B00020159A9B8646EDA561DB153F0FF6B4FCDE2E1E7FF4A1F3C155742E9298CA19A3F360FCC6CEC154802771F81F7214709DAEFB8D7732D311C2D11BE133D9F4882A82EE5B16A204B102FC8B21E9F3F841589EB85A97ED72781A2A2482A7E81ADB16628D3C7E8B15BDE350A18D9C459A43DE5B048F8C97A92B56E39C05B41AC0119427AE80E5A85FF7D52D25AFFF8B361FE938051399238864B4ED9983BEB4BE0F467530ABA03BF9EAAAAC9899A934E8FDB7DBDF5FE7F6B10B461D88045DEFBE3B872D11DBE975F2EE94A4BE9225653EFE1D6B06CBD6B0987E74B15E348135C41A583A0B5F249B08615FBD9DADFF8C29C9ED9886501B39857A7E2971DE338BC25379CC1E525A1201DE30922C9E3975D7F7E7538FE3D08B9DDF34E7C9DAB5FC961747A4F6F2FAF5E1BEE8F1EBEC4403FE3F6AC90369A04CB64AEBFF8C2457EFB0FE7714F72712C5256CBF18F25BF1AF13F6B639CCBED04CDC6FBA65F09B3ADF0F912995C5AF40157706D7F572C3481AA215F6B1AF5B7DCD519EDCD02EF66358588A756F3AB8C4C7D7B446D425F0DC7D309BADA9078DE415175DDCEDBDEDD6028D67DD4B83DB1D15EAC3F1A8926D11903F1C48484EF953E846203E5EDF6FA62F93D1FCD5E70C3E17017CFB7FC7C9B8A71B4F2B290893E18C7CC2E0BD8CA9FA940D1DC5129B062CBD2FACEDE3D26F5CDB2CC38F013B032835F1E0C6F2898A77DC8859F485FD64CCA79BA79A0911F87F5EA2C1AE5F72D530E8AE17F094A964ABD43C55E7BB7EBD63479C0E1F4014E5BA6B11FBA230A038B9C1470E289555D4313A2C166B34316BDFA84C428F11E61C11B300039B6FAA1D44ABD313ACCAB31DEE5E7D461BE78428EFEBC7DFBC49CBCB5F98DE92F4F07B477A57CB3426D7A66E5A07CC49A1061F8912C68F7C691BEFBD6DF536A9F26AEAEB6968F3F35017760B1840D4CF1E277FE8D9A99326A9FAD68814DE6F929253F2D4F3AF046C578A434DBFEA4B2CC9834633CF5919085126D95F74A444328113408AE6D798FF6961C38822D4523F9AA99C766AE3E5104BE7EE0E027C2F9B73BA07ADA882762FD93F590BF29FD0429BBC83DB4F531C1187B8DECEC0E5171027433358CE6E0AAAF50B59AC32EDE3D5B198B7C6AD462F00F9E7E52A21DE992037FDED63EF5646C236701729096AC704DA4A649C244B24242795DA49B25C34AB8F2E824DE4F42E1D4F06CC79F594DB4F62F31CD928C4CD678451CA7511FBB30F771F45522410586A22321C683F98774C89864E9ADF030216BC083E991CA96E4E751324B7E0AC2775996CDF33A46E09BCC24856D3112D844D337C57B9519F966A4";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nMDB+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tBytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_lsa_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_libg_100, "MDB+LIBG Process Security LONG", num_frames_100, 0);

    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, LSA_KMC_LONG_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C07FF00000A0000000000000000000000042DD72659FA856512F4C35CA125B94FA62D41A46ECE953F746436776EDBB107E4CB804D02C0A794341D4D7D5A83C8735001B649FABAC5D32D62E64D3A7768CA60B79861A05434DAF398873705D0226717B99079451D42F01FCA9CC895277B705096CA10A9873760CE387FCAB553B93D907F0C299B8427A514C09B36D9008DEFD8C38F7D9E2E7880430D08BFD76C98AE0A1E4A78A5D6E3651C81C418A20C1AA6871BD2C9170A411AB9C00376BC7019E867F7BA0D6A7C28A49E8462216D35C97DA05779F1DEE2A2C1C83E12362A2748E9D7555E8F8CAAAA85611DD3BE5E68C55949329FC64A94804449DA2442406FDFAD6878945EFC27479F4F4DCB82399978F9BAB3D583AC548CEB7EFFEC13D6EE49ECD258781B8F395B9B129F41A72CEDA58D5AE2373EDE39C037042BBFB926DC5C01C92A8D32AF6908754612C2CF6311CAEDF8E78DC3E632C4485D972CF70250A376E687551BB5CE544779AC915CB39ED489B0FA5F7B2948333F5D4DC9CD07D712C764A1085C696473FE62AB77DF0E7E67D91EAF1B1A96F9FE3014B33450B63E6783D2DB965EED2BD26392B221814AA01EEB646B54B2AA45A29F9808283E5FBF04B49C6A3BEE6480E67169825A4E2DA8EB0C7AC690C380107CC888722844DE1C600B2ACFB74ECEB4425B63E8B7AF906540D30333D27BB3DEDAC1A7F04A0584D06EBF0867BC6ADDFBF52B17A7FBE3AD2E814DA4307607DA9C3FC2818A527CDF4E41F4CBF853F25086E90BF8836A9C839830AA9D72283E92A5C5CAACC786CF7FBED1528666FEE7B02CA1ED6F5A05630366AA0DFA37D3B0AB13ADBB2EE053465F7C39A01FF125EADA21619420A89B7FC1706B7E2C6F21ECC923AE9E602FAAD137DBEA66B7CA8C536B00218DC58C398CA465F20DB15438E0D8A2D421AA56FFC7765B7B1903C20312103B86B96B2F8A2F8A72CEBC7D66F86FC2B1EC1662B602C72EEC1C2D6A0B6AF0DF1BC2AFE635C2AB2C083F06D303FE3E45766C80499073177429C7A81EF3883A86FC4271D8F0C91EAB043DCF130CFC2AA1A48C3C20F1ABC1CE1E17B3E64DF5FE4996E285DEC0011A22DAAED5C58529B77E273A2389548748B780271D33A8BB8C380CE1C3CE8F3B2A487DD10D828F3146A2CE61F94CAFF3A5A099A59BF8B59196F271FFF718D097779D56BA71ECFEC97FDDF7BCAC120C264581B3EE45D6C2B01DD0382178134B940D4048847CFB5555A95E33DE7D59C35D41BC37625A64E87AC5F425F7CF88C3D78FF3449464AD4BE53818E8238C9EDB9A1389CAA421A656CDDE86057D08F636AD4462EEBB09B942CE6C86ABA6935DE352AF100257C7B416842C1B4DE70F5DBF55087B297C32A26DC47920B1CD70D1D893EB12703CF04DBD58C4EAE5B5CB674582C69FFD4A06F8491F56DAC15DADFB508EDF1FAA";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nLSA+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_lsa_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_kmc_100, "LSA+KMC Process Security LONG", num_frames_100, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_KMC_LONG_100)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C07FF00000200000000000000000000721BAC6AEED1D245278896BFCE8F455FC3DA3DFFFC84F3A42360697AC41AA8387B67F79EE9E336B4F2900A074274C3D380C3076550FF491C2CD0131DE6EB2F2D2E5F1F8222A1421E911AD331872BF8A6A48165A8D4B0126B8F156EA11117F975D7F1289375EEC9972796EAE4554AD30C9EDB323518644DC504F4484BBB8447DDE7464F74BF271002141DCD5D961D2FA774703F4D708D21922D5D322D95F87762F93BC53AB12E7539784A7622502BD8BDDAD8CFF1415AD0CC27834CF6009A32E50AAC9B20612D4848B93689F1283C844739D03F96A81970A473167F37CAA1E7FF66C539285EB79AC17AF709D3FC7395479CAA2724189ED064AFEEE81D28ECD0CDEEA105A7F3D8AC2AC42C5FD4BC25569EDD6A5B9674A1F90034E031DB30EFDE4789BC381BAF2D367165CA77114B2B72155DD90A48BE229AC984A6153C3E78B3A6C453CC7D791A1FDF6982F8530EAE61649B5FB83776CE0F607B438A7FF0C13F79A778B295F020FA993ADA08CCE57CB7B6098CC3ABF96EEBC6313C361F7DD0230B9FDDF04ED5E0D206178B8F63F072D4DE6DE8A60D1D5279E86F1E518FB875EC7F86406C4719BB6C4F8682F7F2693341599587EC884B882252437BDE838C318F13C2474D909331A737F0BB651656DF1CF46DB16B911851B1C2CCE0A03E3D9DF7494B3AFB5C24FC793A9D52144482B8A4FEA666B472CBD6E4B8355F39E02BEF428C5B950571D3D195561E0BD004A9BA089CA0776FC42C60E95CD5B190A12143F71473A352DC64BD8E5796C7ECC88506F0A6BEE0600E922053ADC2CB43EDC6852E52C82C388CE39C1C30F6DC30DD5B67B3A326F099C0FC5B8A3BDDDD3D3E0E136889AE5578FF746C2D81162023DA4F7C7EE2312284BB88CCA91AC5090BA5C2E101234E6D50F642F77960205CB9DDAB3E09FE77997B7CC4BF0BBC5AFC11CFB8E53936AD637101390BEC5B534AA48236DEEAEA2901EC42EA699B3DF1E0F91A533E0D1D76432DEDC1A5A2E6763662BD1E8D29D29FDA13C072C549B2F42B0E3B796981853DD7B776CA27142E60C65FCECD23CE7624CA0D81E966248C4C5D10953A6F742AD27C87A4950B4F172B706F65CCA2EFDA0FA6715BD95DD2841DB5C3262B210BF126A548D09C1EF0F7F83FA379D389C1890804AEE56B1CC7F45BF4422CCA3FC165F36BC5DD3546DB386A3551F0F467377D952C82D2890E70840F738FDC49838B1F30A16D1AF8DFE9E594D88EEBAEAE3B6DBA33F8DC69D95246E43A394E1463D0EFCAD040FE57CE9E95C57098E7EE76C6507889EB94232DA84B11572D462F932C04CCD60E3372024B7978B8960EA9145A297E7DF1114E48E6048CFDD31C1859B1A468991E1E67FAEAD138652A0BAA7A4D99669882357ECC0893E4D96A1E6E3D754CA24D5D997EDB91C647436A18A47377";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_mdb_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_100);
    printf("\nMDB+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_100);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_mdb_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_100)/ttl_time_mdb_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_mdb_kmc_100, "MDB+KMC Process Security LONG", num_frames_100, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

// *********************************************** 1K Tests *********************************************//

UTEST(PERFORMANCE, LSA_LIBG_SHORT_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);

    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C047F00000A00000000000000000000006367CCB04793EECE4ECFAE6926856AB15F27C747E4F00F0314AC3174263FCC8ABEEE245A705DF168E7AF81057111A8776502606B698CA119FFDAEE33FD3027358EC40BC2C166D6E5312BF6A813D97864A037D8E3696EFBF2052228DFB63A4245482C24985171000B61A0C7F0386C";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nLSA+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tBytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_lsa_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_libg_100, "LSA+LIBG Process Security SHORT", num_frames_1K, 0);

    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_LIBG_SHORT_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C047F0000020000000000000000000070E304CDF655C3FE953D03F0C9322A30FC1E9E93A753017B3B7890A0FF7DECFFE57CBBE804F7CB184436CD7F21D92E01586D243D128E195834F3070365D9CE59D7F71F7F71C4E60FA424ADE3C3976200268804BB9CD6027F9BCFA3BF13F126C5565AF370736625F4A32B1B390B11D3";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_mdb_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nMDB+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_mdb_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_mdb_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_mdb_libg_100, "MDB+LIBG Process Security SHORT", num_frames_1K, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, LSA_KMC_SHORT_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C047F00000A00000000000000000000006367CCB04793EECE4ECFAE6926856AB15F27C747E4F00F0314AC3174263FCC8ABEEE245A705DF168E7AF81057111A8776502606B698CA119FFDAEE33FD3027358EC40BC2C166D6E5312BF6A813D97864A037D8E3696EFBF2052228DFB63A4245482C24985171000B61A0C7F0386C";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nLSA+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_lsa_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_kmc_100, "LSA+KMC Process Security SHORT", num_frames_1K, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_KMC_SHORT_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C047F0000020000000000000000000071B20E13F2B09519E820E696F04588AACE79E1827D42E5EA66F450E2C4893674185EC19C970BE7CABD06AB8768B04F5A29A1AA58FC539A3010EB674B2FC821441BA36AF225474E8E0998513417C525336E858704588E4F3083EC3EA4245D3C6F1CA5312A20DC3AADC47A0310C7FB09";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_mdb_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nMDB+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_mdb_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_mdb_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_mdb_kmc_100, "MDB+KMC Process Security SHORT", num_frames_1K, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

// MEDIUM TESTS

UTEST(PERFORMANCE, LSA_LIBG_MED_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);

    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C05FF00000A000000000000000000000063CC818D81B0A3B0B8CFAE6926856AB15F27C747E4F00F0314AC3174263FCC8ABEEE245A705DF168E7AF81057111A8776502606B698CA119FFDAEE33FD3027358EC40BC2C166D6E5312BF6A813D97864A037D8E3696EFBF2052228DF90F3545628E3182AADD4E7084E423A4CCA88F7C0BAE07A50169E687A1D6232EA056F02AD1F8362D9168A239CDF20EA0615E2FF9B3FC9E02852DD335F0ABCEBBC45A037E073A09B3300B3A2275A646209F4F5BF9C95A9D2A20881273A269B5DB614572D1E117CB73587832D3D63ACD4AD8C9C73AE9A0E521A8C85E19D20F9D670E709924849C46D578D91C0790EF998663E03DE0B830360B2C8E14DF8FA33BC0AC0120CCCA5823543E999C48064B140D8034EBB299E238E526B0443C239EE1CBA826BDAA8705DF421B073A08706D38E11DBD988E08EF9A38C4E4E726326FF54DC43AA76B0EAF004973BCDD51265B306D68EF393E6389AE35858D1B619A3B7D6A3656C3F8EA9512FA6685A3F2710A5A6274FCA0B69275339BC09F3349700E4214A275B9362EE08D2E1E6BBFE0D038007470DD17D8133451B027D1C73AA491256489F6FA2B1964BBA4A6746544ABF98C20C9511E5EFF08678A4B04BFBDFDF401D092FEF153DAB01DB3EBBF0C1879758A6485342DF30D84F46059846F2B910AC279437195F7B80DB14495CA46D9BC075A94CEE7F";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nLSA+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tBytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_lsa_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_libg_100, "LSA+LIBG Process Security MED", num_frames_1K, 0);

    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_LIBG_MED_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C05FF000002000000000000000000007147C4888DE20936C8FFF8772894382BC0EADCFDA9B684BC64250309930E745CB9B300EA84D6C694C8688DCFA9007C276FDC33CDFE2CA12415C359FEDED084549487AA3FD876D04BC947B2EDA171983D7FEE5E627D93ADEF5EA9D9790203E1683B6454AD33614D47903A9D2BD46620FCB1A20DA9138B7A42DDA9F4E5207E3A1A15ECE4C917903B0CACEEED9EC8391AC0010F5BBD309EE3FDD5337BFE51F70DC07EB006B646967269CE93073402CCFB547577AA45CAC5823C35F6F76496F1621252491306EE70089F7DFAE6C1A9E515409E1603F61ADDD12C3BDFF98B2E8595B2CCC0F8339D081380EBBDC295DF274F8C4A02BBE1FC7E405CD54CF11FFA4FF6983A2AD6EAF2EB98EE3418191AE5CFCEBB8653091E4605D017C382990B18E2569A64DE56152CBF5B76D23614E60B449CE24924D549325A0447B88D931C8A0580DD167F5FD1B670A36D965FD3411005C4809F1CF1245C1DA008F1003B7334F933C89DDBF21BC556F8E5F244464A77FFB4320C64DBCD9DF82B3D720A8C9796C3BB8677355A7FF0BDC43D48D8990DC8EA34DA3B796AB0515341522D67FF629C283EA8B71CF261BD2F758443E880A3BEB61C5A839BD702D6D35F7B783B3752D59A1D4A4909A677F88572B84665184AE5149E9492728DA5BBDEA36B6B27E2E6F8194136604C98497056815197F871B8C36B51";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nMDB+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tBytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_lsa_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_libg_100, "MDB+LIBG Process Security MED", num_frames_1K, 0);

    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, LSA_KMC_MED_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C05FF00000A000000000000000000000010B7D5264AA13C588EBCE851BB4CF923A94BDCB9E04ABB6688055EE94074AEFF78139C195EFB6D26F9D5DF2A002D4D26F6C1420F623D9EC8AC1B47EF469314F30D2466B5A1F8E4DC1ED2FFDA3B82C6BF6A8CC93B220C9B15A7FDCC1C3D86AEAA7EC2158D603F5FA4E102AE14917E5CF9B4A5EDC23E4EC5E42368C0D8FB1CF9FBCEE6ADC4790ACDE3B91BA41907416B949B7852DBFF244752242405E58A2C9B48D26E428DC89168A7AD434D3800B60192016F7925A27E12EE8F6C58BFC4D5297C39139B4871A2A37A1B5E4669F753A95003569BDD6CA8DB454CB25677D9227D9744EC09391F56A22970580AF34E5743918CF87387918596155B153CC913B588D07E96D765B11703B2D6C5910BFF92042C5ABD4FC474A0E050DACA184FCE4CAF82903F5C2BE659BD8551D1CA66BBA61B3611D4E9DA7E3060400A80F7F9504867F0943BCAC62EA2D07DD1BEE2FBD52439FA45A5F1AB8041D724E6B73A3803AA0B701BA7821B797C30C71C3B3BAF0CFA3C76DBC8323FFB22FF8507C995B5C552883141054E8B0B01594BCA4E6741E6D5DCC5CCA0D5D8A0F07E4771607513AEC948157966E0D0A8B0C8F8AC3D114F1095781B6F29B37655484F8C7C700D41F7B231D2A4637B10EAFDEFA26D133ECE3FDECF73E379BE93E3488F91F82C01031839E851EB324969EA367D98965AC0FA351B";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nLSA+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_lsa_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_kmc_100, "LSA+KMC Process Security MED", num_frames_1K, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_KMC_MED_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C05FF0000020000000000000000000071B8A9140EDCF90BEB2E84643FB928463D5E7CA5A2CA190B13DFCCBD7C150FC57FCAE7812FD90A672132370F05C11740089A0A263DE28CCF66901393AD69E63E71BF7795929B3F1ECB93D8C73168C84150835C3942C6DE5C015FEEC35DF5227FC068098CFB6307D7D1D9888B81688DFED4D6A16915A636DD6D93C46DE65C869A9E08985D238D5898B07760EAC9DEF46E9F3A38BDF6A28B9185350DB8C0AD33CDA11E6DF84EB849E7288138CEA52F8E9BACB6C461D6E30E365E89697D1FEE1D484452207403A988B643779A07D56A91CFC0C7C197DDC0C68AD837D0FF248AFE3D0F5A46FEB4380EEF796C46D1A279A4D1E12103107FDF84BB1A4FCCF7E56460CEC85F99580597966B5214BBFE22E84E078EFB664D79A98A850F1FC2DDCCD43A92E25D5732C4700F86D2D342A67EBD2363032F7B2E1C1F2D7C003D0590FD4ABD064AE5C8FCFCD656A2AF510223345CC9F2F8837F3060A66F6DAF811E93600D9CB9BC3B3B66EFC395B86DF065C66C9C8A86192092AED70AC44A1D33D219ABE453E47764B78B5ED8689E06FA40A1276874E99560BA983B01B4268C1FD6B7CAA90B5148D2B39E2026C2E6AD56A9071894A7F6FD0BBE91F75519A0ACC72196F3CD72ACACD0820DA674215E80D63D3C9AFE59FFE547AB2F5F7EE16FFF9328EF6473BD7D3121116AD14868BDA4EA305636D744";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_mdb_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nMDB+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_mdb_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_mdb_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_mdb_kmc_100, "MDB+KMC Process Security MED", num_frames_1K, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

// LONG TESTS

UTEST(PERFORMANCE, LSA_LIBG_LONG_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);

    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C07FF00000A000000000000000000000063CC818D81B0A3B0B8CFAE6926856AB15F27C747E4F00F0314AC3174263FCC8ABEEE245A705DF168E7AF81057111A8776502606B698CA119FFDAEE33FD3027358EC40BC2C166D6E5312BF6A813D97864A037D8E3696EFBF2052228DF90F3545628E3182AADD4E7084E423A4CCA88F7C0BAE07A50169E687A1D6232EA056F02AD1F8362D9168A239CDF20EA0615E2FF9B3FC9E02852DD335F0ABCEBBC45A037E073A09B3300B3A2275A646209F4F5BF9C95A9D2A20881273A269B5DB614572D1E117CB73587832D3D63ACD4AD8C9C73AE9A0E521A8C85E19D20F9D670E709924849C46D578D91C0790EF998663E03DE0B830360B2C8E14DF8FA33BC0AC0120CCCA5823543E999C48064B140D8034EBB299E238E526B0443C239EE1CBA826BDAA8705DF421B073A08706D38E11DBD988E08EF9A38C4E4E726326FF54DC43AA76B0EAF004973BCDD51265B306D68EF393E6389AE35858D1B619A3B7D6A3656C3F8EA9512FA6685A3F2710A5A6274FCA0B69275339BC09F3349700E4214A275B9362EE08D2E1E6BBFE0D038007470DD17D8133451B027D1C73AA491256489F6FA2B1964BBA4A6746544ABF98C20C9511E5EFF08678A4B04BFBDFDF401D092FEF153DAB01DB3EBBF0C1879758A6485342DF30D84F46059846F2B9100CEA4A31F68604E41C4448D56A4174B38CF4BA1B365904A442ABCAE1773DBD4007470E674DD5422C5F6DE74EBB068C1C0EEBB68378BB1CFFBC8893DB94136AA501D30C7AEA14135C95C7FA017A893681DF3696448D7F4523102B0A93D183097560B75145754158C7A77B8CE69A7BC7625E28B59FCAD104FDB619B2BB9D5BA7C621697EBC87F80A7FD43480A46828E433314522B9146FCA62CB2105D1EB22D19F55FAE320ED16D54F150FD20081F1336572D128F6D2803A09E8E35456ECB1D6AE0A3A8ECCE231C4602893171538BF40E5AD79003B2CEFA33FDD83D5A79E0BCF26A25754D1E91B279222393F8BDB7A07A0B5BD15458FAB9FB6138192D43A294A9FDE48F660A497305C49726BB3AF29521F8EB686441C34E2DF0BB5EE4E7B0FA14E0A56879A44D252BDA7939B777B6D283C85522F77202A574C0BA9049A3B9BBD059B2CE6CEAEE88B7C979FCB4333BB39AF5F14CFF8B8E8F477C15F11FC6A89365DD8CD258339AB6B748EAB34F93D007805E904A532E7BB5C90AE88209E6170A6656AFCBA6C9F6F5902A8117694C28BF9CF396648E993F5C59D5C60C5C175EEE70E2EA72EA67E2E6535E56E4F95B03B3B077572C6A021D1F1E54EA83DA804E84CD4EE2368917D367552B102B80A5DA8203F65FA9C1BDB5992C0A75F9FF4B9052CD1A59D1AFFC4F31397702C795E36FD31DB437F2376F0E5C9D451777AF0BF88CFE466EE9F4BF2B7929689EDFB2A529ECF8DAFF177E382";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nLSA+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tBytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_lsa_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_libg_100, "LSA+LIBG Process Security LONG", num_frames_1K, 0);

    Crypto_Shutdown();
    free(processed_frame);
    free(data_b);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_LIBG_LONG_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C07FF000002000000000000000000007217E059763EF5ADFC613DFAC3D96B906BE1361B1652B72637738C5731EDEF6C0C8EF2A5915169F1C6BBF7755B2D96BEE2F6DBC490A432A1515A89F4164B00020159A9B8646EDA561DB153F0FF6B4FCDE2E1E7FF4A1F3C155742E9298CA19A3F360FCC6CEC154802771F81F7214709DAEFB8D7732D311C2D11BE133D9F4882A82EE5B16A204B102FC8B21E9F3F841589EB85A97ED72781A2A2482A7E81ADB16628D3C7E8B15BDE350A18D9C459A43DE5B048F8C97A92B56E39C05B41AC0119427AE80E5A85FF7D52D25AFFF8B361FE938051399238864B4ED9983BEB4BE0F467530ABA03BF9EAAAAC9899A934E8FDB7DBDF5FE7F6B10B461D88045DEFBE3B872D11DBE975F2EE94A4BE9225653EFE1D6B06CBD6B0987E74B15E348135C41A583A0B5F249B08615FBD9DADFF8C29C9ED9886501B39857A7E2971DE338BC25379CC1E525A1201DE30922C9E3975D7F7E7538FE3D08B9DDF34E7C9DAB5FC961747A4F6F2FAF5E1BEE8F1EBEC4403FE3F6AC90369A04CB64AEBFF8C2457EFB0FE7714F72712C5256CBF18F25BF1AF13F6B639CCBED04CDC6FBA65F09B3ADF0F912995C5AF40157706D7F572C3481AA215F6B1AF5B7DCD519EDCD02EF66358588A756F3AB8C4C7D7B446D425F0DC7D309BADA9078DE415175DDCEDBDEDD6028D67DD4B83DB1D15EAC3F1A8926D11903F1C48484EF953E846203E5EDF6FA62F93D1FCD5E70C3E17017CFB7FC7C9B8A71B4F2B290893E18C7CC2E0BD8CA9FA940D1DC5129B062CBD2FACEDE3D26F5CDB2CC38F013B032835F1E0C6F2898A77DC8859F485FD64CCA79BA79A0911F87F5EA2C1AE5F72D530E8AE17F094A964ABD43C55E7BB7EBD63479C0E1F4014E5BA6B11FBA230A038B9C1470E289555D4313A2C166B34316BDFA84C428F11E61C11B300039B6FAA1D44ABD313ACCAB31DEE5E7D461BE78428EFEBC7DFBC49CBCB5F98DE92F4F07B477A57CB3426D7A66E5A07CC49A1061F8912C68F7C691BEFBD6DF536A9F26AEAEB6968F3F35017760B1840D4CF1E277FE8D9A99326A9FAD68814DE6F929253F2D4F3AF046C578A434DBFEA4B2CC9834633CF5919085126D95F74A444328113408AE6D798FF6961C38822D4523F9AA99C766AE3E5104BE7EE0E027C2F9B73BA07ADA882762FD93F590BF29FD0429BBC83DB4F531C1187B8DECEC0E5171027433358CE6E0AAAF50B59AC32EDE3D5B198B7C6AD462F00F9E7E52A21DE992037FDED63EF5646C236701729096AC704DA4A649C244B24242795DA49B25C34AB8F2E824DE4F42E1D4F06CC79F594DB4F62F31CD928C4CD678451CA7511FBB30F771F45522410586A22321C683F98774C89864E9ADF030216BC083E991CA96E4E751324B7E0AC2775996CDF33A46E09BCC24856D3112D844D337C57B9519F966A4";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_libg_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nMDB+LIBG Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tBytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_libg_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_lsa_libg_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_libg_100, "MDB+LIBG Process Security LONG", num_frames_1K, 0);

    Crypto_Shutdown();
    free(processed_frame);
    free(data_b);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, LSA_KMC_LONG_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C07FF00000A0000000000000000000000042DD72659FA856512F4C35CA125B94FA62D41A46ECE953F746436776EDBB107E4CB804D02C0A794341D4D7D5A83C8735001B649FABAC5D32D62E64D3A7768CA60B79861A05434DAF398873705D0226717B99079451D42F01FCA9CC895277B705096CA10A9873760CE387FCAB553B93D907F0C299B8427A514C09B36D9008DEFD8C38F7D9E2E7880430D08BFD76C98AE0A1E4A78A5D6E3651C81C418A20C1AA6871BD2C9170A411AB9C00376BC7019E867F7BA0D6A7C28A49E8462216D35C97DA05779F1DEE2A2C1C83E12362A2748E9D7555E8F8CAAAA85611DD3BE5E68C55949329FC64A94804449DA2442406FDFAD6878945EFC27479F4F4DCB82399978F9BAB3D583AC548CEB7EFFEC13D6EE49ECD258781B8F395B9B129F41A72CEDA58D5AE2373EDE39C037042BBFB926DC5C01C92A8D32AF6908754612C2CF6311CAEDF8E78DC3E632C4485D972CF70250A376E687551BB5CE544779AC915CB39ED489B0FA5F7B2948333F5D4DC9CD07D712C764A1085C696473FE62AB77DF0E7E67D91EAF1B1A96F9FE3014B33450B63E6783D2DB965EED2BD26392B221814AA01EEB646B54B2AA45A29F9808283E5FBF04B49C6A3BEE6480E67169825A4E2DA8EB0C7AC690C380107CC888722844DE1C600B2ACFB74ECEB4425B63E8B7AF906540D30333D27BB3DEDAC1A7F04A0584D06EBF0867BC6ADDFBF52B17A7FBE3AD2E814DA4307607DA9C3FC2818A527CDF4E41F4CBF853F25086E90BF8836A9C839830AA9D72283E92A5C5CAACC786CF7FBED1528666FEE7B02CA1ED6F5A05630366AA0DFA37D3B0AB13ADBB2EE053465F7C39A01FF125EADA21619420A89B7FC1706B7E2C6F21ECC923AE9E602FAAD137DBEA66B7CA8C536B00218DC58C398CA465F20DB15438E0D8A2D421AA56FFC7765B7B1903C20312103B86B96B2F8A2F8A72CEBC7D66F86FC2B1EC1662B602C72EEC1C2D6A0B6AF0DF1BC2AFE635C2AB2C083F06D303FE3E45766C80499073177429C7A81EF3883A86FC4271D8F0C91EAB043DCF130CFC2AA1A48C3C20F1ABC1CE1E17B3E64DF5FE4996E285DEC0011A22DAAED5C58529B77E273A2389548748B780271D33A8BB8C380CE1C3CE8F3B2A487DD10D828F3146A2CE61F94CAFF3A5A099A59BF8B59196F271FFF718D097779D56BA71ECFEC97FDDF7BCAC120C264581B3EE45D6C2B01DD0382178134B940D4048847CFB5555A95E33DE7D59C35D41BC37625A64E87AC5F425F7CF88C3D78FF3449464AD4BE53818E8238C9EDB9A1389CAA421A656CDDE86057D08F636AD4462EEBB09B942CE6C86ABA6935DE352AF100257C7B416842C1B4DE70F5DBF55087B297C32A26DC47920B1CD70D1D893EB12703CF04DBD58C4EAE5B5CB674582C69FFD4A06F8491F56DAC15DADFB508EDF1FAA";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;;
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 10
    sadb_routine->sadb_get_sa_from_spi(10, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_lsa_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nLSA+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_lsa_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_lsa_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_lsa_kmc_100, "LSA+KMC Process Security LONG", num_frames_1K, 0);
    Crypto_Shutdown();
    free(data_b);
    free(processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(PERFORMANCE, MDB_KMC_LONG_1K)
{
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_MariaDB("client-demo-kmc.example.com","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/home/itc/Desktop/CERTS/ammos-ca-bundle.crt", NULL,  "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "/home/itc/Desktop/CERTS/ammos-client-key.pem",NULL,"robert", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "client-demo-kmc.example.com", 8443, "crypto-service","/home/itc/Desktop/CERTS/ammos-ca-bundle.crt",NULL, CRYPTO_FALSE, "/home/itc/Desktop/CERTS/ammos-client-cert.pem", "PEM","/home/itc/Desktop/CERTS/ammos-client-key.pem", NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    char* data_h = "202C07FF00000200000000000000000000721BAC6AEED1D245278896BFCE8F455FC3DA3DFFFC84F3A42360697AC41AA8387B67F79EE9E336B4F2900A074274C3D380C3076550FF491C2CD0131DE6EB2F2D2E5F1F8222A1421E911AD331872BF8A6A48165A8D4B0126B8F156EA11117F975D7F1289375EEC9972796EAE4554AD30C9EDB323518644DC504F4484BBB8447DDE7464F74BF271002141DCD5D961D2FA774703F4D708D21922D5D322D95F87762F93BC53AB12E7539784A7622502BD8BDDAD8CFF1415AD0CC27834CF6009A32E50AAC9B20612D4848B93689F1283C844739D03F96A81970A473167F37CAA1E7FF66C539285EB79AC17AF709D3FC7395479CAA2724189ED064AFEEE81D28ECD0CDEEA105A7F3D8AC2AC42C5FD4BC25569EDD6A5B9674A1F90034E031DB30EFDE4789BC381BAF2D367165CA77114B2B72155DD90A48BE229AC984A6153C3E78B3A6C453CC7D791A1FDF6982F8530EAE61649B5FB83776CE0F607B438A7FF0C13F79A778B295F020FA993ADA08CCE57CB7B6098CC3ABF96EEBC6313C361F7DD0230B9FDDF04ED5E0D206178B8F63F072D4DE6DE8A60D1D5279E86F1E518FB875EC7F86406C4719BB6C4F8682F7F2693341599587EC884B882252437BDE838C318F13C2474D909331A737F0BB651656DF1CF46DB16B911851B1C2CCE0A03E3D9DF7494B3AFB5C24FC793A9D52144482B8A4FEA666B472CBD6E4B8355F39E02BEF428C5B950571D3D195561E0BD004A9BA089CA0776FC42C60E95CD5B190A12143F71473A352DC64BD8E5796C7ECC88506F0A6BEE0600E922053ADC2CB43EDC6852E52C82C388CE39C1C30F6DC30DD5B67B3A326F099C0FC5B8A3BDDDD3D3E0E136889AE5578FF746C2D81162023DA4F7C7EE2312284BB88CCA91AC5090BA5C2E101234E6D50F642F77960205CB9DDAB3E09FE77997B7CC4BF0BBC5AFC11CFB8E53936AD637101390BEC5B534AA48236DEEAEA2901EC42EA699B3DF1E0F91A533E0D1D76432DEDC1A5A2E6763662BD1E8D29D29FDA13C072C549B2F42B0E3B796981853DD7B776CA27142E60C65FCECD23CE7624CA0D81E966248C4C5D10953A6F742AD27C87A4950B4F172B706F65CCA2EFDA0FA6715BD95DD2841DB5C3262B210BF126A548D09C1EF0F7F83FA379D389C1890804AEE56B1CC7F45BF4422CCA3FC165F36BC5DD3546DB386A3551F0F467377D952C82D2890E70840F738FDC49838B1F30A16D1AF8DFE9E594D88EEBAEAE3B6DBA33F8DC69D95246E43A394E1463D0EFCAD040FE57CE9E95C57098E7EE76C6507889EB94232DA84B11572D462F932C04CCD60E3372024B7978B8960EA9145A297E7DF1114E48E6048CFDD31C1859B1A468991E1E67FAEAD138652A0BAA7A4D99669882357ECC0893E4D96A1E6E3D754CA24D5D997EDB91C647436A18A47377";
    int32_t status = Crypto_Init();

    char* data_b = NULL;
    int data_l = 0;

    TC_t* processed_frame;
    processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Convert hex to binary
    hex_conversion(data_h, &data_b, &data_l);

    // Variables for gathering Time data
    float ttl_time_mdb_kmc_100 = Process_Security_Loop(data_b, &data_l, processed_frame, num_frames_1K);
    printf("\nMDB+KMC Process Security\n");
    printf("\tNumber of Frames Sent: %d\n", num_frames_1K);
    printf("\t\tEncrypted Bytes Per Frame: %d\n", processed_frame->tc_pdu_len);
    printf("\t\tTotal Time: %f\n", ttl_time_mdb_kmc_100);
    printf("\tMbps: %f\n", (((processed_frame->tc_pdu_len * 8 * num_frames_1K)/ttl_time_mdb_kmc_100)/1024/1024));
    printf("\n");
    Write_To_File(processed_frame->tc_pdu_len, ttl_time_mdb_kmc_100, "MDB+KMC Process Security LONG", num_frames_1K, 0);
    Crypto_Shutdown();
    free(processed_frame);
    free(data_b);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST_MAIN();