#include "ut_ep_sa_mgmt.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"

UTEST(EP_SA_MGMT, SA_6_REKEY_133)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);
    
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    
    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_REKEY_h = "2003002a00ff000100001880d0ac0018197f0b0016000c00060085000000000000000000000000da959fc8555555555555";
    //                     |2003002a00| = Primary Header
    //                               |ff| = Ext. Procs
    //                                 |0001| = SPI
    //                                     |0000| = ARSN
    //                                         |1880| = CryptoLib App ID
    //                                             |d0ac| = seq, pktid
    //                                                 |0018| = pkt_length
    //                                                     |197f| = pusv, ack, st
    //                                                         |0b| = sst, sid, spare
    //                                                           |0016| = PDU Tag
    //                                                               |000c| = PDU Length
    //                                                                   |0006| = SA
    //                                                                       |0085| = Key ID
    //                                                                           |000000000000000000000000da959fc8| = IV

    uint8_t *buffer_REKEY_b = NULL;
    int buffer_REKEY_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Modify SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->shivf_len = 0;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_UNKEYED;

    // Convert frames that will be processed
    hex_conversion(buffer_REKEY_h, (char**) &buffer_REKEY_b, &buffer_REKEY_len);
    
    status = Crypto_TC_ProcessSecurity(buffer_REKEY_b, &buffer_REKEY_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    
    free(buffer_REKEY_b);
}

UTEST(EP_SA_MGMT, SA_START_6)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);
    
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    
    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_START_h = "2003002000ff000100001880d0ad000e197f0b001b0004000600003040f6f7a61a5555";
    //                     |2003002000| = Primary Header
    //                               |ff| = Ext. Procs
    //                                 |0001| = SPI
    //                                     |0000| = ARSN
    //                                         |1880| = CryptoLib App ID
    //                                             |d0ad| = seq, pktid
    //                                                 |000e| = pkt_length
    //                                                     |197f| = pusv, ack, st
    //                                                         |0b| = sst, sid, spare
    //                                                           |001b| = PDU Tag
    //                                                               |0004| = PDU Length
    //                                                                   |0006| = SA being started

    uint8_t *buffer_START_b = NULL;
    int buffer_START_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Modify SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->shivf_len = 0;
    
    // Convert frames that will be processed
    hex_conversion(buffer_START_h, (char**) &buffer_START_b, &buffer_START_len);
    
    status = Crypto_TC_ProcessSecurity(buffer_START_b, &buffer_START_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    
    free(buffer_START_b);
}

UTEST(EP_SA_MGMT, SA_6_READ_ARSN)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);
    
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    
    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_READ_h = "2003001c00ff000100001880d0b0000a197f0b001000020006555555555555";
    //                    |2003001c00| = Primary Header
    //                              |ff| = Ext. Procs
    //                                |0001| = SPI
    //                                    |0000| = ARSN
    //                                        |1880| = CryptoLib App ID
    //                                            |d0ad| = seq, pktid
    //                                                |000e| = pkt_length
    //                                                    |197f| = pusv, ack, st
    //                                                        |0b| = sst, sid, spare
    //                                                          |001b| = PDU Tag
    //                                                              |0002| = PDU Length
    //                                                                  |0006| = SA being read

    uint8_t *buffer_READ_b = NULL;
    int buffer_READ_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Modify SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->shivf_len = 0;

    // Modify SA 1
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->arsn_len = 4;
    test_association->arsn[0] = 0xDE;
    test_association->arsn[1] = 0xAD;
    test_association->arsn[2] = 0xBE;
    test_association->arsn[3] = 0xEF;
    
    // Convert frames that will be processed
    hex_conversion(buffer_READ_h, (char**) &buffer_READ_b, &buffer_READ_len);
    
    status = Crypto_TC_ProcessSecurity(buffer_READ_b, &buffer_READ_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    
    free(buffer_READ_b);
}

UTEST(EP_SA_MGMT, SA_6_SET_ARSNW)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);
    
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    
    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_SET_h = "2003001a00ff000100001880d0b1000a197f0b0015000400060955";
    //                   |2003002800| = Primary Header
    //                             |ff| = Ext. Procs
    //                               |0001| = SPI
    //                                   |0000| = ARSN
    //                                       |1880| = CryptoLib App ID
    //                                           |d0b1| = seq, pktid
    //                                               |0009| = pkt_length
    //                                                   |197f| = pusv, ack, st
    //                                                       |0b| = sst, sid, spare
    //                                                         |0015| = PDU Tag
    //                                                             |000a| = PDU Length
    //                                                                 |0006| = SA being modified
    //                                                                     |09| = ARSNW

    uint8_t *buffer_SET_b = NULL;
    int buffer_SET_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Modify SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->shivf_len = 0;

    // Modify SA 1
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    
    // Convert frames that will be processed
    hex_conversion(buffer_SET_h, (char**) &buffer_SET_b, &buffer_SET_len);
    
    status = Crypto_TC_ProcessSecurity(buffer_SET_b, &buffer_SET_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    sa_if->sa_get_from_spi(6, &test_association);

    printf("\n");
    Crypto_Shutdown();
    
    free(buffer_SET_b);
}

UTEST(EP_SA_MGMT, SA_6_SET_ARSN)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);
    
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    
    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_SET_h = "2003002800ff000100001880d0b10016197f0b001a000a000600000000000000000000006413b5983e55";
    //                   |2003002800| = Primary Header
    //                             |ff| = Ext. Procs
    //                               |0001| = SPI
    //                                   |0000| = ARSN
    //                                       |1880| = CryptoLib App ID
    //                                           |d0b1| = seq, pktid
    //                                               |0016| = pkt_length
    //                                                   |197f| = pusv, ack, st
    //                                                       |0b| = sst, sid, spare
    //                                                         |001a| = PDU Tag
    //                                                             |000a| = PDU Length
    //                                                                 |0006| = SA being modified
    //                                                                     |00000000000000000000006413b5983e| = ARSN

    uint8_t *buffer_SET_b = NULL;
    int buffer_SET_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Modify SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->shivf_len = 0;

    // Modify SA 1
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->arsn_len = 16;
    
    // Convert frames that will be processed
    hex_conversion(buffer_SET_h, (char**) &buffer_SET_b, &buffer_SET_len);
    
    status = Crypto_TC_ProcessSecurity(buffer_SET_b, &buffer_SET_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    sa_if->sa_get_from_spi(6, &test_association);

    printf("\n");
    Crypto_Shutdown();
    
    free(buffer_SET_b);
}

UTEST(EP_SA_MGMT, SA_6_STATUS)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);
    
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    
    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_STATUS_h = "2003001800ff000100001880d0b00008197f0b001f00020006";
    //                      |2003002000| = Primary Header
    //                                |ff| = Ext. Procs
    //                                  |0001| = SPI
    //                                      |0000| = ARSN
    //                                          |1880| = CryptoLib App ID
    //                                              |d0b0| = seq, pktid
    //                                                  |000e| = pkt_length
    //                                                      |197f| = pusv, ack, st
    //                                                          |0b| = sst, sid, spare
    //                                                            |001b| = PDU Tag
    //                                                                |0002| = PDU Length
    //                                                                    |0006| = SA being started

    uint8_t *buffer_STATUS_b = NULL;
    int buffer_STATUS_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Modify SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->shivf_len = 0;

    // Modify SA 1
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    
    // Convert frames that will be processed
    hex_conversion(buffer_STATUS_h, (char**) &buffer_STATUS_b, &buffer_STATUS_len);
    
    status = Crypto_TC_ProcessSecurity(buffer_STATUS_b, &buffer_STATUS_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    
    free(buffer_STATUS_b);
}

UTEST(EP_SA_MGMT, SA_STOP_6)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);
    
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    
    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_STOP_h = "2003001c00ff000100001880d0b6000a197f0b001e00020006938f21c4555555555555";
    //                    |2003001c00| = Primary Header
    //                              |ff| = Ext. Procs
    //                                |0001| = SPI
    //                                    |0000| = ARSN
    //                                        |1880| = CryptoLib App ID
    //                                            |d0b6| = seq, pktid
    //                                                |000a| = pkt_length
    //                                                    |197f| = pusv, ack, st
    //                                                        |0b| = sst, sid, spare
    //                                                          |001e| = PDU Tag
    //                                                              |0002| = PDU Length
    //                                                                  |0006| = SA being stopped

    uint8_t *buffer_STOP_b = NULL;
    int buffer_STOP_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Modify SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->shivf_len = 0;

    // Modify SA 1
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    
    // Convert frames that will be processed
    hex_conversion(buffer_STOP_h, (char**) &buffer_STOP_b, &buffer_STOP_len);
    
    status = Crypto_TC_ProcessSecurity(buffer_STOP_b, &buffer_STOP_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    
    free(buffer_STOP_b);
}

UTEST(EP_SA_MGMT, SA_EXPIRE_6)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);
    
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    
    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_EXPIRE_h = "2003001c00ff000100001880d0b7000a197f0b001900020006f72e21c4555555555555";
    //                      |2003001c00| = Primary Header
    //                                |ff| = Ext. Procs
    //                                  |0001| = SPI
    //                                      |0000| = ARSN
    //                                          |1880| = CryptoLib App ID
    //                                              |d0b7| = seq, pktid
    //                                                  |000a| = pkt_length
    //                                                      |197f| = pusv, ack, st
    //                                                          |0b| = sst, sid, spare
    //                                                            |0019| = PDU Tag
    //                                                                |0002| = PDU Length
    //                                                                    |0006| = SA being stopped

    uint8_t *buffer_EXPIRE_b = NULL;
    int buffer_EXPIRE_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Modify SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->shivf_len = 0;
    
    // Convert frames that will be processed
    hex_conversion(buffer_EXPIRE_h, (char**) &buffer_EXPIRE_b, &buffer_EXPIRE_len);
    
    status = Crypto_TC_ProcessSecurity(buffer_EXPIRE_b, &buffer_EXPIRE_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    
    free(buffer_EXPIRE_b);
}

UTEST_MAIN();