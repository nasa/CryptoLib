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
                            IV_INTERNAL);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_FALSE,
                     TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    TCGvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, 41, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface sa_if = get_sa_interface_inmemory();

    status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_REKEY_h = "2003002800ff00001980d0ac0018197f0b001600A000060085000000000000000000000000da959fc8";

    uint8_t *buffer_REKEY_b   = NULL;
    int      buffer_REKEY_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->iv_len         = 12;
    test_association->shsnf_len      = 0;
    test_association->arsnw          = 5;
    test_association->arsnw_len      = 1;
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.scid = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_UNKEYED;

    // Convert frames that will be processed
    hex_conversion(buffer_REKEY_h, (char **)&buffer_REKEY_b, &buffer_REKEY_len);

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
                            IV_INTERNAL);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_FALSE,
                     TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    TCGvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, 31, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface sa_if = get_sa_interface_inmemory();

    status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_START_TC_h  = "2003002000ff000000001880d0ad000e197f0b001b0060000600003000f6f7a61a";
    char *buffer_START_MAP_h = "2003002000ff000000001880d0ad000e197f0b001b0006000600003001f6f7a61a";
    char *buffer_START_TM_h  = "2003002000ff000000001880d0ad000e197f0b001b0006000600003042f6f7a61a";
    char *buffer_START_AOS_h = "2003002000ff000000001880d0ad000e197f0b001b0006000610003043f6f7a61a";
    char *buffer_START_UK_h  = "2003002000ff000000001880d0ad000e197f0b001b0006000610003044f6f7a61a";
    //                                                                   |0006000600003000|
    //                                                                   |0006| = PDU Len
    //                                                                       |0006| = SPI
    //                                                                           |0| = TFVN (4 bits)
    //                                                                            |0003| = SCID (16 bits)
    //                                                                                |000000| = VCID (6 bits)
    //                                                                                (expanded)
    //                                                                                 |000000| = MAPID (6 bits)
    //                                                                                 (expanded)
    //
    char *buffer_START_MAX_h = "2003020800ff000000001880d0ad01EE197f0b001b0F90000610003041"
                               "100030421000304310003044100030441000304410003044100030441000304410003044100030441000304"
                               "4100030441000304410003044100030441000304410003044100030441000304410003042"
                               "100030441000304410003044100030441000304410003044100030441000304410003044100030441000304"
                               "4100030441000304410003044100030441000304410003044100030441000304410003042"
                               "100030441000304410003044100030441000304410003044100030441000304410003044100030441000304"
                               "4100030441000304410003044100030441000304410003044100030441000304410003042"
                               "100030441000304410003044100030441000304410003044100030441000304410003044100030441000304"
                               "4100030441000304410003044100030441000304410003044100030441000304410003042"
                               "100030441000304410003044100030441000304410003044100030441000304410003044100030441000304"
                               "4100030441000304410003044100030441000304410003044100030441000304410003042"
                               "100030441000304410003044100030441000304410003044100030441000304410003044100030441000304"
                               "4100030441000304110003041100030411000304110003041100030401000304110003042"
                               "1000304310003044"
                               "f6f7a61a";

    uint8_t *buffer_START_TC_b, *buffer_START_TM_b, *buffer_START_MAP_b, *buffer_START_AOS_b, *buffer_START_UK_b,
        *buffer_START_MAX_b = NULL;
    int buffer_START_TC_len, buffer_START_TM_len, buffer_START_MAP_len, buffer_START_AOS_len, buffer_START_UK_len,
        buffer_START_MAX_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->iv_len         = 12;
    test_association->shsnf_len      = 0;
    test_association->arsnw          = 5;
    test_association->arsnw_len      = 1;
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.scid = SCID & 0x3FF;

    // Convert frames that will be processed
    hex_conversion(buffer_START_TC_h, (char **)&buffer_START_TC_b, &buffer_START_TC_len);
    hex_conversion(buffer_START_TM_h, (char **)&buffer_START_TM_b, &buffer_START_TM_len);
    hex_conversion(buffer_START_MAP_h, (char **)&buffer_START_MAP_b, &buffer_START_MAP_len);
    hex_conversion(buffer_START_AOS_h, (char **)&buffer_START_AOS_b, &buffer_START_AOS_len);
    hex_conversion(buffer_START_UK_h, (char **)&buffer_START_UK_b, &buffer_START_UK_len);
    hex_conversion(buffer_START_MAX_h, (char **)&buffer_START_MAX_b, &buffer_START_MAX_len);

    // TFVN = 0, SCID = 3, VCID = 0, MAPID = 0
    status = Crypto_TC_ProcessSecurity(buffer_START_TC_b, &buffer_START_TC_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_KEYED;

    // TFVN = 0, SCID = 3, VCID = 0, MAPID = 1
    status = Crypto_TC_ProcessSecurity(buffer_START_MAP_b, &buffer_START_MAP_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_KEYED;

    // TFVN = 0, SCID = 3, VCID = 1, MAPID = 2
    status = Crypto_TC_ProcessSecurity(buffer_START_TM_b, &buffer_START_TM_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_KEYED;

    // TFVN = 1, SCID = 3, VCID = 1, MAPID = 3
    status = Crypto_TC_ProcessSecurity(buffer_START_AOS_b, &buffer_START_AOS_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_KEYED;

    // TFVN = 1, SCID = 3, VCID = 1, MAPID = 4
    status = Crypto_TC_ProcessSecurity(buffer_START_UK_b, &buffer_START_UK_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_KEYED;

    // TFVN = 1, SCID = 3, VCID = 1, MAPID = 4, max PDU length
    status = Crypto_TC_ProcessSecurity(buffer_START_MAX_b, &buffer_START_MAX_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();

    free(buffer_START_TC_b);
    free(buffer_START_MAP_b);
    free(buffer_START_TM_b);
    free(buffer_START_AOS_b);
    free(buffer_START_UK_b);
    free(buffer_START_MAX_b);
}

UTEST(EP_SA_MGMT, SA_4_READ_ARSN)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_FALSE,
                     TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    TCGvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, 23, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface sa_if = get_sa_interface_inmemory();

    status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_READ_h = "2003001600ff00001980d0b0000a197f0b001000100004";

    uint8_t *buffer_READ_b   = NULL;
    int      buffer_READ_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->iv_len         = 12;
    test_association->shsnf_len      = 0;
    test_association->arsnw          = 5;
    test_association->arsnw_len      = 1;
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.scid = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->shivf_len = 0;
    test_association->iv_len    = 0;
    test_association->ecs       = 0;
    test_association->arsn_len  = 4;
    test_association->shsnf_len = 0;
    test_association->arsn[0]   = 0xDE;
    test_association->arsn[1]   = 0xAD;
    test_association->arsn[2]   = 0xBE;
    test_association->arsn[3]   = 0xEF;

    // Convert frames that will be processed
    hex_conversion(buffer_READ_h, (char **)&buffer_READ_b, &buffer_READ_len);

    status = Crypto_TC_ProcessSecurity(buffer_READ_b, &buffer_READ_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Check reply values
    uint16_t reply_length = 0;
    uint8_t  sdls_ep_reply_local[1024];
    status = Crypto_Get_Sdls_Ep_Reply(&sdls_ep_reply_local[0], &reply_length);
    // Expect success
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Print local copy
    printf("SDLS Reply LOCAL:  0x");
    for (int i = 0; i < reply_length; i++)
    {
        printf("%02X", sdls_ep_reply_local[i]);
    }
    printf("\n\n");
    // Print Global copy for sanity check
    Crypto_Print_Sdls_Ep_Reply();

    // Let's compare everything.
    for (int i = 0; i < reply_length; i++)
    {
        ASSERT_EQ(sdls_ep_reply[i], sdls_ep_reply_local[i]);
    }

    printf("\n");
    Crypto_Shutdown();

    free(buffer_READ_b);
}

UTEST(EP_SA_MGMT, SA_6_SET_ARSNW)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_FALSE,
                     TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    TCGvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, 24, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface sa_if = get_sa_interface_inmemory();

    status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_SET_h = "2003001700ff00001980d0b1000a197f0b00150018000609";

    uint8_t *buffer_SET_b   = NULL;
    int      buffer_SET_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->iv_len         = 12;
    test_association->shsnf_len      = 0;
    test_association->arsnw          = 5;
    test_association->arsnw_len      = 1;
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.scid = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_OPERATIONAL;

    // Convert frames that will be processed
    hex_conversion(buffer_SET_h, (char **)&buffer_SET_b, &buffer_SET_len);

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
                            IV_INTERNAL);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_FALSE,
                     TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    TCGvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, 39, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface sa_if = get_sa_interface_inmemory();

    status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_SET_h = "2003002600ff00001980d0b10016197f0b001a0090000600000000000000000000006413b5983e";

    uint8_t *buffer_SET_b   = NULL;
    int      buffer_SET_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->iv_len         = 12;
    test_association->shsnf_len      = 0;
    test_association->arsnw          = 5;
    test_association->arsnw_len      = 1;
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.scid = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(7, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->arsn_len = 11;

    // Convert frames that will be processed
    hex_conversion(buffer_SET_h, (char **)&buffer_SET_b, &buffer_SET_len);

    status = Crypto_TC_ProcessSecurity(buffer_SET_b, &buffer_SET_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("SA %d ARSN: 0x", test_association->spi);
    for (int i = 0; i < test_association->arsn_len; i++)
    {
        printf("%02x", test_association->arsn[i]);
    }
    printf("\n");

    Crypto_Shutdown();
    free(buffer_SET_b);
}

UTEST(EP_SA_MGMT, SA_6_STATUS)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_FALSE,
                     TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    TCGvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, 23, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface sa_if = get_sa_interface_inmemory();

    status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_STATUS_h = "2003001600ff00001980d0b00008197f0b001f00100006";
    //                      |2003002000| = Primary Header
    //                                |ff| = Ext. Procs
    //                                  |0000| = SPI
    //                                      |0000| = ARSN
    //                                          |1980| = CryptoLib App ID
    //                                              |d0b0| = seq, pktid
    //                                                  |000e| = pkt_length
    //                                                      |197f| = pusv, ack, st
    //                                                          |0b| = sst, sid, spare
    //                                                            |001b| = PDU Tag
    //                                                                |0002| = PDU Length
    //                                                                    |0006| = SA being started

    uint8_t *buffer_STATUS_b   = NULL;
    int      buffer_STATUS_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->iv_len         = 12;
    test_association->shsnf_len      = 0;
    test_association->arsnw          = 5;
    test_association->arsnw_len      = 1;
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.scid = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_OPERATIONAL;

    // Convert frames that will be processed
    hex_conversion(buffer_STATUS_h, (char **)&buffer_STATUS_b, &buffer_STATUS_len);

    status = Crypto_TC_ProcessSecurity(buffer_STATUS_b, &buffer_STATUS_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Check reply values
    uint16_t reply_length = 0;
    uint8_t  sdls_ep_reply_local[1024];
    status = Crypto_Get_Sdls_Ep_Reply(&sdls_ep_reply_local[0], &reply_length);
    // Expect success
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Print local copy
    printf("SDLS Reply LOCAL:  0x");
    for (int i = 0; i < reply_length; i++)
    {
        printf("%02X", sdls_ep_reply_local[i]);
    }
    printf("\n\n");
    // Print Global copy for sanity check
    Crypto_Print_Sdls_Ep_Reply();

    // Let's compare everything.
    for (int i = 0; i < reply_length; i++)
    {
        ASSERT_EQ(sdls_ep_reply[i], sdls_ep_reply_local[i]);
    }

    printf("\n");
    Crypto_Shutdown();

    free(buffer_STATUS_b);
}

UTEST(EP_SA_MGMT, SA_STOP_6)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_FALSE,
                     TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    TCGvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, 27, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface sa_if = get_sa_interface_inmemory();

    status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_STOP_h = "2003001a00ff00001980d0b6000a197f0b001e00300006938f21c4";

    uint8_t *buffer_STOP_b   = NULL;
    int      buffer_STOP_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->iv_len         = 12;
    test_association->shsnf_len      = 0;
    test_association->arsnw          = 5;
    test_association->arsnw_len      = 1;
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.scid = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_OPERATIONAL;

    // Convert frames that will be processed
    hex_conversion(buffer_STOP_h, (char **)&buffer_STOP_b, &buffer_STOP_len);

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
                            IV_INTERNAL);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_FALSE,
                     TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    TCGvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, 27, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_EXPIRE_h = "2003001a00ff00001980d0b7000a197f0b001900300006f72e21c4";
    //                      |2003001c00| = Primary Header
    //                                |ff| = Ext. Procs
    //                                  |0000| = SPI
    //                                      |0000| = ARSN
    //                                          |1980| = CryptoLib App ID
    //                                              |d0b7| = seq, pktid
    //                                                  |000a| = pkt_length
    //                                                      |197f| = pusv, ack, st
    //                                                          |0b| = sst, sid, spare
    //                                                            |0019| = PDU Tag
    //                                                                |0002| = PDU Length
    //                                                                    |0006| = SA being stopped

    uint8_t *buffer_EXPIRE_b   = NULL;
    int      buffer_EXPIRE_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->iv_len         = 12;
    test_association->shsnf_len      = 0;
    test_association->arsnw          = 5;
    test_association->arsnw_len      = 1;
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.scid = SCID & 0x3FF;

    // Convert frames that will be processed
    hex_conversion(buffer_EXPIRE_h, (char **)&buffer_EXPIRE_b, &buffer_EXPIRE_len);

    status = Crypto_TC_ProcessSecurity(buffer_EXPIRE_b, &buffer_EXPIRE_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();

    free(buffer_EXPIRE_b);
}

UTEST(EP_SA_MGMT, SA_STOP_SELF)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_FALSE,
                     TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    TCGvcidManagedParameters_t TC_0_Managed_Parameters = {0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, 27, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    int status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface sa_if = get_sa_interface_inmemory();

    status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_STOP_h = "2003001a00ff00001980d0b6000a197f0b001e00300000938f21c4";

    uint8_t *buffer_STOP_b   = NULL;
    int      buffer_STOP_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len      = 0;
    test_association->sa_state       = SA_OPERATIONAL;
    test_association->iv_len         = 12;
    test_association->shsnf_len      = 0;
    test_association->arsnw          = 5;
    test_association->arsnw_len      = 1;
    test_association->arsn_len       = 0;
    test_association->gvcid_blk.scid = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_OPERATIONAL;

    // Convert frames that will be processed
    hex_conversion(buffer_STOP_h, (char **)&buffer_STOP_b, &buffer_STOP_len);

    status = Crypto_TC_ProcessSecurity(buffer_STOP_b, &buffer_STOP_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_SDLS_EP_WRONG_SPI, status);

    printf("\n");
    Crypto_Shutdown();

    free(buffer_STOP_b);
}

UTEST_MAIN();