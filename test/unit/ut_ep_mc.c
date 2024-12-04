#include "ut_ep_mc.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"

UTEST(EP_MC, MC_REGULAR_PING)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();

    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_PING_h = "2003001a00ff000000001880d2c70008197f0b00310000b1fe312855";
    //                    |2003001a00| = Primary Header
    //                              |ff| = Ext. Procs
    //                                |0000| = SPI
    //                                    |0000| = ARSN
    //                                        |1880| = CryptoLib App ID
    //                                            |d2c7| = seq, pktid
    //                                                |0008| = pkt_length
    //                                                    |197f| = pusv, ack, st
    //                                                        |0b| = sst, sid, spare
    //                                                          |0031| = PDU Tag
    //                                                              |0000| = PDU Length
    //                                                                  |b1fe3128| = FSR
    //                                                                          |55| = Padding

    uint8_t *buffer_PING_b   = NULL;
    int      buffer_PING_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->iv_len          = 12;
    test_association->shsnf_len       = 2;
    test_association->arsnw           = 5;
    test_association->arsnw_len       = 1;
    test_association->arsn_len        = 2;
    test_association->gvcid_blk.scid  = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_UNKEYED;

    // Convert frames that will be processed
    hex_conversion(buffer_PING_h, (char **)&buffer_PING_b, &buffer_PING_len);

    status = Crypto_TC_ProcessSecurity(buffer_PING_b, &buffer_PING_len, &tc_nist_processed_frame);
    // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    printf("\n");

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

    Crypto_Shutdown();

    free(buffer_PING_b);
}

UTEST(EP_MC, MC_STATUS)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();

    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_STATUS_h = "2003001a00ff000000001880d2c70008197f0b00320000b1fe312855";

    uint8_t *buffer_STATUS_b   = NULL;
    int      buffer_STATUS_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->iv_len          = 12;
    test_association->shsnf_len       = 2;
    test_association->arsnw           = 5;
    test_association->arsnw_len       = 1;
    test_association->arsn_len        = 2;
    test_association->gvcid_blk.scid  = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_UNKEYED;

    // Convert frames that will be processed
    hex_conversion(buffer_STATUS_h, (char **)&buffer_STATUS_b, &buffer_STATUS_len);

    status = Crypto_TC_ProcessSecurity(buffer_STATUS_b, &buffer_STATUS_len, &tc_nist_processed_frame);
    // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    printf("\n");

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

    Crypto_Shutdown();

    free(buffer_STATUS_b);
}

UTEST(EP_MC, MC_DUMP)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();

    int status = CRYPTO_LIB_SUCCESS;

    char *buffer_DUMP_h = "2003001a00ff000000001880d2c70008197f0b00330000b1fe312855";

    uint8_t *buffer_DUMP_b   = NULL;
    int      buffer_DUMP_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->iv_len          = 12;
    test_association->shsnf_len       = 2;
    test_association->arsnw           = 5;
    test_association->arsnw_len       = 1;
    test_association->arsn_len        = 2;
    test_association->gvcid_blk.scid  = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_UNKEYED;

    // Convert frames that will be processed
    hex_conversion(buffer_DUMP_h, (char **)&buffer_DUMP_b, &buffer_DUMP_len);

    status = Crypto_TC_ProcessSecurity(buffer_DUMP_b, &buffer_DUMP_len, &tc_nist_processed_frame);
    // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    printf("\n");

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

    Crypto_Shutdown();

    free(buffer_DUMP_b);
}

UTEST(EP_MC, MC_ERASE)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();

    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_ERASE_h = "2003001a00ff000000001880d2c70008197f0b00340000b1fe312855";

    uint8_t *buffer_ERASE_b   = NULL;
    int      buffer_ERASE_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->iv_len          = 12;
    test_association->shsnf_len       = 2;
    test_association->arsnw           = 5;
    test_association->arsnw_len       = 1;
    test_association->arsn_len        = 2;
    test_association->gvcid_blk.scid  = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_UNKEYED;

    // Convert frames that will be processed
    hex_conversion(buffer_ERASE_h, (char **)&buffer_ERASE_b, &buffer_ERASE_len);

    status = Crypto_TC_ProcessSecurity(buffer_ERASE_b, &buffer_ERASE_len, &tc_nist_processed_frame);
    // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    printf("\n");

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

    Crypto_Shutdown();

    free(buffer_ERASE_b);
}

UTEST(EP_MC, MC_SELF_TEST)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();

    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_SELF_h = "2003001a00ff000000001880d2c70008197f0b00350000b1fe312855";

    uint8_t *buffer_SELF_b   = NULL;
    int      buffer_SELF_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->iv_len          = 12;
    test_association->shsnf_len       = 2;
    test_association->arsnw           = 5;
    test_association->arsnw_len       = 1;
    test_association->arsn_len        = 2;
    test_association->gvcid_blk.scid  = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_UNKEYED;

    // Convert frames that will be processed
    hex_conversion(buffer_SELF_h, (char **)&buffer_SELF_b, &buffer_SELF_len);

    status = Crypto_TC_ProcessSecurity(buffer_SELF_b, &buffer_SELF_len, &tc_nist_processed_frame);
    // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    printf("\n");

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

    Crypto_Shutdown();

    free(buffer_SELF_b);
}

UTEST(EP_MC, MC_ALARM_FLAG_RESET)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();

    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_ALARM_h = "2003001a00ff000000001880d2c70008197f0b00370000b1fe312855";
 
    uint8_t *buffer_ALARM_b   = NULL;
    int      buffer_ALARM_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Modify SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->shivf_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->iv_len          = 12;
    test_association->shsnf_len       = 2;
    test_association->arsnw           = 5;
    test_association->arsnw_len       = 1;
    test_association->arsn_len        = 2;
    test_association->gvcid_blk.scid  = SCID & 0x3FF;

    // Modify SA 6
    sa_if->sa_get_from_spi(6, &test_association);
    test_association->sa_state = SA_UNKEYED;

    // Convert frames that will be processed
    hex_conversion(buffer_ALARM_h, (char **)&buffer_ALARM_b, &buffer_ALARM_len);

    status = Crypto_TC_ProcessSecurity(buffer_ALARM_b, &buffer_ALARM_len, &tc_nist_processed_frame);
    // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();

    free(buffer_ALARM_b);
}

UTEST_MAIN()