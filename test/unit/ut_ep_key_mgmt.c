#include "ut_ep_key_mgmt.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"

UTEST(EP_KEY_MGMT, OTAR_0_140_142)
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

    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();

    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    // char* buffer_nist_iv_h = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    char *buffer_OTAR_h =
        "2003009e00ff000000001880d037008c197f0b000100840000344892bbc54f5395297d4c37172f2a3c46f6a81c1349e9e26ac80985d8bb"
        "d55a5814c662e49fba52f99ba09558cd21cf268b8e50b2184137e80f76122034c580464e2f06d2659a50508bdfe9e9a55990ba4148af89"
        "6d8a6eebe8b5d2258685d4ce217a20174fdd4f0efac62758c51b04e55710a47209c923b641d19a39001f9e986166f5ffd95555";

    uint8_t *buffer_nist_key_b, *buffer_OTAR_b    = NULL;
    int      buffer_nist_key_len, buffer_OTAR_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Activate SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->ecs_len   = 1;
    test_association->ecs       = CRYPTO_CIPHER_NONE;
    test_association->est       = 0;
    test_association->ast       = 0;
    test_association->shsnf_len = 2;
    test_association->arsn_len  = 2;
    test_association->arsnw     = 5;
    test_association->iv_len    = 0;
    test_association->shivf_len = 0;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);

    // Convert frames that will be processed
    hex_conversion(buffer_OTAR_h, (char **)&buffer_OTAR_b, &buffer_OTAR_len);
    // Convert/Set input IV

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking  next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_OTAR_b, &buffer_OTAR_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    free(buffer_nist_key_b);
    free(buffer_OTAR_b);
}

UTEST(EP_KEY_MGMT, ACTIVATE_141_142)
{
    remove("sa_save_file.bin");
    uint8_t *ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    Crypto_Init();
    SaInterface   sa_if  = get_sa_interface_inmemory();
    crypto_key_t *ekp    = NULL;
    int           status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    char *buffer_nist_iv_h  = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    char *buffer_ACTIVATE_h = "2003001e00ff000000001880d038000c197f0b00020004008d008e82ebe4fc55555555";

    uint8_t *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_ACTIVATE_b     = NULL;
    int      buffer_nist_iv_len, buffer_nist_key_len, buffer_ACTIVATE_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;

    // Activate SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->ecs_len   = 1;
    test_association->ecs       = CRYPTO_CIPHER_NONE;
    test_association->shsnf_len = 2;
    test_association->arsn_len  = 2;
    test_association->arsnw     = 5;
    test_association->iv_len    = 12;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert frames that will be processed
    hex_conversion(buffer_ACTIVATE_h, (char **)&buffer_ACTIVATE_b, &buffer_ACTIVATE_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char **)&buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking  next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_ACTIVATE_b, &buffer_ACTIVATE_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    free(ptr_enc_frame);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_ACTIVATE_b);
}

UTEST(EP_KEY_MGMT, DEACTIVATE_142)
{
    remove("sa_save_file.bin");
    uint8_t *ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    GvcidManagedParameters_t TC_0_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_0_Managed_Parameters);

    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    Crypto_Init();
    SaInterface   sa_if  = get_sa_interface_inmemory();
    crypto_key_t *ekp    = NULL;
    int           status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h   = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    char *buffer_nist_iv_h    = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    char *buffer_DEACTIVATE_h = "2003001c00ff000000001880d039000a197f0b00030002008e1f6d21c4555555555555";

    uint8_t *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_DEACTIVATE_b     = NULL;
    int      buffer_nist_iv_len, buffer_nist_key_len, buffer_DEACTIVATE_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;

    // Activate SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    // test_association->ecs_len = 1;
    test_association->ecs       = CRYPTO_CIPHER_NONE;
    test_association->est       = 0;
    test_association->ast       = 0;
    test_association->iv_len    = 12;
    test_association->shsnf_len = 2;
    test_association->arsn_len  = 2;
    test_association->arsnw     = 5;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(142);
    memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);
    ekp->key_state = KEY_ACTIVE;

    // Convert frames that will be processed
    hex_conversion(buffer_DEACTIVATE_h, (char **)&buffer_DEACTIVATE_b, &buffer_DEACTIVATE_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char **)&buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking  next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_DEACTIVATE_b, &buffer_DEACTIVATE_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    free(ptr_enc_frame);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_DEACTIVATE_b);
}

UTEST(EP_KEY_MGMT, INVENTORY_132_134)
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

    int status = CRYPTO_LIB_SUCCESS;
    status     = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface   sa_if = get_sa_interface_inmemory();
    crypto_key_t *ekp   = NULL;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h  = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    char *buffer_nist_iv_h   = "000000000000000000000000"; // The last valid IV that was seen by the SA
    char *buffer_INVENTORY_h = "2003001e00ff000000001880d03b000a197f0b00070004008400861f6d82ebe4fc55555555";


    uint8_t *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_INVENTORY_b     = NULL;
    int      buffer_nist_iv_len, buffer_nist_key_len, buffer_INVENTORY_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;

    // Activate SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->ecs_len   = 1;
    test_association->ecs       = CRYPTO_CIPHER_NONE;
    test_association->est       = 0;
    test_association->ast       = 0;
    test_association->shsnf_len = 2;
    test_association->arsn_len  = 2;
    test_association->arsnw     = 5;
    test_association->iv_len    = 12;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);
    // Convert frames that will be processed
    hex_conversion(buffer_INVENTORY_h, (char **)&buffer_INVENTORY_b, &buffer_INVENTORY_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char **)&buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking  next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_INVENTORY_b, &buffer_INVENTORY_len, &tc_nist_processed_frame);
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
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    ASSERT_EQ(0, 0);
}

UTEST(EP_KEY_MGMT, VERIFY_132_134)
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

    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    int status = CRYPTO_LIB_SUCCESS;
    status     = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    SaInterface   sa_if = get_sa_interface_inmemory();
    crypto_key_t *ekp   = NULL;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    char *buffer_VERIFY_h = "2003003e00ff000000001880d03a002c197f0b00040024008471fc3ad5b1c36ad56bd5a5432315cdab008675c0"
                            "6302465bc6d5091a29957eebed35c00a6ed8";
    // TRUTH PDU
    char *buffer_TRUTH_RESPONSE_h =
        "0880D03A0068197F0B008402E00084000000000000000000000001D8EAA795AFFAA0E951BB6CF0116192E16B1977D6723E92E01123CCEF"
        "548E2885008600000000000000000000000275C47F30CA26E64AF30C19EBFFE0B314849133E138AC65BC2806E520A90C96A8";

    uint8_t *buffer_nist_key_b, *buffer_VERIFY_b, *buffer_TRUTH_RESPONSE_b     = NULL;
    int      buffer_nist_key_len, buffer_VERIFY_len, buffer_TRUTH_RESPONSE_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame = {0};

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;

    // Activate SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->ecs_len   = 0;
    test_association->ecs       = CRYPTO_CIPHER_NONE;
    test_association->est       = 0;
    test_association->ast       = 0;
    test_association->shsnf_len = 2;
    test_association->arsn_len  = 2;
    test_association->arsnw_len = 1;
    test_association->arsnw     = 5;
    test_association->shivf_len = 0;
    test_association->iv_len    = 0;
    test_association->gvcid_blk.scid = 0;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert frames that will be processed
    hex_conversion(buffer_VERIFY_h, (char **)&buffer_VERIFY_b, &buffer_VERIFY_len);

    hex_conversion(buffer_TRUTH_RESPONSE_h, (char **)&buffer_TRUTH_RESPONSE_b, &buffer_TRUTH_RESPONSE_len);

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_VERIFY_b, &buffer_VERIFY_len, &tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
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

    // Let's compare everything. All should match
    for (int i = 0; i < reply_length; i++)
    {
        ASSERT_EQ(buffer_TRUTH_RESPONSE_b[i], sdls_ep_reply_local[i]);
        ASSERT_EQ(buffer_TRUTH_RESPONSE_b[i], sdls_ep_reply[i]);
    }

    Crypto_Shutdown();
    free(buffer_nist_key_b);
    free(buffer_VERIFY_b);
}

/*
** Test that an OTAR attempt with non-active Master Key will bubble up to a top-level error. 
*/
UTEST(EP_KEY_MGMT, OTAR_0_140_142_MK_NOT_ACTIVE)
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

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    // crypto_key_t* ekp = NULL;
    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    // char* buffer_nist_iv_h = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    char *buffer_OTAR_h =
        "2003009e00ff000000001880d037008c197f0b00010084007F344892bbc54f5395297d4c37172f2a3c46f6a81c1349e9e26ac80985d8bb"
        "d55a5814c662e49fba52f99ba09558cd21cf268b8e50b2184137e80f76122034c580464e2f06d2659a50508bdfe9e9a55990ba4148af89"
        "6d8a6eebe8b5d2258685d4ce217a20174fdd4f0efac62758c51b04e55710a47209c923b641d19a39001f9e986366f5ffd95555";
    //                    |2003009e00| = Primary Header
    //                              |ff| = Ext. Procs
    //                                |0000| = SPI
    //                                    |0000| = ARSN
    //                                        |1880| = CryptoLib App ID
    //                                            |d037| = seq, pktid
    //                                                |008c| = pkt_length
    //                                                    |197f| = pusv, ack, st
    //                                                        |0b| = sst, sid, spare
    //                                                          |0001| = PDU Tag
    //                                                              |0084| = PDU Length
    //                                                                  |007F| = Master Key ID - Valid id, invalid that it isn't set up in the keyring!
    //                                                                      |344892bbc54f5395297d4c37| = IV
    //                                                                                              |172f| = Encrypted
    //                                                                                              Key ID
    //                                                                                                  |2a3c46f6a81c1349e9e26ac80985d8bbd55a5814c662e49fba52f99ba09558cd|
    //                                                                                                  = Encrypted Key
    //                                                                                                                                                                  |21cf| = Encrypted Key ID
    //                                                                                                                                                                      |268b8e50b2184137e80f76122034c580464e2f06d2659a50508bdfe9e9a55990| = Encrypted Key
    //                                                                                                                                                                                                                                      |ba41| = EKID
    //                                                                                                                                                                                                                                          |48af896d8a6eebe8b5d2258685d4ce217a20174fdd4f0efac62758c51b04e557| = EK
    //                                                                                                                                                                                                                                                                                                          |10a47209c923b641d19a39001f9e9861| = MAC
    //                                                                                                                                                                                                                                                                                                                                          |66f5ffd95555| = Trailer or Padding???

    uint8_t *buffer_nist_key_b, *buffer_OTAR_b    = NULL;
    int      buffer_nist_key_len, buffer_OTAR_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Activate SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->ecs_len   = 1;
    test_association->ecs       = CRYPTO_CIPHER_NONE;
    test_association->est       = 0;
    test_association->ast       = 0;
    test_association->shsnf_len = 2;
    test_association->arsn_len  = 2;
    test_association->arsnw     = 5;
    test_association->iv_len    = 0;
    test_association->shivf_len = 0;
    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    // ekp = key_if->get_key(test_association->ekid);
    // memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert frames that will be processed
    hex_conversion(buffer_OTAR_h, (char **)&buffer_OTAR_b, &buffer_OTAR_len);
    // Convert/Set input IV
    // hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    // memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_OTAR_b, &buffer_OTAR_len, &tc_nist_processed_frame);
    // Not sure where it'll fail yet, but shouldn't be a success
    ASSERT_NE(CRYPTO_LIB_SUCCESS, status);
    printf("\n");
    Crypto_Shutdown();
    // free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_OTAR_b);
}

/*
** Test that a fail OTAR key decryption will bubble up to a top-level error. 
*/
UTEST(EP_KEY_MGMT, OTAR_0_140_142_BAD_DECRYPT)
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

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_1_Managed_Parameters = {
        0, 0x0003, 1, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_1_Managed_Parameters);

    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    crypto_key_t* ekp = NULL;
    int status = CRYPTO_LIB_SUCCESS;

    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    // char* buffer_nist_iv_h = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    char *buffer_OTAR_h =
        "2003009e00ff000000001880d037008c197f0b00010084007F344892bbc54f5395297d4c37172f2a3c46f6a81c1349e9e26ac80985d8bb"
        "d55a5814c662e49fba52f99ba09558cd21cf268b8e50b2184137e80f76122034c580464e2f06d2659a50508bdfe9e9a55990ba4148af89"
        "6d8a6eebe8b5d2258685d4ce217a20174fdd4f0efac62758c51b04e55710a47209c923b641d19a39001f9e986366f5ffd95555";
    //                    |2003009e00| = Primary Header
    //                              |ff| = Ext. Procs
    //                                |0000| = SPI
    //                                    |0000| = ARSN
    //                                        |1880| = CryptoLib App ID
    //                                            |d037| = seq, pktid
    //                                                |008c| = pkt_length
    //                                                    |197f| = pusv, ack, st
    //                                                        |0b| = sst, sid, spare
    //                                                          |0001| = PDU Tag
    //                                                              |0084| = PDU Length
    //                                                                  |007F| = Master Key ID - Valid id, invalid that it isn't set up in the keyring!
    //                                                                      |344892bbc54f5395297d4c37| = IV
    //                                                                                              |172f| = Encrypted
    //                                                                                              Key ID
    //                                                                                                  |2a3c46f6a81c1349e9e26ac80985d8bbd55a5814c662e49fba52f99ba09558cd|
    //                                                                                                  = Encrypted Key
    //                                                                                                                                                                  |21cf| = Encrypted Key ID
    //                                                                                                                                                                      |268b8e50b2184137e80f76122034c580464e2f06d2659a50508bdfe9e9a55990| = Encrypted Key
    //                                                                                                                                                                                                                                      |ba41| = EKID
    //                                                                                                                                                                                                                                          |48af896d8a6eebe8b5d2258685d4ce217a20174fdd4f0efac62758c51b04e557| = EK
    //                                                                                                                                                                                                                                                                                                          |10a47209c923b641d19a39001f9e9861| = MAC
    //                                                                                                                                                                                                                                                                                                                                          |66f5ffd95555| = Trailer or Padding???

    uint8_t *buffer_nist_key_b, *buffer_OTAR_b    = NULL;
    int      buffer_nist_key_len, buffer_OTAR_len = 0;

    // Setup Processed Frame For Decryption
    TC_t tc_nist_processed_frame;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association;

    // Activate SA 0
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->sa_state  = SA_OPERATIONAL;
    test_association->ecs_len   = 1;
    test_association->ecs       = CRYPTO_CIPHER_NONE;
    test_association->est       = 0;
    test_association->ast       = 0;
    test_association->shsnf_len = 2;
    test_association->arsn_len  = 2;
    test_association->arsnw     = 5;
    test_association->iv_len    = 0;
    test_association->shivf_len = 0;
    test_association->ekid      = 127;
    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(test_association->ekid);
    ekp->key_state = KEY_ACTIVE;
    // memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert frames that will be processed
    hex_conversion(buffer_OTAR_h, (char **)&buffer_OTAR_b, &buffer_OTAR_len);
    // Convert/Set input IV
    // hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    // memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_OTAR_b, &buffer_OTAR_len, &tc_nist_processed_frame);
    // Not sure where it'll fail yet, but shouldn't be a success
    ASSERT_NE(CRYPTO_LIB_SUCCESS, status);
    printf("\n");
    Crypto_Shutdown();
    // free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_OTAR_b);
}

UTEST_MAIN();