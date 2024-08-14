#include "ut_ep_key_validation.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"

UTEST(EP_KEY_VALIDATION, OTAR_0_140_142)
{
    remove("sa_save_file.bin");
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    crypto_key_t* ekp = NULL;
    int status = 0;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    char* buffer_nist_iv_h = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    char* buffer_OTAR_h = "2003009e00ff000100001880d037008c197f0b000100840000344892bbc54f5395297d4c37172f2a3c46f6a81c1349e9e26ac80985d8bbd55a5814c662e49fba52f99ba09558cd21cf268b8e50b2184137e80f76122034c580464e2f06d2659a50508bdfe9e9a55990ba4148af896d8a6eebe8b5d2258685d4ce217a20174fdd4f0efac62758c51b04e55710a47209c923b641d19a39001f9e986166f5ffd95555";
    //                    |2003009e00| = Primary Header
    //                              |ff00010000| = ???
    //                                        |1880| = CryptoLib App ID
    //                                            |d037008c197f0b| = ???
    //                                                          |0001| = PDU Tag
    //                                                              |0084| = Length
    //                                                                  |0000| = Master Key ID
    //                                                                      |344892bbc54f5395297d4c37| = IV
    //                                                                                              |172f| = Encrypted Key ID
    //                                                                                                  |2a3c46f6a81c1349e9e26ac80985d8bbd55a5814c662e49fba52f99ba09558cd| = Encrypted Key
    //                                                                                                                                                                  |21cf| = Encrypted Key ID
    //                                                                                                                                                                      |268b8e50b2184137e80f76122034c580464e2f06d2659a50508bdfe9e9a55990| = Encrypted Key
    //                                                                                                                                                                                                                                      |ba41| = EKID
    //                                                                                                                                                                                                                                          |48af896d8a6eebe8b5d2258685d4ce217a20174fdd4f0efac62758c51b04e557| = EK
    //                                                                                                                                                                                                                                                                                                          |10a47209c923b641d19a39001f9e9861| = MAC???
    //                                                                                                                                                                                                                                                                                                                                          |66f5ffd95555| = Trailer???
    
    uint8_t *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_OTAR_b = NULL;
    int buffer_nist_iv_len, buffer_nist_key_len, buffer_OTAR_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;

    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs_len = 1;
    test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->est = 0;
    test_association->ast = 0;
    test_association->shsnf_len = 2;
    test_association->arsn_len = 2;
    test_association->arsnw = 5;
    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert frames that will be processed
    hex_conversion(buffer_OTAR_h, (char**) &buffer_OTAR_b, &buffer_OTAR_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking  next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_OTAR_b, &buffer_OTAR_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    free(ptr_enc_frame);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(tc_nist_processed_frame);
}

UTEST(EP_KEY_VALIDATION, ACTIVATE_141_142)
{
    remove("sa_save_file.bin");
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    crypto_key_t* ekp = NULL;
    int status = 0;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    char* buffer_nist_iv_h = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    // char* buffer_ACTIVATE_h = "2003001e00ff000100001880d038000c197f0b00020004008d008e82ebe4fc55555555";
    char* buffer_ACTIVATE_h = "2003001e0000000100001880d038000c197f0b00020004008d008e82ebe4fc55555555";
    //                        |2003001e00| = Primary Header
    //                                  |ff| = SPI
    //                                    |00010000| = Security Header or Sequence #???
    //                                            |1880| = CryptoLib App ID
    //                                                |d038000c197f0b00| = ???
    //                                                |d| = seq/start of pktid
    //                                                 |038| = end of pktid
    //                                                    |000c| = pkt_length
    //                                                        |197f0b00| = PUS Header
    //                                                                |02| = PDU Tag
    //                                                                  |0004| = Length
    //                                                                      |008d| = Key ID
    //                                                                          |008e| = Key ID
    //                                                                              |82ebe4fc55555555| = Trailer???
    
    uint8_t *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_ACTIVATE_b = NULL;
    int buffer_nist_iv_len, buffer_nist_key_len, buffer_ACTIVATE_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;

    // Activate SA 9
    sa_if->sa_get_from_spi(0, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs_len = 1;
    test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    test_association->est = 1;
    test_association->ast = 1;
    test_association->shsnf_len = 2;
    test_association->arsn_len = 2;
    test_association->arsnw = 5;
    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert frames that will be processed
    hex_conversion(buffer_ACTIVATE_h, (char**) &buffer_ACTIVATE_b, &buffer_ACTIVATE_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking  next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_ACTIVATE_b, &buffer_ACTIVATE_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    free(ptr_enc_frame);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(tc_nist_processed_frame);
}

UTEST(EP_KEY_VALIDATION, DEACTIVATE_142)
{
    remove("sa_save_file.bin");
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    crypto_key_t* ekp = NULL;
    int status = 0;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    char* buffer_nist_iv_h = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    char* buffer_DEACTIVATE_h = "2003001c00ff000100001880d039000a197f0b00030002008e1f6d21c4555555555555";
    //                          |2003001c00| = Primary Header
    //                                    |ff| = SPI
    //                                      |00010000| = ???
    //                                              |1880| = CryptoLib App ID
    //                                                  |d039000a197f0b| = ???
    //                                                                |0003| = PDU Tag
    //                                                                    |0002| = Length
    //                                                                        |008e| = Key ID
    //                                                                            |1f6d82ebe4fc55555555| = Trailer???
    
    uint8_t *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_DEACTIVATE_b = NULL;
    int buffer_nist_iv_len, buffer_nist_key_len, buffer_DEACTIVATE_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;

    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs_len = 1;
    test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->est = 0;
    test_association->ast = 0;
    test_association->shsnf_len = 2;
    test_association->arsn_len = 2;
    test_association->arsnw = 5;
    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert frames that will be processed
    hex_conversion(buffer_DEACTIVATE_h, (char**) &buffer_DEACTIVATE_b, &buffer_DEACTIVATE_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking  next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_DEACTIVATE_b, &buffer_DEACTIVATE_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    free(ptr_enc_frame);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(tc_nist_processed_frame);
}

UTEST(EP_KEY_VALIDATION, VERIFY_132_134)
{
    remove("sa_save_file.bin");
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, 
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_FALSE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    Crypto_Init();
    SaInterface sa_if = get_sa_interface_inmemory();
    crypto_key_t* ekp = NULL;
    int status = 0;

    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";
    char* buffer_nist_iv_h = "b6ac8e4963f49207ffd6374b"; // The last valid IV that was seen by the SA
    char* buffer_VERIFY_h = "2003003e00ff000100001880d03a002c197f0b00040024008471fc3ad5b1c36ad56bd5a5432315cdab008675c06302465bc6d5091a29957eebed35c00a6ed8";
    //                      |2003003e00| = Primary Header
    //                                |ff| = SPI
    //                                  |00010000| = Security header
    //                                          |1880| = CryptoLib App ID
    //                                              |d03a002c197f0b| = ???
    //                                                            |0004| = PDU Tag
    //                                                                |0024| = Length
    //                                                                    |0084| = Key ID
    //                                                                        |71fc3ad5b1c36ad56bd5a543| = IV
    //                                                                                                |2315cdab008675c06302465bc6d5091a| = ENC Challenge
    //                                                                                                                                |
    
    uint8_t *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_VERIFY_b = NULL;
    int buffer_nist_iv_len, buffer_nist_key_len, buffer_VERIFY_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association;

    // Deactivate SA 1
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;

    // Activate SA 9
    sa_if->sa_get_from_spi(9, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs_len = 1;
    test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->est = 0;
    test_association->ast = 0;
    test_association->shsnf_len = 2;
    test_association->arsn_len = 2;
    test_association->arsnw = 5;
    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    ekp = key_if->get_key(test_association->ekid);
    memcpy(ekp->value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert frames that will be processed
    hex_conversion(buffer_VERIFY_h, (char**) &buffer_VERIFY_b, &buffer_VERIFY_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);

    // Expect success on next valid IV && ARSN
    printf(KGRN "Checking  next valid IV && valid ARSN... should be able to receive it... \n" RESET);
    status = Crypto_TC_ProcessSecurity(buffer_VERIFY_b, &buffer_VERIFY_len, tc_nist_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("\n");
    Crypto_Shutdown();
    free(ptr_enc_frame);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(tc_nist_processed_frame);
}

UTEST_MAIN();