/* Copyright (C) 2009 - 2017 National Aeronautics and Space Administration.
   All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including,
   but not limited to, any warranty that the software will conform to, specifications any implied warranties of
   merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty that the
   documentation will conform to the program, or any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
   consequential damages, arising out of, resulting from, or in any way connected with the software or its
   documentation.  Whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was
   sustained from, or arose out of the results of, or use of, the software, documentation or services provided hereunder

   ITC Team
   NASA IV&V
   ivv-itc@lists.nasa.gov
*/

/**
 *  Unit Tests that macke use of TC_ApplySecurity function on the data.
 *  These tests will require Python3, as well as the pycryptodome module to be installed.
 */

#include "et_dt_validation.h"
#include "utest.h"
#include <Python.h>

#include "crypto_error.h"
#include "sadb_routine.h"

// Setup for some Unit Tests using a Python Script to Verify validiy of frames
PyObject *pName, *pModule, *pDict, *pFunc, *pValue, *pArgs, *pClass, *pInstance;

/**
 * @brief Python Teardown
 * Used to dereference variables and free memory used during the python truth baseline process.
 * Must be called or tests could cause memory leaks, and erroneous data.
 **/
int EndPython()
{
    Py_XDECREF(pInstance);
    Py_XDECREF(pValue);
    Py_XDECREF(pModule);
    Py_XDECREF(pName);
    Py_Finalize();
    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Python Setup
 * Sets up the use of python encryption class within CTests
 **/
void setup_python()
{
    Py_Initialize();
    PyRun_SimpleString("import sys\nsys.path.append('../test')");
    PyRun_SimpleString("import sys\nsys.path.append('../../test')");
    pName = PyUnicode_FromString("encryption_test");
    pModule = PyImport_Import(pName);
    if (pModule == NULL)
    {
        printf("ERROR, NO MODULE FOUND\n");
        EndPython();
        return;
    }

    pDict = PyModule_GetDict(pModule);
    pClass = PyDict_GetItemString(pDict, "Encryption");

    if (PyCallable_Check(pClass))
    {
        pInstance = PyObject_CallObject(pClass, NULL);
    }
    else
    {
        printf("ERROR, NO CLASS INSTANCE FOUND\n");
        EndPython();
        return;
    }
}

/**
 * @brief Python Cryptodoem CMAC Truth Baseline
 * @param data Hexstring of the plain text
 * @param key Hexstring of the key to be used
 * @param expected Output character array that will be allocated within this function.  Memory must be freed upon completion of the test
 * @param expected_length The length of the expected character array this is set within this function
 * @note User must free memory themselves.
 **/
void python_cmac(char* data, char* key, uint8_t** expected, long *expected_length)
{
    setup_python();

    pValue = PyObject_CallMethod(pInstance, "encrypt_cmac", "ss", data, key);
    pValue = PyObject_CallMethod(pInstance, "get_len", NULL);
    long temp_length = PyLong_AsLong(pValue);
    *expected_length = temp_length;
    pValue = PyObject_CallMethod(pInstance, "get_results", NULL);
    char* temp_expected = PyBytes_AsString(pValue);
    *expected = (uint8_t* )malloc(sizeof(uint8_t) * (int)*expected_length);
    memcpy(*expected, temp_expected, (int)*expected_length);
    return;
}

/**
 * @brief Python Cryptodome Truth Baseline
 * Used to generate truth data for Authorized Encryption.  Results are compared against TC_ApplySecurity Functionality,
 * as well as in reverse using the TC_ProcessSecurity function.
 * @param data Hexstring of the plain text to be encrypted
 * @param key Hexstring of the key to be used during encryption
 * @param iv Hextring of the IV to be used during encryption
 * @param header Hextring of the header (AAD) that will be used during encryption
 * @param bitmask Hexstring of the bitmask that will be used on the header
 * @param expected Ouput character array that will be allocated within this function.  Memory must be freed upon
 *completion of test.
 * @param expected_length The length of the expected character array that is set within this function
 * @note The char** expected that is passsed to this function must be freed by the user upon completion of unit test or
 *other call.
 **/
void python_auth_encryption(char* data, char* key, char* iv, char* header, char* bitmask, uint8_t** expected,
                            long *expected_length)
{
    setup_python();
    pValue = PyObject_CallMethod(pInstance, "encrypt", "sssss", data, key, iv, header, bitmask);

    pValue = PyObject_CallMethod(pInstance, "get_len", NULL);
    long temp_length = PyLong_AsLong(pValue);
    *expected_length = temp_length;
    pValue = PyObject_CallMethod(pInstance, "get_results", NULL);
    char* temp_expected = PyBytes_AsString(pValue);
    *expected = (uint8_t* )malloc(sizeof(uint8_t) * (int)*expected_length);
    memcpy(*expected, temp_expected, (int)*expected_length);
    return;
}

/**
 * @brief Validation Test: Authorized Encryption using Python Truth Data
 * Utilizes the python_auth_encryption(uint8_t* data, uint8_t* key, uint8_t* iv, uint8_t* header, uint8_t* bitmask,
 *uint8_t** expected, long* expected_length) function to create baseline truth data.  This data is then compared against
 *the generated tag and cipher text that is generated by the Crypto_TC_ApplySecurity(const uint8_t* p_in_frame, const
 *uint16_t in_frame_length, uint8_t** pp_in_frame, uint16_t* p_enc_frame_len) function, as well as the FECF.
 **/
UTEST(ET_VALIDATION, AUTH_ENCRYPTION_TEST)
{
    // Setup & Initialize CryptoLib
    Crypto_Init_Unit_Test();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    uint8_t* expected = NULL;
    long expected_length = 0;

    char* activate_sa4_h = "2003002000ff000100011880d2c9000e197f0b001b0004000400003040d95ecbc2";
    char* enc_test_ping_h = "2003041600ff1880d2ca0008197f0b0031000039c5082d";
    char* previous_iv_h = "";

    uint8_t* activate_sa4_b, *enc_test_ping_b, *buffer_previous_iv_b = NULL;
    int activate_sa4_len, enc_test_ping_len = 0;

    buffer_previous_iv_b = buffer_previous_iv_b;
    previous_iv_h = previous_iv_h;

    hex_conversion(activate_sa4_h, (char**) &activate_sa4_b, &activate_sa4_len);
    hex_conversion(enc_test_ping_h, (char**) &enc_test_ping_b, &enc_test_ping_len);
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t return_val = -1;
    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));
    // Default SA
    // Expose SA 1 for testing
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    // Ensure that Process Security can activate SA 4
    return_val = Crypto_TC_ProcessSecurity(activate_sa4_b, &activate_sa4_len, tc_sdls_processed_frame);
    //printf("Verifying TC_Process Return Value\n");
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    // Deactive SA 1
    test_association->sa_state = SA_NONE;
    // Expose SA 4 for testing
    sadb_routine->sadb_get_sa_from_spi(4, &test_association);
    test_association->arsn_len = 0;
    test_association->gvcid_tc_blk.vcid = 1;
    test_association->iv[11] = 1;
    test_association->ast = 1;
    test_association->est = 1;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    return_val = Crypto_TC_ApplySecurity(enc_test_ping_b, enc_test_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    // Get Truth Baseline
    python_auth_encryption("1880d2ca0008197f0b0031000039c5",
                           "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210",
                           "000000000000000000000001", "2003043400FF0004", "00", &expected, &expected_length);

    for (int i = 0; i < expected_length; i++)
    {
        //printf("[%d]: %02x -> %02x \n", i, expected[i], ptr_enc_frame[i]);
        ASSERT_EQ(expected[i], ptr_enc_frame[i]);
    }
    Crypto_Shutdown();
    // sadb_routine->sadb_close();
    free(activate_sa4_b);
    free(enc_test_ping_b);
    free(ptr_enc_frame);
    free(expected);
    // free(test_association->ecs);
    free(tc_sdls_processed_frame);
    EndPython();
}

/**
 * @brief Validation Test: Authorized Decryption
 * Makes use of truth data created from the previous AUTH_ENCRYPTION_TEST, to validate that Crypto_TC_ProcessSecurity(
 *uint8_t* ingest, int* len_ingest,TC_t* tc_sdls_processed_frame) properly decrypts data and returns it to the intial
 *truth data created by the python_auth_encryption(uint8_t* data, uint8_t* key, uint8_t* iv, uint8_t* header, uint8_t*
 *bitmask, uint8_t** expected, long* expected_length) function.
 **/
UTEST(DT_VALIDATION, AUTH_DECRYPTION_TEST)
{
    // Setup & Initialize CryptoLib
    Crypto_Init_Unit_Test();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    char* activate_sa4_h = "2003002000ff000100011880d2c9000e197f0b001b0004000400003040d95ecbc2";
    char* dec_test_ping_h =
        "2003043400FF00040000000000000000000000017E1D8EEA8D45CEBA17888E0CDCD747DC78E5F372F997F2A63AA5DFC168395DC987";
    char* enc_test_ping_h = "1880d2ca0008197f0b0031000039c5";

    uint8_t* activate_sa4_b, *dec_test_ping_b, *enc_test_ping_b = NULL;
    int activate_sa4_len, dec_test_ping_len, enc_test_ping_len = 0;

    hex_conversion(activate_sa4_h, (char**) &activate_sa4_b, &activate_sa4_len);
    hex_conversion(dec_test_ping_h, (char**) &dec_test_ping_b, &dec_test_ping_len);
    hex_conversion(enc_test_ping_h, (char**) &enc_test_ping_b, &enc_test_ping_len);

    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));

    int32_t return_val = -1;

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));

    // Default SA
    // Expose SA 1 for testing
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;

    // Ensure that Process Security can activate SA 4
    return_val = Crypto_TC_ProcessSecurity(activate_sa4_b, &activate_sa4_len, tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    // Deactive SA 1
    test_association->sa_state = SA_NONE;

    // Expose SA 4 for testing
    sadb_routine->sadb_get_sa_from_spi(4, &test_association);
    test_association->arsn_len = 0;
    test_association->gvcid_tc_blk.vcid = 1;
    test_association->iv = calloc(1, test_association->shivf_len * sizeof(uint8_t));
    test_association->iv[11] = 0;
    test_association->ast = 1;
    test_association->est = 1;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    return_val = Crypto_TC_ProcessSecurity(dec_test_ping_b, &dec_test_ping_len, tc_sdls_processed_frame);
    ASSERT_EQ(9, return_val); // 9 is the number of pings in that EP PDU.

    Crypto_Shutdown();

    // printf("PDU:\n\t");
    // for (int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    // {
    //     printf("%02x", enc_test_ping_b[i]);
    // }
    // printf("\nPF PDU:\n\t");
    // for (int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    // {
    //     printf("%02x", tc_sdls_processed_frame->tc_pdu[i]);
    // }
    // printf("\n");
    for (int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(enc_test_ping_b[i], tc_sdls_processed_frame->tc_pdu[i]);
    }

    free(activate_sa4_b);
    free(dec_test_ping_b);
    // free(test_association->ecs);
    free(tc_sdls_processed_frame);
    // sadb_routine->sadb_close();
    EndPython();
}

/**
 * @brief Validation Test: AES-GCM 256 Test Vectors
 * Reference:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 **/
UTEST(NIST_ENC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_0)
{
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    // Crypto_Init_Unit_Test();
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "ef9f9284cf599eac3b119905a7d18851e7e374cf63aea04358586b0f757670f8";
    char* buffer_nist_pt_h = "2003001600722ee47da4b77424733546c2d400c4e567a8";
    char* buffer_nist_iv_h = "b6ac8e4963f49207ffd6374c";
    char* buffer_nist_ct_h = "1224dfefb72a20d49e09256908874979";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_ct_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_ct_len, buffer_nist_key_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    test_association->iv = malloc(*buffer_nist_iv_b * sizeof(uint8_t));
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_ct_h, (char**) &buffer_nist_ct_b, &buffer_nist_ct_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_nist_ct_len - 2;
    Crypto_Shutdown();
    for (int i = 0; i < buffer_nist_pt_len - 7; i++)
    {
        //printf("[%d]: %02x -> %02x \n", i, *(ptr_enc_frame + enc_data_idx), buffer_nist_ct_b[i]);
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_nist_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_ct_b);
    free(buffer_nist_key_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: AES-GCM 256 Test Vectors
 * Reference:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 **/
UTEST(NIST_DEC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_0)
{
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "ef9f9284cf599eac3b119905a7d18851e7e374cf63aea04358586b0f757670f8";
    char* buffer_nist_pt_h = "2003001600722ee47da4b77424733546c2d400c4e567a8";
    char* buffer_nist_iv_h = "b6ac8e4963f49207ffd6374b";
    char* buffer_nist_et_h = "2003002500FF0009B6AC8E4963F49207FFD6374C1224DFEFB72A20D49E09256908874979AD6F";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_et_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_et_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;
    test_association->ast =1;
    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    printf("NIST IV LEN: %d\n", buffer_nist_iv_len);
    // Convert input encryptedtext
    hex_conversion(buffer_nist_et_h, (char**) &buffer_nist_et_b, &buffer_nist_et_len);

    Crypto_TC_ProcessSecurity(buffer_nist_et_b, &buffer_nist_et_len, tc_nist_processed_frame);

    Crypto_Shutdown();

    for (int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
        //printf("[%d]: %02x -> %02x \n", i, buffer_nist_pt_b[i + 5], tc_nist_processed_frame->tc_pdu[i]);
        ASSERT_EQ(buffer_nist_pt_b[i + 5], tc_nist_processed_frame->tc_pdu[i]);
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_et_b);
    free(buffer_nist_key_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: AES-GCM 256 Test Vectors
 * Reference:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 **/
UTEST(NIST_ENC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_1)
{
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "e9ccd6eef27f740d1d5c70b187734e11e76a8ac0ad1702ff02180c5c1c9e5399";
    char* buffer_nist_pt_h = "2003001600419635e6e12b257a8ecae411f94480ff56be";
    char* buffer_nist_iv_h = "1af2613c4184dbd101fcedce";
    char* buffer_nist_ct_h = "9cd21f414f1f54d5f6f58b1f2f77e5b6";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_ct_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_ct_len, buffer_nist_key_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_ct_h, (char**) &buffer_nist_ct_b, &buffer_nist_ct_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_nist_ct_len - 2;
    Crypto_Shutdown();
    for (int i = 0; i < buffer_nist_pt_len - 7; i++)
    {
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_nist_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_ct_b);
    free(buffer_nist_key_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: AES-GCM 256 Test Vectors
 * Reference:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 **/
UTEST(NIST_DEC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_1)
{
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "e9ccd6eef27f740d1d5c70b187734e11e76a8ac0ad1702ff02180c5c1c9e5399";
    char* buffer_nist_pt_h = "2003001600419635e6e12b257a8ecae411f94480ff56be";
    char* buffer_nist_iv_h = "1af2613c4184dbd101fcedcd";
    char* buffer_nist_et_h = "2003002500FF00091AF2613C4184DBD101FCEDCE9CD21F414F1F54D5F6F58B1F2F77E5B66987";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_et_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_et_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_et_h, (char**) &buffer_nist_et_b, &buffer_nist_et_len);

    int32_t status;

    status = Crypto_TC_ProcessSecurity(buffer_nist_et_b, &buffer_nist_et_len, tc_nist_processed_frame);
    ASSERT_EQ(0,status);

    Crypto_Shutdown();
    for (int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(buffer_nist_pt_b[i + 5], tc_nist_processed_frame->tc_pdu[i]);
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_et_b);
    free(buffer_nist_key_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: AES-GCM 256 Test Vectors
 * Reference:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 **/
UTEST(NIST_ENC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_2)
{
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "7ecc9dcb3d5b413cadc3af7b7812758bd869295f8aaf611ba9935de76bd87013";
    char* buffer_nist_pt_h = "200300160073d4d7984ce422ac983797c0526ac6f9446b";
    char* buffer_nist_iv_h = "6805be41e983717bf6781052";
    char* buffer_nist_ct_h = "487211dd440f4d09d00bc5c3158a822c";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_ct_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_ct_len, buffer_nist_key_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_ct_h, (char**) &buffer_nist_ct_b, &buffer_nist_ct_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_nist_ct_len - 2;
    Crypto_Shutdown();
    for (int i = 0; i < buffer_nist_pt_len - 7; i++)
    {
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_nist_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_ct_b);
    free(buffer_nist_key_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: AES-GCM 256 Test Vectors
 * Reference:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 **/
UTEST(NIST_DEC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_2)
{
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "7ecc9dcb3d5b413cadc3af7b7812758bd869295f8aaf611ba9935de76bd87013";
    char* buffer_nist_pt_h = "200300160073d4d7984ce422ac983797c0526ac6f9446b";
    char* buffer_nist_iv_h = "6805be41e983717bf6781051";
    char* buffer_nist_et_h = "2003002500FF00096805BE41E983717BF6781052487211DD440F4D09D00BC5C3158A822C46E3";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_et_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_et_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_et_h, (char**) &buffer_nist_et_b, &buffer_nist_et_len);

    Crypto_TC_ProcessSecurity(buffer_nist_et_b, &buffer_nist_et_len, tc_nist_processed_frame);

    Crypto_Shutdown();
    for (int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(buffer_nist_pt_b[i + 5], tc_nist_processed_frame->tc_pdu[i]);
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_et_b);
    free(buffer_nist_key_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: AES-GCM 256 Test Vectors
 * Reference:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 **/
UTEST(NIST_ENC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_3)
{
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "a881373e248615e3d6576f5a5fb68883515ae72d6a2938e3a6f0b8dcb639c9c0";
    char* buffer_nist_pt_h = "200300160007d1dc9930e710b1ebe533c81f671101e43c";
    char* buffer_nist_iv_h = "f0b744f157087df4e41818a9";
    char* buffer_nist_ct_h = "b65a2878b9dddbd4a0204dae6a6a6fc0";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_ct_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_ct_len, buffer_nist_key_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_ct_h, (char**) &buffer_nist_ct_b, &buffer_nist_ct_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_nist_ct_len - 2;
    Crypto_Shutdown();
    for (int i = 0; i < buffer_nist_pt_len - 7; i++)
    {
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_nist_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_ct_b);
    free(buffer_nist_key_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: AES-GCM 256 Test Vectors
 * Reference:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 **/
UTEST(NIST_DEC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_3)
{
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "a881373e248615e3d6576f5a5fb68883515ae72d6a2938e3a6f0b8dcb639c9c0";
    char* buffer_nist_pt_h = "200300160007d1dc9930e710b1ebe533c81f671101e43c";
    char* buffer_nist_iv_h = "f0b744f157087df4e41818a8";
    char* buffer_nist_et_h = "2003002500FF0009F0B744F157087DF4E41818A9B65A2878B9DDDBD4A0204DAE6A6A6FC0C327";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_et_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_et_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_et_h, (char**) &buffer_nist_et_b, &buffer_nist_et_len);

    Crypto_TC_ProcessSecurity(buffer_nist_et_b, &buffer_nist_et_len, tc_nist_processed_frame);

    Crypto_Shutdown();
    for (int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(buffer_nist_pt_b[i + 5], tc_nist_processed_frame->tc_pdu[i]);
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_et_b);
    free(buffer_nist_key_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: AES-GCM 256 Test Vectors
 * Reference:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 **/
UTEST(NIST_ENC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_4)
{
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "84c90349539c2a7989cb24dfae5e4182382ae94ba717d385977017f74f0d87d6";
    char* buffer_nist_pt_h = "200300160031c4e1d0ccece6b7a999bfc31f38559af5dd";
    char* buffer_nist_iv_h = "eeddeaf4355c826dfd153393";
    char* buffer_nist_ct_h = "5c6cfbdd06c19445ecf500c21aeca173";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_ct_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_ct_len, buffer_nist_key_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_ct_h, (char**) &buffer_nist_ct_b, &buffer_nist_ct_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_nist_ct_len - 2;
    Crypto_Shutdown();
    for (int i = 0; i < buffer_nist_pt_len - 7; i++)
    {
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_nist_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_ct_b);
    free(buffer_nist_key_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: AES-GCM 256 Test Vectors
 * Reference:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 **/
UTEST(NIST_DEC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_4)
{
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "84c90349539c2a7989cb24dfae5e4182382ae94ba717d385977017f74f0d87d6";
    char* buffer_nist_pt_h = "200300160031c4e1d0ccece6b7a999bfc31f38559af5dd";
    char* buffer_nist_iv_h = "eeddeaf4355c826dfd153392";
    char* buffer_nist_et_h = "2003002500FF0009EEDDEAF4355C826DFD1533935C6CFBDD06C19445ECF500C21AECA1738A7D";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_et_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_et_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_et_h, (char**) &buffer_nist_et_b, &buffer_nist_et_len);

    Crypto_TC_ProcessSecurity(buffer_nist_et_b, &buffer_nist_et_len, tc_nist_processed_frame);

    Crypto_Shutdown();
    for (int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(buffer_nist_pt_b[i + 5], tc_nist_processed_frame->tc_pdu[i]);
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_et_b);
    free(buffer_nist_key_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: MAC
 * Reference 1:
 *https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'GCM','Hex','Hex',%7B'option':'Hex','string':''%7D)
 * Reference 2:
 *https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
 * Spot check of MAC tags assuming no plaintext payload
 * Accomplished by a multi-step process:
 * 1) Ensure a valid implementation - Utilize Cyberchef's AES Encrypt to re-create a NIST test vector with AAD
 * 2) Generate Truth data - Use same CyberChef settings on a created TF
 * 3) Validate Cryptolib output with CyberChef output
 * Bit Mask of zeros
 * Bit-mask of zeros in this test for a total length of:
 * Header (5) + Segment Hdr (1) + SPI (2) + IV (12)
 * This means zero input to the MAC, which precedes the TF FECF
 **/
UTEST(NIST_ENC_MAC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_0)
{
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223";
    char* buffer_nist_pt_h = "200300060028C2"; // Empty Transfer frame
    char* buffer_nist_iv_h = "d79cf22d504cc793c3fb6c8a";
    char* buffer_nist_aad_h = "b96baa8c1c75a671bfb2d08d06be5f36"; // Zeroed out by abm
    char* buffer_cyber_chef_mac_h = "77e98911a1704df3d9745bc7b97cc66d";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_nist_aad_b,
        *buffer_cyber_chef_mac_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_key_len, buffer_nist_aad_len, buffer_cyber_chef_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arsn_len = 0;
    test_association->shivf_len = 12;
    test_association->abm_len = 1024;
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input aad
    hex_conversion(buffer_nist_aad_h, (char**) &buffer_nist_aad_b, &buffer_nist_aad_len);
    // Convert input mac
    hex_conversion(buffer_cyber_chef_mac_h, (char**) &buffer_cyber_chef_mac_b, &buffer_cyber_chef_mac_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_cyber_chef_mac_len - 2;
    Crypto_Shutdown();
    for (int i = 0; i < buffer_cyber_chef_mac_len; i++)
    {
        // printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_cyber_chef_mac_b[i],
        // *(ptr_enc_frame+enc_data_idx));
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_cyber_chef_mac_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_cyber_chef_mac_b);
    free(buffer_nist_aad_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: MAC
 * Bit Mask of ones
 * Bit-mask of ones in this test on an empty frame for a total length of:
 * Header (5) + Segment Hdr (1) + SPI (2) + IV (12)
 * All bits are unmasked input to the MAC algorithm
 **/
UTEST(NIST_ENC_MAC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_1)
{
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223";
    char* buffer_nist_pt_h = "200300060028C2"; // Empty Transfer frame
    char* buffer_nist_iv_h = "d79cf22d504cc793c3fb6c8a";
    char* buffer_cyber_chef_mac_h = "629c2143c30e2f8450b059cd559a7102";
    uint8_t* buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_cyber_chef_mac_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_key_len, buffer_cyber_chef_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arsn_len = 0;
    test_association->shivf_len = 12;
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input mac
    hex_conversion(buffer_cyber_chef_mac_h, (char**) &buffer_cyber_chef_mac_b, &buffer_cyber_chef_mac_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);

    // Note: For comparison, primarily interested in the MAC
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_cyber_chef_mac_len - 2;
    Crypto_Shutdown();

    for (int i = 0; i < buffer_cyber_chef_mac_len; i++)
    {
        //printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_cyber_chef_mac_b[i],
        //       *(ptr_enc_frame + enc_data_idx));
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_cyber_chef_mac_b[i]);
        enc_data_idx++;
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_cyber_chef_mac_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Validation Test: MAC
 * Bit-mask of ones
 **/
UTEST(NIST_DEC_MAC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_0)
{
    // Setup & Initialize CryptoLib
    int32_t status;
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    char* buffer_nist_key_h = "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223";
    char* buffer_nist_iv_h = "d79cf22d504cc793c3fb6c89";
    char* buffer_cyber_chef_mac_h = "34d0e323f5e4b80426401d4aa37930da";
    char* buffer_nist_pt_h = "722ee47da4b77424733546c2d400c4e5";

    // Create a MAC'd frame by adding our headers and a fecf
    //  |  Header | SPI |           iv          |         plaintext             |             mac               |fecf|
    char* buffer_nist_mac_frame_h =
        "2003003500FF0009D79CF22D504CC793C3FB6C8A722ee47da4b77424733546c2d400c4e534d0e323f5e4b80426401d4aa37930daf55f";

    uint8_t* buffer_nist_iv_b, *buffer_nist_pt_b, *buffer_nist_key_b, *buffer_cyber_chef_mac_b,
        *buffer_nist_mac_frame_b, *buffer_nist_cp_b = NULL;
    int buffer_nist_iv_len, buffer_nist_pt_len, buffer_nist_key_len, buffer_cyber_chef_mac_len,
        buffer_nist_mac_frame_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arsn_len = 0;
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t)));
    test_association->shivf_len = 12;
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);
    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input mac
    hex_conversion(buffer_cyber_chef_mac_h, (char**) &buffer_cyber_chef_mac_b, &buffer_cyber_chef_mac_len);
    // Convert mac frame
    hex_conversion(buffer_nist_mac_frame_h, (char**) &buffer_nist_mac_frame_b, &buffer_nist_mac_frame_len);

    status = Crypto_TC_ProcessSecurity(buffer_nist_mac_frame_b, &buffer_nist_mac_frame_len, tc_nist_processed_frame);
    //printf("TC_Process returned status %d\n", status);

    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
#ifdef DEBUG
         printf("Expected MAC: ");
         for (int i=0; i<buffer_cyber_chef_mac_len; i++)
         {
             printf("%02x ", buffer_cyber_chef_mac_b[i]);
         }
         printf("\nReceived MAC: ");
         for (int i=0; i<test_association->stmacf_len; i++)
         {
             printf("%02x ", tc_nist_processed_frame->tc_sec_trailer.mac[i]);
         }
         printf("\n");
#endif

#ifdef DEBUG
        printf("PDU Length: %d \n",tc_nist_processed_frame->tc_pdu_len);
        printf("Expected PDU: ");
         for (int i=0; i < tc_nist_processed_frame->tc_pdu_len; i++)
         {
             printf("%02x ", buffer_nist_pt_b[i]);
         }
         printf("\nReceived PDU: ");
         for (int i=0; i < tc_nist_processed_frame->tc_pdu_len; i++)
         {
             printf("%02x ", tc_nist_processed_frame->tc_pdu[i]);
         }
         printf("\n");
#endif

    Crypto_Shutdown();
    // Verify the MAC
    for (int i = 0; i < test_association->stmacf_len; i++)
    {
        ASSERT_EQ(tc_nist_processed_frame->tc_sec_trailer.mac[i], buffer_cyber_chef_mac_b[i]);
    }
    for (int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    // Verify the PDU Data is present and not stomped
    {
        ASSERT_EQ(tc_nist_processed_frame->tc_pdu[i], buffer_nist_pt_b[i]);
    }
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_cyber_chef_mac_b);
    free(buffer_nist_mac_frame_b);
    free(buffer_nist_cp_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Unit Test: Bad Data, Fail MAC validation
 **/
UTEST(NIST_DEC_MAC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_0_BAD_DATA)
{
    // Setup & Initialize CryptoLib
    int32_t status;
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    char* buffer_nist_key_h = "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223";
    char* buffer_nist_iv_h = "d79cf22d504cc793c3fb6c89";
    // char* buffer_cyber_chef_mac_h = "99eff39be8327e6950f03a329209d577";
    char* buffer_cyber_chef_mac_h = "34d0e323f5e4b80426401d4aa37930da";
    char* buffer_nist_pt_h = "722ee47da4b77424733546c2d400c4e5";

    // Create a MAC'd frame by adding our headers and a fecf
    //  |  Header | SPI |           iv          |         plaintext             |             mac               |fecf|
    char* buffer_nist_mac_frame_h =
        "2003003500FF0009D79CF22D504CC793C3FB6C8A722ee47da4b77424733546c2d400c40034d0e323f5e4b80426401d4aa37930da123b";

    uint8_t* buffer_nist_iv_b, *buffer_nist_pt_b, *buffer_nist_key_b, *buffer_cyber_chef_mac_b,
        *buffer_nist_mac_frame_b, *buffer_nist_cp_b = NULL;
    int buffer_nist_iv_len, buffer_nist_pt_len, buffer_nist_key_len, buffer_cyber_chef_mac_len,
        buffer_nist_mac_frame_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arsn_len = 0;
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t)));
    test_association->shivf_len = 12;
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input mac
    hex_conversion(buffer_cyber_chef_mac_h, (char**) &buffer_cyber_chef_mac_b, &buffer_cyber_chef_mac_len);
    // Convert mac frame
    hex_conversion(buffer_nist_mac_frame_h, (char**) &buffer_nist_mac_frame_b, &buffer_nist_mac_frame_len);

    status = Crypto_TC_ProcessSecurity(buffer_nist_mac_frame_b, &buffer_nist_mac_frame_len, tc_nist_processed_frame);
    //printf("TC_Process returned status %d\n", status);

    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    // #ifdef DEBUG
    //     printf("Expected MAC: ");
    //     for (int i=0; i<buffer_cyber_chef_mac_len; i++)
    //     {
    //         printf("%02x ", buffer_cyber_chef_mac_b[i]);
    //     }
    //     printf("\nReceived MAC: ");
    //     for (int i=0; i<test_association->stmacf_len; i++)
    //     {
    //         printf("%02x ", tc_nist_processed_frame->tc_sec_trailer.mac[i]);
    //     }
    //     printf("\n");
    // #endif

    Crypto_Shutdown();
    ASSERT_EQ(CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR, status);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_cyber_chef_mac_b);
    free(buffer_nist_mac_frame_b);
    free(buffer_nist_cp_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Unit Test: Bad MAC, Fail MAC validation
 **/
UTEST(NIST_DEC_MAC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_0_BAD_MAC)
{
    // Setup & Initialize CryptoLib
    int32_t status;
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    char* buffer_nist_key_h = "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223";
    char* buffer_nist_iv_h = "d79cf22d504cc793c3fb6c89";
    // char* buffer_cyber_chef_mac_h = "99eff39be8327e6950f03a329209d577";
    char* buffer_cyber_chef_mac_h = "34d0e323f5e4b80426401d4aa37930da";
    char* buffer_nist_pt_h = "722ee47da4b77424733546c2d400c4e5";

    // Create a MAC'd frame by adding our headers and a fecf
    //  |  Header | SPI |           iv          |         plaintext             |             mac               |fecf|
    char* buffer_nist_mac_frame_h =
        "2003003500FF0009D79CF22D504CC793C3FB6C8A722ee47da4b77424733546c2d400c4e534d0e323f5e4b80426401d4aa37930009f68";

    uint8_t* buffer_nist_iv_b, *buffer_nist_pt_b, *buffer_nist_key_b, *buffer_cyber_chef_mac_b,
        *buffer_nist_mac_frame_b, *buffer_nist_cp_b = NULL;
    int buffer_nist_iv_len, buffer_nist_pt_len, buffer_nist_key_len, buffer_cyber_chef_mac_len,
        buffer_nist_mac_frame_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arsn_len = 0;
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t)));
    test_association->shivf_len = 12;
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_AES256_GCM;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, (char**) &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, (char**) &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input mac
    hex_conversion(buffer_cyber_chef_mac_h, (char**) &buffer_cyber_chef_mac_b, &buffer_cyber_chef_mac_len);
    // Convert mac frame
    hex_conversion(buffer_nist_mac_frame_h, (char**) &buffer_nist_mac_frame_b, &buffer_nist_mac_frame_len);

    status = Crypto_TC_ProcessSecurity(buffer_nist_mac_frame_b, &buffer_nist_mac_frame_len, tc_nist_processed_frame);
    //printf("TC_Process returned status %d\n", status);

    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    // #ifdef DEBUG
    //     printf("Expected MAC: ");
    //     for (int i=0; i<buffer_cyber_chef_mac_len; i++)
    //     {
    //         printf("%02x ", buffer_cyber_chef_mac_b[i]);
    //     }
    //     printf("\nReceived MAC: ");
    //     for (int i=0; i<test_association->stmacf_len; i++)
    //     {
    //         printf("%02x ", tc_nist_processed_frame->tc_sec_trailer.mac[i]);
    //     }
    //     printf("\n");
    // #endif

    Crypto_Shutdown();
    ASSERT_EQ(CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR, status);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_cyber_chef_mac_b);
    free(buffer_nist_mac_frame_b);
    free(buffer_nist_cp_b);
    // free(test_association->ecs);
    // sadb_routine->sadb_close();
}

/**
 * @brief Unit Test: Test CMAC, bitmask of 0s
 **/
UTEST(NIST_ENC_CMAC_VALIDATION, AES_CMAC_256_PT_128_TEST_0)
{
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |           NIST CMAC Test Vector                                                                                               |FECF|
    char* buffer_frame_pt_h = "2003004600C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258C925";
    // Python truth string passed below is ZEROed out, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatever the variable mac length to be updated in the header
    //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    // "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"         
    // Python output MAC   
    char* buffer_python_mac_h = "7629961f6b92145290ad3e149940511a";
    uint8_t* buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arsn_len = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn = 0;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0x00, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_CMAC_AES256;
    test_association->ekid = 0;
    test_association->akid = 136;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char**) &buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char**) &buffer_python_mac_b, &buffer_python_mac_len);

    Crypto_TC_ApplySecurity(buffer_frame_pt_b, buffer_frame_pt_len, &ptr_enc_frame, &enc_frame_len);

    // Note: For comparison, primarily interested in the MAC
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_python_mac_len - 2;
    Crypto_Shutdown();

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_python_mac_b[i], *(ptr_enc_frame + enc_data_idx));
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_python_mac_b[i]);
        enc_data_idx++;
    }

    free(ptr_enc_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
    // free(test_association->arsn);
    // sadb_routine->sadb_close();
    // free(test_association);
}

/**
 * @brief Unit Test: Test CMAC, bitmask of 1s
 **/
UTEST(NIST_ENC_CMAC_VALIDATION, AES_CMAC_256_PT_128_TEST_1)
{
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |           NIST CMAC Test Vector                                                                                               |FECF|
    char* buffer_frame_pt_h = "2003004600C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258C925";
    // Python truth string passed below, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatevr the variable mac length to be updated in the header
    //                           | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // char* buffer_frame_pt_h = "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    //                           2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258CF549CC15D63EAB7AD25EB3089D94E6C2D9D
    // Python output MAC   
    char* buffer_python_mac_h = "cf549cc15d63eab7ad25eb3089d94e6c";
    uint8_t* buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arsn_len = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn = 0;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_CMAC_AES256;
    test_association->ekid = 0;
    test_association->akid = 136;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char**) &buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char**) &buffer_python_mac_b, &buffer_python_mac_len);

    int status = Crypto_TC_ApplySecurity(buffer_frame_pt_b, buffer_frame_pt_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    // Note: For comparison, primarily interested in the MAC
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_python_mac_len - 2;
    Crypto_Shutdown();

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        // printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_python_mac_b[i], *(ptr_enc_frame + enc_data_idx));
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_python_mac_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
    // free(test_association);
    // sadb_routine->sadb_close();
}

/**
 * @brief Unit Test: Test CMAC, bitmask of 0s
 **/
UTEST(NIST_DEC_CMAC_VALIDATION, AES_CMAC_256_PT_128_TEST_0)
{
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        | Header  |SPI|  ARSN  |           NIST CMAC Test Vector                                                                                               |   MAC                        |FECF|
    char* buffer_frame_pt_h = "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F193942587629961f6b92145290ad3e149940511a46ce";
    // Python truth string passed below, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatevr the variable mac length to be updated in the header
    //                           | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // char* buffer_frame_pt_h = "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    //                           2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258CF549CC15D63EAB7AD25EB3089D94E6C2D9D
    // Zeroed out w. bitmask      000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    // Python output MAC   
    char* buffer_python_mac_h = "7629961f6b92145290ad3e149940511a";
    uint8_t* buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arsn_len = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn = 0;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0x00, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_CMAC_AES256;
    test_association->ekid = 0;
    test_association->akid = 136;

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = calloc(1, sizeof(uint8_t) * TC_SIZE);

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char**) &buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char**) &buffer_python_mac_b, &buffer_python_mac_len);

    int32_t status = Crypto_TC_ProcessSecurity(buffer_frame_pt_b, &buffer_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    // Note: For comparison, primarily interested in the MAC
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_python_mac_len - 2;
    Crypto_Shutdown();

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_python_mac_b[i], (tc_sdls_processed_frame->tc_sec_trailer.mac[i]));
        ASSERT_EQ(tc_sdls_processed_frame->tc_sec_trailer.mac[i], buffer_python_mac_b[i]);
        enc_data_idx++;
    }

    free(tc_sdls_processed_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
    // free(test_association->arsn);
    // free(test_association);
    // sadb_routine->sadb_close();
}

/**
 * @brief Unit Test: Test CMAC, bitmask of 1s
 **/
UTEST(NIST_DEC_CMAC_VALIDATION, AES_CMAC_256_PT_128_TEST_1)
{
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        | Header  |SPI|  ARSN  |           NIST CMAC Test Vector                                                                                               |   MAC                        |FECF|
    char* buffer_frame_pt_h = "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258CF549CC15D63EAB7AD25EB3089D94E6C2D9D";
    // Python truth string passed below, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatevr the variable mac length to be updated in the header
    //                           | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // char* buffer_frame_pt_h = "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    //                           2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258CF549CC15D63EAB7AD25EB3089D94E6C2D9D
    // Python output MAC   
    char* buffer_python_mac_h = "cf549cc15d63eab7ad25eb3089d94e6c";
    uint8_t* buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arsn_len = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_CMAC_AES256;
    test_association->ekid = 0;
    test_association->akid = 136;

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = calloc(1, sizeof(uint8_t) * TC_SIZE);

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char**) &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char**) &buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char**) &buffer_python_mac_b, &buffer_python_mac_len);

    Crypto_TC_ProcessSecurity(buffer_frame_pt_b, &buffer_frame_pt_len, tc_sdls_processed_frame);

    // Note: For comparison, primarily interested in the MAC
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_python_mac_len - 2;
    Crypto_Shutdown();

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_python_mac_b[i], (tc_sdls_processed_frame->tc_sec_trailer.mac[i]));
        ASSERT_EQ(tc_sdls_processed_frame->tc_sec_trailer.mac[i], buffer_python_mac_b[i]);
        enc_data_idx++;
    }

    free(tc_sdls_processed_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
    // free(test_association->arsn);
    // free(test_association);
}

/**
 * @brief Unit Test: Test HMAC SHA-256, bitmask of 0s
 **/
UTEST(NIST_ENC_HMAC_VALIDATION, SHA_256_PT_128_TEST_0)
{
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |           NIST CMAC Test Vector                                                                                               |FECF|
    char *buffer_frame_pt_h = "2003004600C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258C925";
    // Python truth string passed below is ZEROed out, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatever the variable mac length to be updated in the header
    //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    // "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"         
    // Python output MAC   
    // 6b5953e41cffb4d15a62e25da5e092f98bd26b7487f0c98f440374d42e136f13
    // Trunc to first 16 bytes
    // 6b5953e41cffb4d15a62e25da5e092f9
    char* buffer_python_mac_h = "6b5953e41cffb4d15a62e25da5e092f9";
    uint8_t *buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0x00, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_HMAC_SHA256;
    test_association->ekid = 0;
    test_association->akid = 136;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char **)&buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char **)&buffer_python_mac_b, &buffer_python_mac_len);

    int status = Crypto_TC_ApplySecurity(buffer_frame_pt_b, buffer_frame_pt_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    // Note: For comparison, primarily interested in the MAC
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_python_mac_len - 2;
    Crypto_Shutdown();

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x \n", enc_data_idx, buffer_python_mac_b[i], *(ptr_enc_frame + enc_data_idx));
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_python_mac_b[i]);
        enc_data_idx++;
    }

    free(ptr_enc_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
}

/**
 * @brief Unit Test: Test HMAC SHA-256, bitmask of 1s
 **/
UTEST(NIST_ENC_HMAC_VALIDATION, SHA_256_PT_128_TEST_1)
{
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |           NIST CMAC Test Vector                                                                                               |FECF|
    char *buffer_frame_pt_h = "2003004600C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258C925";
    // Python truth string passed below is ZEROed out, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatever the variable mac length to be updated in the header
    //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    // Python output MAC   
    // 5d0ae5c3859d51d9c1e31681db475acba1f2cd1ade8e5ba7356ae9f2372e4444
    // Trunc to first 16 bytes
    // 5d0ae5c3859d51d9c1e31681db475acb
    char* buffer_python_mac_h = "5d0ae5c3859d51d9c1e31681db475acb";
    uint8_t *buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_HMAC_SHA256;
    test_association->ekid = 0;
    test_association->akid = 136;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);
    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char **)&buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char **)&buffer_python_mac_b, &buffer_python_mac_len);

    Crypto_TC_ApplySecurity(buffer_frame_pt_b, buffer_frame_pt_len, &ptr_enc_frame, &enc_frame_len);

    // Note: For comparison, primarily interested in the MAC
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_python_mac_len - 2;
    Crypto_Shutdown();

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_python_mac_b[i], *(ptr_enc_frame + enc_data_idx));
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_python_mac_b[i]);
        enc_data_idx++;
    }

    free(ptr_enc_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
}

/**
 * @brief Unit Test: Test HMAC SHA-512, key length 64 bytes, bitmask of 0s
 **/
UTEST(NIST_ENC_HMAC_VALIDATION, SHA_512_PT_128_TEST_0)
{
   uint8_t *ptr_enc_frame = NULL;
   uint16_t enc_frame_len = 0;
   int32_t status;
   // Setup & Initialize CryptoLib
   Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                           TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                           TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
   Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
   Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
   Crypto_Init();
   SadbRoutine sadb_routine = get_sadb_routine_inmemory();
   crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

   // NIST supplied vectors
   // NOTE: Added Transfer Frame header to the plaintext
   char *buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
   //                        |  Header |           NIST CMAC Test Vector                                                                                               |FECF|
   char *buffer_frame_pt_h = "2003004600C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258C925";
   // Python truth string passed below is ZEROed out, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
   // Length is dependent on whatever the variable mac length to be updated in the header
   //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
   // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
   // "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
   // Python output MAC
   // 676e9ebdf306b7db7ad41892887342e892bcc59688caef44693c1659b6a683e844d584030b7c532105b8c2539e0aed51af6df77e87f1834e92c2085889d1c44b
   // Trunc to first 16 bytes
   // 676e9ebdf306b7db7ad41892887342e8
   char* buffer_python_mac_h = "676e9ebdf306b7db7ad41892887342e8";
   uint8_t *buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
   int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

   // Expose/setup SAs for testing
   SecurityAssociation_t *test_association = NULL;
   test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
   // Deactivate SA 1
   sadb_routine->sadb_get_sa_from_spi(1, &test_association);
   test_association->sa_state = SA_NONE;
   // Activate SA 9
   sadb_routine->sadb_get_sa_from_spi(9, &test_association);
   test_association->ast = 1;
   test_association->est = 0;
   test_association->shivf_len = 0;
   test_association->iv_len = 0;
   test_association->shsnf_len = 4;
   test_association->arsn_len = 4;
   test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
   test_association->abm_len = 1024;
   memset(test_association->abm, 0x00, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
   test_association->stmacf_len = 16;
   test_association->sa_state = SA_OPERATIONAL;
   test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
   *test_association->ecs = CRYPTO_CIPHER_NONE;
   test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
   *test_association->acs = CRYPTO_MAC_HMAC_SHA512;
   test_association->ekid = 0;
   test_association->akid = 136;

   // Insert key into keyring of SA 9
   hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
   memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);
   ek_ring[test_association->akid].key_len = 64;

   // Convert input plaintext
   hex_conversion(buffer_frame_pt_h, (char **)&buffer_frame_pt_b, &buffer_frame_pt_len);
   // Convert input mac
   hex_conversion(buffer_python_mac_h, (char **)&buffer_python_mac_b, &buffer_python_mac_len);

   status = Crypto_TC_ApplySecurity(buffer_frame_pt_b, buffer_frame_pt_len, &ptr_enc_frame, &enc_frame_len);
   ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

   // Note: For comparison, primarily interested in the MAC
   // Calc payload index: total length - pt length
   uint16_t enc_data_idx = enc_frame_len - buffer_python_mac_len - 2;
   Crypto_Shutdown();

   for (int i = 0; i < buffer_python_mac_len; i++)
   {
       printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_python_mac_b[i], *(ptr_enc_frame + enc_data_idx));
       ASSERT_EQ(*(ptr_enc_frame + enc_data_idx), buffer_python_mac_b[i]);
       enc_data_idx++;
   }

   free(ptr_enc_frame);
   free(buffer_frame_pt_b);
   free(buffer_nist_key_b);
   free(buffer_python_mac_b);
}

/**
* @brief Unit Test: Test HMAC SHA-512, key length 64 bytes, bitmask of 1s
**/
UTEST(NIST_ENC_HMAC_VALIDATION, SHA_512_PT_128_TEST_1)
{
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    int32_t status;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |           NIST CMAC Test Vector                                                                                               |FECF|
    char *buffer_frame_pt_h = "2003004600C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258C925";
    // Python truth string passed below, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatever the variable mac length to be updated in the header
    //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    // Python output MAC
    // 907bbd1d9f2fd37e541f0b1ee12f5db0b1e0cbc57cfe08aecfc74b001371db711abb39caf658ee692d418725dc92cabd8d0a93ce423ff7594adf3fd91e7a6435
    // Trunc to first 16 bytes
    // 907bbd1d9f2fd37e541f0b1ee12f5db0
    char* buffer_python_mac_h = "907bbd1d9f2fd37e541f0b1ee12f5db0";
    uint8_t *buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association = calloc(1, sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    test_association->abm = calloc(1, test_association->abm_len * sizeof(uint8_t));
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_HMAC_SHA512;
    test_association->ekid = 0;
    test_association->akid = 136;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);
    ek_ring[test_association->akid].key_len = 64;

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char **)&buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char **)&buffer_python_mac_b, &buffer_python_mac_len);

    status = Crypto_TC_ApplySecurity(buffer_frame_pt_b, buffer_frame_pt_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    // Note: For comparison, primarily interested in the MAC
    // Calc payload index: total length - pt length
    uint16_t enc_data_idx = enc_frame_len - buffer_python_mac_len - 2;
    Crypto_Shutdown();

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_python_mac_b[i], *(ptr_enc_frame + enc_data_idx + i));
        ASSERT_EQ(*(ptr_enc_frame + enc_data_idx + i), buffer_python_mac_b[i]);
        // enc_data_idx++;
    }

    free(ptr_enc_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
}

/**
 * @brief Unit Test: Test HMAC SHA-256, bitmask of 0s
 **/
UTEST(NIST_DEC_HMAC_VALIDATION, SHA_256_PT_128_TEST_0)
{
    int32_t status = 0;
    uint8_t *ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |SPI | arsn   |     Payload                                                                                                                   | SHA 256 HMAC                |FECF|
    char *buffer_frame_pt_h = "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F193942586B5953E41CFFB4D15A62E25DA5E092F969F2";
    // Python truth string passed below is ZEROed out, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatever the variable mac length to be updated in the header
    //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    // "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    // Python output MAC
    // 6b5953e41cffb4d15a62e25da5e092f98bd26b7487f0c98f440374d42e136f13
    // Trunc to first 16 bytes
    // 6b5953e41cffb4d15a62e25da5e092f9
    char* buffer_python_mac_h = "6b5953e41cffb4d15a62e25da5e092f9";
    uint8_t *buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0x00, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_HMAC_SHA256;
    test_association->ekid = 0;
    test_association->akid = 136;

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = calloc(1, sizeof(uint8_t) * TC_SIZE);

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char **)&buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char **)&buffer_python_mac_b, &buffer_python_mac_len);

    status = Crypto_TC_ProcessSecurity(buffer_frame_pt_b, &buffer_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    // Note: For comparison, primarily interested in the MAC

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", i, buffer_python_mac_b[i], *(tc_sdls_processed_frame->tc_sec_trailer.mac + i));
        ASSERT_EQ(*(tc_sdls_processed_frame->tc_sec_trailer.mac + i), buffer_python_mac_b[i]);
    }

    Crypto_Shutdown();

    free(ptr_enc_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
    free(tc_sdls_processed_frame);
}

/**
 * @brief Unit Test: Test HMAC SHA-256, bitmask of 1s
 **/
UTEST(NIST_DEC_HMAC_VALIDATION, SHA_256_PT_128_TEST_1)
{
    int32_t status = 0;
    uint8_t *ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |SPI | arsn   |     Payload                                                                                                                   | SHA 256 HMAC                | FECF|
    char *buffer_frame_pt_h = "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F193942585d0ae5c3859d51d9c1e31681db475acb5b35";
    // Python truth string passed below, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatever the variable mac length to be updated in the header.
    //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    // Python output MAC   
    // 5d0ae5c3859d51d9c1e31681db475acba1f2cd1ade8e5ba7356ae9f2372e4444
    // Trunc to first 16 bytes
    // 5d0ae5c3859d51d9c1e31681db475acb
    char* buffer_python_mac_h = "5d0ae5c3859d51d9c1e31681db475acb";
    uint8_t *buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_HMAC_SHA256;
    test_association->ekid = 0;
    test_association->akid = 136;

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = calloc(1, sizeof(uint8_t) * TC_SIZE);

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char **)&buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char **)&buffer_python_mac_b, &buffer_python_mac_len);

    status = Crypto_TC_ProcessSecurity(buffer_frame_pt_b, &buffer_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    // Note: For comparison, primarily interested in the MAC
    Crypto_Shutdown();

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", i, buffer_python_mac_b[i], *(tc_sdls_processed_frame->tc_sec_trailer.mac + i));
        ASSERT_EQ(*(tc_sdls_processed_frame->tc_sec_trailer.mac + i), buffer_python_mac_b[i]);
    }

    free(ptr_enc_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
    free(tc_sdls_processed_frame);
}

/**
 * @brief Unit Test: Test HMAC SHA-512, keylength of 64 bytes, bitmask of 0s
 **/
UTEST(NIST_DEC_HMAC_VALIDATION, SHA_512_PT_128_TEST_0)
{
    int32_t status = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |SPI | ARSN   |     Payload                                                                                                                   | SHA 512 HMAC                 |FECF|
    char *buffer_frame_pt_h = "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258676e9ebdf306b7db7ad41892887342e80DC5";
    // Python truth string passed below is ZEROed out, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatever the variable mac length to be updated in the header
    //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    // "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    // Python output MAC
    // 676e9ebdf306b7db7ad41892887342e892bcc59688caef44693c1659b6a683e844d584030b7c532105b8c2539e0aed51af6df77e87f1834e92c2085889d1c44b
    // Trunc to first 16 bytes
    // 676e9ebdf306b7db7ad41892887342e8
    char* buffer_python_mac_h = "676e9ebdf306b7db7ad41892887342e8";
    uint8_t *buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0x00, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_HMAC_SHA512;
    test_association->ekid = 0;
    test_association->akid = 136;

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = calloc(1, sizeof(uint8_t) * TC_SIZE);

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);
    ek_ring[test_association->akid].key_len = 64;

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char **)&buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char **)&buffer_python_mac_b, &buffer_python_mac_len);

    status = Crypto_TC_ProcessSecurity(buffer_frame_pt_b, &buffer_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    // Note: For comparison, primarily interested in the MAC
    Crypto_Shutdown();

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", i, buffer_python_mac_b[i], *(tc_sdls_processed_frame->tc_sec_trailer.mac + i));
        ASSERT_EQ(*(tc_sdls_processed_frame->tc_sec_trailer.mac + i), buffer_python_mac_b[i]);
    }

    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
}

/**
 * @brief Unit Test: Test HMAC SHA-512, keylength of 64 bytes, bitmask of 1s
 **/
UTEST(NIST_DEC_HMAC_VALIDATION, SHA_512_PT_128_TEST_1)
{
    int32_t status = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |SPI | ARSN   |     Payload                                                                                                                   | SHA 512 HMAC                 |FECF|
    char *buffer_frame_pt_h = "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258907bbd1d9f2fd37e541f0b1ee12f5db0679a";
    // Python truth string passed below is ZEROed out, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatever the variable mac length to be updated in the header
    //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    // "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    // Python output MAC
    // 907bbd1d9f2fd37e541f0b1ee12f5db0b1e0cbc57cfe08aecfc74b001371db711abb39caf658ee692d418725dc92cabd8d0a93ce423ff7594adf3fd91e7a6435
    // Trunc to first 16 bytes
    // 907bbd1d9f2fd37e541f0b1ee12f5db0b1e0cbc57cfe08aecfc74b001371db711abb39caf658ee692d418725dc92cabd8d0a93ce423ff7594adf3fd91e7a6435
    char* buffer_python_mac_h = "907bbd1d9f2fd37e541f0b1ee12f5db0";
    uint8_t *buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_HMAC_SHA512;
    test_association->ekid = 0;
    test_association->akid = 136;

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = calloc(1, sizeof(uint8_t) * TC_SIZE);

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);
    ek_ring[test_association->akid].key_len = 64;

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char **)&buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char **)&buffer_python_mac_b, &buffer_python_mac_len);

    status = Crypto_TC_ProcessSecurity(buffer_frame_pt_b, &buffer_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    // Note: For comparison, primarily interested in the MAC
    Crypto_Shutdown();

    for (int i = 0; i < buffer_python_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", i, buffer_python_mac_b[i], *(tc_sdls_processed_frame->tc_sec_trailer.mac + i));
        ASSERT_EQ(*(tc_sdls_processed_frame->tc_sec_trailer.mac + i), buffer_python_mac_b[i]);
    }

    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
}

/**
 * @brief Unit Test: Encrypts a frame, then decrypts the output to ensure the reverse doesn't error
 **/
UTEST(PLAINTEXT, ENCRYPT_DECRYPT)
{
    int32_t status = CRYPTO_LIB_ERROR;
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_TRUE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();

    char* jpl_frame_pt_h = "2003001c00ff000100001880d03e000a197f0b000300020093d4ba21c4555555555555";
    uint8_t* jpl_frame_pt_b = NULL;
    int jpl_frame_pt_len = 0;
    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = calloc(1, sizeof(uint8_t) * TC_SIZE);

    // Convert input jpl frame
    hex_conversion(jpl_frame_pt_h, (char**) &jpl_frame_pt_b, &jpl_frame_pt_len);

    // Apply, save the generated frame
    status = Crypto_TC_ApplySecurity(jpl_frame_pt_b, jpl_frame_pt_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);
    
    // Process the generated frame
    int len = (int)enc_frame_len;
    status = Crypto_TC_ProcessSecurity(ptr_enc_frame, &len, tc_sdls_processed_frame);
    Crypto_Shutdown();
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);
}

/**
 * @brief Unit Test: Test HMAC SHA-512, encryption key length too short
 * Supply a 32-byte key when SHA512 requires a 64-byte key
 **/
UTEST(NIST_ENC_HMAC_VALIDATION, SHA_512_SHORT_KEY)
{
    int32_t status = 0;
    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |           NIST CMAC Test Vector                                                                                               |FECF|
    char *buffer_frame_pt_h = "2003004600C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258C925";
    // Python truth string passed below is ZEROed out, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatever the variable mac length to be updated in the header
    //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    // Python output MAC   
    // 75c570016a9458a71cea6aaca6ff46971ea007ed0a84e97fd2df79f6634c3efbb62edef3d1fb6549d0c9319e2d1dea866f634f67a2006c435b5bd2a3dd314fef
    // Trunc to first 16 bytes
    // 75c570016a9458a71cea6aaca6ff4697
    char* buffer_python_mac_h = "75c570016a9458a71cea6aaca6ff4697";
    uint8_t *buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_HMAC_SHA512;
    test_association->ekid = 0;
    test_association->akid = 136;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);
    ek_ring[test_association->akid].key_len = 32;

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char **)&buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char **)&buffer_python_mac_b, &buffer_python_mac_len);

    status = Crypto_TC_ApplySecurity(buffer_frame_pt_b, buffer_frame_pt_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(status, CRYPTO_LIB_ERR_KEY_LENGTH_ERROR);

    Crypto_Shutdown();

    free(ptr_enc_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
}

/**
 * @brief Unit Test: Test HMAC SHA-512, decryption key too short for algorithm
 **/
UTEST(NIST_DEC_HMAC_VALIDATION, SHA_512_SHORT_KEY)
{
    int32_t status = 0;
    uint8_t *ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();

    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "b228c753292acd5df351000a591bf960d8555c3f6284afe7c6846cbb6c6f5445";
    //                        |  Header |SPI | arsn   |     Payload                                                                                                                   | SHA 512 HMAC                 |FECF|
    char *buffer_frame_pt_h = "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F1939425875c570016a9458a71cea6aaca6ff46970f67";
    // Python truth string passed below, not including a MAC or FECF which isn't hashed against, but the LENGTH (including fecf) needs to be updated in the Tf Header
    // Length is dependent on whatever the variable mac length to be updated in the header
    //  | Header |SPI|  ARSN  | NIST CMAC Frame Data                                                                                                         |
    // "2003005C00000900000000C66D322247EBF272E6A353F9940B00847CF78E27F2BC0C81A696DB411E47C0E9630137D3FA860A71158E23D80B699E8006E52345FB7273B2E084407F19394258";
    // Python output MAC   
    // 75c570016a9458a71cea6aaca6ff46971ea007ed0a84e97fd2df79f6634c3efbb62edef3d1fb6549d0c9319e2d1dea866f634f67a2006c435b5bd2a3dd314fef
    // Trunc to first 16 bytes
    // 75c570016a9458a71cea6aaca6ff4697
    char* buffer_python_mac_h = "75c570016a9458a71cea6aaca6ff4697";
    uint8_t *buffer_frame_pt_b, *buffer_nist_key_b, *buffer_python_mac_b = NULL;
    int buffer_frame_pt_len, buffer_nist_key_len, buffer_python_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t *test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->shivf_len = 0;
    test_association->iv_len = 0;
    test_association->shsnf_len = 4;
    test_association->arsn_len = 4;
    test_association->arsn = calloc(1, test_association->arsn_len * sizeof(uint8_t));
    test_association->abm_len = 1024;
    memset(test_association->abm, 0xFF, (test_association->abm_len * sizeof(uint8_t))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_CIPHER_NONE;
    test_association->acs = calloc(1, test_association->acs_len * sizeof(uint8_t));
    *test_association->acs = CRYPTO_MAC_HMAC_SHA512;
    test_association->ekid = 0;
    test_association->akid = 136;

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = calloc(1, sizeof(uint8_t) * TC_SIZE);

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, (char **)&buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->akid].value, buffer_nist_key_b, buffer_nist_key_len);
    ek_ring[test_association->akid].key_len = 32;

    // Convert input plaintext
    hex_conversion(buffer_frame_pt_h, (char **)&buffer_frame_pt_b, &buffer_frame_pt_len);
    // Convert input mac
    hex_conversion(buffer_python_mac_h, (char **)&buffer_python_mac_b, &buffer_python_mac_len);

    status = Crypto_TC_ProcessSecurity(buffer_frame_pt_b, &buffer_frame_pt_len, tc_sdls_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_KEY_LENGTH_ERROR, status);

    free(ptr_enc_frame);
    free(buffer_frame_pt_b);
    free(buffer_nist_key_b);
    free(buffer_python_mac_b);
    free(tc_sdls_processed_frame);
}

UTEST_MAIN();