/* Copyright (C) 2009 - 2017 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
   limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
   any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
   arising out of, resulting from, or in any way connected with the software or its documentation.  Whether or not based upon warranty,
   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
   documentation or services provided hereunder

   ITC Team
   NASA IV&V
   ivv-itc@lists.nasa.gov
*/

/*
 *  Unit Tests that macke use of TC_ApplySecurity function on the data.
 */

#include "et_dt_validation.h"
#include "utest.h"
#include <python3.8/Python.h>

#include "sadb_routine.h"
#include "crypto_error.h"


// Setup for some Unit Tests using a Python Script to Verify validiy of frames
PyObject *pName, *pModule, *pDict, *pFunc, *pValue, *pArgs, *pClass, *pInstance;
int EndPython()
{
    Py_XDECREF(pInstance);
    Py_XDECREF(pValue);
    Py_XDECREF(pModule);
    Py_XDECREF(pName);
    Py_Finalize();
}

void python_auth_encryption(char* data, char* key, char* iv, char* header, char* bitmask, uint8** expected, long* expected_length)
{
    Py_Initialize();
    PyRun_SimpleString("import sys\nsys.path.append('../../python')");

    pName = PyUnicode_FromString("encryption_test");
    pModule = PyImport_Import(pName);
    if(pModule == NULL)
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

    pValue = PyObject_CallMethod(pInstance, "encrypt", "sssss", data, key, iv, header, bitmask);

    pValue = PyObject_CallMethod(pInstance, "get_len", NULL);
    long temp_length = PyLong_AsLong(pValue);
    *expected_length = temp_length;
    pValue = PyObject_CallMethod(pInstance, "get_results", NULL);
    char* temp_expected = PyBytes_AsString(pValue);
    *expected= (uint8*)malloc(sizeof(uint8) * (int)*expected_length);
    memcpy(*expected, temp_expected, (int)*expected_length);
    return;
}

// Test by utilizing python cryptography library
UTEST(ET_VALIDATION, AUTH_ENCRYPTION_TEST)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();

    uint8* expected = NULL;
    long expected_length = 0;

    char *activate_sa4_h  = "2003002000ff000100001880d2c9000e197f0b001b0004000400003040d95ea61a";
    char *enc_test_ping_h = "20030415001880d2ca0008197f0b0031000039c5a111";               

    uint8 *activate_sa4_b, *enc_test_ping_b = NULL;
    int activate_sa4_len, enc_test_ping_len = 0;

    hex_conversion(activate_sa4_h, &activate_sa4_b, &activate_sa4_len);
    hex_conversion(enc_test_ping_h, &enc_test_ping_b, &enc_test_ping_len);

    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));

    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    int32 return_val = -1;

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8) * TC_SIZE));

    // Ensure that Process Security can activate SA 4
    Crypto_TC_ProcessSecurity(activate_sa4_b, &activate_sa4_len, tc_sdls_processed_frame);
    
    // Expose SA 1 for testing
    expose_sadb_get_sa_from_spi(1,&test_association);

    // Deactive SA 1
    test_association->sa_state = SA_NONE;

    // Expose SA 4 for testing
    expose_sadb_get_sa_from_spi(4, &test_association);
    test_association->arc_len = 0;
    test_association->gvcid_tc_blk.vcid=1;
    test_association->iv[11] = 1;
    test_association->ast = 1;
    test_association->est = 1;
    Crypto_TC_ApplySecurity(enc_test_ping_b, enc_test_ping_len, &ptr_enc_frame, &enc_frame_len);

    // Get Truth Baseline
    python_auth_encryption("1880d2ca0008197f0b0031000039c5", "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210", "000000000000000000000001", "2003043400FF0004", "00", &expected, &expected_length);

    for(int i = 0; i < expected_length; i++)
    {
        //printf("[%d]: %02x -> %02x \n", i, expected[i], ptr_enc_frame[i]);
        ASSERT_EQ(expected[i], ptr_enc_frame[i]);
    }

    free(activate_sa4_b);
    free(enc_test_ping_b);
    free(ptr_enc_frame); 
    free(expected);
    free(tc_sdls_processed_frame);
    EndPython();
}

UTEST(DT_VALIDATION, AUTH_DECRYPTION_TEST)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();

    char *activate_sa4_h  = "2003002000ff000100001880d2c9000e197f0b001b0004000400003040d95ea61a"; 
    char *dec_test_ping_h = "2003043400FF00040000000000000000000000017E1D8EEA8D45CEBA17888E0CDCD747DC78E5F372F997F2A63AA5DFC168395DC987"; 
    char *enc_test_ping_h = "1880d2ca0008197f0b0031000039c5";              

    uint8 *activate_sa4_b, *dec_test_ping_b, *enc_test_ping_b = NULL;
    int activate_sa4_len, dec_test_ping_len, enc_test_ping_len = 0;

    hex_conversion(activate_sa4_h, &activate_sa4_b, &activate_sa4_len);
    hex_conversion(dec_test_ping_h, &dec_test_ping_b, &dec_test_ping_len);
    hex_conversion(enc_test_ping_h, &enc_test_ping_b, &enc_test_ping_len);

    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));

    int32 return_val = -1;

    TC_t *tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8) * TC_SIZE));

    // Ensure that Process Security can activate SA 4
    Crypto_TC_ProcessSecurity(activate_sa4_b, &activate_sa4_len, tc_sdls_processed_frame);
    
    // Expose SA 1 for testing
    expose_sadb_get_sa_from_spi(1,&test_association);

    // Deactive SA 1
    test_association->sa_state = SA_NONE;

    // Expose SA 4 for testing
    expose_sadb_get_sa_from_spi(4, &test_association);
    test_association->arc_len = 0;
    test_association->gvcid_tc_blk.vcid=1;
    test_association->iv[11] = 1;
    test_association->ast = 1;
    test_association->est = 1;

    Crypto_TC_ProcessSecurity(dec_test_ping_b, &dec_test_ping_len, tc_sdls_processed_frame);

    for(int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(enc_test_ping_b[i], tc_sdls_processed_frame->tc_pdu[i]);
    }

    free(activate_sa4_b);
    free(dec_test_ping_b);
    free(tc_sdls_processed_frame);
    EndPython();
}

// AES-GCM 256 Test Vectors
// Reference: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
UTEST(NIST_ENC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_0)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "ef9f9284cf599eac3b119905a7d18851e7e374cf63aea04358586b0f757670f8";
    char *buffer_nist_pt_h  = "2003001100722ee47da4b77424733546c2d400c4e51069";
    char *buffer_nist_iv_h  = "b6ac8e4963f49207ffd6374c";
    char *buffer_nist_ct_h  = "1224dfefb72a20d49e09256908874979";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_ct_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_ct_len, buffer_nist_key_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_ct_h, &buffer_nist_ct_b, &buffer_nist_ct_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16 enc_data_idx = enc_frame_len - buffer_nist_ct_len - 2;
    for (int i=0; i<buffer_nist_pt_len-7; i++)
    {
        ASSERT_EQ(*(ptr_enc_frame+enc_data_idx), buffer_nist_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_ct_b);
    free(buffer_nist_key_b);
}

// AES-GCM 256 Test Vectors
// Reference: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
UTEST(NIST_DEC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_0)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "ef9f9284cf599eac3b119905a7d18851e7e374cf63aea04358586b0f757670f8";
    char *buffer_nist_pt_h  = "2003001100722ee47da4b77424733546c2d400c4e51069";
    char *buffer_nist_iv_h  = "b6ac8e4963f49207ffd6374c";
    char *buffer_nist_et_h  = "2003002500FF0009B6AC8E4963F49207FFD6374C1224DFEFB72A20D49E09256908874979AD6F";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_et_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_et_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8) * TC_SIZE);
    
    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input encryptedtext
    hex_conversion(buffer_nist_et_h, &buffer_nist_et_b, &buffer_nist_et_len);

    Crypto_TC_ProcessSecurity(buffer_nist_et_b, &buffer_nist_et_len, tc_nist_processed_frame);

    for(int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(buffer_nist_pt_b[i+5], tc_nist_processed_frame->tc_pdu[i]);
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_et_b);
    free(buffer_nist_key_b);
}

UTEST(NIST_ENC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_1)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "e9ccd6eef27f740d1d5c70b187734e11e76a8ac0ad1702ff02180c5c1c9e5399";
    char *buffer_nist_pt_h  = "2003001100419635e6e12b257a8ecae411f94480ffa02a";
    char *buffer_nist_iv_h  = "1af2613c4184dbd101fcedce";
    char *buffer_nist_ct_h  = "9cd21f414f1f54d5f6f58b1f2f77e5b6";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_ct_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_ct_len, buffer_nist_key_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_ct_h, &buffer_nist_ct_b, &buffer_nist_ct_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16 enc_data_idx = enc_frame_len - buffer_nist_ct_len - 2;
    for (int i=0; i<buffer_nist_pt_len-7; i++)
    {
        ASSERT_EQ(*(ptr_enc_frame+enc_data_idx), buffer_nist_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_ct_b);
    free(buffer_nist_key_b);
}

UTEST(NIST_DEC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_1)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "e9ccd6eef27f740d1d5c70b187734e11e76a8ac0ad1702ff02180c5c1c9e5399";
    char *buffer_nist_pt_h  = "2003001100419635e6e12b257a8ecae411f94480ffa02a";
    char *buffer_nist_iv_h  = "1af2613c4184dbd101fcedce";
    char *buffer_nist_et_h  = "2003002500FF00091AF2613C4184DBD101FCEDCE9CD21F414F1F54D5F6F58B1F2F77E5B66987";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_et_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_et_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_et_h, &buffer_nist_et_b, &buffer_nist_et_len);

    Crypto_TC_ProcessSecurity(buffer_nist_et_b, &buffer_nist_et_len, tc_nist_processed_frame);

    for(int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(buffer_nist_pt_b[i+5], tc_nist_processed_frame->tc_pdu[i]);
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_et_b);
    free(buffer_nist_key_b);
}

UTEST(NIST_ENC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_2)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "7ecc9dcb3d5b413cadc3af7b7812758bd869295f8aaf611ba9935de76bd87013";
    char *buffer_nist_pt_h  = "200300110073d4d7984ce422ac983797c0526ac6f9ba60";
    char *buffer_nist_iv_h  = "6805be41e983717bf6781052";
    char *buffer_nist_ct_h  = "487211dd440f4d09d00bc5c3158a822c";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_ct_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_ct_len, buffer_nist_key_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_ct_h, &buffer_nist_ct_b, &buffer_nist_ct_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16 enc_data_idx = enc_frame_len - buffer_nist_ct_len - 2;
    for (int i=0; i<buffer_nist_pt_len-7; i++)
    {
        ASSERT_EQ(*(ptr_enc_frame+enc_data_idx), buffer_nist_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_ct_b);
    free(buffer_nist_key_b);
}

UTEST(NIST_DEC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_2)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "7ecc9dcb3d5b413cadc3af7b7812758bd869295f8aaf611ba9935de76bd87013";
    char *buffer_nist_pt_h  = "200300110073d4d7984ce422ac983797c0526ac6f9ba60";
    char *buffer_nist_iv_h  = "6805be41e983717bf6781052";
    char *buffer_nist_et_h  = "2003002500FF00096805BE41E983717BF6781052487211DD440F4D09D00BC5C3158A822C46E3";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_et_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_et_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_et_h, &buffer_nist_et_b, &buffer_nist_et_len);

    Crypto_TC_ProcessSecurity(buffer_nist_et_b, &buffer_nist_et_len, tc_nist_processed_frame);

    for(int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(buffer_nist_pt_b[i+5], tc_nist_processed_frame->tc_pdu[i]);
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_et_b);
    free(buffer_nist_key_b);
}

UTEST(NIST_ENC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_3)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "a881373e248615e3d6576f5a5fb68883515ae72d6a2938e3a6f0b8dcb639c9c0";
    char *buffer_nist_pt_h  = "200300110007d1dc9930e710b1ebe533c81f671101ba60";
    char *buffer_nist_iv_h  = "f0b744f157087df4e41818a9";
    char *buffer_nist_ct_h  = "b65a2878b9dddbd4a0204dae6a6a6fc0";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_ct_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_ct_len, buffer_nist_key_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_ct_h, &buffer_nist_ct_b, &buffer_nist_ct_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16 enc_data_idx = enc_frame_len - buffer_nist_ct_len - 2;
    for (int i=0; i<buffer_nist_pt_len-7; i++)
    {
        ASSERT_EQ(*(ptr_enc_frame+enc_data_idx), buffer_nist_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_ct_b);
    free(buffer_nist_key_b);
}

UTEST(NIST_DEC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_3)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "a881373e248615e3d6576f5a5fb68883515ae72d6a2938e3a6f0b8dcb639c9c0";
    char *buffer_nist_pt_h  = "200300110007d1dc9930e710b1ebe533c81f671101ba60";
    char *buffer_nist_iv_h  = "f0b744f157087df4e41818a9";
    char *buffer_nist_et_h  = "2003002500FF0009F0B744F157087DF4E41818A9B65A2878B9DDDBD4A0204DAE6A6A6FC0C327";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_et_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_et_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_et_h, &buffer_nist_et_b, &buffer_nist_et_len);

    Crypto_TC_ProcessSecurity(buffer_nist_et_b, &buffer_nist_et_len, tc_nist_processed_frame);

    for(int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(buffer_nist_pt_b[i+5], tc_nist_processed_frame->tc_pdu[i]);
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_et_b);
    free(buffer_nist_key_b);
}

UTEST(NIST_ENC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_4)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "84c90349539c2a7989cb24dfae5e4182382ae94ba717d385977017f74f0d87d6";
    char *buffer_nist_pt_h  = "200300110031c4e1d0ccece6b7a999bfc31f38559ab87b";
    char *buffer_nist_iv_h  = "eeddeaf4355c826dfd153393";
    char *buffer_nist_ct_h  = "5c6cfbdd06c19445ecf500c21aeca173";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_ct_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_ct_len, buffer_nist_key_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_ct_h, &buffer_nist_ct_b, &buffer_nist_ct_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16 enc_data_idx = enc_frame_len - buffer_nist_ct_len - 2;
    for (int i=0; i<buffer_nist_pt_len-7; i++)
    {
        ASSERT_EQ(*(ptr_enc_frame+enc_data_idx), buffer_nist_ct_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_ct_b);
    free(buffer_nist_key_b);
}

UTEST(NIST_DEC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_4)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "84c90349539c2a7989cb24dfae5e4182382ae94ba717d385977017f74f0d87d6";
    char *buffer_nist_pt_h  = "200300110031c4e1d0ccece6b7a999bfc31f38559ab87b";
    char *buffer_nist_iv_h  = "eeddeaf4355c826dfd153393";
    char *buffer_nist_et_h  = "2003002500FF0009EEDDEAF4355C826DFD1533935C6CFBDD06C19445ECF500C21AECA1738A7D";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_et_b, *buffer_nist_key_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_et_len, buffer_nist_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_nist_et_h, &buffer_nist_et_b, &buffer_nist_et_len);

    Crypto_TC_ProcessSecurity(buffer_nist_et_b, &buffer_nist_et_len, tc_nist_processed_frame);

    for(int i = 0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(buffer_nist_pt_b[i+5], tc_nist_processed_frame->tc_pdu[i]);
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_et_b);
    free(buffer_nist_key_b);
}

// Spot check of MAC tags assuming no plaintext payload
// Accomplished by a multi-step process:
// 1) Ensure a valid implementation - Utilize Cyberchef's AES Encrypt to re-create a NIST test vector with AAD
// 2) Generate Truth data - Use same CyberChef settings on a created TF
// 3) Validate Cryptolib output with CyberChef output
// Reference 1: https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'GCM','Hex','Hex',%7B'option':'Hex','string':''%7D)
// Reference 2: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip

// Bit Mask of zeros
// Bit-mask of zeros in this test for a total length of:
// Header (5) + Segment Hdr (1) + SPI (2) + IV (12)
// This means zero input to the MAC, which precedes the TF FECF
UTEST(NIST_ENC_MAC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_0)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223";
    char *buffer_nist_pt_h  = "200300040028C2"; // Empty Transfer frame
    char *buffer_nist_iv_h  = "d79cf22d504cc793c3fb6c8a";
    char *buffer_nist_aad_h = "b96baa8c1c75a671bfb2d08d06be5f36"; // Zeroed out by abm
    char *buffer_cyber_chef_mac_h = "79238ca36970658073f5d59d7aa874ef";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_nist_aad_b, *buffer_cyber_chef_mac_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_key_len, buffer_nist_aad_len, buffer_cyber_chef_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arc_len = 0;
    test_association->shivf_len = 12;
    test_association->abm_len = 20;
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input aad
    hex_conversion(buffer_nist_aad_h, &buffer_nist_aad_b, &buffer_nist_aad_len);
    // Convert input mac
    hex_conversion(buffer_cyber_chef_mac_h, &buffer_cyber_chef_mac_b, &buffer_cyber_chef_mac_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    uint16 enc_data_idx = enc_frame_len - buffer_cyber_chef_mac_len - 2;
    for (int i=0; i<buffer_cyber_chef_mac_len; i++)
    {
        // printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_cyber_chef_mac_b[i], *(ptr_enc_frame+enc_data_idx));
        ASSERT_EQ(*(ptr_enc_frame+enc_data_idx), buffer_cyber_chef_mac_b[i]);
        enc_data_idx++;
    }
    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_cyber_chef_mac_b);
    free(buffer_nist_aad_b);
}

// Bit Mask of ones
// Bit-mask of ones in this test on an empty frame for a total length of:
// Header (5) + Segment Hdr (1) + SPI (2) + IV (12)
// All bits are unmasked input to the MAC algorithm
UTEST(NIST_ENC_MAC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_1)
{
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    // Setup & Initialize CryptoLib
    Crypto_Init();  
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char *buffer_nist_key_h = "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223";
    char *buffer_nist_pt_h  = "200300040028C2"; // Empty Transfer frame
    char *buffer_nist_iv_h  = "d79cf22d504cc793c3fb6c8a";
    char *buffer_cyber_chef_mac_h = "08b3adfaa8305fe08a6bf6a12507ea39";
    uint8 *buffer_nist_pt_b, *buffer_nist_iv_b, *buffer_nist_key_b, *buffer_cyber_chef_mac_b = NULL;
    int buffer_nist_pt_len, buffer_nist_iv_len, buffer_nist_key_len, buffer_cyber_chef_mac_len = 0;

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arc_len = 0;
    test_association->shivf_len = 12;
    test_association->abm_len = 20;
    memset(test_association->abm, 0xFF, (test_association->abm_len*sizeof(unsigned char))); // Bitmask
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(&test_association->iv[0], buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input mac
    hex_conversion(buffer_cyber_chef_mac_h, &buffer_cyber_chef_mac_b, &buffer_cyber_chef_mac_len);

    Crypto_TC_ApplySecurity(buffer_nist_pt_b, buffer_nist_pt_len, &ptr_enc_frame, &enc_frame_len);
    
    // Note: For comparison, primarily interested in the MAC
    // Calc payload index: total length - pt length
    uint16 enc_data_idx = enc_frame_len - buffer_cyber_chef_mac_len - 2;
    for (int i=0; i<buffer_cyber_chef_mac_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", enc_data_idx, buffer_cyber_chef_mac_b[i], *(ptr_enc_frame+enc_data_idx));
        ASSERT_EQ(*(ptr_enc_frame+enc_data_idx), buffer_cyber_chef_mac_b[i]);
        enc_data_idx++;
    }

    free(ptr_enc_frame);
    free(buffer_nist_pt_b);
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_cyber_chef_mac_b);
}

// Bit-mask of ones
UTEST(NIST_DEC_MAC_VALIDATION, AES_GCM_256_IV_96_PT_128_TEST_0)
{
    // Setup & Initialize CryptoLib
    uint16 enc_frame_len = 0;
    Crypto_Init();  
    // NIST supplied vectors
    char *buffer_nist_key_h = "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223";
    char *buffer_nist_iv_h  = "d79cf22d504cc793c3fb6c8a";
    char *buffer_cyber_chef_mac_h = "99eff39be8327e6950f03a329209d577";
    char *buffer_nist_pt_h = "722ee47da4b77424733546c2d400c4e5";

    // Create a MAC'd frame by adding our headers and a fecf
                                 //  |  Header | SPI |           iv          |         plaintext             |             mac               |fecf|
    char *buffer_nist_mac_frame_h = "2003003500FF0009D79CF22D504CC793C3FB6C8A722ee47da4b77424733546c2d400c4e599eff39be8327e6950f03a329209d5776cb8";

    uint8 *buffer_nist_iv_b, *buffer_nist_pt_b, *buffer_nist_key_b, *buffer_cyber_chef_mac_b , *buffer_nist_mac_frame_b, *buffer_nist_cp_b = NULL;
    int buffer_nist_iv_len, buffer_nist_pt_len, buffer_nist_key_len, buffer_cyber_chef_mac_len , buffer_nist_mac_frame_len, buffer_nist_cp_len = 0;

    // Setup Processed Frame For Decryption
    TC_t *tc_nist_processed_frame;
    tc_nist_processed_frame = malloc(sizeof(uint8) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));
    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->ast = 1;
    test_association->est = 0;
    test_association->arc_len = 0;
    test_association->abm_len = 20;
    memset(test_association->abm, 0xFF, (test_association->abm_len*sizeof(unsigned char)));
    test_association->shivf_len = 12;
    test_association->stmacf_len = 16;
    test_association->sa_state = SA_OPERATIONAL;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_nist_key_h, &buffer_nist_key_b, &buffer_nist_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_nist_key_b, buffer_nist_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_nist_pt_h, &buffer_nist_pt_b, &buffer_nist_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_nist_iv_h, &buffer_nist_iv_b, &buffer_nist_iv_len);
    memcpy(test_association->iv, buffer_nist_iv_b, buffer_nist_iv_len);
    // Convert input mac
    hex_conversion(buffer_cyber_chef_mac_h, &buffer_cyber_chef_mac_b, &buffer_cyber_chef_mac_len);
    // Convert mac frame
    hex_conversion(buffer_nist_mac_frame_h, &buffer_nist_mac_frame_b, &buffer_nist_mac_frame_len);

    Crypto_TC_ProcessSecurity(buffer_nist_mac_frame_b, &buffer_nist_mac_frame_len, tc_nist_processed_frame);

    // Note: For comparison, interested in the TF payload (exclude headers and FECF if present)
    // Calc payload index: total length - pt length
    #ifdef DEBUG
        printf("Expected MAC: ");
        for (int i=0; i<tc_nist_processed_frame->tc_pdu_len; i++)
        {
            printf("%02x ", buffer_cyber_chef_mac_b[i]);
        }
        printf("\nReceived MAC: ");
        for (int i=0; i<tc_nist_processed_frame->tc_pdu_len; i++)
        {
            printf("%02x ", tc_nist_processed_frame->tc_sec_trailer.mac[i]);
        }    
        printf("\n");
    #endif

    // Verify the MAC
    for (int i=0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    {
       ASSERT_EQ(tc_nist_processed_frame->tc_sec_trailer.mac[i], buffer_cyber_chef_mac_b[i]);
    }
    for (int i=0; i < tc_nist_processed_frame->tc_pdu_len; i++)
    // Verify the PDU Data is present and not stomped
    {
       ASSERT_EQ(tc_nist_processed_frame->tc_pdu[i], buffer_nist_pt_b[i]);
    }
    free(buffer_nist_iv_b);
    free(buffer_nist_key_b);
    free(buffer_cyber_chef_mac_b);
    free(buffer_nist_mac_frame_b);
    free(buffer_nist_cp_b);
}

UTEST_MAIN();
