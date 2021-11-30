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

#include "et_validation.h"
#include "utest.h"
#include <python3.8/Python.h>

#include "sadb_routine.h"


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

// UTEST(ET_VALIDATION, ENCRYPTION_TEST)
// {
//     //Setup & Initialize CryptoLib
//     Crypto_Init();
//     Py_Initialize();

//     uint8* expected = NULL;
//     long expected_length = 0;
//     long buffer_size = 0;
//     long buffer2_size = 0;
//     long buffer3_size = 0;

//     char *buffer = c_read_file("../../fsw/crypto_tests/data/encryption_test_ping.dat", &buffer_size);
//     char *buffer2 = c_read_file("../../fsw/crypto_tests/data/activate_sa4.dat", &buffer2_size);

//     SecurityAssociation_t* test_association = NULL;
//     test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));

//     uint16 buffer_size_i = (uint16) buffer_size;
//     int buffer2_size_i = (int) buffer2_size;

//     uint8 *ptr_enc_frame = NULL;
//     uint16 enc_frame_len = 0;
//     int32 return_val = -1;
//     TC_t *tc_sdls_processed_frame;

//     tc_sdls_processed_frame = malloc(sizeof(uint8) * TC_SIZE);
    
//     Crypto_TC_ProcessSecurity(buffer2, &buffer2_size_i, tc_sdls_processed_frame);
    
//     expose_sadb_get_sa_from_spi(1,&test_association);

//     test_association->sa_state = SA_NONE;

//     expose_sadb_get_sa_from_spi(4, &test_association);
//     test_association->arc_len = 0;
//     test_association->gvcid_tc_blk.vcid=1;
    
//     return_val = Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len);

//     python_auth_encryption("1880d2ca0008197f0b0031000039c5", "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210", "000000000000000000000001", "2003043400FF0004", "00", &expected, &expected_length);
                            
//     printf("\nGot: \n");
//     for (int i = 0; i < expected_length; i++)
//     {
//         printf("0x%02x ", ptr_enc_frame[i]);
//     }
//     printf("\n");
//     printf("\nExpected:\n");
//     for (int i = 0; i < expected_length; i++)
//     {
//         printf("0x%02x ", expected[i]);
//     }    
//     printf("\n");
//     for( int i = 0; i < expected_length; i++)
//     {
//         printf("EXPECTED: 0x%02x, GOT: 0x%02x\n", expected[i], ptr_enc_frame[i]);
//         ASSERT_EQ(expected[i], ptr_enc_frame[i]);
//     }
//     for( int i = 0; i < expected_length; i++)
//     {
//         //printf("EXPECTED: 0x%02x, GOT: 0x%02x\n", expected[i], ptr_enc_frame[i]);
//         ASSERT_EQ(expected[i], ptr_enc_frame[i]);
//     }
    
//     free(buffer);
//     free(ptr_enc_frame); 
//     free(expected);
//     free(tc_sdls_processed_frame);
//     //free(tc_sdls_processed_frame2);
//     EndPython();
// }

int convert_hexstring_to_byte_array(char* source_str, uint8* dest_buffer)
{
    char *line = source_str;
    char *data = line;
    int offset;
    int read_byte;
    int data_len = 0;

    while (sscanf(data, " %02x%n", &read_byte, &offset) == 1) 
    {
        dest_buffer[data_len++] = read_byte;
        data += offset;
    }
    return data_len;
}

UTEST(ET_VALIDATION, VALIDATION_TEST)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();  

    //char *buffer = "2003002000ff000100001880d2c9000e197f0b001b0004000900003040713830095555"; //Activate SA-9
    // char *buffer_nist_h = "2003001100014730f80ac625fe84f026c60bfd547d1069";
    char *buffer_nist_h    = "2003001100722ee47da4b77424733546c2d400c4e51069";
    //uint8 *buffer_b = NULL;
    //int32 buffer_b_length = convert_hexstring_to_byte_array(buffer, buffer_b);
    uint8 *buffer_nist_b = malloc((sizeof(buffer_nist_h) / 2) * sizeof(uint8));
    int buffer_nist_b_length = convert_hexstring_to_byte_array(buffer_nist_h, buffer_nist_b);

    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(unsigned char));

    // Deactivate SA 1
    expose_sadb_get_sa_from_spi(1,&test_association);
    test_association->sa_state = SA_NONE;

    printf("STATE: %0d\n", test_association->sa_state);

    // Activate SA 9
    expose_sadb_get_sa_from_spi(9, &test_association);
    test_association->arc_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    printf("STATE: %0d\n", test_association->sa_state);
    expose_sadb_get_sa_from_spi(9, &test_association);

    // Set IV manually for this test
    test_association->iv[0] = 0xb6;
    test_association->iv[1] = 0xac;
    test_association->iv[2] = 0x8e;
    test_association->iv[3] = 0x49;
    test_association->iv[4] = 0x63;
    test_association->iv[5] = 0xf4;
    test_association->iv[6] = 0x92;
    test_association->iv[7] = 0x07;
    test_association->iv[8] = 0xff;
    test_association->iv[9] = 0xd6;
    test_association->iv[10] = 0x37;
    test_association->iv[11] = 0x4c;

    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    int32 return_val = -1;  
    #undef INCREMENT
    return_val = Crypto_TC_ApplySecurity(buffer_nist_b, buffer_nist_b_length, &ptr_enc_frame, &enc_frame_len);
    #define INCREMENT
    //Convert back to hex string
    //compare output to: 5c9d844ed46f9885085e5d6a4f94c7d7
    printf("RET VALUE = %d\n", return_val);

    free(ptr_enc_frame);
}

UTEST_MAIN();
