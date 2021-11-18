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

void python_encryption(char* data, char* key, char* iv, uint8** expected, long* expected_length)
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

    pValue = PyObject_CallMethod(pInstance, "encrypt", "sss", data, key, iv);

    pValue = PyObject_CallMethod(pInstance, "get_len", NULL);
    long temp_length = PyLong_AsLong(pValue);
    *expected_length = temp_length;
    pValue = PyObject_CallMethod(pInstance, "get_results", NULL);
    char* temp_expected = PyBytes_AsString(pValue);
    *expected= (uint8*)malloc(sizeof(uint8) * (int)*expected_length);
    memcpy(*expected, temp_expected, (int)*expected_length);
    return;
}

//Encryption Test HERE
UTEST(ET_VALIDATION, ENCRYPTION_TEST)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();
    Py_Initialize();

    uint8* expected = NULL;
    long expected_length = 0;
    long buffer_size = 0;
    long buffer2_size = 0;

    char *buffer = c_read_file("../../fsw/crypto_tests/data/encryption_test_ping.dat", &buffer_size);
    char *buffer2 = c_read_file("../../fsw/crypto_tests/data/activate_sa4.dat", &buffer2_size);

    uint16 buffer_size_i = (uint16) buffer_size;
    int buffer2_size_i = (int) buffer2_size;

    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    int32 return_val = -1;
    TC_t *tc_sdls_processed_frame;
    
    //Crypto_TC_ProcessSecurity(buffer2, &buffer2_size_i, tc_sdls_processed_frame);
    
    return_val = Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len);
    
    python_encryption("1880d2ca0008197f0b0031000039c5", "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210", "000000000000000000000001", &expected, &expected_length);
    
    printf("\nGot: \n");
    for (int i = 0; i < expected_length; i++)
    {
        printf("0x%02x ", ptr_enc_frame[i]);
    }
    printf("\n");
    for( int i = 0; i < expected_length; i++)
    {
        printf("EXPECTED: 0x%02x, GOT: 0x%02x\n", expected[i], ptr_enc_frame[i]);
        ASSERT_EQ(expected[i], ptr_enc_frame[i]);
    }
    for( int i = 0; i < expected_length; i++)
    {
        //printf("EXPECTED: 0x%02x, GOT: 0x%02x\n", expected[i], ptr_enc_frame[i]);
        ASSERT_EQ(expected[i], ptr_enc_frame[i]);
    }
    
    free(buffer);
    free(ptr_enc_frame); 
    free(expected);
    EndPython();
}

UTEST(ET_VALIDATION, VALIDATION_TEST)
{
    //Setup & Initialize CryptoLib
    Crypto_Init();  
    uint8* expected = NULL;
    long expected_length = 0;
    long buffer_size = 0;
    long buffer2_size = 0;    

    char *buffer = c_read_file("../../fsw/crypto_tests/data/validation1.dat", &buffer_size);
    char *buffer2 = c_read_file("../../fsw/crypto_tests/data/activate_sa4.dat", &buffer2_size);
    uint16 buffer_size_i = (uint16) buffer_size;
    int buffer2_size_i = (int) buffer2_size;
    uint8 *ptr_enc_frame = NULL;
    uint16 enc_frame_len = 0;
    int32 return_val = -1;
    TC_t *tc_sdls_processed_frame;
    //Crypto_TC_ProcessSecurity(buffer2, &buffer2_size_i, tc_sdls_processed_frame);
    return_val = Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len);
    python_encryption("", "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210", "000000000000000000000001", &expected, &expected_length);

    printf("\nExpected: %d\n", (int)expected_length);
    for (int i = 0; i < expected_length; i++)
    {        
        printf("0x%02x ", expected[i]);
    }
    printf("\n");

    // printf("TC_APPLY: \n");
    // for (int i = 0; i < expected_length; i++)
    // {        
    //     printf("0x%02x ", ptr_enc_frame[i]);
    // }
    // printf("\n");

    // printf("\nGot: \n");
    // for (int i = 0; i < expected_length; i++)
    // {
    //     printf("0x%02x ", ptr_enc_frame[i]);
    // }
    // printf("\n");
    // for( int i = 0; i < expected_length; i++)
    // {
    //     printf("EXPECTED: 0x%02x, GOT: 0x%02x\n", expected[i], ptr_enc_frame[i]);
    //     ASSERT_EQ(expected[i], ptr_enc_frame[i]);
    // }
    free(buffer);
    free(buffer2);
    free(ptr_enc_frame);
    EndPython();
}

UTEST_MAIN();
