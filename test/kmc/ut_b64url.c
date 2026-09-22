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

#include "ut_b64url.h"
#include "utest.h"

typedef char         char_t;
typedef unsigned int uint_t;

// Base64url decoding table
static const uint8_t base64urlDecTable[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
    0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF,
    0x3F, 0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define ERROR_INVALID_PARAMETER 21
#define ERROR_INVALID_LENGTH    22
#define ERROR_INVALID_CHARACTER 23
#define NO_ERROR                0

void base64urlDecode_rempadding(size_t inputLen, uint32_t value, size_t *n, uint8_t *p)
{
    // All trailing pad characters are omitted in Base64url
    if ((inputLen % 4) == 2)
    {
        // The last block contains only 1 byte
        if (p != NULL)
        {
            // Decode the last byte
            p[*n] = (value >> 4) & 0xFF;
        }

        // Adjust the length of the decoded data
        *n = *n + 1;
    }
    else if ((inputLen % 4) == 3)
    {
        // The last block contains only 2 bytes
        if (p != NULL)
        {
            // Decode the last two bytes
            p[*n]     = (value >> 10) & 0xFF;
            p[*n + 1] = (value >> 2) & 0xFF;
        }

        // Adjust the length of the decoded data
        *n = *n + 2;
    }
    else
    {
        // No pad characters in this case
    }
}

int32_t base64urlDecode(const char_t *input, size_t inputLen, void *output, uint16_t decoded_buffer_size, size_t *outputLen)
{
    int32_t  error;
    uint32_t value;
    uint_t   c;
    size_t   i;
    size_t   n;
    uint8_t *p;

    uint16_t outputLen_expected = 0;
    uint8_t  padding            = 0;

    // Check parameters
    if (input == NULL && inputLen != 0)
        return ERROR_INVALID_PARAMETER;
    if (outputLen == NULL)
        return ERROR_INVALID_PARAMETER;

    // Empty input is valid; produce empty output
    if (inputLen == 0)
    {
        *outputLen = 0;
        return NO_ERROR;
    }

    // Safely strip optional '=' padding
    while (inputLen > 0 && input[inputLen - 1] == '=')
    {
        inputLen--;
        padding++;
    }

    // Check the length of the input string
    if ((inputLen % 4) == 1)
        return ERROR_INVALID_LENGTH;

    // Initialize status code
    error = NO_ERROR;

    // Check expected output buffer size is large enough for decoded input
    outputLen_expected = ((inputLen * 3) / 4) - padding;

    // Special debug prints for UT
    printf("InputLen: %ld\n \
        Expected Dec Buf Length: %d\n \
        Passed In Dec Length: %d\n",
           inputLen, outputLen_expected, decoded_buffer_size);
           
    if (decoded_buffer_size < outputLen_expected)
        return ERROR_INVALID_LENGTH;

    // Point to the buffer where to write the decoded data
    p = (uint8_t *)output;

    // Initialize variables
    n     = 0;
    value = 0;

    // Process the Base64url-encoded string
    for (i = 0; i < inputLen && !error; i++)
    {
        // Get current character
        c = (uint_t)input[i];

        // Check the value of the current character
        if (c < 128 && base64urlDecTable[c] < 64)
        {
            // Decode the current character
            value = (value << 6) | base64urlDecTable[c];

            // Divide the input stream into blocks of 4 characters
            if ((i % 4) == 3)
            {
                // Map each 4-character block to 3 bytes
                if (p != NULL)
                {
                    p[n]     = (value >> 16) & 0xFF;
                    p[n + 1] = (value >> 8) & 0xFF;
                    p[n + 2] = value & 0xFF;
                }

                // Adjust the length of the decoded data
                n += 3;
                // Decode next block
                value = 0;
            }
        }
        else
        {
            // Implementations must reject the encoded data if it contains
            // characters outside the base alphabet
            error = ERROR_INVALID_CHARACTER;
        }
    }

    // Check status code
    if (!error)
    {
        base64urlDecode_rempadding(inputLen, value, &n, p);
    }

    // Total number of bytes that have been written
    *outputLen = n;

    // Return status code
    return error;
}

UTEST(CRYPTO_B64URL, OVERSIZE_DECODE)
{
    int32_t status = CRYPTO_LIB_ERROR;

    // Success Case, This_one_is_just_the_right_size (len = 31)
    char    *ciphertext_base64      = "VGhpc19vbmVfaXNfanVzdF90aGVfcmlnaHRfc2l6ZQ==";
    uint8_t  len_data_out           = 15;
    uint16_t decoded_buffer_size    = (len_data_out)*2 + 1; // 31
    uint8_t *ciphertext_decoded     = malloc(decoded_buffer_size);
    size_t   ciphertext_decoded_len = 0;
    status = base64urlDecode(ciphertext_base64, strlen(ciphertext_base64), ciphertext_decoded, decoded_buffer_size,
                          &ciphertext_decoded_len);
    printf("Status: %d\n\n", status);
    free(ciphertext_decoded);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Success Case, This_one_allocates_too_much (len = 27)
    ciphertext_base64      = "VGhpc19vbmVfYWxsb2NhdGVzX3Rvb19tdWNo";
    len_data_out           = 15;
    decoded_buffer_size    = (len_data_out)*2 + 1; // 31
    ciphertext_decoded     = malloc(decoded_buffer_size);
    ciphertext_decoded_len = 0;
    status = base64urlDecode(ciphertext_base64, strlen(ciphertext_base64), ciphertext_decoded, decoded_buffer_size,
                          &ciphertext_decoded_len);
    printf("Status: %d\n\n", status);
    free(ciphertext_decoded);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    // Failure Case, This_one_is_2_too_short (len = 23)
    ciphertext_base64      = "VGhpc19vbmVfaXNfMl90b29fc2hvcnQ=";
    len_data_out           = 10;
    decoded_buffer_size    = (len_data_out)*2 + 1;
    ciphertext_decoded     = malloc(decoded_buffer_size);
    ciphertext_decoded_len = 0;
    status = base64urlDecode(ciphertext_base64, strlen(ciphertext_base64), ciphertext_decoded, decoded_buffer_size,
                          &ciphertext_decoded_len);
    printf("Status: %d\n\n", status);
    free(ciphertext_decoded);
    ASSERT_EQ(ERROR_INVALID_LENGTH, status);

    // Failure Case, This_one_is_1_tooo_short (len = 24)
    ciphertext_base64      = "VGhpc19vbmVfaXNfMV90b29vX3Nob3J0";
    len_data_out           = 11;
    decoded_buffer_size    = (len_data_out)*2 + 1;
    ciphertext_decoded     = malloc(decoded_buffer_size);
    ciphertext_decoded_len = 0;
    status = base64urlDecode(ciphertext_base64, strlen(ciphertext_base64), ciphertext_decoded, decoded_buffer_size,
                          &ciphertext_decoded_len);
    printf("Status: %d\n\n", status);
    free(ciphertext_decoded);
    ASSERT_EQ(ERROR_INVALID_LENGTH, status);
}
UTEST_MAIN()