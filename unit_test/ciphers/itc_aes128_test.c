#include <stdio.h>
#include "itc_aes128.h"

//represents a test vector for AES 128-bit encryption:
//    - the 128-bit key
//    - the input plaintext
//    - the expected ciphertext
struct aes128_test_vector
{
    unsigned char key[16];
    unsigned char plaintext[16];
    unsigned char ciphertext[16];
};

#define NUM_TESTS    4

static const struct aes128_test_vector test_vector_1 = 
{
    { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, // key
    { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, // plaintext
    { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 }  // ciphertext
};

static const struct aes128_test_vector test_vector_2 = 
{
    { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, // key
    { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, // plaintext
    { 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf }  // ciphertext
};

static const struct aes128_test_vector test_vector_3 = 
{
    { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, // key
    { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, // plaintext
    { 0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88 }  // ciphertext
};

static const struct aes128_test_vector test_vector_4 = 
{
    { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, // key
    { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, // plaintext
    { 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4 }  // ciphertext
};


void print128(const unsigned char * block); //prints 128-bit key/block & a newline
//returns 0 if equal; non-zero if different
int compare128(const unsigned char * a, const unsigned char * b); 

int main(void)
{
    //array of test vectors
    const struct aes128_test_vector* test_vectors[NUM_TESTS];
    test_vectors[0] = &test_vector_1;
    test_vectors[1] = &test_vector_2;
    test_vectors[2] = &test_vector_3;
    test_vectors[3] = &test_vector_4;

    int i;
    int pass_count = 0;
    int fail_count = 0;

    printf("********************************************************************************\n");
    printf("                            Validating Encryption\n");
    printf("********************************************************************************\n");
    for(i = 0; i < NUM_TESTS; ++i)
    {
        unsigned char output[16];
        struct itc_aes128_context ctx;
        int pass = 0;

        printf("Checking Test Vector %d:\n", i+1);

        itc_aes128_init(&ctx, test_vectors[i]->key);
        itc_aes128_encrypt(&ctx, test_vectors[i]->plaintext, output);
        pass = !compare128(test_vectors[i]->ciphertext, output);
        if(pass)
            ++pass_count;
        else
            ++fail_count;

        printf("  Key:                 ");
        print128(test_vectors[i]->key);
        printf("  Plaintext:           ");
        print128(test_vectors[i]->plaintext);
        printf("  Output:              ");
        print128(output);
        printf("  Expected Ciphertext: ");
        print128(test_vectors[i]->ciphertext);
        printf( pass ? "[PASSED]" : "[FAILED]");
        printf("\n\n");
    }

    printf("********************************************************************************\n");
    printf("                            Validating Decryption\n");
    printf("********************************************************************************\n");
    for(i = 0; i < NUM_TESTS; ++i)
    {
        unsigned char output[16];
        struct itc_aes128_context ctx;
        int pass = 0;

        printf("Checking Test Vector %d:\n", i+1);

        itc_aes128_init(&ctx, test_vectors[i]->key);
        itc_aes128_decrypt(&ctx, test_vectors[i]->ciphertext, output);
        pass = !compare128(test_vectors[i]->plaintext, output);
        
        if(pass)
            ++pass_count;
        else
            ++fail_count;

        printf("  Key:                ");
        print128(test_vectors[i]->key);
        printf("  Ciphertext:         ");
        print128(test_vectors[i]->ciphertext);
        printf("  Output:             ");
        print128(output);
        printf("  Expected Plaintext: ");
        print128(test_vectors[i]->plaintext);
        printf( pass ? "[PASSED]" : "[FAILED]");
        printf("\n\n");
    }

    printf("Testing finished. Passed %d/%d cases.\n", pass_count, pass_count + fail_count);

    //TOOD: performance testing
}

void print128(const unsigned char * block)
{
    int i;
    for(i = 0; i < 16; ++i)
    {
        printf("%02x ", block[i]);
    }
    printf("\n");
}

int compare128(const unsigned char * a, const unsigned char * b)
{
    int i;
    for(i = 0; i < 16; ++i)
    {
        if(a[i] != b[i])
            return -1;
    }
    return 0;
}