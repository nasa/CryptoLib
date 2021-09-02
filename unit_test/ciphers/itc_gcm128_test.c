#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "itc_gcm128.h"

#define MAX_LINE_SIZE    2048  // Max line size. If it is longer in a file, bad things will happen.

// todo: API tests (check error returns for bad input)
// todo: decryption tests

enum pass_fail
{
    FAIL,
    PASS
};

enum test_mode
{
    ENCRYPT,
    DECRYPT
};

struct gcm128_test_vector
{
    unsigned char key[16];
    unsigned char iv[12];
    size_t aad_length;
    unsigned char * aad;
    size_t data_length;
    unsigned char * plaintext;
    unsigned char * ciphertext;
    unsigned char tag[16];
    enum pass_fail tag_valid;
};

// releases any memory that was allocated for aad/plaintext/ciphertext. does not free struct itself.
static void uninit_test_vector(struct gcm128_test_vector *tv)
{
    if(tv != NULL)
    {      
        tv->aad_length = 0;
        tv->data_length = 0;

        if(tv->aad != NULL)
        {
            free(tv->aad);
            tv->aad = NULL;
        }
        if(tv->plaintext != NULL)
        {
            free(tv->plaintext);
            tv->plaintext = NULL;

        }
        if(tv->ciphertext != NULL)
        {
            free(tv->ciphertext);
            tv->ciphertext = NULL;
        }
    }
}

// allocates space for aad/plaintext/ciphertext
static int init_test_vector(struct gcm128_test_vector *tv, size_t aad_length, size_t data_length)
{
    assert(tv != NULL);

    tv->aad_length = aad_length;
    tv->data_length = data_length;
    tv->aad = NULL;
    tv->plaintext = NULL;
    tv->ciphertext = NULL;

    if(aad_length > 0)
    {
        tv->aad = malloc(aad_length * sizeof(unsigned char));
    }

    if(data_length > 0)
    {
        tv->plaintext = malloc(data_length * sizeof(unsigned char));
        tv->ciphertext = malloc(data_length * sizeof(unsigned char));
    }

    if( (aad_length > 0 && tv->aad == NULL) || 
        (data_length > 0 && (tv->plaintext == NULL || tv->ciphertext == NULL)) )
    {
        uninit_test_vector(tv);
        return -1;
    }
    else
    {
        return 0;
    }

}

static void print_hex(const unsigned char * hex, size_t length)
{
    size_t i;

    for(i = 0; i < length; ++i)
    {
        printf("%02x ", hex[i]);
    }
    printf("\n");
}

//zero if equal
static int compare_hex(const unsigned char * hex1, const unsigned char * hex2, size_t length)
{
    size_t i;

    for(i = 0; i < length; ++i)
    {
        if(hex1[i] != hex2[i])
            return -1;
    }
    return 0;
}

//Parses integer value of simple key/value pair. specifier should specify everything before the number.
// e.g., for line [Keylen = 128], to get 128 out, call as: parse_field(line, "[Keylen = ", val_out);
static int parse_field(const char *line, const char * specifier, long int * value)
{
    const char * match;

    match = strstr(line, specifier);

    if(match != NULL) //found match!
    {
        //match points to start of matching string - add strlen of specifier to get start of num
        long int tempValue = strtol(match + strlen(specifier), NULL, 10);
        
        //not really any point in checking for the error values of strtol...
        *value = tempValue;
        return 0;
    }
    else
    {
        return -1;
    }
}

//parses string of hex until a NULL character is found. Returns number of unsigned char's parsed.
// max specifies maximum number of unsigned chars that can be placed in output
static int parse_hex(const char *hex_string, const char * specifier, unsigned char * output, int max)
{
    assert(hex_string != NULL);

    const char *string;
    int index = 0;
    int bytes_parsed = 0;
    unsigned int temp;

    if(specifier != NULL)
    {
        const char * match = strstr(hex_string, specifier);
        if(match == NULL)
            return 0;

        string = match + strlen(specifier);
    }
    else
    {
        string = hex_string;
    }

    //short-circuit evaluation should prevent out-of-bounds access on [index+1]
    while(bytes_parsed <= max)
    {
        if(string[index] == '\0' || string[index] == '\n')
            break;
        if(string[index+1] == '\0' || string[index+1] == '\n')
            break;

        if(sscanf(string+index, "%2x", &temp) != 1)
        {
            printf("failed to parse a byte from hex string.\n");
            break;
        }
        else
        {
            output[bytes_parsed] = (unsigned char)temp;
            ++bytes_parsed;
            index += 2;
        }
    }

    return bytes_parsed;
}

// Reads the file stream to parse the header info.
static int parse_test_header(FILE *fp, long int * keylen, long int * ivlen, long int * ptlen, long int * aadlen, long int * taglen)
{
    char tempLine[MAX_LINE_SIZE];
    int returnVal = -1; // default value (failed)

    //read until find a line that starts "[Keylen = "
    while(feof(fp) == 0)
    {
        if(fgets(tempLine, MAX_LINE_SIZE, fp) == tempLine)
        {
            //is line a match for Keylen?
            if(parse_field(tempLine, "[Keylen = ", keylen))
            {
                // didn't find, keep looking.
                continue;
            }
            else
            {
                // woohoo! found they key length! find the other fields
                if(fgets(tempLine, MAX_LINE_SIZE, fp) == tempLine) // IVlen line
                {
                    if(parse_field(tempLine, "[IVlen = ", ivlen)) 
                       break;
                }
                else
                {
                    break;
                }

                if(fgets(tempLine, MAX_LINE_SIZE, fp) == tempLine) // PTlen line
                {
                    if(parse_field(tempLine, "[PTlen = ", ptlen))
                       break;
                }
                else
                {
                    break;
                }

                if(fgets(tempLine, MAX_LINE_SIZE, fp) == tempLine) // AADlen line
                {
                    if(parse_field(tempLine, "[AADlen = ", aadlen))
                       break;
                }
                else
                {
                    break;
                }

                if(fgets(tempLine, MAX_LINE_SIZE, fp) == tempLine) // Taglen line
                {
                    if(parse_field(tempLine, "[Taglen = ", taglen))
                       break;
                }
                else
                {
                    break;
                }

                returnVal = 0;
                break;
            }
        }
        else
        {
            // error reading from file (EOF or other issue)
            break;
        }
    }

    return returnVal;
}

// reads from current location in file stream and tries to find the next test. Return 0 if success.
static int get_next_test(FILE *fp, struct gcm128_test_vector *tv, enum test_mode mode)
{
    char tempLine[MAX_LINE_SIZE];
    int returnCode = -1; // default value (failed)
    long int count;

    //then read the next 6 lines to get Key, IV, PT, AAD, CT, and Tag

    while(feof(fp) == 0)
    {
        if(fgets(tempLine, MAX_LINE_SIZE, fp) == tempLine)
        {
            if(parse_field(tempLine, "Count = ", &count))
            {
                // didn't find, keep looking.
                continue;
            }

            // Key 
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read Key line\n");
                break;
            }

            if(parse_hex(tempLine, "Key = ", tv->key, sizeof(tv->key)) != sizeof(tv->key))
            {
                printf("could not parse key\n");
                break;
            }

            // IV
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read IV line\n");
                break;
            }

            if(parse_hex(tempLine, "IV = ", tv->iv, sizeof(tv->iv)) != sizeof(tv->iv))
            {
                printf("could not parse IV\n");
                break;
            }

            // PT or CT
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read %s line\n", mode == ENCRYPT ? "PT" : "CT");
                break;
            }

            if(tv->data_length > 0)
            {
                if(mode == ENCRYPT)
                {    
                    if((int) parse_hex(tempLine, "PT = ", tv->plaintext, tv->data_length) != (int) tv->data_length)
                    {
                        printf("could not parse PT\n");
                        break;
                    }
                }
                else
                {
                    if((int) parse_hex(tempLine, "CT = ", tv->ciphertext, tv->data_length) != (int) tv->data_length)
                    {
                        printf("could not parse CT\n");
                        break;
                    }
                }
            }

            // AAD
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read AAD line\n");
                break;
            }

            if(tv->aad_length > 0)
            {
                if((int) parse_hex(tempLine, "AAD = ", tv->aad, tv->aad_length) != (int) tv->aad_length)
                {
                    printf("could not parse AAD\n");
                    break;
                }
            }

            // CT
            if(mode == ENCRYPT)
            {
                if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
                {
                    printf("could not read CT line\n");
                    break;
                }

                if(tv->data_length > 0)
                {
                    if((int) parse_hex(tempLine, "CT = ", tv->ciphertext, tv->data_length) != (int) tv->data_length)
                    {
                        printf("could not parse CT\n");
                        break;
                    }
                }
            }

            // Tag
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read Tag line\n");
                break;
            }

            if((int) parse_hex(tempLine, "Tag = ", tv->tag, sizeof(tv->tag)) != (int) sizeof(tv->tag))
            {
                printf("could not parse Tag\n");
                break;
            }

            //FAIL or plaintext if decrypt mode
            if(mode == DECRYPT)
            {
                if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
                {
                    printf("could not read FAIL/PT line\n");
                    break;
                }

                if(strncmp("FAIL", tempLine, 4) == 0)
                {  
                    tv->tag_valid = FAIL;
                }
                else 
                {
                    tv->tag_valid = PASS;
                    if(tv->data_length > 0)
                    { 
                        if((int) parse_hex(tempLine, "PT = ", tv->plaintext, tv->data_length) != (int) tv->data_length)
                        {                            
                            printf("could not parse PT\n");
                            break;
                        }
                    }
                }
            }

            returnCode = 0;
            break;
        }
    }

    return returnCode;
}

static int run_encryption_test(struct gcm128_test_vector *tv)
{
    struct itc_gcm128_context ctx;
    unsigned char tag[16];
    int err, returnCode = -1;

    unsigned char * computed_ciphertext = NULL;

    itc_gcm128_init(&ctx, tv->key);

    err = itc_gcm128_encrypt_start(&ctx, tv->iv, tv->aad_length, tv->aad);
    if(err != ITC_GCM128_SUCCESS)
    {
        printf("Error during call to itc_gcm128_encrypt_start()\n");
        returnCode = -1;
        goto exit;
    }

    if(tv->data_length > 0)
    {
        computed_ciphertext = malloc(tv->data_length * sizeof(unsigned char));
        if(computed_ciphertext == NULL)
        {
            printf("Could not allocate memory to store ciphertext.\n");
            returnCode = -1;
            goto exit;
        }
    }
    err = itc_gcm128_encrypt_update(&ctx, tv->data_length, tv->plaintext, computed_ciphertext);
    if(err != ITC_GCM128_SUCCESS)
    {
        printf("Error during call to itc_gcm128_encrypt_update()\n");
        returnCode = -1;
        goto exit;
    }

    err = itc_gcm128_encrypt_finish(&ctx, tag);
    if(err != ITC_GCM128_SUCCESS)
    {
        printf("Error during call to itc_gcm128_encrypt_finish()\n");
        returnCode = -1;
        goto exit;
    }

    //compare tags
    printf("Expected tag: ");    
    print_hex(tv->tag, 16);
    printf("Computed tag: ");
    print_hex(tag, 16);

    if(compare_hex(tv->tag, tag, sizeof(tag)))
    {
        printf("Test FAILED! Tag does not match.\n");
        returnCode = -1;
        goto exit;
    }

    //compare plaintext/ciphertext
    if(tv->data_length > 0)
    {
        printf("Plaintext: ");
        print_hex(tv->plaintext, tv->data_length);
        printf("Expected Ciphertext: ");
        print_hex(tv->ciphertext, tv->data_length);
        printf("Computed Ciphertext: ");
        print_hex(computed_ciphertext, tv->data_length);

        if(compare_hex(tv->ciphertext, computed_ciphertext, tv->data_length))
        {
            printf("Test FAILED! ciphertext does not match.\n");
            returnCode = -1;
            goto exit;
        }
    }

    printf("Test PASSED!\n\n");
    returnCode = 0;

exit:
    if(computed_ciphertext != NULL)
        free(computed_ciphertext);
    return returnCode;

}

static int run_decryption_test(struct gcm128_test_vector *tv)
{
    struct itc_gcm128_context ctx;
    int err, returnCode = -1;

    unsigned char * computed_plaintext = NULL;

    itc_gcm128_init(&ctx, tv->key);

    err = itc_gcm128_decrypt_start(&ctx, tv->iv, tv->aad_length, tv->aad);
    if(err != ITC_GCM128_SUCCESS)
    {
        printf("Error during call to itc_gcm128_decrypt_start()\n");
        returnCode = -1;
        goto exit;
    }

    if(tv->data_length > 0)
    {
        computed_plaintext = malloc(tv->data_length * sizeof(unsigned char));
        if(computed_plaintext == NULL)
        {
            printf("Could not allocate memory to store plaintext.\n");
            returnCode = -1;
            goto exit;
        }
    }
    err = itc_gcm128_decrypt_update(&ctx, tv->data_length, tv->ciphertext, computed_plaintext);
    if(err != ITC_GCM128_SUCCESS)
    {
        printf("Error during call to itc_gcm128_decrypt_update()\n");
        returnCode = -1;
        goto exit;
    }

    err = itc_gcm128_decrypt_finish(&ctx, tv->tag);

    printf("Expected result: Tag %s\n", tv->tag_valid == PASS ? "Passed" : "Failed");
    printf("Actual result:   Tag %s\n", err == ITC_GCM128_SUCCESS ? "Passed" : "Failed");

    // err should either be success if tag matched, or bad_tag if not
    if(err == ITC_GCM128_SUCCESS && tv->tag_valid == FAIL)
    {
        printf("Test FAILED! Tag should have been invalid but was accepted.\n");
        returnCode = -1;
        goto exit;
    }
    if(err == ITC_GCM128_BAD_TAG && tv->tag_valid == PASS)
    {
        printf("Test FAILED! Tag should have been valid but was rejected.\n");
        returnCode = -1;
        goto exit;
    }

    // if tag_valid == PASS && err == SUCCESS, or tag_valid == FAIL && err == BAD_TAG, continue...

    //compare plaintext/ciphertext (only if it was supposed to pass)
    if(tv->tag_valid == PASS && tv->data_length > 0)
    {
        printf("Ciphertext: ");
        print_hex(tv->ciphertext, tv->data_length);
        printf("Expected Plaintext: ");
        print_hex(tv->plaintext, tv->data_length);
        printf("Computed Plaintext: ");
        print_hex(computed_plaintext, tv->data_length);

        if(compare_hex(tv->plaintext, computed_plaintext, tv->data_length))
        {
            printf("Test FAILED! plaintext does not match.\n");
            returnCode = -1;
            goto exit;
        }
    }

    printf("Test PASSED!\n\n");
    returnCode = 0;

exit:
    if(computed_plaintext != NULL)
        free(computed_plaintext);
    return returnCode;
}


/* Runs encryption tests from file. Files must be extremely well-formed, parser is very brittle.
 *
 * \param filepath     file path 
*/
static void run_tests(const char *filepath, enum test_mode mode)
{
    FILE *fp;
    int err, result = -1;
    struct gcm128_test_vector test;
    int testsPassed = 0, testsFailed = 0;

    assert(filepath != NULL);

    fp = fopen(filepath, "r");

    if(fp == NULL)
    {
        perror("Could not open file");
        goto exit;
    }

    long int keyLength, ivLength, ptLength, aadLength, tagLength;

    err = parse_test_header(fp, &keyLength, &ivLength, &ptLength, &aadLength, &tagLength);
    if(err)
    {
        printf("error parsing header.\n");
        goto exit;
    }

    printf("Test attributes for file %s:\n\tKey Length: %ld\n\tIV  Length: %ld\n\tPT  Length: %ld\n\tAAD Length: %ld\n\tTag Length: %ld\n",
            filepath, keyLength, ivLength, ptLength, aadLength, tagLength);

    if(keyLength != 128 || ivLength != 96 || tagLength != 128)
    {
        printf("Test attributes not valid. Ignoring file.\n");
        goto exit;
    }

    //divide by 8 to get length in bytes
    if(init_test_vector(&test, aadLength/8, ptLength/8))
    {
        printf("Could not initialized test struct\n");
        goto exit;
    }

    while( (feof(fp) == 0) )
    {
        err = get_next_test(fp, &test, mode);

        if(err)
        {
            printf("Could not parse test. Checking for another next one...\n");
        }
        else
        {
            //Run test!
            printf("\nRunning test %d...\n", testsFailed + testsPassed + 1);

            if(mode == ENCRYPT)
            {
                result = run_encryption_test(&test);
            }
            else
            {
                result = run_decryption_test(&test);
            }

            if(result)
                ++testsFailed;
            else
                ++testsPassed;
        }
    }

    printf("Finished running tests. %d/%d cases passed.\n", testsPassed, testsPassed+testsFailed);

exit:
    uninit_test_vector(&test);
    if(fp != NULL) 
        fclose(fp);
}

int main(int argc, char* argv[])
{
    if(argc < 3)
    {
        printf("Missing arguments. usage:\n\t%s <-e|-d> <test_file>\n", argv[0]);
        return -1;
    }

    //check arg 1 for encrypt or decrypt
    if(strncmp("-e", argv[1], 2) == 0)
    {
        run_tests(argv[2], ENCRYPT);
    }
    else if(strncmp("-d", argv[1], 2) == 0)
    {
        run_tests(argv[2], DECRYPT);
    }
    else
    {
        printf("Unexpected value for mode. Must be -e for an encryption test or -d for decryption test\n");
        return -1;
    }

    return 0;
}