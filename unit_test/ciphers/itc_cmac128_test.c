#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "itc_cmac128.h"

#define MAX_LINE_SIZE    2048

enum pass_fail
{
    FAIL,
    PASS
};

struct cmac128_test_vector
{
    unsigned char key[16];
    size_t length;
    unsigned char * message;
    unsigned char tag[16];
    enum pass_fail tag_valid;
};

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

static void uninit_test_vector(struct cmac128_test_vector *tv)
{
    if(tv != NULL)
    {
        tv->length = 0;
        if(tv->message != NULL)
        {
            free(tv->message);
            tv->message = NULL;
        }
    }
}

static int init_test_vector(struct cmac128_test_vector *tv, size_t length)
{
    assert(tv != NULL);

    tv->length = length;
    tv->message = NULL;

    if(length > 0)
    {
        tv->message = malloc(length * sizeof(unsigned char));

        if(tv->message == NULL)
        {            
            uninit_test_vector(tv);
            return -1;
        }
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

static int get_next_test(FILE *fp, struct cmac128_test_vector *tv)
{
    char tempLine[MAX_LINE_SIZE];
    int returnCode = -1; // default value (failed)
    long int count, keyLength, msgLength, tagLength;

    while(feof(fp) == 0)
    {
        if(fgets(tempLine, MAX_LINE_SIZE, fp) == tempLine)
        {

            if(parse_field(tempLine, "Count = ", &count))
            {
                // didn't find, keep looking.
                continue;
            }

            // Key Length
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read Key length line\n");
                break;
            }

            if(parse_field(tempLine, "Klen = ", &keyLength))
            {
                printf("Could not parse key length\n");
                break;
            }

            if(keyLength != 16)
            {
                printf("Key length is incorrect.\n");
                break;
            }

            // Message Length
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read message length line\n");
                break;
            }

            if(parse_field(tempLine, "Mlen = ", &msgLength))
            {
                printf("Could not parse message length\n");
                break;
            }

            // Tag Length
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read tag length line\n");
                break;
            }

            if(parse_field(tempLine, "Tlen = ", &tagLength))
            {
                printf("Could not parse tag length\n");
                break;
            }

            if(tagLength != 16)
            {
                printf("Tag length is incorrect.\n");
                break;
            }

            // initialize test vector
            if(init_test_vector(tv, msgLength))
            {
                printf("Could not initialize test struct\n");
                break;
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

            // Message
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read Message line\n");
                break;
            }

            if(tv->length > 0)
            {
                if((int) parse_hex(tempLine, "Msg = ", tv->message, tv->length) != (int) tv->length)
                {
                    printf("could not parse message\n");
                    break;
                }
            }

            // Mac
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read Mac line\n");
                break;
            }

            if(parse_hex(tempLine, "Mac = ", tv->tag, sizeof(tv->tag)) != sizeof(tv->tag))
            {
                printf("could not parse tag\n");
                break;
            }

            // Result
            if(fgets(tempLine, MAX_LINE_SIZE, fp) != tempLine) 
            {
                printf("could not read Result line\n");
                break;
            }

            if(strncmp("Result = F", tempLine, 10) == 0)
            {
                tv->tag_valid = FAIL;
            }
            else if(strncmp("Result = P", tempLine, 10) == 0)
            {
                tv->tag_valid = PASS;
            }
            else
            {
                printf("Could not parse Result line\n");
                break;
            }

            returnCode = 0;
            break;
        }
    }

    return returnCode;
}

static int run_mac_validation_test(struct cmac128_test_vector * tv)
{
    struct itc_cmac128_context ctx;
    unsigned char temp_tag[16];
    int err;

    itc_cmac128_init(&ctx, tv->key);

    err = itc_cmac128_generate_tag(&ctx, tv->length, tv->message, temp_tag);

    if(err != ITC_CMAC128_SUCCESS)
    {
        printf("Call to itc_cmac128_generate_tag() failed.\n\n");
        return -1;
    }

    err = compare_hex(tv->tag, temp_tag, sizeof(tv->tag));

    printf("Provided Tag: ");
    print_hex(tv->tag, sizeof(tv->tag));
    printf("Computed Tag: ");
    print_hex(temp_tag, sizeof(temp_tag));
    printf("Expected Result: Tag %s\n", tv->tag_valid == PASS ? "Passed" : "Failed" );
    printf("Actual Result:   Tag %s\n", err == 0 ? "Passed" : "Failed");

    if(tv->tag_valid == PASS && err != 0)
    {
        printf("Test FAILED! Tag should have been valid but was rejected.\n\n");
        return -1;
    }
    else if(tv->tag_valid == FAIL && err == 0)
    {
        printf("Test FAILED! Tag should have been rejected but was passed.\n\n");
        return -1;
    }
    else
    {
        printf("Test PASSED!\n\n");
        return 0;
    }
}

static void run_tests(const char *filepath)
{
    FILE *fp;
    int err, result;
    int testsPassed = 0, testsFailed = 0;
    struct cmac128_test_vector test;

    assert(filepath != NULL);

    fp = fopen(filepath, "r");

    if(fp == NULL)
    {
        perror("Could not open file");
        goto exit;
    }

    init_test_vector(&test, 0);

    while( (feof(fp) == 0) )
    {
        uninit_test_vector(&test);
        err = get_next_test(fp, &test);

        if(err)
        {
            printf("Could not parse test. Checking for another next one...\n");
        }
        else
        {
            //Run test!
            printf("\nRunning test %d...\n", testsFailed + testsPassed + 1);

            result = run_mac_validation_test(&test);

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


int main(int argc, char * argv[])
{
    if(argc < 2)
    {
        printf("Missing arguments. usage:\n\t%s <test_file>\n", argv[0]);
        return -1;
    }

    run_tests(argv[1]);

    return 0;
}