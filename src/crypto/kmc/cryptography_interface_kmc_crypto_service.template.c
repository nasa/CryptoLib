/*
 * Copyright 2021, by the California Institute of Technology.
 * ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
 * Any commercial use must be negotiated with the Office of Technology
 * Transfer at the California Institute of Technology.
 *
 * This software may be subject to U.S. export control laws. By accepting
 * this software, the user agrees to comply with all applicable U.S.
 * export laws and regulations. User has the responsibility to obtain
 * export licenses, or other export authority as may be required before
 * exporting such information to foreign countries or providing access to
 * foreign persons.
 */

#include "crypto_error.h"
#include "cryptography_interface.h"
#include "crypto.h"

#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

// base64 & base64url encoding/decoding libraries
#include "base64url.h"
#include "base64.h"
// JSON marshalling libraries
#include "jsmn.h"

#define CAM_MAX_AUTH_RETRIES 4

// libcurl call-back response handling Structures
typedef struct
{
    char  *response;
    size_t size;
} memory_write;
#define MEMORY_WRITE_SIZE (sizeof(memory_write))
typedef struct
{
    char  *response;
    size_t size;
} memory_read;
#define MEMORY_READ_SIZE (sizeof(memory_read))

// Cryptography Interface Initialization & Management Functions
static int32_t cryptography_config(void);
static int32_t cryptography_init(void);
static int32_t cryptography_shutdown(void);
// Cryptography Interface Functions
static int32_t cryptography_encrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                    uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                    uint32_t iv_len, uint8_t *ecs, uint8_t padding, char *cam_cookies);
static int32_t cryptography_decrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                    uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                    uint32_t iv_len, uint8_t *ecs, uint8_t *acs, char *cam_cookies);
static int32_t cryptography_authenticate(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                         uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                         uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad,
                                         uint32_t aad_len, uint8_t ecs, uint8_t acs, char *cam_cookies);
static int32_t cryptography_validate_authentication(uint8_t *data_out, size_t len_data_out, const uint8_t *data_in,
                                                    const size_t len_data_in, uint8_t *key, uint32_t len_key,
                                                    SecurityAssociation_t *sa_ptr, const uint8_t *iv, uint32_t iv_len,
                                                    const uint8_t *mac, uint32_t mac_size, const uint8_t *aad,
                                                    uint32_t aad_len, uint8_t ecs, uint8_t acs, char *cam_cookies);
static int32_t cryptography_aead_encrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                         uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                         uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad,
                                         uint32_t aad_len, uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t *ecs, uint8_t *acs, char *cam_cookies);
static int32_t cryptography_aead_decrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                         uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                         uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad,
                                         uint32_t aad_len, uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t *ecs, uint8_t *acs, char *cam_cookies);
static int32_t cryptography_get_acs_algo(int8_t algo_enum);
static int32_t cryptography_get_ecs_algo(int8_t algo_enum);

// Local support functions
static int32_t get_auth_algorithm_from_acs(uint8_t acs_enum, const char **algo_ptr);
static int32_t get_cam_sso_token(void);
static int32_t initialize_kerberos_keytab_file_login(void);
static int32_t curl_perform_with_cam_retries(CURL *curl_handle, memory_write *chunk_write, memory_read *chunk_read);

// libcurl call back and support function declarations
static int32_t configure_curl_connect_opts(CURL *curl, char *cam_cookies);
static int32_t handle_cam_cookies(CURL *curl, char *cam_cookies);
static int32_t curl_response_error_check(CURL *curl, char *response);
static size_t  write_callback(void *data, size_t size, size_t nmemb, void *userp);
static size_t  read_callback(char *dest, size_t size, size_t nmemb, void *userp);
static char   *int_to_str(uint32_t int_src, uint32_t *converted_str_length);
static int     jsoneq(const char *json, jsmntok_t *tok, const char *s);

/*
** Module Variables
*/
// Cryptography Interface
static CryptographyInterfaceStruct cryptography_if_struct;
static CURL                       *curl;
struct curl_slist                 *http_headers_list;
// KMC Crypto Service Endpoints
static char *kmc_root_uri;
// static const char* status_endpoint = "/status";
static const char *encrypt_endpoint         = "encrypt?keyRef=%s&transformation=%s&iv=%s";
static const char *encrypt_endpoint_null_iv = "encrypt?keyRef=%s&transformation=%s";
static const char *encrypt_offset_endpoint  = "encrypt?keyRef=%s&transformation=%s&iv=%s&encryptOffset=%s&macLength=%s";
static const char *encrypt_offset_endpoint_null_iv =
    "encrypt?keyRef=%s&transformation=%s&encryptOffset=%s&macLength=%s";
static const char *decrypt_endpoint = "decrypt?metadata=keyLength:%s,keyRef:%s,cipherTransformation:%s,initialVector:%"
                                      "s,cryptoAlgorithm:%s,metadataType:EncryptionMetadata";
static const char *decrypt_offset_endpoint =
    "decrypt?metadata=keyLength:%s,keyRef:%s,cipherTransformation:%s,initialVector:%s,cryptoAlgorithm:%s,macLength:%s,"
    "metadataType:EncryptionMetadata,encryptOffset:%s";
static const char *icv_create_endpoint = "icv-create?keyRef=%s";
static const char *icv_verify_endpoint = "icv-verify?metadata=integrityCheckValue:%s,keyRef:%s,cryptoAlgorithm:%s,"
                                         "macLength:%s,metadataType:IntegrityCheckMetadata";

// CAM Security Endpoints
static const char *cam_kerberos_uri = "%s/cam-api/ssoToken?loginMethod=kerberos";

// Supported KMC Cipher Transformation Strings
static const char *AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
static const char *AES_CBC_TRANSFORMATION = "AES/CBC/PKCS5Padding";
static const char *AES_CRYPTO_ALGORITHM   = "AES";
// static const char* AES_CBC_TRANSFORMATION="AES/CBC/PKCS5Padding";
static const char *AES_CMAC_TRANSFORMATION = "AESCMAC";
static const char *HMAC_SHA256             = "HmacSHA256";
static const char *HMAC_SHA512             = "HmacSHA512";
// static const char* AES_DES_CMAC_TRANSFORMATION="DESedeCMAC";

CryptographyInterface get_cryptography_interface_kmc_crypto_service(void)
{
    cryptography_if_struct.cryptography_config                  = cryptography_config;
    cryptography_if_struct.cryptography_init                    = cryptography_init;
    cryptography_if_struct.cryptography_shutdown                = cryptography_shutdown;
    cryptography_if_struct.cryptography_encrypt                 = cryptography_encrypt;
    cryptography_if_struct.cryptography_decrypt                 = cryptography_decrypt;
    cryptography_if_struct.cryptography_authenticate            = cryptography_authenticate;
    cryptography_if_struct.cryptography_validate_authentication = cryptography_validate_authentication;
    cryptography_if_struct.cryptography_aead_encrypt            = cryptography_aead_encrypt;
    cryptography_if_struct.cryptography_aead_decrypt            = cryptography_aead_decrypt;
    cryptography_if_struct.cryptography_get_acs_algo            = cryptography_get_acs_algo;
    cryptography_if_struct.cryptography_get_ecs_algo            = cryptography_get_ecs_algo;
    return &cryptography_if_struct;
}

static int32_t cryptography_config(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Error out if Crypto_Config_Kmc_Crypto_Service(...) function was not called before intializing library.
    if (cryptography_kmc_crypto_config == NULL)
    {
        fprintf(stderr, "You must configure the KMC Crypto Service before starting the interface!\n");
        status = CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIGURATION_NOT_COMPLETE;
        return status;
    }

    if (curl)
    {
        // Determine length of port and convert to string for use in URL
        uint32_t port_str_len = 0;
        char    *port_str     = int_to_str(cryptography_kmc_crypto_config->kmc_crypto_port, &port_str_len);

        // Form Root URI
        // len(protocol)+len(://)+len(hostname)+ len(:) + len(port_str) + len(/) + len(app_uri) + strlen('\0')
        uint32_t len_root_uri = strlen(cryptography_kmc_crypto_config->protocol) + 3 +            // "://"
                                strlen(cryptography_kmc_crypto_config->kmc_crypto_hostname) + 1 + // ":"
                                port_str_len + 1 +                                                // "/"
                                strlen(cryptography_kmc_crypto_config->kmc_crypto_app_uri) + 2;   // "/\0"

        kmc_root_uri = malloc(len_root_uri);
        snprintf(kmc_root_uri, len_root_uri, "%s://%s:%s/%s/", cryptography_kmc_crypto_config->protocol,
                 cryptography_kmc_crypto_config->kmc_crypto_hostname, port_str,
                 cryptography_kmc_crypto_config->kmc_crypto_app_uri);

        free(port_str);
        // KMC Crypto Service status check is impossible in certain CAM configs, commenting it out.
        //  Also, when this library is started up (EG by SDLS service), there's no guarantee the Crypto Service is
        //  available at config time.
        // char* status_uri = (char*) malloc(strlen(kmc_root_uri)+strlen(status_endpoint) + 1);
        // status_uri[0] = '\0';
        // strcat(status_uri, kmc_root_uri);
        // strcat(status_uri, status_endpoint);
#ifdef DEBUG
        printf("Setting up cURL connection to KMC Crypto Service with Params:\n");
        printf("\tKMC Root URI: %s\n", kmc_root_uri);
        // printf("\tKMC Status URL: %s\n",status_uri);
        // printf("\tPort: %d\n",cryptography_kmc_crypto_config->kmc_crypto_port);
        printf("\tSSL Client Cert: %s\n", cryptography_kmc_crypto_config->mtls_client_cert_path);
        printf("\tSSL Client Key: %s\n", cryptography_kmc_crypto_config->mtls_client_key_path);
        printf("\tSSL CA Bundle: %s\n", cryptography_kmc_crypto_config->mtls_ca_bundle);
#endif
        // status = configure_curl_connect_opts(curl, NULL);
        // if(status != CRYPTO_LIB_SUCCESS)
        //{
        //     return status;
        // }
        // curl_easy_setopt(curl, CURLOPT_URL, status_uri);

        // memory_write* chunk = calloc(1,MEMORY_WRITE_SIZE);
        ///* send all data to this function  */
        // curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        ///* we pass our 'chunk' struct to the callback function */
        // curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void* )chunk);

        // CURLcode res;
        // res = curl_easy_perform(curl);

        // if(res != CURLE_OK) // This is not return code, this is successful response!
        //{
        //     status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_CONNECTION_ERROR;
        //     fprintf(stderr, "curl_easy_perform() failed: %s\n",
        //             curl_easy_strerror(res));
        //     free(status_uri);
        //     free(kmc_root_uri);
        //     return status;
        // }

        // if(chunk->response == NULL) // No response, possibly because service is CAM secured.
        //{
        //     status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_EMPTY_RESPONSE;
        //     fprintf(stderr, "curl_easy_perform() unexpected empty response: \n%s\n",
        //             "Empty Crypto Service response can be caused by CAM security, is CAM configured?");
        //     free(status_uri);
        //     return status;
        // }

        //#ifdef DEBUG
        //        printf("cURL response:\n\t %s\n",chunk->response);
        //#endif
        // free(status_uri);
    }
    return status;
}
static int32_t cryptography_init(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    curl           = curl_easy_init();
    curl_global_init(CURL_GLOBAL_ALL);
    http_headers_list = NULL;
    // Prepare HTTP headers list
    http_headers_list = curl_slist_append(http_headers_list, "Content-Type: application/octet-stream");
    // http_headers_list = curl_slist_append(http_headers_list, "Accept: application/json");
    // curl_slist_append(http_headers_list, "Content-Type: application/json");
    // http_headers_list = curl_slist_append(http_headers_list, "charset: utf-8");

    if (curl == NULL)
    {
        status = CRYPTOGRAPHY_KMC_CURL_INITIALIZATION_FAILURE;
    }
    kmc_root_uri = NULL;
    return status;
}
static int32_t cryptography_shutdown(void)
{
    if (curl)
    {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
    }
    if (http_headers_list != NULL)
    {
        curl_slist_free_all(http_headers_list);
    }
    if (kmc_root_uri != NULL)
    {
        free(kmc_root_uri);
    }
    return CRYPTO_LIB_SUCCESS;
}

static int32_t cryptography_encrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                    uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                    uint32_t iv_len, uint8_t *ecs, uint8_t padding, char *cam_cookies)
{

    int32_t status = CRYPTO_LIB_SUCCESS;
    key            = key;     // Direct key input is not supported in KMC interface
    len_key        = len_key; // Direct key input is not supported in KMC interface

    // Remove pre-padding to block (KMC does not want it)
    if (*ecs == CRYPTO_CIPHER_AES256_CBC && padding > 0)
    {
        len_data_in = len_data_in - padding;
    }

#ifdef DEBUG
    printf("PADLENGTH FIELD: 0x%02x\n", *(data_in - sa_ptr->shplf_len));
#endif

    curl_easy_reset(curl);
    status = configure_curl_connect_opts(curl, cam_cookies);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }
    // Base64 URL encode IV for KMC REST Encrypt
    char *iv_base64 = (char *)calloc(1, B64ENCODE_OUT_SAFESIZE(iv_len) + 1);
    if (iv != NULL)
        base64urlEncode(iv, iv_len, iv_base64, NULL);

    uint8_t *encrypt_payload     = data_in;
    size_t   encrypt_payload_len = len_data_in;

#ifdef DEBUG
    printf("IV Base64 URL Encoded: %s\n", iv_base64);
#endif

    if (sa_ptr->ek_ref[0] == '\0')
    {
        status = CRYPTOGRAHPY_KMC_NULL_ENCRYPTION_KEY_REFERENCE_IN_SA;
        return status;
    }

    char *encrypt_uri;

    int len_encrypt_endpoint =
        strlen(encrypt_endpoint) + strlen(sa_ptr->ek_ref) + strlen(iv_base64) + strlen(AES_CBC_TRANSFORMATION);
    char *encrypt_endpoint_final = (char *)malloc(len_encrypt_endpoint);
    if (iv == NULL)
    {
        snprintf(encrypt_endpoint_final, len_encrypt_endpoint, encrypt_endpoint_null_iv, sa_ptr->ek_ref,
                 AES_CBC_TRANSFORMATION);
    }
    else
    {
        snprintf(encrypt_endpoint_final, len_encrypt_endpoint, encrypt_endpoint, sa_ptr->ek_ref, AES_CBC_TRANSFORMATION,
                 iv_base64);
    }

    encrypt_uri    = (char *)malloc(strlen(kmc_root_uri) + len_encrypt_endpoint);
    encrypt_uri[0] = '\0';
    strcat(encrypt_uri, kmc_root_uri);
    strcat(encrypt_uri, encrypt_endpoint_final);

#ifdef DEBUG
    printf("Encrypt URI: %s\n", encrypt_uri);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, encrypt_uri);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers_list);

    memory_write *chunk_write = (memory_write *)calloc(1, MEMORY_WRITE_SIZE);
    memory_read  *chunk_read  = (memory_read *)calloc(1, MEMORY_READ_SIZE);
    ;
    /* Configure CURL for POST */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_READDATA, chunk_read);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, chunk_write);

    /* size of the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)encrypt_payload_len);
    /* binary data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encrypt_payload);

#ifdef DEBUG
    printf("Data to Encrypt: \n");
    for (uint32_t i = 0; i < encrypt_payload_len; i++)
    {
        printf("%02x ", encrypt_payload[i]);
    }
    printf("\n");
#endif

    status = curl_perform_with_cam_retries(curl, chunk_write, chunk_read);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    /* JSON Response Handling */

    // Parse the JSON string response
    jsmn_parser p;
    jsmntok_t   t[64]; /* We expect no more than 64 JSON tokens */
    jsmn_init(&p);
    int parse_result = jsmn_parse(&p, chunk_write->response, strlen(chunk_write->response), t,
                                  64); // "chunk->response" is the char array holding the json content

    // Find the 'base64ciphertext' token
    if (parse_result < 0)
    {
        status = CRYPTOGRAHPY_KMC_CRYPTO_JSON_PARSE_ERROR;
        printf("Failed to parse JSON: %d\n", parse_result);
        return status;
    }

    int     json_idx             = 0;
    uint8_t ciphertext_found     = CRYPTO_FALSE;
    char   *ciphertext_base64    = NULL;
    char   *ciphertext_IV_base64 = NULL;
    for (json_idx = 1; json_idx < parse_result; json_idx++)
    {
        if (jsoneq(chunk_write->response, &t[json_idx], "metadata") == 0)
        {
            uint32_t len_ciphertext = t[json_idx + 1].end - t[json_idx + 1].start;
            ciphertext_IV_base64    = malloc(len_ciphertext + 1);
            memcpy(ciphertext_IV_base64, chunk_write->response + t[json_idx + 1].start, len_ciphertext);
            ciphertext_IV_base64[len_ciphertext] = '\0';

            char *line;
            char *token;
            char  temp_buff[256];
            for (line = strtok(ciphertext_IV_base64, ","); line != NULL; line = strtok(line + strlen(line) + 1, ","))
            {
                strncpy(temp_buff, line, sizeof(temp_buff));

                for (token = strtok(temp_buff, ":"); token != NULL; token = strtok(token + strlen(token) + 1, ":"))
                {
                    if (strcmp(token, "initialVector") == 0)
                    {
                        token                          = strtok(token + strlen(token) + 1, ":");
                        char  *ciphertext_token_base64 = malloc(strlen(token));
                        size_t cipher_text_token_len   = strlen(token);
                        memcpy(ciphertext_token_base64, token, cipher_text_token_len);
#ifdef DEBUG
                        printf("IV LENGTH: %d\n", iv_len);
                        printf("IV ENCODED Text: %s\nIV ENCODED TEXT LEN: %ld\n", ciphertext_token_base64,
                               cipher_text_token_len);
#endif
                        char  *iv_decoded     = malloc((iv_len)*2 + 1);
                        size_t iv_decoded_len = 0;
                        base64urlDecode(ciphertext_token_base64, cipher_text_token_len, iv_decoded, &iv_decoded_len);
#ifdef DEBUG
                        printf("Decoded IV Text Length: %ld\n", iv_decoded_len);
                        printf("Decoded IV Text: \n");
                        for (uint32_t i = 0; i < iv_decoded_len; i++)
                        {
                            printf("%02x ", (uint8_t)iv_decoded[i]);
                        }
                        printf("\n");
#endif

                        if (iv == NULL)
                        {
                            memcpy(data_out - sa_ptr->shsnf_len - sa_ptr->shivf_len - sa_ptr->shplf_len, iv_decoded,
                                   iv_decoded_len);
                        }
                        free(ciphertext_token_base64);
                        break;
                    }
                }
            }

            json_idx++;
            continue;
        }

        if (jsoneq(chunk_write->response, &t[json_idx], "base64ciphertext") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("Json base64ciphertext: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_ciphertext = t[json_idx + 1].end - t[json_idx + 1].start;
            ciphertext_base64       = malloc(len_ciphertext + 1);
            memcpy(ciphertext_base64, chunk_write->response + t[json_idx + 1].start, len_ciphertext);
            ciphertext_base64[len_ciphertext] = '\0';
#ifdef DEBUG
            printf("Parsed base64ciphertext: %s\n", ciphertext_base64);
#endif
            json_idx++;
            ciphertext_found = CRYPTO_TRUE;
            continue;
        }

        if (jsoneq(chunk_write->response, &t[json_idx], "httpCode") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("httpCode: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_httpcode  = t[json_idx + 1].end - t[json_idx + 1].start;
            char    *http_code_str = malloc(len_httpcode + 1);
            memcpy(http_code_str, chunk_write->response + t[json_idx + 1].start, len_httpcode);
            http_code_str[len_httpcode] = '\0';
            int http_code               = atoi(http_code_str);
#ifdef DEBUG
            printf("Parsed http code: %d\n", http_code);
#endif
            if (http_code != 200)
            {
                status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE;
                fprintf(stderr, "KMC Crypto Failure Response:\n%s\n", chunk_write->response);
                return status;
            }
            free(http_code_str);
            json_idx++;
            continue;
        }
    }
    if (ciphertext_found == CRYPTO_FALSE)
    {
        status = CRYPTOGRAHPY_KMC_CIPHER_TEXT_NOT_FOUND_IN_JSON_RESPONSE;
        return status;
    }

    /* JSON Response Handling End */

    uint8_t *ciphertext_decoded     = malloc((len_data_out)*2 + 1);
    size_t   ciphertext_decoded_len = 0;
    base64Decode(ciphertext_base64, strlen(ciphertext_base64), ciphertext_decoded, &ciphertext_decoded_len);
#ifdef DEBUG
    printf("Decoded Cipher Text Length: %ld\n", ciphertext_decoded_len);
    printf("Decoded Cipher Text: \n");
    printf("Data Out Len: %ld\n", len_data_out);
    for (uint32_t i = 0; i < ciphertext_decoded_len; i++)
    {
        printf("%02x ", ciphertext_decoded[i]);
    }
    printf("\n");
#endif

    // Crypto Service returns aad - cipher_text - tag
    memcpy(data_out, ciphertext_decoded, ciphertext_decoded_len);
    return status;
}

static int32_t cryptography_decrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                    uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                    uint32_t iv_len, uint8_t *ecs, uint8_t *acs, char *cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    key            = key; // Direct key input is not supported in KMC interface
    ecs            = ecs;
    acs            = acs;

    // Get the key length in bits, in string format.
    // TODO -- Parse the key length from the keyInfo endpoint of the Crypto Service!
    uint32_t key_len_in_bits         = len_key * 8; // 8 bits per byte.
    uint32_t key_len_in_bits_str_len = 0;
    char    *key_len_in_bits_str     = int_to_str(key_len_in_bits, &key_len_in_bits);

    curl_easy_reset(curl);
    status = configure_curl_connect_opts(curl, cam_cookies);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }
    // Base64 URL encode IV for KMC REST Encrypt
    char *iv_base64 = (char *)calloc(1, B64ENCODE_OUT_SAFESIZE(iv_len) + 1);
    base64urlEncode(iv, iv_len, iv_base64, NULL);

    uint8_t *decrypt_payload     = data_in;
    size_t   decrypt_payload_len = len_data_in;

#ifdef DEBUG
    printf("IV Base64 URL Encoded: %s\n", iv_base64);
#endif

    if (sa_ptr->ek_ref[0] == '\0')
    {
        status = CRYPTOGRAHPY_KMC_NULL_ENCRYPTION_KEY_REFERENCE_IN_SA;
        return status;
    }

    char *decrypt_uri;

    int len_decrypt_endpoint = strlen(decrypt_endpoint) + key_len_in_bits_str_len + strlen(sa_ptr->ek_ref) +
                               strlen(iv_base64) + strlen(AES_CBC_TRANSFORMATION) + strlen(AES_CRYPTO_ALGORITHM);
    char *decrypt_endpoint_final = (char *)malloc(len_decrypt_endpoint);

    snprintf(decrypt_endpoint_final, len_decrypt_endpoint, decrypt_endpoint, key_len_in_bits_str, sa_ptr->ek_ref,
             AES_CBC_TRANSFORMATION, iv_base64, AES_CRYPTO_ALGORITHM);
    free(key_len_in_bits_str);
    decrypt_uri    = (char *)malloc(strlen(kmc_root_uri) + len_decrypt_endpoint);
    decrypt_uri[0] = '\0';
    strcat(decrypt_uri, kmc_root_uri);
    strcat(decrypt_uri, decrypt_endpoint_final);

#ifdef DEBUG
    printf("Decrypt URI: %s\n", decrypt_uri);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, decrypt_uri);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers_list);

    memory_write *chunk_write = (memory_write *)calloc(1, MEMORY_WRITE_SIZE);
    memory_read  *chunk_read  = (memory_read *)calloc(1, MEMORY_READ_SIZE);
    ;

    /* Configure CURL for POST */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_READDATA, chunk_read);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, chunk_write);

    /* size of the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)decrypt_payload_len);
    /* binary data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, decrypt_payload);

#ifdef DEBUG
    printf("Len of decrypt payload: %ld\n", decrypt_payload_len);
    printf("Data to Decrypt: \n");
    for (uint32_t i = 0; i < decrypt_payload_len; i++)
    {
        printf("%02x ", decrypt_payload[i]);
    }
    printf("\n");
#endif

    status = curl_perform_with_cam_retries(curl, chunk_write, chunk_read);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    /* JSON Response Handling */

    // Parse the JSON string response
    jsmn_parser p;
    jsmntok_t   t[64]; /* We expect no more than 64 JSON tokens */
    jsmn_init(&p);
    int parse_result = jsmn_parse(&p, chunk_write->response, strlen(chunk_write->response), t,
                                  64); // "chunk->response" is the char array holding the json content

    // Find the 'base64ciphertext' token
    if (parse_result < 0)
    {
        status = CRYPTOGRAHPY_KMC_CRYPTO_JSON_PARSE_ERROR;
        printf("Failed to parse JSON: %d\n", parse_result);
        return status;
    }

    int     json_idx         = 0;
    uint8_t ciphertext_found = CRYPTO_FALSE;
    char   *cleartext_base64 = NULL;
    for (json_idx = 1; json_idx < parse_result; json_idx++)
    {
        // check "httpCode" field for non-200 status codes!!!
        if (jsoneq(chunk_write->response, &t[json_idx], "base64cleartext") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("Json base64cleartext: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_cleartext = t[json_idx + 1].end - t[json_idx + 1].start;
            cleartext_base64       = malloc(len_cleartext + 1);
            memcpy(cleartext_base64, chunk_write->response + t[json_idx + 1].start, len_cleartext);
            cleartext_base64[len_cleartext] = '\0';
#ifdef DEBUG
            printf("Parsed base64cleartext: %s\n", cleartext_base64);
#endif
            json_idx++;
            ciphertext_found = CRYPTO_TRUE;
            continue;
        }
        if (jsoneq(chunk_write->response, &t[json_idx], "httpCode") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("httpCode: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_httpcode  = t[json_idx + 1].end - t[json_idx + 1].start;
            char    *http_code_str = malloc(len_httpcode + 1);
            memcpy(http_code_str, chunk_write->response + t[json_idx + 1].start, len_httpcode);
            http_code_str[len_httpcode] = '\0';
            int http_code               = atoi(http_code_str);
#ifdef DEBUG
            printf("Parsed http code: %d\n", http_code);
#endif
            if (http_code != 200)
            {
                status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE;
                fprintf(stderr, "KMC Crypto Failure Response:\n%s\n", chunk_write->response);
                return status;
            }
            free(http_code_str);
            json_idx++;
            continue;
        }
    }
    if (ciphertext_found == CRYPTO_FALSE)
    {
        status = CRYPTOGRAHPY_KMC_CIPHER_TEXT_NOT_FOUND_IN_JSON_RESPONSE;
        return status;
    }

    /* JSON Response Handling End */

    uint8_t *cleartext_decoded     = malloc((len_data_out)*2 + 1);
    size_t   cleartext_decoded_len = 0;
    base64Decode(cleartext_base64, strlen(cleartext_base64), cleartext_decoded, &cleartext_decoded_len);
#ifdef DEBUG
    printf("Decoded Cipher Text Length: %ld\n", cleartext_decoded_len);
    printf("Decoded Cipher Text: \n");
    for (uint32_t i = 0; i < cleartext_decoded_len; i++)
    {
        printf("%02x ", cleartext_decoded[i]);
    }
    printf("\n");
#endif
    // Copy the decrypted data to the output stream
    // Crypto Service returns aad - clear_text
    memcpy(data_out, cleartext_decoded, len_data_out);

    return status;
}

static int32_t cryptography_authenticate(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                         uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                         uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad,
                                         uint32_t aad_len, uint8_t ecs, uint8_t acs, char *cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Unneeded cryptography interface vars for current implementation
    len_data_out = len_data_out;
    key          = key;
    len_key      = len_key;
    iv           = iv;
    iv_len       = iv_len;
    ecs          = ecs;

    curl_easy_reset(curl);
    status = configure_curl_connect_opts(curl, cam_cookies);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }
    // Base64 URL encode IV for KMC REST Encrypt
    // Not needed for CMAC/HMAC (only supported auth ciphers now)
    //    char* iv_base64 = (char*)calloc(1,B64ENCODE_OUT_SAFESIZE(iv_len)+1);
    //    base64urlEncode(iv,iv_len,iv_base64,NULL);

    uint8_t *auth_payload     = aad;
    size_t   auth_payload_len = aad_len;

    // Verify valid acs enum
    int32_t algo = cryptography_get_acs_algo(acs);
    if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ACS)
    {
        return CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
    }

    // Need to copy the data over, since authentication won't change/move the data directly
    if (data_out != NULL)
    {
        memcpy(data_out, data_in, len_data_in);
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }

    if (sa_ptr->ak_ref[0] == '\0')
    {
        status = CRYPTOGRAHPY_KMC_NULL_AUTHENTICATION_KEY_REFERENCE_IN_SA;
        return status;
    }

    // Prepare the Authentication Endpoint URI for KMC Crypto Service
    int   len_auth_endpoint   = strlen(icv_create_endpoint) + strlen(sa_ptr->ak_ref);
    char *auth_endpoint_final = (char *)malloc(len_auth_endpoint);
    snprintf(auth_endpoint_final, len_auth_endpoint, icv_create_endpoint, sa_ptr->ak_ref);

    char *auth_uri = (char *)malloc(strlen(kmc_root_uri) + len_auth_endpoint);
    auth_uri[0]    = '\0';
    strcat(auth_uri, kmc_root_uri);
    strcat(auth_uri, auth_endpoint_final);

#ifdef DEBUG
    printf("Authentication URI: %s\n", auth_uri);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, auth_uri);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers_list);

    memory_write *chunk_write = (memory_write *)calloc(1, MEMORY_WRITE_SIZE);
    memory_read  *chunk_read  = (memory_read *)calloc(1, MEMORY_READ_SIZE);
    ;
    /* Configure CURL for POST */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_READDATA, chunk_read);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, chunk_write);

    /* size of the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)auth_payload_len);
    /* binary data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, auth_payload);

#ifdef DEBUG
    printf("Authentication Payload Length: %ld\n", auth_payload_len);
    printf("Data to Authenticate: \n");
    for (uint32_t i = 0; i < auth_payload_len; i++)
    {
        printf("%02x ", auth_payload[i]);
    }
    printf("\n");
#endif

    status = curl_perform_with_cam_retries(curl, chunk_write, chunk_read);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    /* JSON Response Handling */

    // Parse the JSON string response
    jsmn_parser p;
    jsmntok_t   t[64]; /* We expect no more than 64 JSON tokens */
    jsmn_init(&p);
    int parse_result = jsmn_parse(&p, chunk_write->response, strlen(chunk_write->response), t,
                                  64); // "chunk->response" is the char array holding the json content

    // Find the 'integrityCheckValue' token
    if (parse_result < 0)
    {
        status = CRYPTOGRAHPY_KMC_CRYPTO_JSON_PARSE_ERROR;
        printf("Failed to parse JSON: %d\n", parse_result);
        return status;
    }

    int     json_idx      = 0;
    uint8_t icvtext_found = CRYPTO_FALSE;
    char   *icv_base64    = NULL;
    for (json_idx = 1; json_idx < parse_result; json_idx++)
    {
        if (jsoneq(chunk_write->response, &t[json_idx], "metadata") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("Json metadata: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            // search through metadata string for base64 ICV end idx:
            // Format:
            // "integrityCheckValue:xQgnkVrrQj8FRALV3DxnVg==,keyRef:kmc/test/nist_cmac_90,cryptoAlgorithm:AESCMAC,metadataType:IntegrityCheckMetadata"
            uint32_t len_metadata = t[json_idx + 1].end - t[json_idx + 1].start;
            char    *metadata     = malloc(len_metadata + 1);
            char    *metadata_end = &metadata[len_metadata];
            memcpy(metadata, chunk_write->response + t[json_idx + 1].start, len_metadata);

            char  *key = "";
            size_t colon_idx;
            size_t comma_idx;
            while (CRYPTO_TRUE)
            {
                colon_idx = strcspn(metadata, ":");
                comma_idx = strcspn(metadata, ",");
                key       = malloc(colon_idx + 1);
                strncpy(key, metadata, colon_idx);
                key[colon_idx] = '\0';
#ifdef DEBUG
                printf("Found key in metadata: %s\n", key);
#endif
                if (strcmp(key, "integrityCheckValue") == 0)
                {
                    break; // key found!
                }
                if (strcmp(key, "integrityCheckValue") != 0)
                {
                    metadata += comma_idx + 1;
                    if (metadata >= metadata_end)
                    {
                        status = CRYPTOGRAHPY_KMC_ICV_NOT_FOUND_IN_JSON_RESPONSE;
                        return status;
                    }
                }
            }

            metadata += colon_idx + 1;
            comma_idx  = strcspn(metadata, ",");
            icv_base64 = malloc(comma_idx + 1);
            strncpy(icv_base64, metadata, comma_idx);
            icv_base64[comma_idx] = '\0';
#ifdef DEBUG
            printf("Parsed integrityCheckValue: %s\n", icv_base64);
#endif
            json_idx++;
            icvtext_found = CRYPTO_TRUE;
            continue;
        }

        if (jsoneq(chunk_write->response, &t[json_idx], "httpCode") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("httpCode: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_httpcode  = t[json_idx + 1].end - t[json_idx + 1].start;
            char    *http_code_str = malloc(len_httpcode + 1);
            memcpy(http_code_str, chunk_write->response + t[json_idx + 1].start, len_httpcode);
            http_code_str[len_httpcode] = '\0';
            int http_code               = atoi(http_code_str);
#ifdef DEBUG
            printf("Parsed http code: %d\n", http_code);
#endif
            if (http_code != 200)
            {
                status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE;
                fprintf(stderr, "KMC Crypto Failure Response:\n%s\n", chunk_write->response);
                return status;
            }
            json_idx++;
            free(http_code_str);
            continue;
        }
    }
    if (icvtext_found == CRYPTO_FALSE)
    {
        status = CRYPTOGRAHPY_KMC_ICV_NOT_FOUND_IN_JSON_RESPONSE;
        return status;
    }

    /* JSON Response Handling End */

    // https://stackoverflow.com/questions/13378815/base64-length-calculation
    uint8_t *icv_decoded     = calloc(1, B64DECODE_OUT_SAFESIZE(strlen(icv_base64)) + 1);
    size_t   icv_decoded_len = 0;
    base64urlDecode(icv_base64, strlen(icv_base64), icv_decoded, &icv_decoded_len);
#ifdef DEBUG
    printf("Mac size: %d\n", mac_size);
    printf("Decoded ICV Length: %ld\n", icv_decoded_len);
    printf("Decoded ICV Text: \n");
    for (uint32_t i = 0; i < icv_decoded_len; i++)
    {
        printf("%02x ", icv_decoded[i]);
    }
    printf("\n");
#endif

    memcpy(mac, icv_decoded, mac_size);
    return status;
}

static int32_t cryptography_validate_authentication(uint8_t *data_out, size_t len_data_out, const uint8_t *data_in,
                                                    const size_t len_data_in, uint8_t *key, uint32_t len_key,
                                                    SecurityAssociation_t *sa_ptr, const uint8_t *iv, uint32_t iv_len,
                                                    const uint8_t *mac, uint32_t mac_size, const uint8_t *aad,
                                                    uint32_t aad_len, uint8_t ecs, uint8_t acs, char *cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Unneeded cryptography interface vars for current implementation
    len_data_out = len_data_out;
    key          = key;
    len_key      = len_key;
    iv           = iv;
    iv_len       = iv_len;
    ecs          = ecs;

    // Verify valid acs enum
    int32_t algo = cryptography_get_acs_algo(acs);
    if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ACS)
    {
        return CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
    }

    // Need to copy the data over, since authentication won't change/move the data directly
    if (data_out != NULL)
    {
        memcpy(data_out, data_in, len_data_in);
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }

    curl_easy_reset(curl);
    status = configure_curl_connect_opts(curl, cam_cookies);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }
    const uint8_t *auth_payload     = aad;
    size_t         auth_payload_len = aad_len;

    // Base64 URL encode MAC for KMC REST Encrypt
    char *mac_base64 = (char *)calloc(1, B64ENCODE_OUT_SAFESIZE(mac_size) + 1);
    base64urlEncode(mac, mac_size, mac_base64, NULL);
#ifdef DEBUG
    printf("MAC Base64 URL Encoded: %s\n", mac_base64);
    printf("Hex Mac:\n");
    Crypto_hexprint(mac, mac_size);
#endif

    if (sa_ptr->ak_ref[0] == '\0')
    {
        status = CRYPTOGRAHPY_KMC_NULL_AUTHENTICATION_KEY_REFERENCE_IN_SA;
        return status;
    }

    const char *auth_algorithm = NULL;
    get_auth_algorithm_from_acs(acs, &auth_algorithm);

    uint32_t mac_size_str_len = 0;
    char    *mac_size_str     = int_to_str(mac_size * 8, &mac_size_str_len);

    // Prepare the Authentication Endpoint URI for KMC Crypto Service
    int len_auth_endpoint = strlen(icv_verify_endpoint) + strlen(mac_base64) + strlen(sa_ptr->ak_ref) +
                            strlen(auth_algorithm) + mac_size_str_len;
    char *auth_endpoint_final = (char *)malloc(len_auth_endpoint);
    snprintf(auth_endpoint_final, len_auth_endpoint, icv_verify_endpoint, mac_base64, sa_ptr->ak_ref, auth_algorithm,
             mac_size_str);
    free(mac_size_str);
    char *auth_uri = (char *)malloc(strlen(kmc_root_uri) + len_auth_endpoint);
    auth_uri[0]    = '\0';
    strcat(auth_uri, kmc_root_uri);
    strcat(auth_uri, auth_endpoint_final);

#ifdef DEBUG
    printf("Authentication Verification URI: %s\n", auth_uri);
#endif

    curl_easy_setopt(curl, CURLOPT_URL, auth_uri);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers_list);

    memory_write *chunk_write = (memory_write *)calloc(1, MEMORY_WRITE_SIZE);
    memory_read  *chunk_read  = (memory_read *)calloc(1, MEMORY_READ_SIZE);
    ;
    /* Configure CURL for POST */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_READDATA, chunk_read);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, chunk_write);

    /* size of the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)auth_payload_len);
    /* binary data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, auth_payload);

#ifdef DEBUG
    printf("Authentication Payload Length: %ld\n", auth_payload_len);
    printf("Data to Authenticate: \n");
    for (uint32_t i = 0; i < auth_payload_len; i++)
    {
        printf("%02x ", auth_payload[i]);
    }
    printf("\n");
#endif

    status = curl_perform_with_cam_retries(curl, chunk_write, chunk_read);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    /* JSON Response Handling */

    // Parse the JSON string response
    jsmn_parser p;
    jsmntok_t   t[64]; /* We expect no more than 64 JSON tokens */
    jsmn_init(&p);
    int parse_result = jsmn_parse(&p, chunk_write->response, strlen(chunk_write->response), t,
                                  64); // "chunk->response" is the char array holding the json content

    if (parse_result < 0)
    {
        status = CRYPTOGRAHPY_KMC_CRYPTO_JSON_PARSE_ERROR;
        printf("Failed to parse JSON: %d\n", parse_result);
        return status;
    }

    int     json_idx          = 0;
    uint8_t http_status_found = CRYPTO_FALSE;
    for (json_idx = 1; json_idx < parse_result; json_idx++)
    {
        if (jsoneq(chunk_write->response, &t[json_idx], "httpCode") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("httpCode: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_httpcode  = t[json_idx + 1].end - t[json_idx + 1].start;
            char    *http_code_str = malloc(len_httpcode + 1);
            memcpy(http_code_str, chunk_write->response + t[json_idx + 1].start, len_httpcode);
            http_code_str[len_httpcode] = '\0';
            http_status_found           = CRYPTO_TRUE;
            int http_code               = atoi(http_code_str);
#ifdef DEBUG
            printf("Parsed http code: %d\n", http_code);
#endif
            if (http_code != 200)
            {
                status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE;
                fprintf(stderr, "KMC Crypto Generic Failure Response:\n%s\n", chunk_write->response);
                return status;
            }
            json_idx++;
            free(http_code_str);
            continue;
        }

        if (jsoneq(chunk_write->response, &t[json_idx], "result") == 0)
        {
#ifdef DEBUG
            printf("result: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_result = t[json_idx + 1].end - t[json_idx + 1].start;
            char    *result_str = malloc(len_result + 1);
            memcpy(result_str, chunk_write->response + t[json_idx + 1].start, len_result);
            result_str[len_result] = '\0';

#ifdef DEBUG
            printf("Parsed result string: %s\n", result_str);
#endif
            if (strcmp(result_str, "true") != 0) // KMC crypto service returns true string if ICV check succeeds.
            {
                status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_MAC_VALIDATION_ERROR;
                fprintf(stderr, "KMC Crypto MAC Validation Failure Response:\n%s\n", chunk_write->response);
                return status;
            }
            continue;
        }
    }
    if (http_status_found == CRYPTO_FALSE)
    {
        status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE;
        fprintf(stderr, "KMC Crypto Generic Failure Response:\n%s\n", chunk_write->response);
        return status;
    }

    /* JSON Response Handling End */

    return status;
}

static int32_t cryptography_aead_encrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                         uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                         uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad,
                                         uint32_t aad_len, uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t *ecs, uint8_t *acs, char *cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    key            = key;     // Direct key input is not supported in KMC interface
    len_key        = len_key; // Direct key input is not supported in KMC interface
    ecs            = ecs;
    acs            = acs;

    curl_easy_reset(curl);
    status = configure_curl_connect_opts(curl, cam_cookies);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }
    // Base64 URL encode IV for KMC REST Encrypt
    char *iv_base64 = (char *)calloc(1, B64ENCODE_OUT_SAFESIZE(iv_len) + 1);
    if (iv != NULL)
    {
        base64urlEncode(iv, iv_len, iv_base64, NULL);
    }

#ifdef DEBUG
    printf("IV_BASE64: %s\n", iv_base64);
#endif

    uint8_t *encrypt_payload     = data_in;
    size_t   encrypt_payload_len = len_data_in;

#ifdef DEBUG
    printf("IV Base64 URL Encoded: %s\n", iv_base64);
#endif

    if (sa_ptr->ek_ref[0] == '\0')
    {
        status = CRYPTOGRAHPY_KMC_NULL_ENCRYPTION_KEY_REFERENCE_IN_SA;
        free(iv_base64);
        return status;
    }

    char *encrypt_uri;
    if (aad_bool == CRYPTO_TRUE)
    {
        // Determine length of aad offset string and convert to string for use in URL
        uint32_t aad_offset_str_len = 0;

        char *aad_offset_str = int_to_str(aad_len, &aad_offset_str_len);
#ifdef DEBUG
        printf("AAD Offset Str: %s\n", aad_offset_str);
#endif

        uint32_t mac_size_str_len = 0;
        char    *mac_size_str     = int_to_str(mac_size * 8, &mac_size_str_len);

        int len_encrypt_endpoint = strlen(encrypt_offset_endpoint) + strlen(sa_ptr->ek_ref) + strlen(iv_base64) +
                                   strlen(AES_GCM_TRANSFORMATION) + aad_offset_str_len + mac_size_str_len;
        char *encrypt_endpoint_final = (char *)malloc(len_encrypt_endpoint);
        if (iv != NULL)
        {

            snprintf(encrypt_endpoint_final, len_encrypt_endpoint, encrypt_offset_endpoint, sa_ptr->ek_ref,
                     AES_GCM_TRANSFORMATION, iv_base64, aad_offset_str, mac_size_str);
        }
        else
        {
            //"encrypt?keyRef=%s&transformation=%s&encryptOffset=%s&macLength=%s";
            snprintf(encrypt_endpoint_final, len_encrypt_endpoint, encrypt_offset_endpoint_null_iv, sa_ptr->ek_ref,
                     AES_GCM_TRANSFORMATION, aad_offset_str, mac_size_str);
        }

        free(aad_offset_str);
        free(mac_size_str);
#ifdef DEBUG
        printf("KMC ROOT URI: %s\n", kmc_root_uri);
#endif
        encrypt_uri    = (char *)malloc(strlen(kmc_root_uri) + len_encrypt_endpoint);
        encrypt_uri[0] = '\0';
        strcat(encrypt_uri, kmc_root_uri);
        strcat(encrypt_uri, encrypt_endpoint_final);

        // Prepare encrypt_payload with AAD at the front for KMC Crypto Service.
        if (encrypt_bool == CRYPTO_FALSE) // Not encrypting data, only passing in AAD for TAG.
        {
            encrypt_payload_len = aad_len;
        }
        else // Encrypt & AAD
        {
            encrypt_payload_len = len_data_in + aad_len;
        }

#ifdef DEBUG
        printf("Encrypt Payload Length: %ld\n", encrypt_payload_len);
#endif
        encrypt_payload = (uint8_t *)malloc(encrypt_payload_len);
        memcpy(&encrypt_payload[0], aad, aad_len);
        if (encrypt_bool == CRYPTO_TRUE)
        {
            memcpy(&encrypt_payload[aad_len], data_in, len_data_in);
        }
        free(encrypt_endpoint_final);
    }
    else // No AAD -- just prepare the endpoint URI
    {
        int len_encrypt_endpoint =
            strlen(encrypt_endpoint) + strlen(sa_ptr->ek_ref) + strlen(iv_base64) + strlen(AES_GCM_TRANSFORMATION);
        char *encrypt_endpoint_final = (char *)malloc(len_encrypt_endpoint);
        if (iv != NULL)
        {
            snprintf(encrypt_endpoint_final, len_encrypt_endpoint, encrypt_endpoint, sa_ptr->ek_ref,
                     AES_GCM_TRANSFORMATION, iv_base64);
        }
        else
        {
            snprintf(encrypt_endpoint_final, len_encrypt_endpoint, encrypt_endpoint_null_iv, sa_ptr->ek_ref,
                     AES_GCM_TRANSFORMATION);
        }

        encrypt_uri    = (char *)malloc(strlen(kmc_root_uri) + len_encrypt_endpoint);
        encrypt_uri[0] = '\0';
        strcat(encrypt_uri, kmc_root_uri);
        strcat(encrypt_uri, encrypt_endpoint_final);
        free(encrypt_endpoint_final);
    }

#ifdef DEBUG
    printf("Encrypt URI AEAD: %s\n", encrypt_uri);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, encrypt_uri);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers_list);

    memory_write *chunk_write = (memory_write *)calloc(1, MEMORY_WRITE_SIZE);
    memory_read  *chunk_read  = (memory_read *)calloc(1, MEMORY_READ_SIZE);
    ;
    /* Configure CURL for POST */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_READDATA, chunk_read);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, chunk_write);

    /* size of the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)encrypt_payload_len);
    /* binary data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encrypt_payload);

#ifdef DEBUG
    printf("Data to Encrypt: \n");
    for (uint32_t i = 0; i < encrypt_payload_len; i++)
    {
        printf("%02x ", encrypt_payload[i]);
    }
    printf("\n");
#endif

    status = curl_perform_with_cam_retries(curl, chunk_write, chunk_read);
#ifdef DEBUG
    printf("Curl Perform Final Status Code: %d\n", status);
    if (chunk_write->response != NULL)
    {
        printf("Chunk Write Response Length: %ld\n", strlen(chunk_write->response));
        printf("Chunk Write Response: %s\n", chunk_write->response);
    }
#endif
    if (status != CRYPTO_LIB_SUCCESS)
    {
        if (iv_base64 != NULL)
            free(iv_base64);
        if (encrypt_uri != NULL)
            free(encrypt_uri);
        if (chunk_write != NULL)
            free(chunk_write);
        if (chunk_read != NULL)
            free(chunk_read);
        if (encrypt_payload != NULL)
            free(encrypt_payload);
        return status;
    }

    /* JSON Response Handling */

    // Parse the JSON string response
    jsmn_parser p;
    jsmntok_t   t[64]; /* We expect no more than 64 JSON tokens */
    jsmn_init(&p);
    int parse_result = jsmn_parse(&p, chunk_write->response, strlen(chunk_write->response), t,
                                  64); // "chunk->response" is the char array holding the json content

    // Find the 'base64ciphertext' token
    if (parse_result < 0)
    {
        status = CRYPTOGRAHPY_KMC_CRYPTO_JSON_PARSE_ERROR;
        printf("Failed to parse JSON: %d\n", parse_result);
        if (iv_base64 != NULL)
            free(iv_base64);
        if (encrypt_uri != NULL)
            free(encrypt_uri);
        if (chunk_write != NULL)
            free(chunk_write);
        if (chunk_read != NULL)
            free(chunk_read);
        if (encrypt_payload != NULL)
            free(encrypt_payload);
        return status;
    }

    int     json_idx             = 0;
    uint8_t ciphertext_found     = CRYPTO_FALSE;
    char   *ciphertext_base64    = NULL;
    char   *ciphertext_IV_base64 = NULL;
    for (json_idx = 1; json_idx < parse_result; json_idx++)
    {
        if (jsoneq(chunk_write->response, &t[json_idx], "metadata") == 0)
        {
            uint32_t len_ciphertext = t[json_idx + 1].end - t[json_idx + 1].start;
            ciphertext_IV_base64    = malloc(len_ciphertext + 1);
            memcpy(ciphertext_IV_base64, chunk_write->response + t[json_idx + 1].start, len_ciphertext);
            ciphertext_IV_base64[len_ciphertext] = '\0';
            // printf("%s\n", ciphertext_IV_base64);

            char *line;
            char *token;
            char  temp_buff[256];
            for (line = strtok(ciphertext_IV_base64, ","); line != NULL; line = strtok(line + strlen(line) + 1, ","))
            {
                strncpy(temp_buff, line, sizeof(temp_buff));

                for (token = strtok(temp_buff, ":"); token != NULL; token = strtok(token + strlen(token) + 1, ":"))
                {
                    if (strcmp(token, "initialVector") == 0)
                    {
                        token                          = strtok(token + strlen(token) + 1, ":");
                        char  *ciphertext_token_base64 = malloc(strlen(token));
                        size_t cipher_text_token_len   = strlen(token);
                        memcpy(ciphertext_token_base64, token, cipher_text_token_len);
#ifdef DEBUG
                        printf("IV LENGTH: %d\n", iv_len);
                        printf("IV ENCODED Text: %s\nIV ENCODED TEXT LEN: %ld\n", ciphertext_token_base64,
                               cipher_text_token_len);
#endif
                        char  *iv_decoded     = malloc((iv_len)*2 + 1);
                        size_t iv_decoded_len = 0;
                        base64urlDecode(ciphertext_token_base64, cipher_text_token_len, iv_decoded, &iv_decoded_len);

#ifdef DEBUG
                        printf("Decoded IV Text Length: %ld\n", iv_decoded_len);
                        printf("Decoded IV Text: \n");
                        for (uint32_t i = 0; i < iv_decoded_len; i++)
                        {
                            printf("%02x ", (uint8_t)iv_decoded[i]);
                        }
                        printf("\n");
#endif

                        if (iv == NULL)
                        {
                            memcpy(data_out - sa_ptr->shsnf_len - sa_ptr->shivf_len - sa_ptr->shplf_len, iv_decoded,
                                   iv_decoded_len);
                        }
                        free(ciphertext_token_base64);
                        break;
                    }
                }
            }

            json_idx++;
            continue;
        }
        if (jsoneq(chunk_write->response, &t[json_idx], "base64ciphertext") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("Json base64ciphertext: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_ciphertext = t[json_idx + 1].end - t[json_idx + 1].start;
            ciphertext_base64       = malloc(len_ciphertext + 1);
            memcpy(ciphertext_base64, chunk_write->response + t[json_idx + 1].start, len_ciphertext);
            ciphertext_base64[len_ciphertext] = '\0';
#ifdef DEBUG
            printf("Parsed base64ciphertext: %s\n", ciphertext_base64);
#endif
            json_idx++;
            ciphertext_found = CRYPTO_TRUE;
            continue;
        }

        if (jsoneq(chunk_write->response, &t[json_idx], "httpCode") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("httpCode: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_httpcode  = t[json_idx + 1].end - t[json_idx + 1].start;
            char    *http_code_str = malloc(len_httpcode + 1);
            memcpy(http_code_str, chunk_write->response + t[json_idx + 1].start, len_httpcode);
            http_code_str[len_httpcode] = '\0';
            int http_code               = atoi(http_code_str);
#ifdef DEBUG
            printf("Parsed http code: %d\n", http_code);
#endif
            if (http_code != 200)
            {
                status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE;
                fprintf(stderr, "KMC Crypto Failure Response:\n%s\n", chunk_write->response);
                if (iv_base64 != NULL)
                    free(iv_base64);
                if (encrypt_uri != NULL)
                    free(encrypt_uri);
                if (chunk_write != NULL)
                    free(chunk_write);
                if (chunk_read != NULL)
                    free(chunk_read);
                if (encrypt_payload != NULL)
                    free(encrypt_payload);
                if (http_code_str != NULL)
                    free(http_code_str);
                if (ciphertext_base64 != NULL)
                    free(ciphertext_base64);
                return status;
            }
            json_idx++;
            if (http_code_str != NULL)
                free(http_code_str);
            continue;
        }
    }
    if (ciphertext_found == CRYPTO_FALSE)
    {
        status = CRYPTOGRAHPY_KMC_CIPHER_TEXT_NOT_FOUND_IN_JSON_RESPONSE;
        if (encrypt_uri != NULL)
            free(encrypt_uri);
        if (iv_base64 != NULL)
            free(iv_base64);
        if (ciphertext_base64 != NULL)
            free(ciphertext_base64);
        if (chunk_write != NULL)
            free(chunk_write);
        if (chunk_read != NULL)
            free(chunk_read);
        if (encrypt_payload != NULL)
            free(encrypt_payload);
        return status;
    }

    /* JSON Response Handling End */

    uint8_t *ciphertext_decoded     = malloc((len_data_out + mac_size + aad_len) * 2 + 1);
    size_t   ciphertext_decoded_len = 0;
    base64Decode(ciphertext_base64, strlen(ciphertext_base64), ciphertext_decoded, &ciphertext_decoded_len);
#ifdef DEBUG
    printf("Mac size: %d\n", mac_size);
    printf("Decoded Cipher Text Length: %ld\n", ciphertext_decoded_len);
    printf("Decoded Cipher Text: \n");
    for (uint32_t i = 0; i < ciphertext_decoded_len; i++)
    {
        printf("%02x ", ciphertext_decoded[i]);
    }
    printf("\n");
#endif

    // Copy the encrypted data to the output stream
    if (encrypt_bool == CRYPTO_TRUE)
    {
        // Crypto Service returns aad - cipher_text - tag
        memcpy(data_out, ciphertext_decoded + aad_len, len_data_out);
    }

    // If authenticate, Copy the MAC to the output stream
    if (authenticate_bool == CRYPTO_TRUE)
    {
        uint32_t data_offset = len_data_out;
        if (encrypt_bool == CRYPTO_FALSE)
        {
            data_offset = 0;
        }
        memcpy(mac, ciphertext_decoded + aad_len + data_offset, mac_size);
    }
    if (ciphertext_base64 != NULL)
        free(ciphertext_base64);
    if (ciphertext_decoded != NULL)
        free(ciphertext_decoded);
    if (iv_base64 != NULL)
        free(iv_base64);
    if (encrypt_uri != NULL)
        free(encrypt_uri);
    // if (encrypt_payload != NULL) free(encrypt_payload);
    if (chunk_write->response != NULL)
        free(chunk_write->response);
    if (chunk_write != NULL)
        free(chunk_write);
    if (chunk_read != NULL)
        free(chunk_read);

#ifdef DEBUG
    printf("DATA OUT:\n");
    for (size_t i = 0; i < len_data_out; i++)
    {
        printf("%02x ", data_out[i]);
    }
    printf("\n");
#endif

    return status;
}

static int32_t cryptography_aead_decrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                                         uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                                         uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad,
                                         uint32_t aad_len, uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t *ecs, uint8_t *acs, char *cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    key            = key; // Direct key input is not supported in KMC interface
    ecs            = ecs;
    acs            = acs;

    // Get the key length in bits, in string format.
    // TODO -- Parse the key length from the keyInfo endpoint of the Crypto Service!
    uint32_t key_len_in_bits         = len_key * 8; // 8 bits per byte.
    uint32_t key_len_in_bits_str_len = 0;
    char    *key_len_in_bits_str     = int_to_str(key_len_in_bits, &key_len_in_bits);

    curl_easy_reset(curl);
    status = configure_curl_connect_opts(curl, cam_cookies);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    // Base64 URL encode IV for KMC REST Encrypt
    char *iv_base64 = (char *)calloc(1, B64ENCODE_OUT_SAFESIZE(iv_len) + 1);
    base64urlEncode(iv, iv_len, iv_base64, NULL);

    uint8_t *decrypt_payload     = data_in;
    size_t   decrypt_payload_len = len_data_in;

#ifdef DEBUG
    printf("IV Base64 URL Encoded: %s\n", iv_base64);
#endif

    if (sa_ptr->ek_ref[0] == '\0')
    {
        status = CRYPTOGRAHPY_KMC_NULL_ENCRYPTION_KEY_REFERENCE_IN_SA;
        return status;
    }

    char *decrypt_uri;
    if (aad_bool == CRYPTO_TRUE)
    {
        // Determine length of aad offset string and convert to string for use in URL
        uint32_t aad_offset_str_len = 0;
        char    *aad_offset_str     = int_to_str(aad_len, &aad_offset_str_len);
#ifdef DEBUG
        printf("AAD Offset Str: %s\n", aad_offset_str);
#endif

        uint32_t mac_size_str_len = 0;
        char    *mac_size_str     = int_to_str(mac_size * 8, &mac_size_str_len);

        int len_decrypt_endpoint = strlen(decrypt_offset_endpoint) + key_len_in_bits_str_len + strlen(sa_ptr->ek_ref) +
                                   strlen(iv_base64) + strlen(AES_GCM_TRANSFORMATION) + strlen(AES_CRYPTO_ALGORITHM) +
                                   mac_size_str_len + aad_offset_str_len;
        char *decrypt_endpoint_final = (char *)malloc(len_decrypt_endpoint);

        snprintf(decrypt_endpoint_final, len_decrypt_endpoint, decrypt_offset_endpoint, key_len_in_bits_str,
                 sa_ptr->ek_ref, AES_GCM_TRANSFORMATION, iv_base64, AES_CRYPTO_ALGORITHM, mac_size_str, aad_offset_str);

        free(key_len_in_bits_str);
        free(aad_offset_str);
        free(mac_size_str);

        decrypt_uri    = (char *)malloc(strlen(kmc_root_uri) + len_decrypt_endpoint);
        decrypt_uri[0] = '\0';
        strcat(decrypt_uri, kmc_root_uri);
        strcat(decrypt_uri, decrypt_endpoint_final);

        // Prepare decrypt_payload with AAD at the front for KMC Crypto Service.
        if (decrypt_bool == CRYPTO_FALSE) // Not decrypting data, only passing in AAD for TAG validation.
        {
            decrypt_payload_len = aad_len + mac_size;
        }
        else // Decrypt & AAD/TAG validation
        {
            decrypt_payload_len = len_data_in + aad_len + mac_size;
        }
#ifdef DEBUG
        printf("Decrypt Payload Length: %ld\n", decrypt_payload_len);
#endif
        decrypt_payload = (uint8_t *)malloc(decrypt_payload_len);
        memcpy(&decrypt_payload[0], aad, aad_len);
        if (decrypt_bool == CRYPTO_TRUE)
        {
            memcpy(&decrypt_payload[aad_len], data_in, len_data_in);
        }
        if (authenticate_bool == CRYPTO_TRUE)
        {
            uint32_t data_offset = len_data_in;
            if (decrypt_bool == CRYPTO_FALSE)
            {
                data_offset = 0;
            }
            memcpy(&decrypt_payload[aad_len + data_offset], mac, mac_size);
        }

        free(decrypt_endpoint_final);
    }
    else // No AAD - just prepare the endpoint URI string
    {
        int len_decrypt_endpoint = strlen(decrypt_endpoint) + key_len_in_bits_str_len + strlen(sa_ptr->ek_ref) +
                                   strlen(iv_base64) + strlen(AES_GCM_TRANSFORMATION) + strlen(AES_CRYPTO_ALGORITHM);
        char *decrypt_endpoint_final = (char *)malloc(len_decrypt_endpoint);

        snprintf(decrypt_endpoint_final, len_decrypt_endpoint, decrypt_endpoint, key_len_in_bits_str, sa_ptr->ek_ref,
                 AES_GCM_TRANSFORMATION, iv_base64, AES_CRYPTO_ALGORITHM);

        decrypt_uri    = (char *)malloc(strlen(kmc_root_uri) + len_decrypt_endpoint);
        decrypt_uri[0] = '\0';
        strcat(decrypt_uri, kmc_root_uri);
        strcat(decrypt_uri, decrypt_endpoint_final);
        free(decrypt_endpoint_final);
    }
#ifdef DEBUG
    printf("Decrypt URI: %s\n", decrypt_uri);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, decrypt_uri);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers_list);

    memory_write *chunk_write = (memory_write *)calloc(1, MEMORY_WRITE_SIZE);
    memory_read  *chunk_read  = (memory_read *)calloc(1, MEMORY_READ_SIZE);
    ;

    /* Configure CURL for POST */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_READDATA, chunk_read);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, chunk_write);

    /* size of the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)decrypt_payload_len);
    /* binary data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, decrypt_payload);

#ifdef DEBUG
    printf("Len of decrypt payload: %ld\n", decrypt_payload_len);
    printf("Data to Decrypt: \n");
    for (uint32_t i = 0; i < decrypt_payload_len; i++)
    {
        printf("%02x ", decrypt_payload[i]);
    }
    printf("\n");
#endif

    status = curl_perform_with_cam_retries(curl, chunk_write, chunk_read);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        // free(decrypt_payload);
        free(decrypt_uri);
        free(iv_base64);
        return status;
    }

    /* JSON Response Handling */

    // Parse the JSON string response
    jsmn_parser p;
    jsmntok_t   t[64]; /* We expect no more than 64 JSON tokens */
    jsmn_init(&p);
    int parse_result = jsmn_parse(&p, chunk_write->response, strlen(chunk_write->response), t,
                                  64); // "chunk->response" is the char array holding the json content

    // Find the 'base64ciphertext' token
    if (parse_result < 0)
    {
        status = CRYPTOGRAHPY_KMC_CRYPTO_JSON_PARSE_ERROR;
        printf("Failed to parse JSON: %d\n", parse_result);
        free(decrypt_payload);
        free(decrypt_uri);
        free(iv_base64);
        return status;
    }

    int     json_idx         = 0;
    uint8_t ciphertext_found = CRYPTO_FALSE;
    char   *cleartext_base64 = NULL;
    for (json_idx = 1; json_idx < parse_result; json_idx++)
    {
        // check "httpCode" field for non-200 status codes!!!
        if (jsoneq(chunk_write->response, &t[json_idx], "base64cleartext") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("Json base64cleartext: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_cleartext = t[json_idx + 1].end - t[json_idx + 1].start;
            cleartext_base64       = malloc(len_cleartext + 1);
            memcpy(cleartext_base64, chunk_write->response + t[json_idx + 1].start, len_cleartext);
            cleartext_base64[len_cleartext] = '\0';
#ifdef DEBUG
            printf("Parsed base64cleartext: %s\n", cleartext_base64);
#endif
            json_idx++;
            ciphertext_found = CRYPTO_TRUE;
            continue;
        }
        if (jsoneq(chunk_write->response, &t[json_idx], "httpCode") == 0)
        {
            /* We may use strndup() to fetch string value */
#ifdef DEBUG
            printf("httpCode: %.*s\n", t[json_idx + 1].end - t[json_idx + 1].start,
                   chunk_write->response + t[json_idx + 1].start);
#endif
            uint32_t len_httpcode  = t[json_idx + 1].end - t[json_idx + 1].start;
            char    *http_code_str = malloc(len_httpcode + 1);
            memcpy(http_code_str, chunk_write->response + t[json_idx + 1].start, len_httpcode);
            http_code_str[len_httpcode] = '\0';
            int http_code               = atoi(http_code_str);
#ifdef DEBUG
            printf("Parsed http code: %d\n", http_code);
#endif
            if (http_code != 200)
            {
                status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE;
                fprintf(stderr, "KMC Crypto Failure Response:\n%s\n", chunk_write->response);
                free(chunk_read);
                free(chunk_write);
                free(http_code_str);
                free(cleartext_base64);
                free(decrypt_uri);
                free(iv_base64);
                return status;
            }
            free(http_code_str);
            json_idx++;
            continue;
        }
    }
    if (ciphertext_found == CRYPTO_FALSE)
    {
        status = CRYPTOGRAHPY_KMC_CIPHER_TEXT_NOT_FOUND_IN_JSON_RESPONSE;
        free(chunk_read);
        free(chunk_write);
        free(cleartext_base64);
        free(decrypt_payload);
        free(decrypt_uri);
        free(iv_base64);
        return status;
    }

    /* JSON Response Handling End */

    uint8_t *cleartext_decoded     = malloc((len_data_out + mac_size + aad_len) * 2 + 1);
    size_t   cleartext_decoded_len = 0;
    base64Decode(cleartext_base64, strlen(cleartext_base64), cleartext_decoded, &cleartext_decoded_len);
#ifdef DEBUG
    printf("Decoded Cipher Text Length: %ld\n", cleartext_decoded_len);
    printf("Decoded Cipher Text: \n");
    for (uint32_t i = 0; i < cleartext_decoded_len; i++)
    {
        printf("%02x ", cleartext_decoded[i]);
    }
    printf("\n");
#endif

    // Copy the decrypted data to the output stream
    // Crypto Service returns aad - clear_text
    if (decrypt_bool == CRYPTO_TRUE)
    {
        memcpy(data_out, cleartext_decoded + aad_len, len_data_out);
    }
    free(cleartext_decoded);
    free(chunk_read);
    free(chunk_write->response);
    free(chunk_write);
    free(cleartext_base64);
    free(decrypt_payload);
    free(decrypt_uri);
    free(iv_base64);
    return status;
}

// Local support functions
static int32_t get_auth_algorithm_from_acs(uint8_t acs_enum, const char **algo_ptr)
{
    int32_t status = CRYPTO_LIB_ERR_UNSUPPORTED_ACS; // All valid algo enums will be positive

    switch (acs_enum)
    {
        case CRYPTO_MAC_CMAC_AES256:
            status    = CRYPTO_LIB_SUCCESS;
            *algo_ptr = AES_CMAC_TRANSFORMATION;
            break;
        case CRYPTO_MAC_HMAC_SHA256:
            status    = CRYPTO_LIB_SUCCESS;
            *algo_ptr = HMAC_SHA256;
            break;
        case CRYPTO_MAC_HMAC_SHA512:
            status    = CRYPTO_LIB_SUCCESS;
            *algo_ptr = HMAC_SHA512;
            break;
        default:
#ifdef DEBUG
            printf("ACS Algo Enum not supported by Crypto Service\n");
#endif
            break;
    }

    return (status);
}

// libcurl local functions
static size_t write_callback(void *data, size_t size, size_t nmemb, void *userp)
{
    size_t        realsize = size * nmemb;
    memory_write *mem      = (memory_write *)userp;

    char *ptr;
    if (mem->response != NULL)
    {
        ptr = realloc(mem->response, mem->size + realsize + 1);
    }
    else
    {
        ptr = malloc(realsize + 1);
    }

    if (ptr == NULL)
        return 0; /* out of memory! */

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

static size_t read_callback(char *dest, size_t size, size_t nmemb, void *userp)
{
    memory_read *wt          = (memory_read *)userp;
    size_t       buffer_size = size * nmemb;
    if (wt->size)
    {
        /* copy as much as possible from the source to the destination */
        size_t copy_this_much = wt->size;
        if (copy_this_much > buffer_size)
            copy_this_much = buffer_size;
        memcpy(dest, wt->response, copy_this_much);

        wt->response += copy_this_much;
        wt->size -= copy_this_much;
        return copy_this_much; /* we copied this many bytes */
    }

    return 0; /* no more data left to deliver */
}

static int32_t configure_curl_connect_opts(CURL *curl_handle, char *cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    status = handle_cam_cookies(curl_handle, cam_cookies);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    // curl_easy_setopt(curl_handle, CURLOPT_PROTOCOLS,CURLPROTO_HTTPS); // use default CURLPROTO_ALL
#ifdef DEBUG
    printf("KMC Crypto Port: %d\n", cryptography_kmc_crypto_config->kmc_crypto_port);
    printf("KMC mTLS Client Cert Path: %s\n", cryptography_kmc_crypto_config->mtls_client_cert_path);
    printf("KMC mTLS Client Key Path: %s\n", cryptography_kmc_crypto_config->mtls_client_key_path);

    if (cryptography_kmc_crypto_config->mtls_client_cert_type != NULL)
    {
        printf("KMC mTLS Client Cert Type: %s\n", cryptography_kmc_crypto_config->mtls_client_cert_type);
    }
    if (cryptography_kmc_crypto_config->mtls_ca_bundle != NULL)
    {
        printf("KMC mTLS CA Bundle: %s\n", cryptography_kmc_crypto_config->mtls_ca_bundle);
    }
    if (cryptography_kmc_crypto_config->mtls_ca_path != NULL)
    {
        printf("KMC mTLS CA Path: %s\n", cryptography_kmc_crypto_config->mtls_ca_path);
    }
    if (cryptography_kmc_crypto_config->mtls_issuer_cert != NULL)
    {
        printf("KMC mTLS Client Issuer Cert: %s\n", cryptography_kmc_crypto_config->mtls_issuer_cert);
    }
#endif
    curl_easy_setopt(curl_handle, CURLOPT_PORT, cryptography_kmc_crypto_config->kmc_crypto_port);
    curl_easy_setopt(curl_handle, CURLOPT_SSLCERT, cryptography_kmc_crypto_config->mtls_client_cert_path);
    curl_easy_setopt(curl_handle, CURLOPT_SSLKEY, cryptography_kmc_crypto_config->mtls_client_key_path);
    if (cryptography_kmc_crypto_config->mtls_client_cert_type != NULL)
    {
        curl_easy_setopt(curl_handle, CURLOPT_SSLCERTTYPE, cryptography_kmc_crypto_config->mtls_client_cert_type);
    }
    if (cryptography_kmc_crypto_config->mtls_client_key_pass != NULL)
    {
        curl_easy_setopt(curl_handle, CURLOPT_KEYPASSWD, cryptography_kmc_crypto_config->mtls_client_key_pass);
    }
    if (cryptography_kmc_crypto_config->mtls_ca_bundle != NULL)
    {
        curl_easy_setopt(curl_handle, CURLOPT_CAINFO, cryptography_kmc_crypto_config->mtls_ca_bundle);
    }
    if (cryptography_kmc_crypto_config->mtls_ca_path != NULL)
    {
        curl_easy_setopt(curl_handle, CURLOPT_CAPATH, cryptography_kmc_crypto_config->mtls_ca_path);
    }
    if (cryptography_kmc_crypto_config->mtls_issuer_cert != NULL)
    {
        curl_easy_setopt(curl_handle, CURLOPT_ISSUERCERT, cryptography_kmc_crypto_config->mtls_issuer_cert);
    }
    if (cryptography_kmc_crypto_config->ignore_ssl_hostname_validation == CRYPTO_TRUE)
    {
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
    }

    return status;
}

static int32_t handle_cam_cookies(CURL *curl_handle, char *cam_cookies)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (cam_config != NULL)
    {
        if (cam_config->cam_enabled)
        {
            if (cam_cookies != NULL) // cam_cookies passed in should ALWAYS take precedence in what's used
            {
                curl_easy_setopt(curl_handle, CURLOPT_COOKIE, cam_cookies);
                return status;
            }

            if (cam_config->cookie_file_path == NULL) // all auth methods rely on cookie file sets/gets, error if null
            {
                status = CAM_INVALID_COOKIE_FILE_CONFIGURATION_NULL;
                return status;
            }
            else
            {
#ifdef DEBUG
                printf("Setting CURLOPT_COOKIEFILE: %s\n", cam_config->cookie_file_path);
#endif
                curl_easy_setopt(curl_handle, CURLOPT_COOKIEFILE, cam_config->cookie_file_path);
            }
        }
    }
    return status;
}

static int32_t get_cam_sso_token()
{
    int32_t  status = CRYPTO_LIB_SUCCESS;
    CURL    *curl_cam;
    CURLcode res;

    if (cam_config->login_method == CAM_LOGIN_KEYTAB_FILE)
    {
        status = initialize_kerberos_keytab_file_login();
        if (status != CRYPTO_LIB_SUCCESS)
        {
            return status;
        }
    }

    curl_cam = curl_easy_init();

    if (curl_cam == NULL)
    {
        status = CRYPTOGRAPHY_KMC_CURL_INITIALIZATION_FAILURE;
        return status;
    }

    // Set CA verification options for curl_cam handle from KMC Crypto Configs...
    if (cryptography_kmc_crypto_config->mtls_ca_bundle != NULL)
    {
        curl_easy_setopt(curl_cam, CURLOPT_CAINFO, cryptography_kmc_crypto_config->mtls_ca_bundle);
    }
    if (cryptography_kmc_crypto_config->mtls_ca_path != NULL)
    {
        curl_easy_setopt(curl_cam, CURLOPT_CAPATH, cryptography_kmc_crypto_config->mtls_ca_path);
    }
    if (cryptography_kmc_crypto_config->mtls_issuer_cert != NULL)
    {
        curl_easy_setopt(curl_cam, CURLOPT_ISSUERCERT, cryptography_kmc_crypto_config->mtls_issuer_cert);
    }
    if (cryptography_kmc_crypto_config->ignore_ssl_hostname_validation == CRYPTO_TRUE)
    {
        curl_easy_setopt(curl_cam, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl_cam, CURLOPT_SSL_VERIFYPEER, 0L);
    }

    if (cam_config->access_manager_uri == NULL)
    {
        status = CAM_INVALID_CONFIGURATION_ACCESS_MANAGER_URI_NULL;
        return status;
    }

    if (cam_config->cookie_file_path == NULL)
    {
        status = CAM_INVALID_COOKIE_FILE_CONFIGURATION_NULL;
        return status;
    }

    curl_easy_setopt(curl_cam, CURLOPT_HTTPAUTH, CURLAUTH_NEGOTIATE);

    if (cam_config->username != NULL)
    {
        curl_easy_setopt(curl_cam, CURLOPT_USERNAME, cam_config->username);
    }
    else
    {
        curl_easy_setopt(curl_cam, CURLOPT_USERNAME, ":");
    }

    // Build the CAM getSsoToken URI
    int   len_kerberos_endpoint   = strlen(cam_kerberos_uri) + strlen(cam_config->access_manager_uri);
    char *kerberos_endpoint_final = (char *)malloc(len_kerberos_endpoint + 1);
    snprintf(kerberos_endpoint_final, len_kerberos_endpoint, cam_kerberos_uri, cam_config->access_manager_uri);

#ifdef DEBUG
    printf("CAM Kerberos Endpoint: %s\n", kerberos_endpoint_final);
#endif
    curl_easy_setopt(curl_cam, CURLOPT_URL, kerberos_endpoint_final);

    memory_read  *chunk_read  = (memory_read *)calloc(1, MEMORY_READ_SIZE);
    memory_write *chunk_write = (memory_write *)calloc(1, MEMORY_WRITE_SIZE);

    /* Configure CURL for POST */
    curl_easy_setopt(curl_cam, CURLOPT_POST, 1L);
    /* send all data to this function  */
    curl_easy_setopt(curl_cam, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl_cam, CURLOPT_WRITEFUNCTION, write_callback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl_cam, CURLOPT_READDATA, chunk_read);
    curl_easy_setopt(curl_cam, CURLOPT_WRITEDATA, chunk_write);
    curl_easy_setopt(curl_cam, CURLOPT_COOKIEJAR, cam_config->cookie_file_path);

    res = curl_easy_perform(curl_cam);

    if (res != CURLE_OK) // This is not return code, this is successful response that's unusable!
    {
        status = CAM_GET_SSO_TOKEN_FAILURE;
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

        // return status;
    }

    long response_code;
    curl_easy_getinfo(curl_cam, CURLINFO_RESPONSE_CODE, &response_code);
#ifdef DEBUG
    printf("Response Code From getSsoToken: %ld\n", response_code);
#endif

    if (response_code == 408) // CAM getSsoToken timeout error
    {
        status = CAM_KERBEROS_REQUEST_TIME_OUT;
    }
    else if (response_code != 200) // getSsoToken failed!
    {
        status = CAM_GET_SSO_TOKEN_FAILURE;
    }
    // Cookies don't write to COOKIEJAR until cleanup.
    curl_easy_cleanup(curl_cam);
    free(kerberos_endpoint_final);
    free(chunk_read);
    free(chunk_write);
    return status;
}

static char *int_to_str(uint32_t int_src, uint32_t *converted_str_length)
{
    int   int_str_len = snprintf(NULL, 0, "%d", int_src);
    char *int_str     = malloc(int_str_len + 1);
    snprintf(int_str, int_str_len + 1, "%d", int_src);
    *converted_str_length = int_str_len;
    return int_str;
}

// JSON local functions

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0)
    {
        return 0;
    }
    return -1;
}

int32_t curl_response_error_check(CURL *curl_handle, char *response)
{
    int32_t response_status = CRYPTO_LIB_SUCCESS;

    long response_code;
    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);

#ifdef DEBUG
    printf("cURL response code: %ld\n", response_code);
#endif

    if (response_code == 302) // redirected
    {
        if (cam_config != NULL)
        {
            if (cam_config->cam_enabled &&
                cam_config->login_method ==
                    CAM_LOGIN_NONE) // redirect with cam enabled and no auth method means auth failure
            {
                response_status = CAM_AUTHENTICATION_FAILURE_REDIRECT;
                return response_status;
            }
            else if (cam_config->cam_enabled && (cam_config->login_method == CAM_LOGIN_KERBEROS ||
                                                 cam_config->login_method == CAM_LOGIN_KEYTAB_FILE))
            {
                response_status = CAM_AUTHENTICATION_REQUIRED;
                return response_status;
            }
            else // CAM not enabled, but cam is configured and 302 received -- likely misconfiguration!
            {
                response_status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE;
                return response_status;
            }
        }
    }

    if (response_code != 200) // unhandled error case
    {
        response_status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE;
        return response_status;
    }

#ifdef DEBUG
    printf("\ncURL Response Body:\n\t %s\n", response);
#endif

    if (response == NULL) // No response, possibly because service is CAM secured.
    {
        response_status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_EMPTY_RESPONSE;
        fprintf(stderr, "curl_easy_perform() unexpected empty response: \n%s\n",
                "Empty Crypto Service response can be caused by CAM security, is CAM configured?");
        return response_status;
    }

    return response_status;
}

int32_t curl_perform_with_cam_retries(CURL *curl_handle, memory_write *chunk_write, memory_read *chunk_read)
{
    int32_t status    = CRYPTO_LIB_SUCCESS;
    uint8_t cam_retry = 0;
    while (cam_retry < CAM_MAX_AUTH_RETRIES)
    {
#ifdef DEBUG
        printf("Entering CAM Authentication Retry Loop, Loop #: %d\n", cam_retry);
#endif
        CURLcode res;
        res = curl_easy_perform(curl_handle);

        if (res != CURLE_OK) // This is not a response w/return code, this is something breaking!
        {
            status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE;
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            break; // Go to Post retry loop cleanup and return status.
        }

        status = curl_response_error_check(curl_handle, chunk_write->response);

        if (status == CRYPTO_LIB_SUCCESS) // Crypto Service REST call worked! Break out of retry loop.
        {
            break;
        }
        else
        {
            // Zero out chunk_write/chunk_read for next cURL perform call
            memset(chunk_write, 0, MEMORY_WRITE_SIZE);
            memset(chunk_read, 0, MEMORY_READ_SIZE);
        }

        if (status == CAM_AUTHENTICATION_REQUIRED) // CAM_AUTHENTICATION_REQUIRED code indicates CAM config setup for
                                                   // authentication
        {
#ifdef DEBUG
            printf("Attempting to authenticate and retrieve CAM SSO Token.\n");
#endif
            status = get_cam_sso_token();
            if (status == CAM_KERBEROS_REQUEST_TIME_OUT)
            {
                // Non-fatal getSsoToken failure... Attempt CAM retry...
            }
            else if (status != CRYPTO_LIB_SUCCESS)
            {
                return status; // Fatal getSsoToken error, break
            }
            else if (status == CRYPTO_LIB_SUCCESS)
            {
                // Re-handle CAM cookie file, when cookie file is regenerated above, the existing curl_handle doesn't
                // recognize it
                status = handle_cam_cookies(curl_handle, NULL);
            }
        }
        else // Conditions not met for CAM retry! Break out of retry loop.
        {
            break;
        }
        cam_retry++;
        if (cam_retry == CAM_MAX_AUTH_RETRIES)
        {
            status = CAM_MAX_AUTH_RETRIES_REACHED;
        }
    }
    if (status == CRYPTO_LIB_SUCCESS &&
        chunk_write->response == NULL) // no error case detected, but invalid NULL response!
    {
        status = CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_EMPTY_RESPONSE;
    }
    return status;
}

/**
 * @brief Function: initialize_kerberos_keytab_file_login
 *
 *  This function launches the kinit kerberos utility to initialize credentials for the current user.
 *  It may be possible to do this with the KRB5 API, but for now all we are doing is launching the kinit utility.
 *  Consider using the KRB5 APIs in a future release:
 *https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/index.html
 *
 *
 **/
int32_t initialize_kerberos_keytab_file_login(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (cam_config->keytab_file_path == NULL)
    {
        status = CAM_INVALID_CONFIGURATION_KEYTAB_FILE_PATH_NULL;
        return status;
    }

    if (cam_config->username == NULL)
    {
        status = CAM_INVALID_CONFIGURATION_KEYTAB_FILE_USERNAME_NULL;
        return status;
    }

    // Build the kinit shell command with keytab file path + username
    char    *kinit_shell_command_base = "kinit -kt %s %s";
    uint32_t len_kinit_shell_command =
        strlen(kinit_shell_command_base) + strlen(cam_config->keytab_file_path) + strlen(cam_config->username);
    char *kinit_shell_command = malloc(len_kinit_shell_command + 1);
    snprintf(kinit_shell_command, len_kinit_shell_command, kinit_shell_command_base, cam_config->keytab_file_path,
             cam_config->username);

    int32_t kinit_status = system(kinit_shell_command);
#ifdef DEBUG
    printf("Kinit Status: %d\n", kinit_status);
#endif
    if (kinit_status != CRYPTO_LIB_SUCCESS)
    {
        status = CAM_KEYTAB_FILE_KINIT_FAILURE;
    }

    free(kinit_shell_command);
    return status;
}

/**
 * @brief Function: cryptography_get_acs_algo. Maps Cryptolib ACS enums to KMC enums
 * It is possible for supported algos to vary between crypto libraries
 * @param algo_enum
 **/
int32_t cryptography_get_acs_algo(int8_t algo_enum)
{
    int32_t algo = CRYPTO_LIB_ERR_UNSUPPORTED_ACS; // All valid algo enums will be positive
    switch (algo_enum)
    {
        case CRYPTO_MAC_CMAC_AES256:
            return CRYPTO_MAC_CMAC_AES256;
        case CRYPTO_MAC_HMAC_SHA256:
            return CRYPTO_MAC_HMAC_SHA256;
        case CRYPTO_MAC_HMAC_SHA512:
            return CRYPTO_MAC_HMAC_SHA512;

        default:
#ifdef DEBUG
            printf("ACS Algo Enum not supported\n");
#endif
            break;
    }

    return (int)algo;
}

/**
 * @brief Function: cryptography_get_ecs_algo. Maps Cryptolib ECS enums to KMC enums
 * It is possible for supported algos to vary between crypto libraries
 * @param algo_enum
 **/
int32_t cryptography_get_ecs_algo(int8_t algo_enum)
{
    int32_t algo = CRYPTO_LIB_ERR_UNSUPPORTED_ECS; // All valid algo enums will be positive
    switch (algo_enum)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            return CRYPTO_CIPHER_AES256_GCM;
        case CRYPTO_CIPHER_AES256_CCM:
            return CRYPTO_CIPHER_AES256_CCM;
        case CRYPTO_CIPHER_AES256_GCM_SIV:
            return CRYPTO_CIPHER_AES256_GCM_SIV;

        default:
#ifdef DEBUG
            printf("ECS Algo Enum not supported\n");
#endif
            break;
    }

    return (int32_t)algo;
}