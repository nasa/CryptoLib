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

// Cryptography Interface Initialization & Management Functions
static int32_t cryptography_config(void);
static int32_t cryptography_init(void);
static crypto_key_t* get_ek_ring(void);
static int32_t cryptography_shutdown(void);
// Cryptography Interface Functions
static int32_t cryptography_encrypt(void);
static int32_t cryptography_decrypt(void);
static int32_t cryptography_authenticate(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs);
static int32_t cryptography_validate_authentication(uint8_t* data_out, size_t len_data_out,
                                                    uint8_t* data_in, size_t len_data_in,
                                                    uint8_t* key, uint32_t len_key,
                                                    SecurityAssociation_t* sa_ptr,
                                                    uint8_t* iv, uint32_t iv_len,
                                                    uint8_t* mac, uint32_t mac_size,
                                                    uint8_t* aad, uint32_t aad_len,
                                                    uint8_t ecs, uint8_t acs);
static int32_t cryptography_aead_encrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool);
static int32_t cryptography_aead_decrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool);
/*
** Module Variables
*/
// Cryptography Interface
static CryptographyInterfaceStruct cryptography_if_struct;
static CURL* curl;

CryptographyInterface get_cryptography_interface_kmc_crypto_service(void)
{
    cryptography_if_struct.cryptography_config = cryptography_config;
    cryptography_if_struct.cryptography_init = cryptography_init;
    cryptography_if_struct.get_ek_ring = get_ek_ring;
    cryptography_if_struct.cryptography_shutdown = cryptography_shutdown;
    cryptography_if_struct.cryptography_encrypt = cryptography_encrypt;
    cryptography_if_struct.cryptography_decrypt = cryptography_decrypt;
    cryptography_if_struct.cryptography_authenticate = cryptography_authenticate;
    cryptography_if_struct.cryptography_validate_authentication = cryptography_validate_authentication;
    cryptography_if_struct.cryptography_aead_encrypt = cryptography_aead_encrypt;
    cryptography_if_struct.cryptography_aead_decrypt = cryptography_aead_decrypt;
    return &cryptography_if_struct;
}

static int32_t cryptography_config(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Error out if Crypto_Config_Kmc_Crypto_Service(...) function was not called before intializing library.
    if(cryptography_kmc_crypto_config == NULL)
    {
        fprintf(stderr, "You must configure the KMC Crypto Service before starting the interface!\n");
        status = CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIGURATION_NOT_COMPLETE;
        return status;
    }

    if(curl)
    {
        //Determine length of port and convert to string for use in URL
        // int port_str_len = snprintf( NULL, 0, "%d", cryptography_kmc_crypto_config->kmc_crypto_port);
        // char* port_str = malloc( port_str_len + 1);
        // snprintf( port_str, port_str_len + 1, "%d", cryptography_kmc_crypto_config->kmc_crypto_port );

        // Form URL
        //len(protocol)+len(://)+len(hostname)+strlen('\0')
        uint32_t len_url = strlen(cryptography_kmc_crypto_config->protocol) + 3 +
                            strlen(cryptography_kmc_crypto_config->kmc_crypto_hostname) + 1;
        char* url_str = malloc(len_url);
        snprintf(url_str,len_url,"%s://%s",cryptography_kmc_crypto_config->protocol,
                 cryptography_kmc_crypto_config->kmc_crypto_hostname);

#ifdef DEBUG
        printf("Setting up cURL connection to KMC Crypto Service with Params:\n");
        printf("\tURL: %s\n",url_str);
        printf("\tPort: %d\n",cryptography_kmc_crypto_config->kmc_crypto_port);
        printf("\tSSL Client Cert: %s\n",cryptography_kmc_crypto_config->mtls_client_cert_path);
        printf("\tSSL Client Key: %s\n",cryptography_kmc_crypto_config->mtls_client_key_path);
#endif

        curl_easy_setopt(curl, CURLOPT_URL, url_str);
        //curl_easy_setopt(curl, CURLOPT_PROTOCOLS,CURLPROTO_HTTPS); // use default CURLPROTO_ALL
        curl_easy_setopt(curl, CURLOPT_PORT, cryptography_kmc_crypto_config->kmc_crypto_port);
        curl_easy_setopt(curl, CURLOPT_SSLCERT, cryptography_kmc_crypto_config->mtls_client_cert_path);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, cryptography_kmc_crypto_config->mtls_client_key_path);
        if(cryptography_kmc_crypto_config->mtls_client_cert_type != NULL){
            curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, cryptography_kmc_crypto_config->mtls_client_cert_type);
        }
        if(cryptography_kmc_crypto_config->mtls_client_key_pass != NULL){
            curl_easy_setopt(curl, CURLOPT_KEYPASSWD, cryptography_kmc_crypto_config->mtls_client_key_pass);
        }
        if(cryptography_kmc_crypto_config->mtls_ca_bundle != NULL){
            curl_easy_setopt(curl, CURLOPT_CAINFO, cryptography_kmc_crypto_config->mtls_ca_bundle);
        }
        if(cryptography_kmc_crypto_config->mtls_ca_path != NULL){
            curl_easy_setopt(curl, CURLOPT_CAPATH, cryptography_kmc_crypto_config->mtls_ca_path);
        }
        if(cryptography_kmc_crypto_config->mtls_issuer_cert != NULL){
            curl_easy_setopt(curl, CURLOPT_ISSUERCERT, cryptography_kmc_crypto_config->mtls_issuer_cert);
        }
        if(cryptography_kmc_crypto_config->ignore_ssl_hostname_validation == CRYPTO_TRUE){
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        }

        curl_easy_perform(curl);
    }
    return status;
}
static int32_t cryptography_init(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    curl = curl_easy_init();
    if(curl == NULL) {
        status = CRYPTOGRAPHY_KMC_CURL_INITIALIZATION_FAILURE;
    }
    return status;
}
static crypto_key_t* get_ek_ring(void)
{
    fprintf(stderr, "Attempting to access key ring with KMC Crypto Service. This shouldn't happen!\n ");
    return NULL;
}
static int32_t cryptography_shutdown(void)
{
    if(curl){
        curl_easy_cleanup(curl);
    }
    return CRYPTO_LIB_SUCCESS;
}
static int32_t cryptography_encrypt(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_decrypt(void){ return CRYPTO_LIB_SUCCESS; }
static int32_t cryptography_authenticate(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs)
{
    data_out = data_out;
    len_data_out = len_data_out;
    data_in = data_in;
    len_data_in = len_data_in;
    key = key;
    len_key = len_key;
    sa_ptr = sa_ptr;
    iv = iv;
    iv_len = iv_len;
    mac = mac;
    mac_size = mac_size;
    aad = aad;
    aad_len = aad_len;
    ecs = ecs;
    acs = acs;
    return CRYPTO_LIB_SUCCESS;
}
static int32_t cryptography_validate_authentication(uint8_t* data_out, size_t len_data_out,
                                                    uint8_t* data_in, size_t len_data_in,
                                                    uint8_t* key, uint32_t len_key,
                                                    SecurityAssociation_t* sa_ptr,
                                                    uint8_t* iv, uint32_t iv_len,
                                                    uint8_t* mac, uint32_t mac_size,
                                                    uint8_t* aad, uint32_t aad_len,
                                                    uint8_t ecs, uint8_t acs)
{
    data_out = data_out;
    len_data_out = len_data_out;
    data_in = data_in;
    len_data_in = len_data_in;
    key = key;
    len_key = len_key;
    sa_ptr = sa_ptr;
    iv = iv;
    iv_len = iv_len;
    mac = mac;
    mac_size = mac_size;
    aad = aad;
    aad_len = aad_len;
    ecs = ecs;
    acs = acs;
    return CRYPTO_LIB_SUCCESS;
}
static int32_t cryptography_aead_encrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    data_out = data_out;
    len_data_out = len_data_out;
    data_in = data_in;
    len_data_in = len_data_in;
    key = key;
    len_key = len_key;
    sa_ptr = sa_ptr;
    iv = iv;
    iv_len = iv_len;
    mac = mac;
    mac_size = mac_size;
    aad = aad;
    aad_len = aad_len;
    encrypt_bool = encrypt_bool;
    authenticate_bool = authenticate_bool;
    aad_bool = aad_bool;
    return status;
}
static int32_t cryptography_aead_decrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool)
{
    data_out = data_out;
    len_data_out = len_data_out;
    data_in = data_in;
    len_data_in = len_data_in;
    key = key;
    len_key = len_key;
    sa_ptr = sa_ptr;
    iv = iv;
    iv_len = iv_len;
    mac = mac;
    mac_size = mac_size;
    aad = aad;
    aad_len = aad_len;
    decrypt_bool = decrypt_bool;
    authenticate_bool = authenticate_bool;
    aad_bool = aad_bool;
    return CRYPTO_LIB_SUCCESS;
}
