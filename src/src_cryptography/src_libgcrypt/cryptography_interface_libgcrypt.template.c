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

#include <gcrypt.h>


#include "crypto.h"
#include "crypto_error.h"
#include "cryptography_interface.h"


// Cryptography Interface Initialization & Management Functions
static int32_t cryptography_config(void);
static int32_t cryptography_init(void);
static crypto_key_t* get_ek_ring(void);
static int32_t cryptography_shutdown(void);
// Cryptography Interface Functions
static int32_t cryptography_encrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,uint8_t* ecs, uint8_t padding, char* cam_cookies);
static int32_t cryptography_decrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr, 
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* ecs, uint8_t* acs, char* cam_cookies);
static int32_t cryptography_authenticate(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs, char* cam_cookies);
static int32_t cryptography_validate_authentication(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs, char* cam_cookies);
static int32_t cryptography_aead_encrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t* ecs, uint8_t* acs, char* cam_cookies);
static int32_t cryptography_aead_decrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t decrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t* ecs, uint8_t* acs, char* cam_cookies);
static int32_t cryptography_get_acs_algo(int8_t algo_enum);
static int32_t cryptography_get_ecs_algo(int8_t algo_enum);
static int32_t cryptography_get_ecs_mode(int8_t algo_enum);

/*
** Module Variables
*/
// Security
static crypto_key_t ek_ring[NUM_KEYS] = {0};
// Cryptography Interface
static CryptographyInterfaceStruct cryptography_if_struct;

CryptographyInterface get_cryptography_interface_libgcrypt(void)
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
    cryptography_if_struct.cryptography_get_acs_algo = cryptography_get_acs_algo;
    cryptography_if_struct.cryptography_get_ecs_algo = cryptography_get_ecs_algo;
    return &cryptography_if_struct;
}

static int32_t cryptography_config(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Master Keys
    // 0 - 000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F -> ACTIVE
    ek_ring[0].value[0] = 0x00;
    ek_ring[0].value[1] = 0x01;
    ek_ring[0].value[2] = 0x02;
    ek_ring[0].value[3] = 0x03;
    ek_ring[0].value[4] = 0x04;
    ek_ring[0].value[5] = 0x05;
    ek_ring[0].value[6] = 0x06;
    ek_ring[0].value[7] = 0x07;
    ek_ring[0].value[8] = 0x08;
    ek_ring[0].value[9] = 0x09;
    ek_ring[0].value[10] = 0x0A;
    ek_ring[0].value[11] = 0x0B;
    ek_ring[0].value[12] = 0x0C;
    ek_ring[0].value[13] = 0x0D;
    ek_ring[0].value[14] = 0x0E;
    ek_ring[0].value[15] = 0x0F;
    ek_ring[0].value[16] = 0x00;
    ek_ring[0].value[17] = 0x01;
    ek_ring[0].value[18] = 0x02;
    ek_ring[0].value[19] = 0x03;
    ek_ring[0].value[20] = 0x04;
    ek_ring[0].value[21] = 0x05;
    ek_ring[0].value[22] = 0x06;
    ek_ring[0].value[23] = 0x07;
    ek_ring[0].value[24] = 0x08;
    ek_ring[0].value[25] = 0x09;
    ek_ring[0].value[26] = 0x0A;
    ek_ring[0].value[27] = 0x0B;
    ek_ring[0].value[28] = 0x0C;
    ek_ring[0].value[29] = 0x0D;
    ek_ring[0].value[30] = 0x0E;
    ek_ring[0].value[31] = 0x0F;
    ek_ring[0].key_len = 32;
    ek_ring[0].key_state = KEY_ACTIVE;
    // 1 - 101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F -> ACTIVE
    ek_ring[1].value[0] = 0x10;
    ek_ring[1].value[1] = 0x11;
    ek_ring[1].value[2] = 0x12;
    ek_ring[1].value[3] = 0x13;
    ek_ring[1].value[4] = 0x14;
    ek_ring[1].value[5] = 0x15;
    ek_ring[1].value[6] = 0x16;
    ek_ring[1].value[7] = 0x17;
    ek_ring[1].value[8] = 0x18;
    ek_ring[1].value[9] = 0x19;
    ek_ring[1].value[10] = 0x1A;
    ek_ring[1].value[11] = 0x1B;
    ek_ring[1].value[12] = 0x1C;
    ek_ring[1].value[13] = 0x1D;
    ek_ring[1].value[14] = 0x1E;
    ek_ring[1].value[15] = 0x1F;
    ek_ring[1].value[16] = 0x10;
    ek_ring[1].value[17] = 0x11;
    ek_ring[1].value[18] = 0x12;
    ek_ring[1].value[19] = 0x13;
    ek_ring[1].value[20] = 0x14;
    ek_ring[1].value[21] = 0x15;
    ek_ring[1].value[22] = 0x16;
    ek_ring[1].value[23] = 0x17;
    ek_ring[1].value[24] = 0x18;
    ek_ring[1].value[25] = 0x19;
    ek_ring[1].value[26] = 0x1A;
    ek_ring[1].value[27] = 0x1B;
    ek_ring[1].value[28] = 0x1C;
    ek_ring[1].value[29] = 0x1D;
    ek_ring[1].value[30] = 0x1E;
    ek_ring[1].value[31] = 0x1F;
    ek_ring[1].key_len = 32;
    ek_ring[1].key_state = KEY_ACTIVE;
    // 2 - 202122232425262728292A2B2C2D2E2F202122232425262728292A2B2C2D2E2F -> ACTIVE
    ek_ring[2].value[0] = 0x20;
    ek_ring[2].value[1] = 0x21;
    ek_ring[2].value[2] = 0x22;
    ek_ring[2].value[3] = 0x23;
    ek_ring[2].value[4] = 0x24;
    ek_ring[2].value[5] = 0x25;
    ek_ring[2].value[6] = 0x26;
    ek_ring[2].value[7] = 0x27;
    ek_ring[2].value[8] = 0x28;
    ek_ring[2].value[9] = 0x29;
    ek_ring[2].value[10] = 0x2A;
    ek_ring[2].value[11] = 0x2B;
    ek_ring[2].value[12] = 0x2C;
    ek_ring[2].value[13] = 0x2D;
    ek_ring[2].value[14] = 0x2E;
    ek_ring[2].value[15] = 0x2F;
    ek_ring[2].value[16] = 0x20;
    ek_ring[2].value[17] = 0x21;
    ek_ring[2].value[18] = 0x22;
    ek_ring[2].value[19] = 0x23;
    ek_ring[2].value[20] = 0x24;
    ek_ring[2].value[21] = 0x25;
    ek_ring[2].value[22] = 0x26;
    ek_ring[2].value[23] = 0x27;
    ek_ring[2].value[24] = 0x28;
    ek_ring[2].value[25] = 0x29;
    ek_ring[2].value[26] = 0x2A;
    ek_ring[2].value[27] = 0x2B;
    ek_ring[2].value[28] = 0x2C;
    ek_ring[2].value[29] = 0x2D;
    ek_ring[2].value[30] = 0x2E;
    ek_ring[2].value[31] = 0x2F;
    ek_ring[2].key_len = 32;
    ek_ring[2].key_state = KEY_ACTIVE;

    // Session Keys
    // 128 - 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF -> ACTIVE
    ek_ring[128].value[0] = 0x01;
    ek_ring[128].value[1] = 0x23;
    ek_ring[128].value[2] = 0x45;
    ek_ring[128].value[3] = 0x67;
    ek_ring[128].value[4] = 0x89;
    ek_ring[128].value[5] = 0xAB;
    ek_ring[128].value[6] = 0xCD;
    ek_ring[128].value[7] = 0xEF;
    ek_ring[128].value[8] = 0x01;
    ek_ring[128].value[9] = 0x23;
    ek_ring[128].value[10] = 0x45;
    ek_ring[128].value[11] = 0x67;
    ek_ring[128].value[12] = 0x89;
    ek_ring[128].value[13] = 0xAB;
    ek_ring[128].value[14] = 0xCD;
    ek_ring[128].value[15] = 0xEF;
    ek_ring[128].value[16] = 0x01;
    ek_ring[128].value[17] = 0x23;
    ek_ring[128].value[18] = 0x45;
    ek_ring[128].value[19] = 0x67;
    ek_ring[128].value[20] = 0x89;
    ek_ring[128].value[21] = 0xAB;
    ek_ring[128].value[22] = 0xCD;
    ek_ring[128].value[23] = 0xEF;
    ek_ring[128].value[24] = 0x01;
    ek_ring[128].value[25] = 0x23;
    ek_ring[128].value[26] = 0x45;
    ek_ring[128].value[27] = 0x67;
    ek_ring[128].value[28] = 0x89;
    ek_ring[128].value[29] = 0xAB;
    ek_ring[128].value[30] = 0xCD;
    ek_ring[128].value[31] = 0xEF;
    ek_ring[128].key_len = 32;
    ek_ring[128].key_state = KEY_ACTIVE;
    // 129 - ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789 -> ACTIVE
    ek_ring[129].value[0] = 0xAB;
    ek_ring[129].value[1] = 0xCD;
    ek_ring[129].value[2] = 0xEF;
    ek_ring[129].value[3] = 0x01;
    ek_ring[129].value[4] = 0x23;
    ek_ring[129].value[5] = 0x45;
    ek_ring[129].value[6] = 0x67;
    ek_ring[129].value[7] = 0x89;
    ek_ring[129].value[8] = 0xAB;
    ek_ring[129].value[9] = 0xCD;
    ek_ring[129].value[10] = 0xEF;
    ek_ring[129].value[11] = 0x01;
    ek_ring[129].value[12] = 0x23;
    ek_ring[129].value[13] = 0x45;
    ek_ring[129].value[14] = 0x67;
    ek_ring[129].value[15] = 0x89;
    ek_ring[129].value[16] = 0xAB;
    ek_ring[129].value[17] = 0xCD;
    ek_ring[129].value[18] = 0xEF;
    ek_ring[129].value[19] = 0x01;
    ek_ring[129].value[20] = 0x23;
    ek_ring[129].value[21] = 0x45;
    ek_ring[129].value[22] = 0x67;
    ek_ring[129].value[23] = 0x89;
    ek_ring[129].value[24] = 0xAB;
    ek_ring[129].value[25] = 0xCD;
    ek_ring[129].value[26] = 0xEF;
    ek_ring[129].value[27] = 0x01;
    ek_ring[129].value[28] = 0x23;
    ek_ring[129].value[29] = 0x45;
    ek_ring[129].value[30] = 0x67;
    ek_ring[129].value[31] = 0x89;
    ek_ring[129].key_len = 32;
    ek_ring[129].key_state = KEY_ACTIVE;
    // 130 - FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210 -> ACTIVE
    ek_ring[130].value[0] = 0xFE;
    ek_ring[130].value[1] = 0xDC;
    ek_ring[130].value[2] = 0xBA;
    ek_ring[130].value[3] = 0x98;
    ek_ring[130].value[4] = 0x76;
    ek_ring[130].value[5] = 0x54;
    ek_ring[130].value[6] = 0x32;
    ek_ring[130].value[7] = 0x10;
    ek_ring[130].value[8] = 0xFE;
    ek_ring[130].value[9] = 0xDC;
    ek_ring[130].value[10] = 0xBA;
    ek_ring[130].value[11] = 0x98;
    ek_ring[130].value[12] = 0x76;
    ek_ring[130].value[13] = 0x54;
    ek_ring[130].value[14] = 0x32;
    ek_ring[130].value[15] = 0x10;
    ek_ring[130].value[16] = 0xFE;
    ek_ring[130].value[17] = 0xDC;
    ek_ring[130].value[18] = 0xBA;
    ek_ring[130].value[19] = 0x98;
    ek_ring[130].value[20] = 0x76;
    ek_ring[130].value[21] = 0x54;
    ek_ring[130].value[22] = 0x32;
    ek_ring[130].value[23] = 0x10;
    ek_ring[130].value[24] = 0xFE;
    ek_ring[130].value[25] = 0xDC;
    ek_ring[130].value[26] = 0xBA;
    ek_ring[130].value[27] = 0x98;
    ek_ring[130].value[28] = 0x76;
    ek_ring[130].value[29] = 0x54;
    ek_ring[130].value[30] = 0x32;
    ek_ring[130].value[31] = 0x10;
    ek_ring[130].key_len = 32;
    ek_ring[130].key_state = KEY_ACTIVE;
    // 131 - 9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA -> ACTIVE
    ek_ring[131].value[0] = 0x98;
    ek_ring[131].value[1] = 0x76;
    ek_ring[131].value[2] = 0x54;
    ek_ring[131].value[3] = 0x32;
    ek_ring[131].value[4] = 0x10;
    ek_ring[131].value[5] = 0xFE;
    ek_ring[131].value[6] = 0xDC;
    ek_ring[131].value[7] = 0xBA;
    ek_ring[131].value[8] = 0x98;
    ek_ring[131].value[9] = 0x76;
    ek_ring[131].value[10] = 0x54;
    ek_ring[131].value[11] = 0x32;
    ek_ring[131].value[12] = 0x10;
    ek_ring[131].value[13] = 0xFE;
    ek_ring[131].value[14] = 0xDC;
    ek_ring[131].value[15] = 0xBA;
    ek_ring[131].value[16] = 0x98;
    ek_ring[131].value[17] = 0x76;
    ek_ring[131].value[18] = 0x54;
    ek_ring[131].value[19] = 0x32;
    ek_ring[131].value[20] = 0x10;
    ek_ring[131].value[21] = 0xFE;
    ek_ring[131].value[22] = 0xDC;
    ek_ring[131].value[23] = 0xBA;
    ek_ring[131].value[24] = 0x98;
    ek_ring[131].value[25] = 0x76;
    ek_ring[131].value[26] = 0x54;
    ek_ring[131].value[27] = 0x32;
    ek_ring[131].value[28] = 0x10;
    ek_ring[131].value[29] = 0xFE;
    ek_ring[131].value[30] = 0xDC;
    ek_ring[131].value[31] = 0xBA;
    ek_ring[131].key_len = 32;
    ek_ring[131].key_state = KEY_ACTIVE;
    // 132 - 0123456789ABCDEFABCDEF01234567890123456789ABCDEFABCDEF0123456789 -> PRE_ACTIVATION
    ek_ring[132].value[0] = 0x01;
    ek_ring[132].value[1] = 0x23;
    ek_ring[132].value[2] = 0x45;
    ek_ring[132].value[3] = 0x67;
    ek_ring[132].value[4] = 0x89;
    ek_ring[132].value[5] = 0xAB;
    ek_ring[132].value[6] = 0xCD;
    ek_ring[132].value[7] = 0xEF;
    ek_ring[132].value[8] = 0xAB;
    ek_ring[132].value[9] = 0xCD;
    ek_ring[132].value[10] = 0xEF;
    ek_ring[132].value[11] = 0x01;
    ek_ring[132].value[12] = 0x23;
    ek_ring[132].value[13] = 0x45;
    ek_ring[132].value[14] = 0x67;
    ek_ring[132].value[15] = 0x89;
    ek_ring[132].value[16] = 0x01;
    ek_ring[132].value[17] = 0x23;
    ek_ring[132].value[18] = 0x45;
    ek_ring[132].value[19] = 0x67;
    ek_ring[132].value[20] = 0x89;
    ek_ring[132].value[21] = 0xAB;
    ek_ring[132].value[22] = 0xCD;
    ek_ring[132].value[23] = 0xEF;
    ek_ring[132].value[24] = 0xAB;
    ek_ring[132].value[25] = 0xCD;
    ek_ring[132].value[26] = 0xEF;
    ek_ring[132].value[27] = 0x01;
    ek_ring[132].value[28] = 0x23;
    ek_ring[132].value[29] = 0x45;
    ek_ring[132].value[30] = 0x67;
    ek_ring[132].value[31] = 0x89;
    ek_ring[132].key_len = 32;
    ek_ring[132].key_state = KEY_PREACTIVE;
    // 133 - ABCDEF01234567890123456789ABCDEFABCDEF01234567890123456789ABCDEF -> ACTIVE
    ek_ring[133].value[0] = 0xAB;
    ek_ring[133].value[1] = 0xCD;
    ek_ring[133].value[2] = 0xEF;
    ek_ring[133].value[3] = 0x01;
    ek_ring[133].value[4] = 0x23;
    ek_ring[133].value[5] = 0x45;
    ek_ring[133].value[6] = 0x67;
    ek_ring[133].value[7] = 0x89;
    ek_ring[133].value[8] = 0x01;
    ek_ring[133].value[9] = 0x23;
    ek_ring[133].value[10] = 0x45;
    ek_ring[133].value[11] = 0x67;
    ek_ring[133].value[12] = 0x89;
    ek_ring[133].value[13] = 0xAB;
    ek_ring[133].value[14] = 0xCD;
    ek_ring[133].value[15] = 0xEF;
    ek_ring[133].value[16] = 0xAB;
    ek_ring[133].value[17] = 0xCD;
    ek_ring[133].value[18] = 0xEF;
    ek_ring[133].value[19] = 0x01;
    ek_ring[133].value[20] = 0x23;
    ek_ring[133].value[21] = 0x45;
    ek_ring[133].value[22] = 0x67;
    ek_ring[133].value[23] = 0x89;
    ek_ring[133].value[24] = 0x01;
    ek_ring[133].value[25] = 0x23;
    ek_ring[133].value[26] = 0x45;
    ek_ring[133].value[27] = 0x67;
    ek_ring[133].value[28] = 0x89;
    ek_ring[133].value[29] = 0xAB;
    ek_ring[133].value[30] = 0xCD;
    ek_ring[133].value[31] = 0xEF;
    ek_ring[133].key_len = 32;
    ek_ring[133].key_state = KEY_ACTIVE;
    // 134 - ABCDEF0123456789FEDCBA9876543210ABCDEF0123456789FEDCBA9876543210 -> DEACTIVE
    ek_ring[134].value[0] = 0xAB;
    ek_ring[134].value[1] = 0xCD;
    ek_ring[134].value[2] = 0xEF;
    ek_ring[134].value[3] = 0x01;
    ek_ring[134].value[4] = 0x23;
    ek_ring[134].value[5] = 0x45;
    ek_ring[134].value[6] = 0x67;
    ek_ring[134].value[7] = 0x89;
    ek_ring[134].value[8] = 0xFE;
    ek_ring[134].value[9] = 0xDC;
    ek_ring[134].value[10] = 0xBA;
    ek_ring[134].value[11] = 0x98;
    ek_ring[134].value[12] = 0x76;
    ek_ring[134].value[13] = 0x54;
    ek_ring[134].value[14] = 0x32;
    ek_ring[134].value[15] = 0x10;
    ek_ring[134].value[16] = 0xAB;
    ek_ring[134].value[17] = 0xCD;
    ek_ring[134].value[18] = 0xEF;
    ek_ring[134].value[19] = 0x01;
    ek_ring[134].value[20] = 0x23;
    ek_ring[134].value[21] = 0x45;
    ek_ring[134].value[22] = 0x67;
    ek_ring[134].value[23] = 0x89;
    ek_ring[134].value[24] = 0xFE;
    ek_ring[134].value[25] = 0xDC;
    ek_ring[134].value[26] = 0xBA;
    ek_ring[134].value[27] = 0x98;
    ek_ring[134].value[28] = 0x76;
    ek_ring[134].value[29] = 0x54;
    ek_ring[134].value[30] = 0x32;
    ek_ring[134].value[31] = 0x10;
    ek_ring[134].key_len = 32;
    ek_ring[134].key_state = KEY_DEACTIVATED;

    // 135 - ABCDEF0123456789FEDCBA9876543210ABCDEF0123456789FEDCBA9876543210 -> DEACTIVE
    ek_ring[135].value[0] = 0x00;
    ek_ring[135].value[1] = 0x00;
    ek_ring[135].value[2] = 0x00;
    ek_ring[135].value[3] = 0x00;
    ek_ring[135].value[4] = 0x00;
    ek_ring[135].value[5] = 0x00;
    ek_ring[135].value[6] = 0x00;
    ek_ring[135].value[7] = 0x00;
    ek_ring[135].value[8] = 0x00;
    ek_ring[135].value[9] = 0x00;
    ek_ring[135].value[10] = 0x00;
    ek_ring[135].value[11] = 0x00;
    ek_ring[135].value[12] = 0x00;
    ek_ring[135].value[13] = 0x00;
    ek_ring[135].value[14] = 0x00;
    ek_ring[135].value[15] = 0x00;
    ek_ring[135].value[16] = 0x00;
    ek_ring[135].value[17] = 0x00;
    ek_ring[135].value[18] = 0x00;
    ek_ring[135].value[19] = 0x00;
    ek_ring[135].value[20] = 0x00;
    ek_ring[135].value[21] = 0x00;
    ek_ring[135].value[22] = 0x00;
    ek_ring[135].value[23] = 0x00;
    ek_ring[135].value[24] = 0x00;
    ek_ring[135].value[25] = 0x00;
    ek_ring[135].value[26] = 0x00;
    ek_ring[135].value[27] = 0x00;
    ek_ring[135].value[28] = 0x00;
    ek_ring[135].value[29] = 0x00;
    ek_ring[135].value[30] = 0x00;
    ek_ring[135].value[31] = 0x00;
    ek_ring[135].key_len = 32;
    ek_ring[135].key_state = KEY_DEACTIVATED;

    // 136 - ef9f9284cf599eac3b119905a7d18851e7e374cf63aea04358586b0f757670f8
    // Reference:
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
    ek_ring[136].value[0] = 0xff;
    ek_ring[136].value[1] = 0x9f;
    ek_ring[136].value[2] = 0x92;
    ek_ring[136].value[3] = 0x84;
    ek_ring[136].value[4] = 0xcf;
    ek_ring[136].value[5] = 0x59;
    ek_ring[136].value[6] = 0x9e;
    ek_ring[136].value[7] = 0xac;
    ek_ring[136].value[8] = 0x3b;
    ek_ring[136].value[9] = 0x11;
    ek_ring[136].value[10] = 0x99;
    ek_ring[136].value[11] = 0x05;
    ek_ring[136].value[12] = 0xa7;
    ek_ring[136].value[13] = 0xd1;
    ek_ring[136].value[14] = 0x88;
    ek_ring[136].value[15] = 0x51;
    ek_ring[136].value[16] = 0xe7;
    ek_ring[136].value[17] = 0xe3;
    ek_ring[136].value[18] = 0x74;
    ek_ring[136].value[19] = 0xcf;
    ek_ring[136].value[20] = 0x63;
    ek_ring[136].value[21] = 0xae;
    ek_ring[136].value[22] = 0xa0;
    ek_ring[136].value[23] = 0x43;
    ek_ring[136].value[24] = 0x58;
    ek_ring[136].value[25] = 0x58;
    ek_ring[136].value[26] = 0x6b;
    ek_ring[136].value[27] = 0x0f;
    ek_ring[136].value[28] = 0x75;
    ek_ring[136].value[29] = 0x76;
    ek_ring[136].value[30] = 0x70;
    ek_ring[136].value[31] = 0xf9;
    ek_ring[136].key_len = 32;
    ek_ring[136].key_state = KEY_DEACTIVATED;

    return status;
}
static crypto_key_t* get_ek_ring(void)
{
    return &ek_ring[0];
}


static int32_t cryptography_init(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    // Initialize libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION))
    {
        fprintf(stderr, "Gcrypt Version: %s", GCRYPT_VERSION);
        printf(KRED "\tERROR: gcrypt version mismatch! \n" RESET);
    }
    if (gcry_control(GCRYCTL_SELFTEST) != GPG_ERR_NO_ERROR)
    {
        status = CRYPTOGRAPHY_LIBRARY_INITIALIZIATION_ERROR;
        printf(KRED "ERROR: gcrypt self test failed\n" RESET);
    }
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    return status;
}
static int32_t cryptography_shutdown(void){ return CRYPTO_LIB_SUCCESS; }

static int32_t cryptography_authenticate(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr, // For key index or key references (when key not passed in explicitly via key param)
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs, char* cam_cookies)
{ 
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    gcry_mac_hd_t tmp_mac_hd;
    int32_t status = CRYPTO_LIB_SUCCESS;
    uint8_t* key_ptr = key;

    if(sa_ptr != NULL) //Using SA key pointer
    {
        key_ptr = &(ek_ring[sa_ptr->akid].value[0]);
    }
    // Need to copy the data over, since authentication won't change/move the data directly
    if(data_out != NULL)
    {
        memcpy(data_out, data_in, len_data_in);
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }
    // Using to fix warning
    len_data_out = len_data_out;
    ecs = ecs;
    cam_cookies = cam_cookies;

    // Select correct libgcrypt acs enum
    int32_t algo = cryptography_get_acs_algo(acs);
    if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ACS)
    {
        return CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
    }

    // Check that key length to be used is atleast as long as the algo requirement
    if (sa_ptr != NULL && len_key > ek_ring[sa_ptr->akid].key_len)
    {
        return CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
    }

    gcry_error = gcry_mac_open(&(tmp_mac_hd), algo, GCRY_MAC_FLAG_SECURE, NULL);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_mac_setkey(tmp_mac_hd, key_ptr, len_key);
    
#ifdef SA_DEBUG
    uint32_t i;
    printf(KYEL "Auth MAC Printing Key:\n\t");
    for (i = 0; i < len_key; i++)
    {
        printf("%02X", *(key_ptr + i));
    }
    printf("\n");
#endif
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        gcry_mac_close(tmp_mac_hd);
        return status;
    }

    // If MAC needs IV, set it (only for certain ciphers)
    if (iv_len > 0)
    {
        gcry_error = gcry_mac_setiv(tmp_mac_hd, iv, iv_len);
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_mac_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERROR;
            gcry_mac_close(tmp_mac_hd);
            return status;
        }
    }

    gcry_error = gcry_mac_write(tmp_mac_hd,
                                aad,    // additional authenticated data
                                aad_len // length of AAD
    );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_write error code %d\n" RESET,
                gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERROR;
        gcry_mac_close(tmp_mac_hd);
        return status;
    }

    uint32_t* tmac_size = &mac_size;
    gcry_error = gcry_mac_read(tmp_mac_hd,
                               mac,      // tag output
                               (size_t* )tmac_size // tag size
    );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_read error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR;
        gcry_mac_close(tmp_mac_hd);
        return status;
    }

    // Zeroise any sensitive information
    gcry_mac_close(tmp_mac_hd);
    return status; 
}
static int32_t cryptography_validate_authentication(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t ecs, uint8_t acs, char* cam_cookies)
{ 
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    gcry_mac_hd_t tmp_mac_hd;
    int32_t status = CRYPTO_LIB_SUCCESS;
    uint8_t* key_ptr = key;
    if(sa_ptr != NULL) //Using SA key pointer
    {
        key_ptr = &(ek_ring[sa_ptr->akid].value[0]);
    }

    // Need to copy the data over, since authentication won't change/move the data directly
    if(data_out != NULL)
    {
        memcpy(data_out, data_in, len_data_in);
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }
    // Using to fix warning
    len_data_out = len_data_out;
    ecs = ecs;
    cam_cookies = cam_cookies;

    // Select correct libgcrypt acs enum
    int32_t algo = cryptography_get_acs_algo(acs);
    if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ACS)
    {
        return CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
    }

    // Check that key length to be used is atleast as long as the algo requirement
    if (sa_ptr != NULL && len_key > ek_ring[sa_ptr->akid].key_len)
    {
        return CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
    }

    gcry_error = gcry_mac_open(&(tmp_mac_hd), algo, GCRY_MAC_FLAG_SECURE, NULL);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n" RESET, gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }

    gcry_error = gcry_mac_setkey(tmp_mac_hd, key_ptr, len_key);
#ifdef SA_DEBUG
    uint32_t i;
    printf(KYEL "Validate MAC Printing Key:\n\t");
    for (i = 0; i < len_key; i++)
    {
        printf("%02X", *(key_ptr + i));
    }
    printf("\n" RESET);
#endif
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n" RESET, gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_mac_close(tmp_mac_hd);
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    // If MAC needs IV, set it (only for certain ciphers)
    if (iv_len > 0)
    {
        gcry_error = gcry_mac_setiv(tmp_mac_hd, iv, iv_len);
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_mac_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n" RESET, gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            gcry_mac_close(tmp_mac_hd);
            status = CRYPTO_LIB_ERROR;
            return status;
        }
    }
    gcry_error = gcry_mac_write(tmp_mac_hd,
                                aad,    // additional authenticated data
                                aad_len // length of AAD
    );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_write error code %d\n" RESET,
                gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n" RESET, gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_mac_close(tmp_mac_hd);
        status = CRYPTO_LIB_ERROR;
        return status;
    }

#ifdef MAC_DEBUG
    uint32_t* tmac_size = &mac_size;
    uint8_t* tmac = calloc(1,*tmac_size);
    gcry_error = gcry_mac_read(tmp_mac_hd,
                               tmac,      // tag output
                               (size_t *)tmac_size // tag size
    );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_read error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        status = CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR;
        return status;
    }

    printf("Calculated Mac Size: %d\n", *tmac_size);
    printf("Calculated MAC (full length):\n\t");
    for (uint32_t i = 0; i < *tmac_size; i ++){
        printf("%02X", tmac[i]);
    }
    printf("\nCalculated MAC (truncated to sa_ptr->stmacf_len):\n\t");
    for (uint32_t i = 0; i < mac_size; i ++){
        printf("%02X", tmac[i]);
    }
    printf("\n");
    free(tmac);

    printf("Received MAC:\n\t");
    for (uint32_t i = 0; i < mac_size; i ++){
        printf("%02X", mac[i]);
    }
    printf("\n");
#endif

    // Compare computed mac with MAC in frame
    gcry_error = gcry_mac_verify(tmp_mac_hd,
                                 mac,      // original mac
                                 (size_t)mac_size // tag size
    );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_mac_verify error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n" RESET, gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_mac_close(tmp_mac_hd);
        status = CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR;
        return status;
    }
#ifdef DEBUG
    else
    {
        printf("Mac verified!\n");
    }
#endif
    // Zeroise any sensitive information
    gcry_mac_reset(tmp_mac_hd);
    gcry_mac_close(tmp_mac_hd);
    return status; 
}

static int32_t cryptography_encrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr,
                                         uint8_t* iv, uint32_t iv_len,uint8_t* ecs, uint8_t padding, char* cam_cookies)
{
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    gcry_cipher_hd_t tmp_hd;
    int32_t status = CRYPTO_LIB_SUCCESS;
    uint8_t* key_ptr = key;

    data_out = data_out;        // TODO:  Look into tailoring these out, as they're not used or needed.
    len_data_out = len_data_out;
    padding = padding;
    cam_cookies = cam_cookies;

    if(sa_ptr != NULL) //Using SA key pointer
    {
        key_ptr = &(ek_ring[sa_ptr->ekid].value[0]);
    }

    // Select correct libgcrypt algorith enum
    int32_t algo = -1;
    if (ecs != NULL)
    {
        algo = cryptography_get_ecs_algo(*ecs);
        if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_MODE)
        {
            return CRYPTO_LIB_ERR_UNSUPPORTED_MODE;
        }
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_MODE_PTR;
    }

    // Verify the mode to accompany the algorithm enum
    int32_t mode = -1;
    mode = cryptography_get_ecs_mode(*ecs);
    if (mode == CRYPTO_LIB_ERR_UNSUPPORTED_MODE) return CRYPTO_LIB_ERR_UNSUPPORTED_MODE;

     // Check that key length to be used is atleast as long as the algo requirement
    if (sa_ptr != NULL && len_key > ek_ring[sa_ptr->ekid].key_len)
    {
        return CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
    }

    gcry_error = gcry_cipher_open(&(tmp_hd), algo, mode, GCRY_CIPHER_NONE);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setkey(tmp_hd, key_ptr, len_key);

#ifdef SA_DEBUG
    uint32_t i;
    printf(KYEL "Printing Key:\n\t");
    for (i = 0; i < len_key; i++)
    {
        printf("%02X", *(key_ptr + i));
    }
    printf("\n");
#endif

    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        gcry_cipher_close(tmp_hd);
        return status;
    }
    gcry_error = gcry_cipher_setiv(tmp_hd, iv, iv_len);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        gcry_cipher_close(tmp_hd);
        return status;
    }

#ifdef TC_DEBUG
    size_t j;
    printf("Input payload length is %ld\n", len_data_in);
    printf(KYEL "Printing Frame Data prior to encryption:\n\t");
    for (j = 0; j < len_data_in; j++)
    {
        printf("%02X", *(data_in + j));
    }
    printf("\n");
#endif


    gcry_error = gcry_cipher_encrypt(tmp_hd, data_in, len_data_in, NULL, 0);
    // TODO:  Add PKCS#7 padding to data_in, and increment len_data_in to match necessary block size
    // TODO:  Remember to remove the padding.
    // TODO:  Does this interfere with max frame size?  Does that need to be taken into account?
    // gcry_error = gcry_cipher_encrypt(tmp_hd,
    //                                     data_out,              // ciphertext output
    //                                     len_data_out,                // length of data
    //                                     data_in, // plaintext input
    //                                     len_data_in                 // in data length
    // );

    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_encrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_ENCRYPTION_ERROR;
        gcry_cipher_close(tmp_hd);
        return status;
    }

#ifdef TC_DEBUG
    printf("Output payload length is %ld\n", len_data_out);
    printf(KYEL "Printing TC Frame Data after encryption:\n\t");
    for (j = 0; j < len_data_out; j++)
    {
        printf("%02X", *(data_out + j));
    }
    printf("\n");
#endif

    gcry_cipher_close(tmp_hd);
    return status;
}

static int32_t cryptography_aead_encrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr, // For key index or key references (when key not passed in explicitly via key param)
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* mac, uint32_t mac_size,
                                         uint8_t* aad, uint32_t aad_len,
                                         uint8_t encrypt_bool, uint8_t authenticate_bool,
                                         uint8_t aad_bool, uint8_t* ecs, uint8_t* acs, char* cam_cookies)
{
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    gcry_cipher_hd_t tmp_hd;
    int32_t status = CRYPTO_LIB_SUCCESS;
    uint8_t* key_ptr = key;

    // Fix warning
    acs = acs;
    cam_cookies = cam_cookies;

    if(sa_ptr != NULL) //Using SA key pointer
    {
        key_ptr = &(ek_ring[sa_ptr->ekid].value[0]);
    }

    // Select correct libgcrypt ecs enum
    int32_t algo = -1;
    if (ecs != NULL)
    {
        algo = cryptography_get_ecs_algo(*ecs);
        if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ECS)
        {
            return CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
        }
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_ECS_PTR;
    }

    // Verify the mode to accompany the ecs enum
    int32_t mode = -1;
    mode = cryptography_get_ecs_mode(*ecs);
    if (mode == CRYPTO_LIB_ERR_UNSUPPORTED_ECS_MODE) return CRYPTO_LIB_ERR_UNSUPPORTED_ECS_MODE;

    // Check that key length to be used is atleast as long as the algo requirement
    if (sa_ptr != NULL && len_key > ek_ring[sa_ptr->ekid].key_len)
    {
        return CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
    }

    gcry_error = gcry_cipher_open(&(tmp_hd), algo, mode, GCRY_CIPHER_NONE);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setkey(tmp_hd, key_ptr, len_key);
#ifdef SA_DEBUG
    uint32_t i;
    printf(KYEL "AEAD MAC: Printing Key:\n\t");
    for (i = 0; i < len_key; i++)
    {
        printf("%02X", *(key_ptr + i));
    }
    printf("\n");
#endif

    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        gcry_cipher_close(tmp_hd);
        return status;
    }
    gcry_error = gcry_cipher_setiv(tmp_hd, iv, iv_len);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        gcry_cipher_close(tmp_hd);
        return status;
    }

#ifdef TC_DEBUG
    size_t j;
    printf("Input payload length is %ld\n", len_data_in);
    printf(KYEL "Printing Frame Data prior to encryption:\n\t");
    for (j = 0; j < len_data_in; j++)
    {
        printf("%02X", *(data_in + j));
    }
    printf("\n");
#endif

    if(aad_bool == CRYPTO_TRUE) // Authenticate with AAD!
    {
        gcry_error = gcry_cipher_authenticate(tmp_hd,
                                              aad,      // additional authenticated data
                                              aad_len // length of AAD
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_authenticate error code %d\n" RESET,
                   gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERR_AUTHENTICATION_ERROR;
            gcry_cipher_close(tmp_hd);
            return status;
        }
    }

    if(encrypt_bool == CRYPTO_TRUE)
    {
        // TODO:  Add PKCS#7 padding to data_in, and increment len_data_in to match necessary block size
        // TODO:  Remember to remove the padding.
        // TODO:  Does this interfere with max frame size?  Does that need to be taken into account?
        gcry_error = gcry_cipher_encrypt(tmp_hd,
                                         data_out,              // ciphertext output
                                         len_data_out,                // length of data
                                         data_in, // plaintext input
                                         len_data_in                 // in data length
        );
    }
    else // AEAD authenticate only
    {
        gcry_error = gcry_cipher_encrypt(tmp_hd,
                                         NULL,              // ciphertext output
                                         0,                // length of data
                                         NULL, // plaintext input
                                         0                 // in data length
        );
    }
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_encrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_ENCRYPTION_ERROR;
        gcry_cipher_close(tmp_hd);
        return status;
    }

#ifdef TC_DEBUG
    printf("Output payload length is %ld\n", len_data_out);
    printf(KYEL "Printing TC Frame Data after encryption:\n\t");
    for (j = 0; j < len_data_out; j++)
    {
        printf("%02X", *(data_out + j));
    }
    printf("\n");
#endif

    if (authenticate_bool == CRYPTO_TRUE)
    {
        gcry_error = gcry_cipher_gettag(tmp_hd,
                                        mac,  // tag output
                                        mac_size // tag size
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET,
                   gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR;
            gcry_cipher_close(tmp_hd);
            return status;
        }

#ifdef MAC_DEBUG
        printf("MAC = 0x");
        for (i = 0; i < mac_size; i++)
        {
            printf("%02x", (uint8_t)mac[i]);
        }
        printf("\n");
#endif
    }

    gcry_cipher_close(tmp_hd);
    return status;
}

static int32_t cryptography_decrypt(uint8_t* data_out, size_t len_data_out,
                                         uint8_t* data_in, size_t len_data_in,
                                         uint8_t* key, uint32_t len_key,
                                         SecurityAssociation_t* sa_ptr, 
                                         uint8_t* iv, uint32_t iv_len,
                                         uint8_t* ecs, uint8_t* acs, char* cam_cookies)
{
    gcry_cipher_hd_t tmp_hd;
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    int32_t status = CRYPTO_LIB_SUCCESS;
    uint8_t* key_ptr = key;
    
    // Fix warnings
    acs = acs;
    cam_cookies = cam_cookies;

    if(sa_ptr != NULL) //Using SA key pointer
    {
        key_ptr = &(ek_ring[sa_ptr->ekid].value[0]);
    }

    // Select correct libgcrypt ecs enum
    int32_t algo = -1;
    if (ecs != NULL)
    {
        algo = cryptography_get_ecs_algo(*ecs);
        if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ECS)
        {
            return CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
        }
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_ECS_PTR;
    }

    // Verify the mode to accompany the algorithm enum
    int32_t mode = -1;
    mode = cryptography_get_ecs_mode(*ecs);
    if (mode == CRYPTO_LIB_ERR_UNSUPPORTED_MODE) return CRYPTO_LIB_ERR_UNSUPPORTED_MODE;

    // Check that key length to be used is atleast as long as the algo requirement
    if (sa_ptr != NULL && len_key > ek_ring[sa_ptr->ekid].key_len)
    {
        return CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
    }

    gcry_error = gcry_cipher_open(&(tmp_hd), algo, mode, GCRY_CIPHER_NONE);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setkey(tmp_hd, key_ptr, len_key);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_cipher_close(tmp_hd);
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }

    gcry_error = gcry_cipher_setiv(tmp_hd, iv, iv_len);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_cipher_close(tmp_hd);
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }

    gcry_error = gcry_cipher_decrypt(tmp_hd,
                                         data_out,      // plaintext output
                                         len_data_out,  // length of data
                                         data_in,       // in place decryption
                                         len_data_in    // in data length
    );
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_decrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        gcry_cipher_close(tmp_hd);
        status = CRYPTO_LIB_ERR_DECRYPT_ERROR;
        return status;
    }


    gcry_cipher_close(tmp_hd);
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
                                         uint8_t aad_bool, uint8_t* ecs, uint8_t* acs, char* cam_cookies)
{
    gcry_cipher_hd_t tmp_hd;
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    int32_t status = CRYPTO_LIB_SUCCESS;
    uint8_t* key_ptr = key;
    
    // Fix warnings
    acs = acs;
    cam_cookies = cam_cookies;

    if(sa_ptr != NULL) //Using SA key pointer
    {
        key_ptr = &(ek_ring[sa_ptr->ekid].value[0]);
    }

    // Select correct libgcrypt ecs enum
    int32_t algo = -1;
    if (ecs != NULL)
    {
        algo = cryptography_get_ecs_algo(*ecs);
        if (algo == CRYPTO_LIB_ERR_UNSUPPORTED_ECS)
        {
            return CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
        }
    }
    else
    {
        return CRYPTO_LIB_ERR_NULL_ECS_PTR;
    }

    // Check that key length to be used is atleast as long as the algo requirement
    if (sa_ptr != NULL && len_key > ek_ring[sa_ptr->ekid].key_len)
    {
        return CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
    }

    gcry_error = gcry_cipher_open(&(tmp_hd), GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, GCRY_CIPHER_NONE);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setkey(tmp_hd, key_ptr, len_key);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_cipher_close(tmp_hd);
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setiv(tmp_hd, iv, iv_len);
    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
        gcry_cipher_close(tmp_hd);
        status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
        return status;
    }
    
    if (aad_bool == CRYPTO_TRUE)
    {
        gcry_error = gcry_cipher_authenticate(tmp_hd,
                                              aad,    // additional authenticated data
                                              aad_len // length of AAD
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_authenticate error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            gcry_cipher_close(tmp_hd);
            status = CRYPTO_LIB_ERR_AUTHENTICATION_ERROR;
            return status;
        }
    }

    if (decrypt_bool == CRYPTO_TRUE)
    {
        gcry_error = gcry_cipher_decrypt(tmp_hd,
                                         data_out,      // plaintext output
                                         len_data_out,  // length of data
                                         data_in,       // in place decryption
                                         len_data_in    // in data length
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_decrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            gcry_cipher_close(tmp_hd);
            status = CRYPTO_LIB_ERR_DECRYPT_ERROR;
            return status;
        }
    }
    else // Authentication only
    {
        // Authenticate only! No input data passed into decryption function, only AAD.
        gcry_error = gcry_cipher_decrypt(tmp_hd,NULL,0, NULL,0);
        // If authentication only, don't decrypt the data. Just pass the data PDU through.
        memcpy(data_out, data_in, len_data_in);

        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_decrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            gcry_cipher_close(tmp_hd);
            status = CRYPTO_LIB_ERR_DECRYPT_ERROR;
            return status;
        }
    }
    if (authenticate_bool == CRYPTO_TRUE)
    {
        gcry_error = gcry_cipher_checktag(tmp_hd,
                                          mac,       // tag input
                                          mac_size   // tag size
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            fprintf(stderr, "gcry_cipher_decrypt failed: %s\n", gpg_strerror(gcry_error));
            gcry_cipher_close(tmp_hd);
            status = CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR;
            return status;
        }
    }

    gcry_cipher_close(tmp_hd);
    return status;
}

/**
 * @brief Function: cryptography_get_acs_algo. Maps Cryptolib ACS enums to libgcrypt enums 
 * It is possible for supported algos to vary between crypto libraries
 * @param algo_enum
 **/
int32_t cryptography_get_acs_algo(int8_t algo_enum)
{
    int32_t algo = CRYPTO_LIB_ERR_UNSUPPORTED_ACS; // All valid algos will be positive
    switch (algo_enum)
    {
        case CRYPTO_MAC_CMAC_AES256:
            algo = GCRY_MAC_CMAC_AES;
            break;
        case CRYPTO_MAC_HMAC_SHA256:
            algo = GCRY_MAC_HMAC_SHA256;
            break;
        case CRYPTO_MAC_HMAC_SHA512:
            algo = GCRY_MAC_HMAC_SHA512;
            break;

        default:
#ifdef DEBUG
            printf("ACS Algo Enum not supported\n");
#endif
            break;
    }

    return (int)algo;
}

/**
 * @brief Function: cryptography_get_ecs_algo. Maps Cryptolib ECS enums to libgcrypt enums 
 * It is possible for supported algos to vary between crypto libraries
 * @param algo_enum
 **/
int32_t cryptography_get_ecs_algo(int8_t algo_enum)
{
    int32_t algo = CRYPTO_LIB_ERR_UNSUPPORTED_ECS; // All valid algos will be positive
    switch (algo_enum)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            algo = GCRY_CIPHER_AES256;
            break;
        case CRYPTO_CIPHER_AES256_CBC:
            algo = GCRY_CIPHER_AES256;
            break;

        default:
#ifdef DEBUG
            printf("Algo Enum not supported\n");
#endif
            break;
    }

    return (int)algo;
}

/**
 * @brief Function: cryptography_get_ecs_mode. Maps Cryptolib ECS enums to libgcrypt enums 
 * It is possible for supported algos to vary between crypto libraries
 * @param algo_enum
 **/
int32_t cryptography_get_ecs_mode(int8_t algo_enum)
{
    int32_t mode = CRYPTO_LIB_ERR_UNSUPPORTED_ECS_MODE; // All valid algos will be positive
    switch (algo_enum)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            mode = GCRY_CIPHER_MODE_GCM;
            break;
        case CRYPTO_CIPHER_AES256_CBC:
            mode = GCRY_CIPHER_MODE_CBC;
            break;

        default:
#ifdef DEBUG
            printf("ECS Mode Enum not supported\n");
#endif
            break;
    }

    return (int)mode;
}

