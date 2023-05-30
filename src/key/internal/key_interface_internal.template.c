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
#include "key_interface.h"

/* Variables */
static crypto_key_t ek_ring[NUM_KEYS] = {0};
static KeyInterfaceStruct key_if_struct;

/* Prototypes */
static int32_t key_init(void);
static int32_t key_shutdown(void);
static crypto_key_t* get_ek_ring(void);

/* Functions */
KeyInterface get_key_interface_internal(void)
{
    key_if_struct.key_init = key_init;
    key_if_struct.key_shutdown = key_shutdown;
    key_if_struct.get_ek_ring = get_ek_ring;
    return &key_if_struct;
}

static int32_t key_init(void)
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

    // 136 - ff9f9284cf599eac3b119905a7d18851e7e374cf63aea04358586b0f757670f9
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

static int32_t key_shutdown(void)
{
    return CRYPTO_LIB_SUCCESS;
}

static crypto_key_t* get_ek_ring(void)
{
    return &ek_ring[0];
}
