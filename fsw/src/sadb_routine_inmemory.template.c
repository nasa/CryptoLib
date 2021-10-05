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

#include "sadb_routine.h"
#include "crypto_structs.h"
#include "crypto_print.h"
#include "crypto.h"

// Security Association Initialization Functions
static int32 sadb_config(void);
static int32 sadb_init(void);
// Security Association Interaction Functions
static int32 sadb_get_sa_from_spi(uint16,SecurityAssociation_t**);
// Security Association Utility Functions
static int32 sadb_sa_start(void);
static int32 sadb_sa_expire(void);
static int32 sadb_sa_rekey(void);
static int32 sadb_sa_status(char*);
static int32 sadb_sa_create(void);
static int32 sadb_sa_setARSN(void);
static int32 sadb_sa_setARSNW(void);
static int32 sadb_sa_delete(void);


/*
** Global Variables
*/
// Security
static SadbRoutineStruct sadb_routine;
static SecurityAssociation_t sa[NUM_SA];

SadbRoutine get_sadb_routine_inmemory(void)
{
    sadb_routine.sadb_config = sadb_config;
    sadb_routine.sadb_init = sadb_init;
    sadb_routine.sadb_get_sa_from_spi = sadb_get_sa_from_spi;
    sadb_routine.sadb_sa_start = sadb_sa_start;
    sadb_routine.sadb_sa_expire = sadb_sa_expire;
    sadb_routine.sadb_sa_rekey = sadb_sa_rekey;
    sadb_routine.sadb_sa_status = sadb_sa_status;
    sadb_routine.sadb_sa_create = sadb_sa_create;
    sadb_routine.sadb_sa_setARSN = sadb_sa_setARSN;
    sadb_routine.sadb_sa_setARSNW = sadb_sa_setARSNW;
    sadb_routine.sadb_sa_delete = sadb_sa_delete;
    return &sadb_routine;
}

int32 sadb_config(void)
{
    int32 status = OS_SUCCESS;
    // Master Keys
    // 0 - 000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F -> ACTIVE
    ek_ring[0].value[0]  = 0x00;
    ek_ring[0].value[1]  = 0x01;
    ek_ring[0].value[2]  = 0x02;
    ek_ring[0].value[3]  = 0x03;
    ek_ring[0].value[4]  = 0x04;
    ek_ring[0].value[5]  = 0x05;
    ek_ring[0].value[6]  = 0x06;
    ek_ring[0].value[7]  = 0x07;
    ek_ring[0].value[8]  = 0x08;
    ek_ring[0].value[9]  = 0x09;
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
    ek_ring[0].key_state = KEY_ACTIVE;
    // 1 - 101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F -> ACTIVE
    ek_ring[1].value[0]  = 0x10;
    ek_ring[1].value[1]  = 0x11;
    ek_ring[1].value[2]  = 0x12;
    ek_ring[1].value[3]  = 0x13;
    ek_ring[1].value[4]  = 0x14;
    ek_ring[1].value[5]  = 0x15;
    ek_ring[1].value[6]  = 0x16;
    ek_ring[1].value[7]  = 0x17;
    ek_ring[1].value[8]  = 0x18;
    ek_ring[1].value[9]  = 0x19;
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
    ek_ring[1].key_state = KEY_ACTIVE;
    // 2 - 202122232425262728292A2B2C2D2E2F202122232425262728292A2B2C2D2E2F -> ACTIVE
    ek_ring[2].value[0]  = 0x20;
    ek_ring[2].value[1]  = 0x21;
    ek_ring[2].value[2]  = 0x22;
    ek_ring[2].value[3]  = 0x23;
    ek_ring[2].value[4]  = 0x24;
    ek_ring[2].value[5]  = 0x25;
    ek_ring[2].value[6]  = 0x26;
    ek_ring[2].value[7]  = 0x27;
    ek_ring[2].value[8]  = 0x28;
    ek_ring[2].value[9]  = 0x29;
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
    ek_ring[2].key_state = KEY_ACTIVE;

    // Session Keys
    // 128 - 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF -> ACTIVE
    ek_ring[128].value[0]  = 0x01;
    ek_ring[128].value[1]  = 0x23;
    ek_ring[128].value[2]  = 0x45;
    ek_ring[128].value[3]  = 0x67;
    ek_ring[128].value[4]  = 0x89;
    ek_ring[128].value[5]  = 0xAB;
    ek_ring[128].value[6]  = 0xCD;
    ek_ring[128].value[7]  = 0xEF;
    ek_ring[128].value[8]  = 0x01;
    ek_ring[128].value[9]  = 0x23;
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
    ek_ring[128].key_state = KEY_ACTIVE;
    // 129 - ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789 -> ACTIVE
    ek_ring[129].value[0]  = 0xAB;
    ek_ring[129].value[1]  = 0xCD;
    ek_ring[129].value[2]  = 0xEF;
    ek_ring[129].value[3]  = 0x01;
    ek_ring[129].value[4]  = 0x23;
    ek_ring[129].value[5]  = 0x45;
    ek_ring[129].value[6]  = 0x67;
    ek_ring[129].value[7]  = 0x89;
    ek_ring[129].value[8]  = 0xAB;
    ek_ring[129].value[9]  = 0xCD;
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
    ek_ring[129].key_state = KEY_ACTIVE;
    // 130 - FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210 -> ACTIVE
    ek_ring[130].value[0]  = 0xFE;
    ek_ring[130].value[1]  = 0xDC;
    ek_ring[130].value[2]  = 0xBA;
    ek_ring[130].value[3]  = 0x98;
    ek_ring[130].value[4]  = 0x76;
    ek_ring[130].value[5]  = 0x54;
    ek_ring[130].value[6]  = 0x32;
    ek_ring[130].value[7]  = 0x10;
    ek_ring[130].value[8]  = 0xFE;
    ek_ring[130].value[9]  = 0xDC;
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
    ek_ring[130].key_state = KEY_ACTIVE;
    // 131 - 9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA -> ACTIVE
    ek_ring[131].value[0]  = 0x98;
    ek_ring[131].value[1]  = 0x76;
    ek_ring[131].value[2]  = 0x54;
    ek_ring[131].value[3]  = 0x32;
    ek_ring[131].value[4]  = 0x10;
    ek_ring[131].value[5]  = 0xFE;
    ek_ring[131].value[6]  = 0xDC;
    ek_ring[131].value[7]  = 0xBA;
    ek_ring[131].value[8]  = 0x98;
    ek_ring[131].value[9]  = 0x76;
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
    ek_ring[131].key_state = KEY_ACTIVE;
    // 132 - 0123456789ABCDEFABCDEF01234567890123456789ABCDEFABCDEF0123456789 -> PRE_ACTIVATION
    ek_ring[132].value[0]  = 0x01;
    ek_ring[132].value[1]  = 0x23;
    ek_ring[132].value[2]  = 0x45;
    ek_ring[132].value[3]  = 0x67;
    ek_ring[132].value[4]  = 0x89;
    ek_ring[132].value[5]  = 0xAB;
    ek_ring[132].value[6]  = 0xCD;
    ek_ring[132].value[7]  = 0xEF;
    ek_ring[132].value[8]  = 0xAB;
    ek_ring[132].value[9]  = 0xCD;
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
    ek_ring[132].key_state = KEY_PREACTIVE;
    // 133 - ABCDEF01234567890123456789ABCDEFABCDEF01234567890123456789ABCDEF -> ACTIVE
    ek_ring[133].value[0]  = 0xAB;
    ek_ring[133].value[1]  = 0xCD;
    ek_ring[133].value[2]  = 0xEF;
    ek_ring[133].value[3]  = 0x01;
    ek_ring[133].value[4]  = 0x23;
    ek_ring[133].value[5]  = 0x45;
    ek_ring[133].value[6]  = 0x67;
    ek_ring[133].value[7]  = 0x89;
    ek_ring[133].value[8]  = 0x01;
    ek_ring[133].value[9]  = 0x23;
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
    ek_ring[133].key_state = KEY_ACTIVE;
    // 134 - ABCDEF0123456789FEDCBA9876543210ABCDEF0123456789FEDCBA9876543210 -> DEACTIVE
    ek_ring[134].value[0]  = 0xAB;
    ek_ring[134].value[1]  = 0xCD;
    ek_ring[134].value[2]  = 0xEF;
    ek_ring[134].value[3]  = 0x01;
    ek_ring[134].value[4]  = 0x23;
    ek_ring[134].value[5]  = 0x45;
    ek_ring[134].value[6]  = 0x67;
    ek_ring[134].value[7]  = 0x89;
    ek_ring[134].value[8]  = 0xFE;
    ek_ring[134].value[9]  = 0xDC;
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
    ek_ring[134].key_state = KEY_DEACTIVATED;

    // Security Associations
    // SA 1 - CLEAR MODE
    sa[1].sa_state = SA_OPERATIONAL;
    sa[1].est = 0;
    sa[1].ast = 0;
    sa[1].arc_len = 1;
    sa[1].arcw_len = 1;
    sa[1].arcw[0] = 5;
    sa[1].gvcid_tc_blk[0].tfvn  = 0;
    sa[1].gvcid_tc_blk[0].scid  = SCID & 0x3FF;
    sa[1].gvcid_tc_blk[0].vcid  = 0;
    sa[1].gvcid_tc_blk[0].mapid = TYPE_TC;
    sa[1].gvcid_tc_blk[1].tfvn  = 0;
    sa[1].gvcid_tc_blk[1].scid  = SCID & 0x3FF;
    sa[1].gvcid_tc_blk[1].vcid  = 1;
    sa[1].gvcid_tc_blk[1].mapid = TYPE_TC;
    // SA 2 - KEYED;  ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: 128
    sa[2].ekid = 128;
    sa[2].sa_state = SA_KEYED;
    sa[2].est = 1;
    sa[2].ast = 1;
    sa[2].shivf_len = 12;
    sa[2].iv_len = IV_SIZE;
    sa[2].iv[IV_SIZE-1] = 0;
    sa[2].abm_len = 0x14; // 20
    for (int i = 0; i < sa[2].abm_len; i++)
    {	// Zero AAD bit mask
        sa[2].abm[i] = 0x00;
    }
    sa[2].arcw_len = 1;
    sa[2].arcw[0] = 5;
    sa[2].arc_len = (sa[2].arcw[0] * 2) + 1;
    // SA 3 - KEYED;   ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: 129
    sa[3].ekid = 129;
    sa[3].sa_state = SA_KEYED;
    sa[3].est = 1;
    sa[3].ast = 1;
    sa[3].shivf_len = 12;
    sa[3].iv_len = IV_SIZE;
    sa[3].iv[IV_SIZE-1] = 0;
    sa[3].abm_len = 0x14; // 20
    for (int i = 0; i < sa[3].abm_len; i++)
    {	// Zero AAD bit mask
        sa[3].abm[i] = 0x00;
    }
    sa[3].arcw_len = 1;
    sa[3].arcw[0] = 5;
    sa[3].arc_len = (sa[3].arcw[0] * 2) + 1;
    // SA 4 - KEYED;  ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: 130
    sa[4].ekid = 130;
    sa[4].sa_state = SA_KEYED;
    sa[4].est = 1;
    sa[4].ast = 1;
    sa[4].shivf_len = 12;
    sa[4].iv_len = IV_SIZE;
    sa[4].iv[IV_SIZE-1] = 0;
    sa[4].abm_len = 0x14; // 20
    for (int i = 0; i < sa[4].abm_len; i++)
    {	// Zero AAD bit mask
        sa[4].abm[i] = 0x00;
    }
    sa[4].arcw_len = 1;
    sa[4].arcw[0] = 5;
    sa[4].arc_len = (sa[4].arcw[0] * 2) + 1;
    sa[4].gvcid_tc_blk[0].tfvn  = 0;
    sa[4].gvcid_tc_blk[0].scid  = SCID & 0x3FF;
    sa[4].gvcid_tc_blk[0].vcid  = 0;
    sa[4].gvcid_tc_blk[0].mapid = TYPE_TC;
    sa[4].gvcid_tc_blk[1].tfvn  = 0;
    sa[4].gvcid_tc_blk[1].scid  = SCID & 0x3FF;
    sa[4].gvcid_tc_blk[1].vcid  = 1;
    sa[4].gvcid_tc_blk[1].mapid = TYPE_TC;
    // SA 5 - KEYED;   ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: 131
    sa[5].ekid = 131;
    sa[5].sa_state = SA_KEYED;
    sa[5].est = 1;
    sa[5].ast = 1;
    sa[5].shivf_len = 12;
    sa[5].iv_len = IV_SIZE;
    sa[5].iv[IV_SIZE-1] = 0;
    sa[5].abm_len = 0x14; // 20
    for (int i = 0; i < sa[5].abm_len; i++)
    {	// Zero AAD bit mask
        sa[5].abm[i] = 0x00;
    }
    sa[5].arcw_len = 1;
    sa[5].arcw[0] = 5;
    sa[5].arc_len = (sa[5].arcw[0] * 2) + 1;
    // SA 6 - UNKEYED; ARCW:5; AES-GCM; IV:00...00; IV-len:12; MAC-len:16; Key-ID: -
    sa[6].sa_state = SA_UNKEYED;
    sa[6].est = 1;
    sa[6].ast = 1;
    sa[6].shivf_len = 12;
    sa[6].iv_len = IV_SIZE;
    sa[6].iv[IV_SIZE-1] = 0;
    sa[6].abm_len = 0x14; // 20
    for (int i = 0; i < sa[6].abm_len; i++)
    {	// Zero AAD bit mask
        sa[6].abm[i] = 0x00;
    }
    sa[6].arcw_len = 1;
    sa[6].arcw[0] = 5;
    sa[6].arc_len = (sa[6].arcw[0] * 2) + 1;
    //itc_gcm128_init(&(sa[6].gcm_ctx), (unsigned char *)&(ek_ring[sa[6].ekid]));

    return status;
}

int32 sadb_init(void)
{
    int32 status = OS_SUCCESS;

    for (int x = 0; x < NUM_SA; x++)
    {
        sa[x].ekid = x;
        sa[x].akid = x;
        sa[x].sa_state = SA_NONE;
        sa[x].ecs_len = 0;
        sa[x].ecs[0] = 0;
        sa[x].ecs[1] = 0;
        sa[x].ecs[2] = 0;
        sa[x].ecs[3] = 0;
        sa[x].iv_len = IV_SIZE;
        sa[x].acs_len = 0;
        sa[x].acs = 0;
        sa[x].arc_len = 0;
        sa[x].arc[0] = 5;
    }
    return status;
}


/*
** Security Association Interaction Functions
*/
static int32 sadb_get_sa_from_spi(uint16 spi,SecurityAssociation_t** security_association)
{
    int32 status = OS_SUCCESS;
    *security_association = &sa[spi];
    return status;
}

/*
** Security Association Management Services
*/
static int32 sadb_sa_start(void)
{
    // Local variables
    uint8 count = 0;
    uint16 spi = 0x0000;
    crypto_gvcid_t gvcid;

    // Read ingest
    spi = ((uint8)sdls_frame.pdu.data[0] << 8) | (uint8)sdls_frame.pdu.data[1];

    // Overwrite last PID
    sa[spi].lpid = (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Check SPI exists and in 'Keyed' state
    if (spi < NUM_SA)
    {
        if (sa[spi].sa_state == SA_KEYED)
        {
            count = 2;

            for(int x = 0; x <= ((sdls_frame.pdu.pdu_len - 2) / 4); x++)
            {   // Read in GVCID
                gvcid.tfvn  = (sdls_frame.pdu.data[count] >> 4);
                gvcid.scid  = (sdls_frame.pdu.data[count] << 12)     |
                              (sdls_frame.pdu.data[count + 1] << 4)  |
                              (sdls_frame.pdu.data[count + 2] >> 4);
                gvcid.vcid  = (sdls_frame.pdu.data[count + 2] << 4)  |
                              (sdls_frame.pdu.data[count + 3] && 0x3F);
                gvcid.mapid = (sdls_frame.pdu.data[count + 3]);

                // TC
                if (gvcid.vcid != tc_frame.tc_header.vcid)
                {   // Clear all GVCIDs for provided SPI
                    if (gvcid.mapid == TYPE_TC)
                    {
                        for (int i = 0; i < NUM_GVCID; i++)
                        {   // TC
                            sa[spi].gvcid_tc_blk[x].tfvn  = 0;
                            sa[spi].gvcid_tc_blk[x].scid  = 0;
                            sa[spi].gvcid_tc_blk[x].vcid  = 0;
                            sa[spi].gvcid_tc_blk[x].mapid = 0;
                        }
                    }
                    // Write channel to SA
                    if (gvcid.mapid != TYPE_MAP)
                    {   // TC
                        sa[spi].gvcid_tc_blk[gvcid.vcid].tfvn  = gvcid.tfvn;
                        sa[spi].gvcid_tc_blk[gvcid.vcid].scid  = gvcid.scid;
                        sa[spi].gvcid_tc_blk[gvcid.vcid].mapid = gvcid.mapid;
                    }
                    else
                    {
                        // TODO: Handle TYPE_MAP
                    }
                }
                // TM
                if (gvcid.vcid != tm_frame.tm_header.vcid)
                {   // Clear all GVCIDs for provided SPI
                    if (gvcid.mapid == TYPE_TM)
                    {
                        for (int i = 0; i < NUM_GVCID; i++)
                        {   // TM
                            sa[spi].gvcid_tm_blk[x].tfvn  = 0;
                            sa[spi].gvcid_tm_blk[x].scid  = 0;
                            sa[spi].gvcid_tm_blk[x].vcid  = 0;
                            sa[spi].gvcid_tm_blk[x].mapid = 0;
                        }
                    }
                    // Write channel to SA
                    if (gvcid.mapid != TYPE_MAP)
                    {   // TM
                        sa[spi].gvcid_tm_blk[gvcid.vcid].tfvn  = gvcid.tfvn;
                        sa[spi].gvcid_tm_blk[gvcid.vcid].scid  = gvcid.scid;
                        sa[spi].gvcid_tm_blk[gvcid.vcid].vcid  = gvcid.vcid;
                        sa[spi].gvcid_tm_blk[gvcid.vcid].mapid = gvcid.mapid;
                    }
                    else
                    {
                        // TODO: Handle TYPE_MAP
                    }
                }

#ifdef PDU_DEBUG
                OS_printf("SPI %d changed to OPERATIONAL state. \n", spi);
                    switch (gvcid.mapid)
                    {
                        case TYPE_TC:
                            OS_printf("Type TC, ");
                            break;
                        case TYPE_MAP:
                            OS_printf("Type MAP, ");
                            break;
                        case TYPE_TM:
                            OS_printf("Type TM, ");
                            break;
                        default:
                            OS_printf("Type Unknown, ");
                            break;
                    }
#endif

                // Change to operational state
                sa[spi].sa_state = SA_OPERATIONAL;
            }
        }
        else
        {
            OS_printf(KRED "ERROR: SPI %d is not in the KEYED state.\n" RESET, spi);
        }
    }
    else
    {
        OS_printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

#ifdef DEBUG
    OS_printf("\t spi = %d \n", spi);
#endif

    return OS_SUCCESS;
}

static int32 sadb_sa_stop(void)
{
    // Local variables
    uint16 spi = 0x0000;

    // Read ingest
    spi = ((uint8)sdls_frame.pdu.data[0] << 8) | (uint8)sdls_frame.pdu.data[1];
    OS_printf("spi = %d \n", spi);

    // Overwrite last PID
    sa[spi].lpid = (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Check SPI exists and in 'Active' state
    if (spi < NUM_SA)
    {
        if (sa[spi].sa_state == SA_OPERATIONAL)
        {
            // Remove all GVC/GMAP IDs
            for (int x = 0; x < NUM_GVCID; x++)
            {   // TC
                sa[spi].gvcid_tc_blk[x].tfvn  = 0;
                sa[spi].gvcid_tc_blk[x].scid  = 0;
                sa[spi].gvcid_tc_blk[x].vcid  = 0;
                sa[spi].gvcid_tc_blk[x].mapid = 0;
                // TM
                sa[spi].gvcid_tm_blk[x].tfvn  = 0;
                sa[spi].gvcid_tm_blk[x].scid  = 0;
                sa[spi].gvcid_tm_blk[x].vcid  = 0;
                sa[spi].gvcid_tm_blk[x].mapid = 0;
            }

            // Change to operational state
            sa[spi].sa_state = SA_KEYED;
#ifdef PDU_DEBUG
            OS_printf("SPI %d changed to KEYED state. \n", spi);
#endif
        }
        else
        {
            OS_printf(KRED "ERROR: SPI %d is not in the OPERATIONAL state.\n" RESET, spi);
        }
    }
    else
    {
        OS_printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

#ifdef DEBUG
    OS_printf("\t spi = %d \n", spi);
#endif

    return OS_SUCCESS;
}

static int32 sadb_sa_rekey(void)
{
    // Local variables
    uint16 spi = 0x0000;
    int count = 0;
    int x = 0;

    // Read ingest
    spi = ((uint8)sdls_frame.pdu.data[count] << 8) | (uint8)sdls_frame.pdu.data[count+1];
    count = count + 2;

    // Overwrite last PID
    sa[spi].lpid = (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Check SPI exists and in 'Unkeyed' state
    if (spi < NUM_SA)
    {
        if (sa[spi].sa_state == SA_UNKEYED)
        {	// Encryption Key
            sa[spi].ekid = ((uint8)sdls_frame.pdu.data[count] << 8) | (uint8)sdls_frame.pdu.data[count+1];
            count = count + 2;

            // Authentication Key
            //sa[spi].akid = ((uint8)sdls_frame.pdu.data[count] << 8) | (uint8)sdls_frame.pdu.data[count+1];
            //count = count + 2;

            // Anti-Replay Counter
#ifdef PDU_DEBUG
            OS_printf("SPI %d IV updated to: 0x", spi);
#endif
            if (sa[spi].iv_len > 0)
            {   // Set IV - authenticated encryption
                for (x = count; x < (sa[spi].iv_len + count); x++)
                {
                    // TODO: Uncomment once fixed in ESA implementation
                    // TODO: Assuming this was fixed...
                    sa[spi].iv[x - count] = (uint8) sdls_frame.pdu.data[x];
#ifdef PDU_DEBUG
                    OS_printf("%02x", sdls_frame.pdu.data[x]);
#endif
                }
            }
            else
            {   // Set SN
                // TODO
            }
#ifdef PDU_DEBUG
            OS_printf("\n");
#endif

            // Change to keyed state
            sa[spi].sa_state = SA_KEYED;
#ifdef PDU_DEBUG
            OS_printf("SPI %d changed to KEYED state with encrypted Key ID %d. \n", spi, sa[spi].ekid);
#endif
        }
        else
        {
            OS_printf(KRED "ERROR: SPI %d is not in the UNKEYED state.\n" RESET, spi);
        }
    }
    else
    {
        OS_printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

#ifdef DEBUG
    OS_printf("\t spi  = %d \n", spi);
        OS_printf("\t ekid = %d \n", sa[spi].ekid);
        //OS_printf("\t akid = %d \n", sa[spi].akid);
#endif

    return OS_SUCCESS;
}

static int32 sadb_sa_expire(void)
{
    // Local variables
    uint16 spi = 0x0000;

    // Read ingest
    spi = ((uint8)sdls_frame.pdu.data[0] << 8) | (uint8)sdls_frame.pdu.data[1];
    OS_printf("spi = %d \n", spi);

    // Overwrite last PID
    sa[spi].lpid = (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Check SPI exists and in 'Keyed' state
    if (spi < NUM_SA)
    {
        if (sa[spi].sa_state == SA_KEYED)
        {	// Change to 'Unkeyed' state
            sa[spi].sa_state = SA_UNKEYED;
#ifdef PDU_DEBUG
            OS_printf("SPI %d changed to UNKEYED state. \n", spi);
#endif
        }
        else
        {
            OS_printf(KRED "ERROR: SPI %d is not in the KEYED state.\n" RESET, spi);
        }
    }
    else
    {
        OS_printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

    return OS_SUCCESS;
}

static int32 sadb_sa_create(void)
{
    // Local variables
    uint8 count = 6;
    uint16 spi = 0x0000;

    // Read sdls_frame.pdu.data
    spi = ((uint8)sdls_frame.pdu.data[0] << 8) | (uint8)sdls_frame.pdu.data[1];
    OS_printf("spi = %d \n", spi);

    // Overwrite last PID
    sa[spi].lpid = (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Write SA Configuration
    sa[spi].est = ((uint8)sdls_frame.pdu.data[2] & 0x80) >> 7;
    sa[spi].ast = ((uint8)sdls_frame.pdu.data[2] & 0x40) >> 6;
    sa[spi].shivf_len = ((uint8)sdls_frame.pdu.data[2] & 0x3F);
    sa[spi].shsnf_len = ((uint8)sdls_frame.pdu.data[3] & 0xFC) >> 2;
    sa[spi].shplf_len = ((uint8)sdls_frame.pdu.data[3] & 0x03);
    sa[spi].stmacf_len = ((uint8)sdls_frame.pdu.data[4]);
    sa[spi].ecs_len = ((uint8)sdls_frame.pdu.data[5]);
    for (int x = 0; x < sa[spi].ecs_len; x++)
    {
        sa[spi].ecs[x] = ((uint8)sdls_frame.pdu.data[count++]);
    }
    sa[spi].iv_len = ((uint8)sdls_frame.pdu.data[count++]);
    for (int x = 0; x < sa[spi].iv_len; x++)
    {
        sa[spi].iv[x] = ((uint8)sdls_frame.pdu.data[count++]);
    }
    sa[spi].acs_len = ((uint8)sdls_frame.pdu.data[count++]);
    for (int x = 0; x < sa[spi].acs_len; x++)
    {
        sa[spi].acs = ((uint8)sdls_frame.pdu.data[count++]);
    }
    sa[spi].abm_len = (uint8)((sdls_frame.pdu.data[count] << 8) | (sdls_frame.pdu.data[count+1]));
    count = count + 2;
    for (int x = 0; x < sa[spi].abm_len; x++)
    {
        sa[spi].abm[x] = ((uint8)sdls_frame.pdu.data[count++]);
    }
    sa[spi].arc_len = ((uint8)sdls_frame.pdu.data[count++]);
    for (int x = 0; x < sa[spi].arc_len; x++)
    {
        sa[spi].arc[x] = ((uint8)sdls_frame.pdu.data[count++]);
    }
    sa[spi].arcw_len = ((uint8)sdls_frame.pdu.data[count++]);
    for (int x = 0; x < sa[spi].arcw_len; x++)
    {
        sa[spi].arcw[x] = ((uint8)sdls_frame.pdu.data[count++]);
    }

    // TODO: Checks for valid data

    // Set state to unkeyed
    sa[spi].sa_state = SA_UNKEYED;

#ifdef PDU_DEBUG
    Crypto_saPrint(&sa[spi]);
#endif

    return OS_SUCCESS;
}

static int32 sadb_sa_delete(void)
{
    // Local variables
    uint16 spi = 0x0000;

    // Read ingest
    spi = ((uint8)sdls_frame.pdu.data[0] << 8) | (uint8)sdls_frame.pdu.data[1];
    OS_printf("spi = %d \n", spi);

    // Overwrite last PID
    sa[spi].lpid = (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | sdls_frame.pdu.pid;

    // Check SPI exists and in 'Unkeyed' state
    if (spi < NUM_SA)
    {
        if (sa[spi].sa_state == SA_UNKEYED)
        {	// Change to 'None' state
            sa[spi].sa_state = SA_NONE;
#ifdef PDU_DEBUG
            OS_printf("SPI %d changed to NONE state. \n", spi);
#endif

            // TODO: Zero entire SA
        }
        else
        {
            OS_printf(KRED "ERROR: SPI %d is not in the UNKEYED state.\n" RESET, spi);
        }
    }
    else
    {
        OS_printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

    return OS_SUCCESS;
}

static int32 sadb_sa_setARSN(void)
{
    // Local variables
    uint16 spi = 0x0000;

    // Read ingest
    spi = ((uint8)sdls_frame.pdu.data[0] << 8) | (uint8)sdls_frame.pdu.data[1];
    OS_printf("spi = %d \n", spi);

    // TODO: Check SA type (authenticated, encrypted, both) and set appropriately
    // TODO: Add more checks on bounds

    // Check SPI exists
    if (spi < NUM_SA)
    {
#ifdef PDU_DEBUG
        OS_printf("SPI %d IV updated to: 0x", spi);
#endif
        if (sa[spi].iv_len > 0)
        {   // Set IV - authenticated encryption
            for (int x = 0; x < IV_SIZE; x++)
            {
                sa[spi].iv[x] = (uint8) sdls_frame.pdu.data[x + 2];
#ifdef PDU_DEBUG
                OS_printf("%02x", sa[spi].iv[x]);
#endif
            }
            Crypto_increment((uint8*)sa[spi].iv, IV_SIZE);
        }
        else
        {   // Set SN
            // TODO
        }
#ifdef PDU_DEBUG
        OS_printf("\n");
#endif
    }
    else
    {
        OS_printf("sadb_sa_setARSN ERROR: SPI %d does not exist.\n", spi);
    }

    return OS_SUCCESS;
}

static int32 sadb_sa_setARSNW(void)
{
    // Local variables
    uint16 spi = 0x0000;

    // Read ingest
    spi = ((uint8)sdls_frame.pdu.data[0] << 8) | (uint8)sdls_frame.pdu.data[1];
    OS_printf("spi = %d \n", spi);

    // Check SPI exists
    if (spi < NUM_SA)
    {
        sa[spi].arcw_len = (uint8) sdls_frame.pdu.data[2];

        // Check for out of bounds
        if (sa[spi].arcw_len > (ARC_SIZE))
        {
            sa[spi].arcw_len = ARC_SIZE;
        }

        for(int x = 0; x < sa[spi].arcw_len; x++)
        {
            sa[spi].arcw[x] = (uint8) sdls_frame.pdu.data[x+3];
        }
    }
    else
    {
        OS_printf("sadb_sa_setARSNW ERROR: SPI %d does not exist.\n", spi);
    }

    return OS_SUCCESS;
}

static int32 sadb_sa_status(char* ingest)
{
    // Local variables
    int count = 0;
    uint16 spi = 0x0000;

    // Read ingest
    spi = ((uint8)sdls_frame.pdu.data[0] << 8) | (uint8)sdls_frame.pdu.data[1];
    OS_printf("spi = %d \n", spi);

    // Check SPI exists
    if (spi < NUM_SA)
    {
        // Prepare for Reply
        sdls_frame.pdu.pdu_len = 3;
        sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
        count = Crypto_Prep_Reply(ingest, 128);
        // PDU
        ingest[count++] = (spi & 0xFF00) >> 8;
        ingest[count++] = (spi & 0x00FF);
        ingest[count++] = sa[spi].lpid;
    }
    else
    {
        OS_printf("sadb_sa_status ERROR: SPI %d does not exist.\n", spi);
    }

#ifdef SA_DEBUG
    Crypto_saPrint(&sa[spi]);
#endif

    return count;
}