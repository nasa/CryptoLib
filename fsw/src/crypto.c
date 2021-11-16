/* Copyright (C) 2009 - 2017 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
any warranty that the software will be error free.

In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
arising out of, resulting from, or in any0 way connected with the software or its documentation.  Whether or not based upon warranty,
contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
documentation or services provided hereunder

ITC Team
NASA IV&V
ivv-itc@lists.nasa.gov
*/
#ifndef _crypto_c_
#define _crypto_c_

/*
** Includes
*/
#include "crypto.h"
#include "sadb_routine.h"

#include "itc_aes128.h"
#include "itc_gcm128.h"

#include "crypto_structs.h"
#include "crypto_print.h"
#include "crypto_config.h"
#include "crypto_events.h"



#include <gcrypt.h>


/*
** Static Library Declaration
*/
#ifdef BUILD_STATIC
    CFS_MODULE_DECLARE_LIB(crypto);
#endif

static SadbRoutine sadb_routine = NULL;

/*
** Static Prototypes
*/
// Assisting Functions
static int32  Crypto_Get_tcPayloadLength(TC_t* tc_frame);
static int32  Crypto_Get_tmLength(int len);
static void   Crypto_TM_updatePDU(char* ingest, int len_ingest);
static void   Crypto_TM_updateOCF(void);
static void   Crypto_Local_Config(void);
static void   Crypto_Local_Init(void);
//static int32  Crypto_gcm_err(int gcm_err);
static int32 Crypto_window(uint8 *actual, uint8 *expected, int length, int window);
static int32 Crypto_compare_less_equal(uint8 *actual, uint8 *expected, int length);
static int32  Crypto_FECF(int fecf, char* ingest, int len_ingest,TC_t* tc_frame);
static uint16 Crypto_Calc_FECF(char* ingest, int len_ingest);
static void   Crypto_Calc_CRC_Init_Table(void);
static uint16 Crypto_Calc_CRC16(char* data, int size);
// Key Management Functions
static int32 Crypto_Key_OTAR(void);
static int32 Crypto_Key_update(uint8 state);
static int32 Crypto_Key_inventory(char*);
static int32 Crypto_Key_verify(char*,TC_t* tc_frame);
// Security Monitoring & Control Procedure
static int32 Crypto_MC_ping(char* ingest);
static int32 Crypto_MC_status(char* ingest);
static int32 Crypto_MC_dump(char* ingest);
static int32 Crypto_MC_erase(char* ingest);
static int32 Crypto_MC_selftest(char* ingest);
static int32 Crypto_SA_readARSN(char* ingest);
static int32 Crypto_MC_resetalarm(void);
// User Functions
static int32 Crypto_User_IdleTrigger(char* ingest);
static int32 Crypto_User_BadSPI(void);
static int32 Crypto_User_BadIV(void);
static int32 Crypto_User_BadMAC(void);
static int32 Crypto_User_BadFECF(void);
static int32 Crypto_User_ModifyKey(void);
static int32 Crypto_User_ModifyActiveTM(void);
static int32 Crypto_User_ModifyVCID(void);
// Determine Payload Data Unit
static int32 Crypto_PDU(char* ingest, TC_t* tc_frame);

/*
** Global Variables
*/
// Security
crypto_key_t ek_ring[NUM_KEYS] = {0};
//static crypto_key_t ak_ring[NUM_KEYS];
CCSDS_t sdls_frame;
TM_t tm_frame;
// OCF
static uint8 ocf = 0;
static SDLS_FSR_t report;
static TM_FrameCLCW_t clcw;
// Flags
static SDLS_MC_LOG_RPLY_t log_summary;
static SDLS_MC_DUMP_BLK_RPLY_t log;
static uint8 log_count = 0;
static uint16 tm_offset = 0;
// ESA Testing - 0 = disabled, 1 = enabled
static uint8 badSPI = 0;
static uint8 badIV = 0;
static uint8 badMAC = 0;
static uint8 badFECF = 0;
//  CRC
static uint32 crc32Table[256];
static uint16 crc16Table[256];

/*
** Initialization Functions
*/
int32 Crypto_Init(void)
{   
    int32 status = OS_SUCCESS;

    //TODO -- Make the routine that gets called variable based on configuration!
    sadb_routine = get_sadb_routine_inmemory();
    //sadb_routine = get_sadb_routine_mariadb();


    // Initialize libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION))
    {
        fprintf(stderr, "Gcrypt Version: %s",GCRYPT_VERSION);
        OS_printf(KRED "\tERROR: gcrypt version mismatch! \n" RESET);
    }
    if (gcry_control(GCRYCTL_SELFTEST) != GPG_ERR_NO_ERROR)
    {
        OS_printf(KRED "ERROR: gcrypt self test failed\n" RESET);
    }
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Init Security Associations
    status = sadb_routine->sadb_init();
    status = sadb_routine->sadb_config();

    Crypto_Local_Init();
    Crypto_Local_Config();

    // TODO - Add error checking

    // Init table for CRC calculations
    Crypto_Calc_CRC_Init_Table();

    // cFS Standard Initialized Message
    OS_printf (KBLU "Crypto Lib Intialized.  Version %d.%d.%d.%d\n" RESET,
                CRYPTO_LIB_MAJOR_VERSION,
                CRYPTO_LIB_MINOR_VERSION, 
                CRYPTO_LIB_REVISION, 
                CRYPTO_LIB_MISSION_REV);
                                
    return status; 
}

static void Crypto_Local_Config(void)
{
    // Initial TM configuration
    tm_frame.tm_sec_header.spi = 1;

    // Initialize Log
    log_summary.num_se = 2;
    log_summary.rs = LOG_SIZE;
    // Add a two messages to the log
    log_summary.rs--;
    log.blk[log_count].emt = STARTUP;
    log.blk[log_count].emv[0] = 0x4E;
    log.blk[log_count].emv[1] = 0x41;
    log.blk[log_count].emv[2] = 0x53;
    log.blk[log_count].emv[3] = 0x41;
    log.blk[log_count++].em_len = 4;
    log_summary.rs--;
    log.blk[log_count].emt = STARTUP;
    log.blk[log_count].emv[0] = 0x4E;
    log.blk[log_count].emv[1] = 0x41;
    log.blk[log_count].emv[2] = 0x53;
    log.blk[log_count].emv[3] = 0x41;
    log.blk[log_count++].em_len = 4;

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
}

static void Crypto_Local_Init(void)
{

    // Initialize TM Frame
    // TM Header
    tm_frame.tm_header.tfvn    = 0;	    // Shall be 00 for TM-/TC-SDLP
    tm_frame.tm_header.scid    = SCID & 0x3FF;
    tm_frame.tm_header.vcid    = 0;
    tm_frame.tm_header.ocff    = 1;
    tm_frame.tm_header.mcfc    = 1;
    tm_frame.tm_header.vcfc    = 1;
    tm_frame.tm_header.tfsh    = 0;
    tm_frame.tm_header.sf      = 0;
    tm_frame.tm_header.pof     = 0;	    // Shall be set to 0
    tm_frame.tm_header.slid    = 3;	    // Shall be set to 11
    tm_frame.tm_header.fhp     = 0;
    // TM Security Header
    tm_frame.tm_sec_header.spi = 0x0000;
    for ( int x = 0; x < IV_SIZE; x++)
    { 	// Initialization Vector
        tm_frame.tm_sec_header.iv[x] = 0x00;
    }
    // TM Payload Data Unit
    for ( int x = 0; x < TM_FRAME_DATA_SIZE; x++)
    {	// Zero TM PDU
        tm_frame.tm_pdu[x] = 0x00;
    }
    // TM Security Trailer
    for ( int x = 0; x < MAC_SIZE; x++)
    { 	// Zero TM Message Authentication Code
        tm_frame.tm_sec_trailer.mac[x] = 0x00;
    }
    for ( int x = 0; x < OCF_SIZE; x++)
    { 	// Zero TM Operational Control Field
        tm_frame.tm_sec_trailer.ocf[x] = 0x00;
    }
    tm_frame.tm_sec_trailer.fecf = 0xFECF;

    // Initialize CLCW
    clcw.cwt 	= 0;			// Control Word Type "0"
    clcw.cvn	= 0;			// CLCW Version Number "00"
    clcw.sf  	= 0;    		// Status Field
    clcw.cie 	= 1;			// COP In Effect
    clcw.vci 	= 0;    		// Virtual Channel Identification
    clcw.spare0 = 0;			// Reserved Spare
    clcw.nrfa	= 0;			// No RF Avaliable Flag
    clcw.nbl	= 0;			// No Bit Lock Flag
    clcw.lo		= 0;			// Lock-Out Flag
    clcw.wait	= 0;			// Wait Flag
    clcw.rt		= 0;			// Retransmit Flag
    clcw.fbc	= 0;			// FARM-B Counter
    clcw.spare1 = 0;			// Reserved Spare
    clcw.rv		= 0;        	// Report Value

    // Initialize Frame Security Report
    report.cwt   = 1;			// Control Word Type "0b1""
    report.vnum  = 4;   		// FSR Version "0b100""
    report.af    = 0;			// Alarm Field
    report.bsnf  = 0;			// Bad SN Flag
    report.bmacf = 0;			// Bad MAC Flag
    report.ispif = 0;			// Invalid SPI Flag
    report.lspiu = 0;	    	// Last SPI Used
    report.snval = 0;			// SN Value (LSB)

}

static void Crypto_Calc_CRC_Init_Table(void)
{   
    uint16 val;
    uint32 poly = 0xEDB88320;
    uint32 crc;

    // http://create.stephan-brumme.com/crc32/
    for (unsigned int i = 0; i <= 0xFF; i++)
    {
        crc = i;
        for (unsigned int j = 0; j < 8; j++)
        {
            crc = (crc >> 1) ^ (-(int)(crc & 1) & poly);
        }
        crc32Table[i] = crc;
        //OS_printf("crc32Table[%d] = 0x%08x \n", i, crc32Table[i]);
    }
    
    // Code provided by ESA
    for (int i = 0; i < 256; i++)
    {
        val = 0;
        if ( (i &   1) != 0 )  val ^= 0x1021;
        if ( (i &   2) != 0 )  val ^= 0x2042;
        if ( (i &   4) != 0 )  val ^= 0x4084;
        if ( (i &   8) != 0 )  val ^= 0x8108;
        if ( (i &  16) != 0 )  val ^= 0x1231;
        if ( (i &  32) != 0 )  val ^= 0x2462;
        if ( (i &  64) != 0 )  val ^= 0x48C4;
        if ( (i & 128) != 0 )  val ^= 0x9188;
        crc16Table[i] = val;
        //OS_printf("crc16Table[%d] = 0x%04x \n", i, crc16Table[i]);
    }
}

/*
** Assisting Functions
*/
static int32 Crypto_Get_tcPayloadLength(TC_t* tc_frame)
// Returns the payload length of current tc_frame in BYTES!
{
    int seg_hdr = 0;if(SEGMENTATION_HDR){seg_hdr=1;}
    int fecf = 0;if(HAS_FECF){fecf=FECF_SIZE;}
    int spi = 2;
    int iv_size = IV_SIZE_TC; if(PUS_HDR){iv_size=IV_SIZE - 1;} //For some reason, the interoperability tests with PUS header frames work with a 12 byte TC IV, so we'll use that for those.
    int tf_hdr = 5;

    return (tc_frame->tc_header.fl - (tf_hdr + seg_hdr + spi + iv_size ) - (MAC_SIZE + FECF_SIZE) );
    //return (tc_frame->tc_header.fl - (5 + 2 + IV_SIZE ) - (MAC_SIZE + FECF_SIZE) );
    //TFHDR=5bytes, SegHdr=1byte,SPI=2bytes,SeqNum=4bytes,MAC=16bytes,FECF=2bytes -- should be 30 bytes max, above calculation seems incorrect.
}

static int32 Crypto_Get_tmLength(int len)
// Returns the total length of the current tm_frame in BYTES!
{
    #ifdef FILL
        len = TM_FILL_SIZE;
    #else
        len = TM_FRAME_PRIMARYHEADER_SIZE + TM_FRAME_SECHEADER_SIZE + len + TM_FRAME_SECTRAILER_SIZE + TM_FRAME_CLCW_SIZE;
    #endif

    return len;
}

static void Crypto_TM_updatePDU(char* ingest, int len_ingest)
// Update the Telemetry Payload Data Unit
{	// Copy ingest to PDU
    int x = 0;
    int fill_size = 0;
    SecurityAssociation_t* sa_ptr;

    if(sadb_routine->sadb_get_sa_from_spi(tm_frame.tm_sec_header.spi,&sa_ptr) != OS_SUCCESS){
        //TODO - Error handling
        return; //Error -- unable to get SA from SPI.
    }

    if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
    {
        fill_size = 1129 - MAC_SIZE - IV_SIZE + 2; // +2 for padding bytes
    }
    else
    {
        fill_size = 1129;
    }

    #ifdef TM_ZERO_FILL
        for (int x = 0; x < TM_FILL_SIZE; x++)
        {
            if (x < len_ingest)
            {	// Fill
                tm_frame.tm_pdu[x] = (uint8)ingest[x];
            }
            else
            {	// Zero
                tm_frame.tm_pdu[x] = 0x00;
            }
        }
    #else
        // Pre-append remaining packet if exist
        if (tm_offset == 63)
        {
            tm_frame.tm_pdu[x++] = 0xff;
            tm_offset--;
        }
        if (tm_offset == 62)
        {
            tm_frame.tm_pdu[x++] = 0x00;
            tm_offset--;
        }
        if (tm_offset == 61)
        {
            tm_frame.tm_pdu[x++] = 0x00;
            tm_offset--;
        }
        if (tm_offset == 60)
        {
            tm_frame.tm_pdu[x++] = 0x00;
            tm_offset--;
        }
        if (tm_offset == 59)
        {
            tm_frame.tm_pdu[x++] = 0x39;
            tm_offset--;
        }
        while (x < tm_offset)
        {
            tm_frame.tm_pdu[x] = 0x00;
            x++;
        }
        // Copy actual packet
        while (x < len_ingest + tm_offset)
        {
            //OS_printf("ingest[x - tm_offset] = 0x%02x \n", (uint8)ingest[x - tm_offset]);
            tm_frame.tm_pdu[x] = (uint8)ingest[x - tm_offset];
            x++;
        }
        #ifdef TM_IDLE_FILL
            // Check for idle frame trigger
            if (((uint8)ingest[0] == 0x08) && ((uint8)ingest[1] == 0x90))
            { 
                // Don't fill idle frames   
            }
            else
            {
                while (x < (fill_size - 64) )
                {
                    tm_frame.tm_pdu[x++] = 0x07;
                    tm_frame.tm_pdu[x++] = 0xff;
                    tm_frame.tm_pdu[x++] = 0x00;
                    tm_frame.tm_pdu[x++] = 0x00;
                    tm_frame.tm_pdu[x++] = 0x00;
                    tm_frame.tm_pdu[x++] = 0x39;
                    for (int y = 0; y < 58; y++)
                    {
                        tm_frame.tm_pdu[x++] = 0x00;
                    }
                }
                // Add partial packet, if possible, and set offset
                if (x < fill_size)
                {
                    tm_frame.tm_pdu[x++] = 0x07;
                    tm_offset = 63;
                }
                if (x < fill_size)
                {
                    tm_frame.tm_pdu[x++] = 0xff;
                    tm_offset--;
                }
                if (x < fill_size)
                {
                    tm_frame.tm_pdu[x++] = 0x00;
                    tm_offset--;
                }
                if (x < fill_size)
                {
                    tm_frame.tm_pdu[x++] = 0x00;
                    tm_offset--;
                }
                if (x < fill_size)
                {
                    tm_frame.tm_pdu[x++] = 0x00;
                    tm_offset--;
                }
                if (x < fill_size)
                {
                    tm_frame.tm_pdu[x++] = 0x39;
                    tm_offset--;
                }
                for (int y = 0; x < fill_size; y++)
                {
                    tm_frame.tm_pdu[x++] = 00;
                    tm_offset--;
                }
            }
            while (x < TM_FILL_SIZE)
            {
                tm_frame.tm_pdu[x++] = 0x00;
            }
        #endif 
    #endif

    return;
}

static void Crypto_TM_updateOCF(void)
{
    if (ocf == 0)
    {	// CLCW
        clcw.vci = tm_frame.tm_header.vcid;

        tm_frame.tm_sec_trailer.ocf[0] = (clcw.cwt << 7) | (clcw.cvn << 5) | (clcw.sf << 2) | (clcw.cie);
        tm_frame.tm_sec_trailer.ocf[1] = (clcw.vci << 2) | (clcw.spare0);
        tm_frame.tm_sec_trailer.ocf[2] = (clcw.nrfa << 7) | (clcw.nbl << 6) | (clcw.lo << 5) | (clcw.wait << 4) | (clcw.rt << 3) | (clcw.fbc << 1) | (clcw.spare1);
        tm_frame.tm_sec_trailer.ocf[3] = (clcw.rv);
        // Alternate OCF
        ocf = 1;
        #ifdef OCF_DEBUG
            Crypto_clcwPrint(&clcw);
        #endif
    } 
    else
    {	// FSR
        tm_frame.tm_sec_trailer.ocf[0] = (report.cwt << 7) | (report.vnum << 4) | (report.af << 3) | (report.bsnf << 2) | (report.bmacf << 1) | (report.ispif);
        tm_frame.tm_sec_trailer.ocf[1] = (report.lspiu & 0xFF00) >> 8;
        tm_frame.tm_sec_trailer.ocf[2] = (report.lspiu & 0x00FF);
        tm_frame.tm_sec_trailer.ocf[3] = (report.snval);  
        // Alternate OCF
        ocf = 0;
        #ifdef OCF_DEBUG
            Crypto_fsrPrint(&report);
        #endif
    }
}

//TODO - Review this. Not sure it quite works how we think
int32 Crypto_increment(uint8 *num, int length)
{
    int i;
    /* go from right (least significant) to left (most signifcant) */
    for(i = length - 1; i >= 0; --i)
    {
        ++(num[i]); /* increment current byte */

        if(num[i] != 0) /* if byte did not overflow, we're done! */
           break;
    }

    if(i < 0) /* this means num[0] was incremented and overflowed */
        return OS_ERROR;
    else
        return OS_SUCCESS;
}

static int32 Crypto_window(uint8 *actual, uint8 *expected, int length, int window)
{
    int status = OS_ERROR;
    int result = 0;
    uint8 temp[length];

    CFE_PSP_MemCpy(temp, expected, length);

    for (int i = 0; i < window; i++)
    {   
        result = 0;
        /* go from right (least significant) to left (most signifcant) */
        for (int j = length - 1; j >= 0; --j)
        {
            if (actual[j] == temp[j])
            {
                result++;
            }
        }        
        if (result == length)
        {
            status = OS_SUCCESS;
            break;
        }
        Crypto_increment(&temp[0], length);
    }
    return status;
}

static int32 Crypto_compare_less_equal(uint8 *actual, uint8 *expected, int length)
{
    int status = OS_ERROR;

    for(int i = 0; i < length - 1; i++)
    {
        if (actual[i] > expected[i])
        {
            status = OS_SUCCESS;
            break;
        }
        else if (actual[i] < expected[i])
        {
            status = OS_ERROR;
            break;
        }
    }
    return status;
}

uint8 Crypto_Prep_Reply(char* ingest, uint8 appID)
// Assumes that both the pkt_length and pdu_len are set properly
{
    uint8 count = 0;
    
    // Prepare CCSDS for reply
    sdls_frame.hdr.pvn   = 0;
    sdls_frame.hdr.type  = 0;
    sdls_frame.hdr.shdr  = 1;
    sdls_frame.hdr.appID = appID;

    sdls_frame.pdu.type	 = 1;
    
    // Fill ingest with reply header
    ingest[count++] = (sdls_frame.hdr.pvn << 5) | (sdls_frame.hdr.type << 4) | (sdls_frame.hdr.shdr << 3) | ((sdls_frame.hdr.appID & 0x700 >> 8));	
    ingest[count++] = (sdls_frame.hdr.appID & 0x00FF);
    ingest[count++] = (sdls_frame.hdr.seq << 6) | ((sdls_frame.hdr.pktid & 0x3F00) >> 8);
    ingest[count++] = (sdls_frame.hdr.pktid & 0x00FF);
    ingest[count++] = (sdls_frame.hdr.pkt_length & 0xFF00) >> 8;
    ingest[count++] = (sdls_frame.hdr.pkt_length & 0x00FF);

    // Fill ingest with PUS
    //ingest[count++] = (sdls_frame.pus.shf << 7) | (sdls_frame.pus.pusv << 4) | (sdls_frame.pus.ack);
    //ingest[count++] = (sdls_frame.pus.st);
    //ingest[count++] = (sdls_frame.pus.sst);
    //ingest[count++] = (sdls_frame.pus.sid << 4) | (sdls_frame.pus.spare);
    
    // Fill ingest with Tag and Length
    ingest[count++] = (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | (sdls_frame.pdu.pid);
    ingest[count++] = (sdls_frame.pdu.pdu_len & 0xFF00) >> 8;
    ingest[count++] = (sdls_frame.pdu.pdu_len & 0x00FF);

    return count;
}

static int32 Crypto_FECF(int fecf, char* ingest, int len_ingest,TC_t* tc_frame)
// Calculate the Frame Error Control Field (FECF), also known as a cyclic redundancy check (CRC)
{
    int32 result = OS_SUCCESS;
    uint16 calc_fecf = Crypto_Calc_FECF(ingest, len_ingest);

    if ( (fecf & 0xFFFF) != calc_fecf )
        {
            if (((uint8)ingest[18] == 0x0B) && ((uint8)ingest[19] == 0x00) && (((uint8)ingest[20] & 0xF0) == 0x40))
            {   
                // User packet check only used for ESA Testing!
            }
            else
            {   // TODO: Error Correction
                OS_printf(KRED "Error: FECF incorrect!\n" RESET);
                if (log_summary.rs > 0)
                {
                    Crypto_increment((uint8*)&log_summary.num_se, 4);
                    log_summary.rs--;
                    log.blk[log_count].emt = FECF_ERR_EID;
                    log.blk[log_count].emv[0] = 0x4E;
                    log.blk[log_count].emv[1] = 0x41;
                    log.blk[log_count].emv[2] = 0x53;
                    log.blk[log_count].emv[3] = 0x41;
                    log.blk[log_count++].em_len = 4;
                }
                #ifdef FECF_DEBUG
                    OS_printf("\t Calculated = 0x%04x \n\t Received   = 0x%04x \n", calc_fecf, tc_frame->tc_sec_trailer.fecf);
                #endif
                result = OS_ERROR;
            }
        }

    return result;
}

static uint16 Crypto_Calc_FECF(char* ingest, int len_ingest)
// Calculate the Frame Error Control Field (FECF), also known as a cyclic redundancy check (CRC)
{
    uint16 fecf = 0xFFFF;
    uint16 poly = 0x1021;	// TODO: This polynomial is (CRC-CCITT) for ESA testing, may not match standard protocol
    uint8 bit;
    uint8 c15;

    for (int i = 0; i <= len_ingest; i++)
    {	// Byte Logic
        for (int j = 0; j < 8; j++)
        {	// Bit Logic
            bit = ((ingest[i] >> (7 - j) & 1) == 1); 
            c15 = ((fecf >> 15 & 1) == 1); 
            fecf <<= 1;
            if (c15 ^ bit)
            {
                fecf ^= poly;
            }
        }
    }

    // Check if Testing
    if (badFECF == 1)
    {
        fecf++;
    }

    #ifdef FECF_DEBUG
        OS_printf(KCYN "Crypto_Calc_FECF: 0x%02x%02x%02x%02x%02x, len_ingest = %d\n" RESET, ingest[0], ingest[1], ingest[2], ingest[3], ingest[4], len_ingest);
        OS_printf(KCYN "0x" RESET);
        for (int x = 0; x < len_ingest; x++)
        {
            OS_printf(KCYN "%02x" RESET, (uint8)*(ingest+x));
        }
        OS_printf(KCYN "\n" RESET);
        OS_printf(KCYN "In Crypto_Calc_FECF! fecf = 0x%04x\n" RESET, fecf);
    #endif
    
    return fecf;
}

static uint16 Crypto_Calc_CRC16(char* data, int size)
{   // Code provided by ESA
    uint16 crc = 0xFFFF;

    for ( ; size > 0; size--)
    {  
        //OS_printf("*data = 0x%02x \n", (uint8) *data);
        crc = ((crc << 8) & 0xFF00) ^ crc16Table[(crc >> 8) ^ *data++];
    }
       
   return crc;
}

/*
** Key Management Services
*/
static int32 Crypto_Key_OTAR(void)
// The OTAR Rekeying procedure shall have the following Service Parameters:
//  a- Key ID of the Master Key (Integer, unmanaged)
//  b- Size of set of Upload Keys (Integer, managed)
//  c- Set of Upload Keys (Integer[Session Key]; managed)
// NOTE- The size of the session keys is mission specific.
//  a- Set of Key IDs of Upload Keys (Integer[Key IDs]; managed)
//  b- Set of Encrypted Upload Keys (Integer[Size of set of Key ID]; unmanaged)
//  c- Agreed Cryptographic Algorithm (managed)
{
    // Local variables
    SDLS_OTAR_t packet;
    int count = 0;
    int x = 0;
    int32 status = OS_SUCCESS;
    int pdu_keys = (sdls_frame.pdu.pdu_len - 30) / (2 + KEY_SIZE);

    gcry_cipher_hd_t tmp_hd;
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;

    // Master Key ID
    packet.mkid = (sdls_frame.pdu.data[0] << 8) | (sdls_frame.pdu.data[1]);

    if (packet.mkid >= 128)
    {
        report.af = 1;
        if (log_summary.rs > 0)
        {
            Crypto_increment((uint8*)&log_summary.num_se, 4);
            log_summary.rs--;
            log.blk[log_count].emt = MKID_INVALID_EID;
            log.blk[log_count].emv[0] = 0x4E;
            log.blk[log_count].emv[1] = 0x41;
            log.blk[log_count].emv[2] = 0x53;
            log.blk[log_count].emv[3] = 0x41;
            log.blk[log_count++].em_len = 4;
        }
        OS_printf(KRED "Error: MKID is not valid! \n" RESET);
        status = OS_ERROR;
        return status;
    }

    for (int count = 2; count < (2 + IV_SIZE); count++)
    {	// Initialization Vector
        packet.iv[count-2] = sdls_frame.pdu.data[count];
        //OS_printf("packet.iv[%d] = 0x%02x\n", count-2, packet.iv[count-2]);
    }
    
    count = sdls_frame.pdu.pdu_len - MAC_SIZE; 
    for (int w = 0; w < 16; w++)
    {	// MAC
        packet.mac[w] = sdls_frame.pdu.data[count + w];
        //OS_printf("packet.mac[%d] = 0x%02x\n", w, packet.mac[w]);
    }

    gcry_error = gcry_cipher_open(
        &(tmp_hd), 
        GCRY_CIPHER_AES256, 
        GCRY_CIPHER_MODE_GCM, 
        GCRY_CIPHER_CBC_MAC
    );
    if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        OS_printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
        status = OS_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setkey(
        tmp_hd, 
        &(ek_ring[packet.mkid].value[0]), 
        KEY_SIZE
    );
    if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        OS_printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
        status = OS_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_setiv(
        tmp_hd, 
        &(packet.iv[0]), 
        IV_SIZE
    );
    if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        OS_printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
        status = OS_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_decrypt(
        tmp_hd,
        &(sdls_frame.pdu.data[14]),                     // plaintext output
        pdu_keys * (2 + KEY_SIZE),   			 		// length of data
        NULL,                                           // in place decryption
        0                                               // in data length
    );
    if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        OS_printf(KRED "ERROR: gcry_cipher_decrypt error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
        status = OS_ERROR;
        return status;
    }
    gcry_error = gcry_cipher_checktag(
        tmp_hd,
        &(packet.mac[0]),                               // tag input
        MAC_SIZE                                        // tag size
    );
    if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
    {
        OS_printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
        status = OS_ERROR;
        return status;
    }
    gcry_cipher_close(tmp_hd);
    
    // Read in Decrypted Data
    for (int count = 14; x < pdu_keys; x++)
    {	// Encrypted Key Blocks
        packet.EKB[x].ekid = (sdls_frame.pdu.data[count] << 8) | (sdls_frame.pdu.data[count+1]);
        if (packet.EKB[x].ekid < 128)
        {
            report.af = 1;
            if (log_summary.rs > 0)
            {
                Crypto_increment((uint8*)&log_summary.num_se, 4);
                log_summary.rs--;
                log.blk[log_count].emt = OTAR_MK_ERR_EID;
                log.blk[log_count].emv[0] = 0x4E; // N
                log.blk[log_count].emv[1] = 0x41; // A
                log.blk[log_count].emv[2] = 0x53; // S
                log.blk[log_count].emv[3] = 0x41; // A
                log.blk[log_count++].em_len = 4;
            }
            OS_printf(KRED "Error: Cannot OTAR master key! \n" RESET);
            status = OS_ERROR;
        return status;
        }
        else
        {   
            count = count + 2;
            for (int y = count; y < (KEY_SIZE + count); y++)
            {	// Encrypted Key
                packet.EKB[x].ek[y-count] = sdls_frame.pdu.data[y];
                #ifdef SA_DEBUG
                    OS_printf("\t packet.EKB[%d].ek[%d] = 0x%02x\n", x, y-count, packet.EKB[x].ek[y-count]);
                #endif

                // Setup Key Ring
                ek_ring[packet.EKB[x].ekid].value[y - count] = sdls_frame.pdu.data[y];
            }
            count = count + KEY_SIZE;

            // Set state to PREACTIVE
            ek_ring[packet.EKB[x].ekid].key_state = KEY_PREACTIVE;
        }
    }

    #ifdef PDU_DEBUG
        OS_printf("Received %d keys via master key %d: \n", pdu_keys, packet.mkid);
        for (int x = 0; x < pdu_keys; x++)
        {
            OS_printf("%d) Key ID = %d, 0x", x+1, packet.EKB[x].ekid);
            for(int y = 0; y < KEY_SIZE; y++)
            {
                OS_printf("%02x", packet.EKB[x].ek[y]);
            }
            OS_printf("\n");
        } 
    #endif
    
    return OS_SUCCESS; 
}

static int32 Crypto_Key_update(uint8 state)
// Updates the state of the all keys in the received SDLS EP PDU
{	// Local variables
    SDLS_KEY_BLK_t packet;
    int count = 0;
    int pdu_keys = sdls_frame.pdu.pdu_len / 2;
    #ifdef PDU_DEBUG
        OS_printf("Keys ");
    #endif
    // Read in PDU
    for (int x = 0; x < pdu_keys; x++)
    {
        packet.kblk[x].kid = (sdls_frame.pdu.data[count] << 8) | (sdls_frame.pdu.data[count+1]);
        count = count + 2;
        #ifdef PDU_DEBUG
            if (x != (pdu_keys - 1))
            {
                OS_printf("%d, ", packet.kblk[x].kid);
            }
            else
            {
                OS_printf("and %d ", packet.kblk[x].kid);
            }
        #endif
    }
    #ifdef PDU_DEBUG
        OS_printf("changed to state ");
        switch (state)
        {
            case KEY_PREACTIVE:
                OS_printf("PREACTIVE. \n");
                break;
            case KEY_ACTIVE:
                OS_printf("ACTIVE. \n");
                break;
            case KEY_DEACTIVATED:
                OS_printf("DEACTIVATED. \n");
                break;
            case KEY_DESTROYED:
                OS_printf("DESTROYED. \n");
                break;
            case KEY_CORRUPTED:
                OS_printf("CORRUPTED. \n");
                break;
            default:
                OS_printf("ERROR. \n");
                break;
        }
    #endif
    // Update Key State
    for (int x = 0; x < pdu_keys; x++)
    {
        if (packet.kblk[x].kid < 128)
        {
            report.af = 1;
            if (log_summary.rs > 0)
            {
                Crypto_increment((uint8*)&log_summary.num_se, 4);
                log_summary.rs--;
                log.blk[log_count].emt = MKID_STATE_ERR_EID;
                log.blk[log_count].emv[0] = 0x4E;
                log.blk[log_count].emv[1] = 0x41;
                log.blk[log_count].emv[2] = 0x53;
                log.blk[log_count].emv[3] = 0x41;
                log.blk[log_count++].em_len = 4;
            }
            OS_printf(KRED "Error: MKID state cannot be changed! \n" RESET);
            // TODO: Exit
        }

        if (ek_ring[packet.kblk[x].kid].key_state == (state - 1))
        {
            ek_ring[packet.kblk[x].kid].key_state = state;
            #ifdef PDU_DEBUG
                //OS_printf("Key ID %d state changed to ", packet.kblk[x].kid);
            #endif
        }
        else 
        {
            if (log_summary.rs > 0)
            {
                Crypto_increment((uint8*)&log_summary.num_se, 4);
                log_summary.rs--;
                log.blk[log_count].emt = KEY_TRANSITION_ERR_EID;
                log.blk[log_count].emv[0] = 0x4E;
                log.blk[log_count].emv[1] = 0x41;
                log.blk[log_count].emv[2] = 0x53;
                log.blk[log_count].emv[3] = 0x41;
                log.blk[log_count++].em_len = 4;
            }
            OS_printf(KRED "Error: Key %d cannot transition to desired state! \n" RESET, packet.kblk[x].kid);
        }
    }
    return OS_SUCCESS; 
}

static int32 Crypto_Key_inventory(char* ingest)
{
    // Local variables
    SDLS_KEY_INVENTORY_t packet;
    int count = 0;
    uint16_t range = 0;

    // Read in PDU
    packet.kid_first = ((uint8)sdls_frame.pdu.data[count] << 8) | ((uint8)sdls_frame.pdu.data[count+1]);
    count = count + 2;
    packet.kid_last = ((uint8)sdls_frame.pdu.data[count] << 8) | ((uint8)sdls_frame.pdu.data[count+1]);
    count = count + 2;

    // Prepare for Reply
    range = packet.kid_last - packet.kid_first;
    sdls_frame.pdu.pdu_len = 2 + (range * (2 + 1));
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);
    ingest[count++] = (range & 0xFF00) >> 8;
    ingest[count++] = (range & 0x00FF);
    for (uint16_t x = packet.kid_first; x < packet.kid_last; x++)
    {   // Key ID
        ingest[count++] = (x & 0xFF00) >> 8;
        ingest[count++] = (x & 0x00FF);
        // Key State
        ingest[count++] = ek_ring[x].key_state;
    }
    return count;
}

static int32 Crypto_Key_verify(char* ingest,TC_t* tc_frame)
{
    // Local variables
    SDLS_KEYV_CMD_t packet;
    int count = 0;
    int pdu_keys = sdls_frame.pdu.pdu_len / SDLS_KEYV_CMD_BLK_SIZE;

    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    gcry_cipher_hd_t tmp_hd;
    uint8 iv_loc;

    //uint8 tmp_mac[MAC_SIZE];

    #ifdef PDU_DEBUG
        OS_printf("Crypto_Key_verify: Requested %d key(s) to verify \n", pdu_keys);
    #endif
    
    // Read in PDU
    for (int x = 0; x < pdu_keys; x++)
    {	
        // Key ID
        packet.blk[x].kid = ((uint8)sdls_frame.pdu.data[count] << 8) | ((uint8)sdls_frame.pdu.data[count+1]);
        count = count + 2;
        #ifdef PDU_DEBUG
            OS_printf("Crypto_Key_verify: Block %d Key ID is %d \n", x, packet.blk[x].kid);
        #endif
        // Key Challenge
        for (int y = 0; y < CHALLENGE_SIZE; y++)
        {
            packet.blk[x].challenge[y] = sdls_frame.pdu.data[count++];
        }
        #ifdef PDU_DEBUG
            OS_printf("\n");
        #endif
    }
    
    // Prepare for Reply
    sdls_frame.pdu.pdu_len = pdu_keys * (2 + IV_SIZE + CHALLENGE_SIZE + CHALLENGE_MAC_SIZE);
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    for (int x = 0; x < pdu_keys; x++)
    {   // Key ID
        ingest[count++] = (packet.blk[x].kid & 0xFF00) >> 8;
        ingest[count++] = (packet.blk[x].kid & 0x00FF);

        // Initialization Vector
        iv_loc = count;
        for (int y = 0; y < IV_SIZE; y++)
        {   
            ingest[count++] = tc_frame->tc_sec_header.iv[y];
        }
        ingest[count-1] = ingest[count-1] + x + 1;

        // Encrypt challenge 
        gcry_error = gcry_cipher_open(
            &(tmp_hd), 
            GCRY_CIPHER_AES256, 
            GCRY_CIPHER_MODE_GCM, 
            GCRY_CIPHER_CBC_MAC
        );
        if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            OS_printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
        }
        gcry_error = gcry_cipher_setkey(
            tmp_hd, 
            &(ek_ring[packet.blk[x].kid].value[0]),
            KEY_SIZE
        );
        if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            OS_printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
        }
        gcry_error = gcry_cipher_setiv(
            tmp_hd, 
            &(ingest[iv_loc]), 
            IV_SIZE
        );
        if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            OS_printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
        }
        gcry_error = gcry_cipher_encrypt(
            tmp_hd,
            &(ingest[count]),                               // ciphertext output
            CHALLENGE_SIZE,			 		                // length of data
            &(packet.blk[x].challenge[0]),                  // plaintext input
            CHALLENGE_SIZE                                  // in data length
        );
        if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            OS_printf(KRED "ERROR: gcry_cipher_encrypt error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
        }
        count = count + CHALLENGE_SIZE; // Don't forget to increment count!
        
        gcry_error = gcry_cipher_gettag(
            tmp_hd,
            &(ingest[count]),                               // tag output
            CHALLENGE_MAC_SIZE                              // tag size
        );
        if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            OS_printf(KRED "ERROR: gcry_cipher_gettag error code %d \n" RESET,gcry_error & GPG_ERR_CODE_MASK);
        }
        count = count + CHALLENGE_MAC_SIZE; // Don't forget to increment count!

        // Copy from tmp_mac into ingest
        //for( int y = 0; y < CHALLENGE_MAC_SIZE; y++)
        //{
        //    ingest[count++] = tmp_mac[y];
        //}
        gcry_cipher_close(tmp_hd);
    }

    #ifdef PDU_DEBUG
        OS_printf("Crypto_Key_verify: Response is %d bytes \n", count);
    #endif

    return count;
}

/*

/*
** Security Association Monitoring and Control
*/
static int32 Crypto_MC_ping(char* ingest)
{
    int count = 0;

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 0;
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    return count;
}

static int32 Crypto_MC_status(char* ingest)
{
    int count = 0;

    // TODO: Update log_summary.rs;

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 2; // 4
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);
    
    // PDU
    //ingest[count++] = (log_summary.num_se & 0xFF00) >> 8;
    ingest[count++] = (log_summary.num_se & 0x00FF);
    //ingest[count++] = (log_summary.rs & 0xFF00) >> 8;
    ingest[count++] = (log_summary.rs & 0x00FF);
    
    #ifdef PDU_DEBUG
        OS_printf("log_summary.num_se = 0x%02x \n",log_summary.num_se);
        OS_printf("log_summary.rs = 0x%02x \n",log_summary.rs);
    #endif

    return count;
}

static int32 Crypto_MC_dump(char* ingest)
{
    int count = 0;
    
    // Prepare for Reply
    sdls_frame.pdu.pdu_len = (log_count * 6);  // SDLS_MC_DUMP_RPLY_SIZE
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    // PDU
    for (int x = 0; x < log_count; x++)
    {
        ingest[count++] = log.blk[x].emt;
        //ingest[count++] = (log.blk[x].em_len & 0xFF00) >> 8;
        ingest[count++] = (log.blk[x].em_len & 0x00FF);
        for (int y = 0; y < EMV_SIZE; y++)
        {
            ingest[count++] = log.blk[x].emv[y];
        }
    }

    #ifdef PDU_DEBUG
        OS_printf("log_count = %d \n", log_count);
        OS_printf("log_summary.num_se = 0x%02x \n",log_summary.num_se);
        OS_printf("log_summary.rs = 0x%02x \n",log_summary.rs);
    #endif

    return count; 
}

static int32 Crypto_MC_erase(char* ingest)
{
    int count = 0;

    // Zero Logs
    for (int x = 0; x < LOG_SIZE; x++)
    {
        log.blk[x].emt = 0;
        log.blk[x].em_len = 0;
        for (int y = 0; y < EMV_SIZE; y++)
        {
            log.blk[x].emv[y] = 0;
        }
    }

    // Compute Summary
    log_count = 0;
    log_summary.num_se = 0;
    log_summary.rs = LOG_SIZE;

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 2; // 4
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    // PDU
    //ingest[count++] = (log_summary.num_se & 0xFF00) >> 8;
    ingest[count++] = (log_summary.num_se & 0x00FF);
    //ingest[count++] = (log_summary.rs & 0xFF00) >> 8;
    ingest[count++] = (log_summary.rs & 0x00FF);

    return count; 
}

static int32 Crypto_MC_selftest(char* ingest)
{
    uint8 count = 0;
    uint8 result = ST_OK;

    // TODO: Perform test

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 1;
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    ingest[count++] = result;
    
    return count; 
}

static int32 Crypto_SA_readARSN(char* ingest)
{
    uint8 count = 0;
    uint16 spi = 0x0000;
    SecurityAssociation_t* sa_ptr;

    // Read ingest
    spi = ((uint8)sdls_frame.pdu.data[0] << 8) | (uint8)sdls_frame.pdu.data[1];

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 2 + IV_SIZE;
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    // Write SPI to reply
    ingest[count++] = (spi & 0xFF00) >> 8;
    ingest[count++] = (spi & 0x00FF);


    if(sadb_routine->sadb_get_sa_from_spi(spi,&sa_ptr) != OS_SUCCESS){
        //TODO - Error handling
        return OS_ERROR; //Error -- unable to get SA from SPI.
    }


    if (sa_ptr->iv_len > 0)
    {   // Set IV - authenticated encryption
        for (int x = 0; x < sa_ptr->iv_len - 1; x++)
        {
            ingest[count++] = sa_ptr->iv[x];
        }
        
        // TODO: Do we need this?
        if (sa_ptr->iv[IV_SIZE - 1] > 0)
        {   // Adjust to report last received, not expected
            ingest[count++] = sa_ptr->iv[IV_SIZE - 1] - 1;
        }
        else
        {   
            ingest[count++] = sa_ptr->iv[IV_SIZE - 1];
        }
    }
    else
    {   
        // TODO
    }

    #ifdef PDU_DEBUG
        OS_printf("spi = %d \n", spi);
        if (sa_ptr->iv_len > 0)
        {
            OS_printf("ARSN = 0x");
            for (int x = 0; x < sa_ptr->iv_len; x++)
            {
                OS_printf("%02x", sa_ptr->iv[x]);
            }
            OS_printf("\n");
        }
    #endif
    
    return count; 
}

static int32 Crypto_MC_resetalarm(void)
{   // Reset all alarm flags
    report.af = 0;
    report.bsnf = 0;
    report.bmacf = 0;
    report.ispif = 0;    
    return OS_SUCCESS; 
}

static int32 Crypto_User_IdleTrigger(char* ingest)
{
    uint8 count = 0;

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 0;
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 144);
    
    return count; 
}
                         
static int32 Crypto_User_BadSPI(void)
{
    // Toggle Bad Sequence Number
    if (badSPI == 0)
    {
        badSPI = 1;
    }   
    else
    {
        badSPI = 0;
    }
    
    return OS_SUCCESS; 
}

static int32 Crypto_User_BadMAC(void)
{
    // Toggle Bad MAC
    if (badMAC == 0)
    {
        badMAC = 1;
    }   
    else
    {
        badMAC = 0;
    }
    
    return OS_SUCCESS; 
}

static int32 Crypto_User_BadIV(void)
{
    // Toggle Bad MAC
    if (badIV == 0)
    {
        badIV = 1;
    }   
    else
    {
        badIV = 0;
    }
    
    return OS_SUCCESS; 
}

static int32 Crypto_User_BadFECF(void)
{
    // Toggle Bad FECF
    if (badFECF == 0)
    {
        badFECF = 1;
    }   
    else
    {
        badFECF = 0;
    }
    
    return OS_SUCCESS; 
}

static int32 Crypto_User_ModifyKey(void)
{
    // Local variables
    uint16 kid = ((uint8)sdls_frame.pdu.data[0] << 8) | ((uint8)sdls_frame.pdu.data[1]);
    uint8 mod = (uint8)sdls_frame.pdu.data[2];

    switch (mod)
    {
        case 1: // Invalidate Key
            ek_ring[kid].value[KEY_SIZE-1]++;
            OS_printf("Key %d value invalidated! \n", kid);
            break;
        case 2: // Modify key state
            ek_ring[kid].key_state = (uint8)sdls_frame.pdu.data[3] & 0x0F;
            OS_printf("Key %d state changed to %d! \n", kid, mod);
            break;
        default:
            // Error
            break;
    }
    
    return OS_SUCCESS; 
}

static int32 Crypto_User_ModifyActiveTM(void)
{
    tm_frame.tm_sec_header.spi = (uint8)sdls_frame.pdu.data[0];   
    return OS_SUCCESS; 
}

static int32 Crypto_User_ModifyVCID(void)
{
    tm_frame.tm_header.vcid = (uint8)sdls_frame.pdu.data[0];
    SecurityAssociation_t* sa_ptr;

    for (int i = 0; i < NUM_GVCID; i++)
    {
        if(sadb_routine->sadb_get_sa_from_spi(i,&sa_ptr) != OS_SUCCESS){
            //TODO - Error handling
            return OS_ERROR; //Error -- unable to get SA from SPI.
        }
        for (int j = 0; j < NUM_SA; j++)
        {

            if (sa_ptr->gvcid_tm_blk[j].mapid == TYPE_TM)
            {
                if (sa_ptr->gvcid_tm_blk[j].vcid == tm_frame.tm_header.vcid)
                {
                    tm_frame.tm_sec_header.spi = i;
                    OS_printf("TM Frame SPI changed to %d \n",i);
                    break;
                }
            }
        }
    }

    return OS_SUCCESS;
}

/*
** Procedures Specifications
*/
static int32 Crypto_PDU(char* ingest,TC_t* tc_frame)
{
    int32 status = OS_SUCCESS;
    
    switch (sdls_frame.pdu.type)
    {
        case 0:	// Command
            switch (sdls_frame.pdu.uf)
            {
                case 0:	// CCSDS Defined Command
                    switch (sdls_frame.pdu.sg)
                    {
                        case SG_KEY_MGMT:  // Key Management Procedure
                            switch (sdls_frame.pdu.pid)
                            {
                                case PID_OTAR:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "Key OTAR\n" RESET);
                                    #endif
                                    status = Crypto_Key_OTAR();
                                    break;
                                case PID_KEY_ACTIVATION:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "Key Activate\n" RESET);
                                    #endif
                                    status = Crypto_Key_update(KEY_ACTIVE);
                                    break;
                                case PID_KEY_DEACTIVATION:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "Key Deactivate\n" RESET);
                                    #endif
                                    status = Crypto_Key_update(KEY_DEACTIVATED);
                                    break;
                                case PID_KEY_VERIFICATION:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "Key Verify\n" RESET);
                                    #endif
                                    status = Crypto_Key_verify(ingest,tc_frame);
                                    break;
                                case PID_KEY_DESTRUCTION:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "Key Destroy\n" RESET);
                                    #endif
                                    status = Crypto_Key_update(KEY_DESTROYED);
                                    break;
                                case PID_KEY_INVENTORY:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "Key Inventory\n" RESET);
                                    #endif
                                    status = Crypto_Key_inventory(ingest);
                                    break;
                                default:
                                    OS_printf(KRED "Error: Crypto_PDU failed interpreting Key Management Procedure Identification Field! \n" RESET);
                                    break;
                            }
                            break;
                        case SG_SA_MGMT:  // Security Association Management Procedure
                            switch (sdls_frame.pdu.pid)
                            {
                                case PID_CREATE_SA:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "SA Create\n" RESET); 
                                    #endif
                                    status = sadb_routine->sadb_sa_create();
                                    break;
                                case PID_DELETE_SA:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "SA Delete\n" RESET);
                                    #endif
                                    status = sadb_routine->sadb_sa_delete();
                                    break;
                                case PID_SET_ARSNW:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "SA setARSNW\n" RESET);
                                    #endif
                                    status = sadb_routine->sadb_sa_setARSNW();
                                    break;
                                case PID_REKEY_SA:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "SA Rekey\n" RESET); 
                                    #endif
                                    status = sadb_routine->sadb_sa_rekey();
                                    break;
                                case PID_EXPIRE_SA:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "SA Expire\n" RESET);
                                    #endif
                                    status = sadb_routine->sadb_sa_expire();
                                    break;
                                case PID_SET_ARSN:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "SA SetARSN\n" RESET);
                                    #endif
                                    status = sadb_routine->sadb_sa_setARSN();
                                    break;
                                case PID_START_SA:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "SA Start\n" RESET); 
                                    #endif
                                    status = sadb_routine->sadb_sa_start(tc_frame);
                                    break;
                                case PID_STOP_SA:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "SA Stop\n" RESET);
                                    #endif
                                    status = sadb_routine->sadb_sa_stop();
                                    break;
                                case PID_READ_ARSN:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "SA readARSN\n" RESET);
                                    #endif
                                    status = Crypto_SA_readARSN(ingest);
                                    break;
                                case PID_SA_STATUS:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "SA Status\n" RESET);
                                    #endif
                                    status = sadb_routine->sadb_sa_status(ingest);
                                    break;
                                default:
                                    OS_printf(KRED "Error: Crypto_PDU failed interpreting SA Procedure Identification Field! \n" RESET);
                                    break;
                            }
                            break;
                        case SG_SEC_MON_CTRL:  // Security Monitoring & Control Procedure
                            switch (sdls_frame.pdu.pid)
                            {
                                case PID_PING:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "MC Ping\n" RESET);
                                    #endif
                                    status = Crypto_MC_ping(ingest);
                                    break;
                                case PID_LOG_STATUS:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "MC Status\n" RESET);
                                    #endif
                                    status = Crypto_MC_status(ingest);
                                    break;
                                case PID_DUMP_LOG:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "MC Dump\n" RESET);
                                    #endif
                                    status = Crypto_MC_dump(ingest);
                                    break;
                                case PID_ERASE_LOG:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "MC Erase\n" RESET);
                                    #endif
                                    status = Crypto_MC_erase(ingest);
                                    break;
                                case PID_SELF_TEST:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "MC Selftest\n" RESET);
                                    #endif
                                    status = Crypto_MC_selftest(ingest);
                                    break;
                                case PID_ALARM_FLAG:
                                    #ifdef PDU_DEBUG
                                        OS_printf(KGRN "MC Reset Alarm\n" RESET);
                                    #endif
                                    status = Crypto_MC_resetalarm();
                                    break;
                                default:
                                    OS_printf(KRED "Error: Crypto_PDU failed interpreting MC Procedure Identification Field! \n" RESET);
                                    break;
                            }
                            break;
                        default: // ERROR
                            OS_printf(KRED "Error: Crypto_PDU failed interpreting Service Group! \n" RESET);
                            break;
                    }
                    break;
                    
                case 1: 	// User Defined Command
                    switch (sdls_frame.pdu.sg)
                    {
                        default:
                            switch (sdls_frame.pdu.pid)
                            {
                                case 0: // Idle Frame Trigger
                                    #ifdef PDU_DEBUG
                                        OS_printf(KMAG "User Idle Trigger\n" RESET);
                                    #endif
                                    status = Crypto_User_IdleTrigger(ingest);
                                    break;
                                case 1: // Toggle Bad SPI
                                    #ifdef PDU_DEBUG
                                        OS_printf(KMAG "User Toggle Bad SPI\n" RESET);
                                    #endif
                                    status = Crypto_User_BadSPI();
                                    break;
                                case 2: // Toggle Bad IV
                                    #ifdef PDU_DEBUG
                                        OS_printf(KMAG "User Toggle Bad IV\n" RESET);
                                    #endif
                                    status = Crypto_User_BadIV();\
                                    break;
                                case 3: // Toggle Bad MAC
                                    #ifdef PDU_DEBUG
                                        OS_printf(KMAG "User Toggle Bad MAC\n" RESET);
                                    #endif
                                    status = Crypto_User_BadMAC();
                                    break; 
                                case 4: // Toggle Bad FECF
                                    #ifdef PDU_DEBUG
                                        OS_printf(KMAG "User Toggle Bad FECF\n" RESET);
                                    #endif
                                    status = Crypto_User_BadFECF();
                                    break;
                                case 5: // Modify Key
                                    #ifdef PDU_DEBUG
                                        OS_printf(KMAG "User Modify Key\n" RESET);
                                    #endif
                                    status = Crypto_User_ModifyKey();
                                    break;
                                case 6: // Modify ActiveTM
                                    #ifdef PDU_DEBUG
                                        OS_printf(KMAG "User Modify Active TM\n" RESET);
                                    #endif
                                    status = Crypto_User_ModifyActiveTM();
                                    break;
                                case 7: // Modify TM VCID
                                    #ifdef PDU_DEBUG
                                        OS_printf(KMAG "User Modify VCID\n" RESET);
                                    #endif
                                    status = Crypto_User_ModifyVCID();
                                    break;
                                default:
                                    OS_printf(KRED "Error: Crypto_PDU received user defined command! \n" RESET);
                                    break;
                            }
                    }
                    break;
            }
            break;
            
        case 1:	// Reply
            OS_printf(KRED "Error: Crypto_PDU failed interpreting PDU Type!  Received a Reply!?! \n" RESET);
            break;
    }

    #ifdef CCSDS_DEBUG
        if (status > 0)
        {
            OS_printf(KMAG "CCSDS message put on software bus: 0x" RESET);
            for (int x = 0; x < status; x++)
            {
                OS_printf(KMAG "%02x" RESET, (uint8) ingest[x]);
            }
            OS_printf("\n");
        }
    #endif

    return status;
}
int32 Crypto_TC_ApplySecurity(const uint8* p_in_frame, const uint16 in_frame_length, \
    uint8 **pp_in_frame, uint16 *p_enc_frame_len)
{
    // Local Variables
    int32 status = OS_SUCCESS;
    TC_FramePrimaryHeader_t temp_tc_header;
    SecurityAssociation_t* sa_ptr = NULL;
    uint8 *p_new_enc_frame = NULL;
    uint8 sa_service_type = -1;
    uint16 mac_loc = 0;
    uint16 tf_payload_len = 0x0000;
    uint16 new_fecf = 0x0000;
    uint8 aad[20];
    gcry_cipher_hd_t tmp_hd;
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;

    #ifdef DEBUG
        OS_printf(KYEL "\n----- Crypto_TC_ApplySecurity START -----\n" RESET);
    #endif

    if (p_in_frame == NULL)
    {
        status = OS_ERROR;
        OS_printf(KRED "Error: Input Buffer NULL! \n" RESET);
        return status;  //Just return here, nothing can be done.
    }

    #ifdef DEBUG
        OS_printf("%d TF Bytes received\n", in_frame_length);
        OS_printf("DEBUG - ");
        for(int i=0; i < in_frame_length; i++)
        {
            OS_printf("%02X", ((uint8 *)&*p_in_frame)[i]);
        }
        OS_printf("\nPrinted %d bytes\n", in_frame_length);
    #endif

    // Primary Header
    temp_tc_header.tfvn   = ((uint8)p_in_frame[0] & 0xC0) >> 6;
    temp_tc_header.bypass = ((uint8)p_in_frame[0] & 0x20) >> 5;
    temp_tc_header.cc     = ((uint8)p_in_frame[0] & 0x10) >> 4;
    temp_tc_header.spare  = ((uint8)p_in_frame[0] & 0x0C) >> 2;
    temp_tc_header.scid   = ((uint8)p_in_frame[0] & 0x03) << 8;
    temp_tc_header.scid   = temp_tc_header.scid | (uint8)p_in_frame[1];
    temp_tc_header.vcid   = ((uint8)p_in_frame[2] & 0xFC) >> 2 & VCID_BITMASK;
    temp_tc_header.fl     = ((uint8)p_in_frame[2] & 0x03) << 8;
    temp_tc_header.fl     = temp_tc_header.fl | (uint8)p_in_frame[3];
    temp_tc_header.fsn	  = (uint8)p_in_frame[4];

    //TODO -- Handle segmentation header logic (this is a per-VCID managed parameter!)
    //If segmentation header for VCID, parse out MAP_ID
    // probably need to augment crypto_structs.h to handle segmentation headers.
    uint8 map_id = 0;

    // Check if command frame flag set
    if ((temp_tc_header.cc == 1) && (status == OS_SUCCESS))
    {
        /*
        ** CCSDS 232.0-B-3
        ** Section 6.3.1
        ** "Type-C frames do not have the Security Header and Security Trailer."
        */
        #ifdef TC_DEBUG
            OS_printf(KYEL "DEBUG - Received Control/Command frame - nothing to do.\n" RESET);
        #endif
        status = OS_ERROR;
    }

    // TODO: If command frame flag not set, need to know SDLS parameters
    // What is the best way to do this - copy in the entire SA for a channel?
    // Expect these calls will return an error is the SA is not usable
    // Will need to know lengths of various parameters from the SA DB
    if (status == OS_SUCCESS)
    {
        // Query SA DB for active SA / SDLS parameters
        status = sadb_routine->sadb_get_operational_sa_from_gvcid(temp_tc_header.tfvn, temp_tc_header.scid, temp_tc_header.vcid, map_id,&sa_ptr);

        // If unable to get operational SA, can return
        if (status != OS_SUCCESS)
        {
            return status;
        }

        #ifdef SA_DEBUG
            OS_printf(KYEL "DEBUG - Printing SA Entry for current frame.\n" RESET);
            Crypto_saPrint(sa_ptr);
        #endif

        // Determine SA Service Type
        if ((sa_ptr->est == 0) && (sa_ptr->ast == 0))
        {
            sa_service_type = SA_PLAINTEXT;
        }
        else if ((sa_ptr->est == 0) && (sa_ptr->ast == 1))
        {
            sa_service_type = SA_AUTHENTICATION;
        }
        else if ((sa_ptr->est == 1) && (sa_ptr->ast == 0))
        {
            sa_service_type = SA_ENCRYPTION;
        }
        else if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
        {
            sa_service_type = SA_AUTHENTICATED_ENCRYPTION;
        }
        else
        {
            // Probably unnecessary check
            // Leaving for now as it would be cleaner in SA to have an association enum returned I believe
            OS_printf(KRED "Error: SA Service Type is not defined! \n" RESET);
            status = OS_ERROR;
            return status;
        }

        #ifdef TC_DEBUG
            switch(sa_service_type)
            {
                case SA_PLAINTEXT:
                    OS_printf(KBLU "Creating a TC - CLEAR!\n" RESET);
                    break;
                case SA_AUTHENTICATION:
                    OS_printf(KBLU "Creating a TC - AUTHENTICATED!\n" RESET);
                    break;
                case SA_ENCRYPTION:
                    OS_printf(KBLU "Creating a TC - ENCRYPTED!\n" RESET);
                    break;
                case SA_AUTHENTICATED_ENCRYPTION:
                    OS_printf(KBLU "Creating a TC - AUTHENTICATED ENCRYPTION!\n" RESET);
                    break;
            }
        #endif

        // Determine length of buffer to be malloced
        // TODO: Determine presence of FECF & TC_PAD_SIZE
        // TODO: Note: Currently assumes ciphertext output length is same as ciphertext input length
        switch(sa_service_type)
        {
            case SA_PLAINTEXT:
                // Ingest length + segment header (1) + spi_index (2) + some variable length fields
                    *p_enc_frame_len = in_frame_length + 1 + 2 + sa_ptr->shplf_len;
            case SA_AUTHENTICATION:
                // Ingest length + segment header (1) + spi_index (2) + shivf_len (varies) + shsnf_len (varies) \
                //   + shplf_len + arc_len + pad_size + stmacf_len
                *p_enc_frame_len = in_frame_length + 1 + 2 + sa_ptr->shivf_len + sa_ptr->shsnf_len + \
                sa_ptr->shplf_len + sa_ptr->arc_len + TC_PAD_SIZE + sa_ptr->stmacf_len;;
            case SA_ENCRYPTION:
                // Ingest length + segment header (1) + spi_index (2) + shivf_len (varies) + shsnf_len (varies) \
                //   + shplf_len + arc_len + pad_size
                *p_enc_frame_len = in_frame_length + 1 + 2 + sa_ptr->shivf_len + sa_ptr->shsnf_len + \
                sa_ptr->shplf_len + sa_ptr->arc_len + TC_PAD_SIZE;
            case SA_AUTHENTICATED_ENCRYPTION:
                // Ingest length + segment header (1) + spi_index (2) + shivf_len (varies) + shsnf_len (varies) \
                //   + shplf_len + arc_len + pad_size + stmacf_len
                *p_enc_frame_len = in_frame_length + 1 + 2 + sa_ptr->shivf_len + sa_ptr->shsnf_len + \
                sa_ptr->shplf_len + sa_ptr->arc_len + TC_PAD_SIZE + sa_ptr->stmacf_len;
        }

        #ifdef TC_DEBUG
            OS_printf(KYEL "DEBUG - Total TC Buffer to be malloced is: %d bytes\n" RESET, *p_enc_frame_len);
            OS_printf(KYEL "\tlen of TF\t = %d\n" RESET, in_frame_length);
            OS_printf(KYEL "\tsegment hdr\t = 1\n" RESET); // TODO: Determine presence of this so not hard-coded
            OS_printf(KYEL "\tspi len\t\t = 2\n" RESET);
            OS_printf(KYEL "\tshivf_len\t = %d\n" RESET, sa_ptr->shivf_len);
            OS_printf(KYEL "\tshsnf_len\t = %d\n" RESET, sa_ptr->shsnf_len);
            OS_printf(KYEL "\tshplf len\t = %d\n" RESET, sa_ptr->shplf_len);
            OS_printf(KYEL "\tarc_len\t\t = %d\n" RESET, sa_ptr->arc_len);
            OS_printf(KYEL "\tpad_size\t = %d\n" RESET, TC_PAD_SIZE);
            OS_printf(KYEL "\tstmacf_len\t = %d\n" RESET, sa_ptr->stmacf_len);
        #endif

        // Accio buffer
        p_new_enc_frame = (uint8 *)malloc(*p_enc_frame_len * sizeof (unsigned char));
        if(!p_new_enc_frame)
        {
            OS_printf(KRED "Error: Malloc for encrypted output buffer failed! \n" RESET);
            status = OS_ERROR;
            return status;
        }
        CFE_PSP_MemSet(p_new_enc_frame, 0, *p_enc_frame_len);

        // Copy original TF header
        CFE_PSP_MemCpy(p_new_enc_frame, p_in_frame, TC_FRAME_PRIMARYHEADER_SIZE);

        // Set new TF Header length
        // Recall: Length field is one minus total length per spec
        *(p_new_enc_frame+2) = ((*(p_new_enc_frame+2) & 0xFC) | (((*p_enc_frame_len - 1) & (0x0300)) >> 8));
        *(p_new_enc_frame+3) = ((*p_enc_frame_len - 1) & (0x00FF));

        #ifdef TC_DEBUG
            OS_printf(KYEL "Printing updated TF Header:\n\t");
            for (int i=0; i<TC_FRAME_PRIMARYHEADER_SIZE; i++)
            {
                OS_printf("%02X", *(p_new_enc_frame+i));
            }
            // Recall: The buffer length is 1 greater than the field value set in the TCTF
            OS_printf("\n\tLength set to 0x%02X\n" RESET, *p_enc_frame_len-1);
        #endif

        /*
        ** Start variable length fields
        */
        uint16_t index = TC_FRAME_PRIMARYHEADER_SIZE;
        
        // Set Segment Header flags
        // TODO: Determine segment header exists
        *(p_new_enc_frame + index) = 0xFF;
        index++;

        /*
        ** Begin Security Header Fields
        ** Reference CCSDS SDLP 3550b1 4.1.1.1.3
        */
        // Set SPI
        *(p_new_enc_frame + index) = ((sa_ptr->spi & 0xFF00) >> 8);
        *(p_new_enc_frame + index + 1) = (sa_ptr->spi & 0x00FF);
        index += 2;

        // Set initialization vector if specified
        if ((sa_service_type == SA_AUTHENTICATION) || \
            (sa_service_type == SA_AUTHENTICATED_ENCRYPTION))
        {
            #ifdef SA_DEBUG
                OS_printf(KYEL "Old IV value was:\n\t");
                for(int i=0; i<sa_ptr->shivf_len; i++) {OS_printf("%02x", sa_ptr->iv[i]);}
                OS_printf("\n" RESET);
            #endif
            #ifdef INCREMENT
                Crypto_increment(sa_ptr->iv, sa_ptr->shivf_len);
            #endif
            #ifdef SA_DEBUG
                OS_printf(KYEL "New IV value is:\n\t");
                for(int i=0; i<sa_ptr->shivf_len; i++) {OS_printf("%02x", sa_ptr->iv[i]);}
                OS_printf("\n" RESET);
            #endif

            for (int i=0; i < sa_ptr->shivf_len; i++)
            {
                // TODO: Likely API call
                // Copy in IV from SA
                *(p_new_enc_frame + index) = sa_ptr->iv[i];
                index++;
            }
        }

        // Set anti-replay sequence number if specified
        /*
        ** See also: 4.1.1.4.2
        ** 4.1.1.4.4 If authentication or authenticated encryption is not selected 
        ** for an SA, the Sequence Number field shall be zero octets in length.
        ** Reference CCSDS 3550b1
        */
        // Determine if seq num field is needed
        // TODO: Likely SA API Call
        if (sa_ptr->shsnf_len > 0)
        {
            // If using anti-replay counter, increment it
            // TODO: API call instead?
            // TODO: Check return code
            Crypto_increment(sa_ptr->arc, sa_ptr->shsnf_len);
            for (int i=0; i < sa_ptr->shsnf_len; i++)
            {
                *(p_new_enc_frame + index) = sa_ptr->arc[i];
                index++;
            }
        }

        // Set security header padding if specified
        /*
        ** 4.2.3.4 h) if the algorithm and mode selected for the SA require the use of 
        ** fill padding, place the number of fill bytes used into the Pad Length field 
        ** of the Security Header - Reference CCSDS 3550b1
        */
        // TODO: Revisit this
        // TODO: Likely SA API Call
        for (int i=0; i < sa_ptr->shplf_len; i++)
        {
            /* 4.1.1.5.2 The Pad Length field shall contain the count of fill bytes used in the
            ** cryptographic process, consisting of an integral number of octets. - CCSDS 3550b1
            */
            // TODO: Set this depending on crypto cipher used
            *(p_new_enc_frame + index) = 0x00;
            index++;
        }

        /*
        ** End Security Header Fields
        */

        // Copy in original TF data - except FECF
        // Will be over-written if using encryption later
        // TODO: This will change depending on how we handle segment header and FECF above, 
        // and if it was present in the original TCTF
        //if FECF
        tf_payload_len = in_frame_length - TC_FRAME_PRIMARYHEADER_SIZE - FECF_SIZE;
        //if no FECF
        //tf_payload_len = in_frame_length - TC_FRAME_PRIMARYHEADER_SIZE;
        CFE_PSP_MemCpy((p_new_enc_frame+index), (p_in_frame+TC_FRAME_PRIMARYHEADER_SIZE), tf_payload_len);
        //index += tf_payload_len;

        /*
        ** Begin Security Trailer Fields
        */

        // Set MAC Field if present
        /*
        ** May be present and unused if switching between clear and authenticated
        ** CCSDS 3550b1 4.1.2.3
        */
        // By leaving MAC as zeros, can use index for encryption output
        // for (int i=0; i < temp_SA.stmacf_len; i++)
        // {
        //     // Temp fill MAC
        //     *(p_new_enc_frame + index) = 0x00;
        //     index++;
        // }

        /*
        ** End Security Trailer Fields
        */

        /* 
        ** Begin Authentication / Encryption
        */

        if (sa_service_type != SA_PLAINTEXT)
        {
            gcry_error = gcry_cipher_open(
                &(tmp_hd), 
                GCRY_CIPHER_AES256, 
                GCRY_CIPHER_MODE_GCM, 
                GCRY_CIPHER_CBC_MAC
                );
            if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                OS_printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                status = OS_ERROR;
                return status;
            }
            gcry_error = gcry_cipher_setkey(
                tmp_hd, 
                &(ek_ring[sa_ptr->ekid].value[0]),
                KEY_SIZE //TODO:  look into this
            );
            if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                OS_printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                status = OS_ERROR;
                return status;
            }
            gcry_error = gcry_cipher_setiv(
                tmp_hd, 
                &(sa_ptr->iv[0]),
                sa_ptr->iv_len
            );
            if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                OS_printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                status = OS_ERROR;
                return status;
            }

            // Prepare additional authenticated data, if needed
            if ((sa_service_type == SA_AUTHENTICATION) || \
                (sa_service_type == SA_AUTHENTICATED_ENCRYPTION))
            {
                for (int y = 0; y < sa_ptr->abm_len; y++)
                {
                    aad[y] = p_in_frame[y] & sa_ptr->abm[y];
                }
                #ifdef MAC_DEBUG 
                    OS_printf(KYEL "Preparing AAD:\n");
                    OS_printf("\tUsing ABM Length of %d\n\t", sa_ptr->abm_len);
                    for (int y = 0; y < sa_ptr->abm_len; y++)
                    {
                        OS_printf("%02x", aad[y]);
                    }
                    OS_printf("\n" RESET);
                #endif

                gcry_error = gcry_cipher_authenticate(
                    tmp_hd,
                    &(aad[0]),                                      // additional authenticated data
                    sa_ptr->abm_len 		                        // length of AAD
                );
                if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                {
                    OS_printf(KRED "ERROR: gcry_cipher_authenticate error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                    OS_printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error),gcry_strerror (gcry_error));
                    status = OS_ERROR;
                    return status;
                }
            }

            if ((sa_service_type == SA_ENCRYPTION) || \
                (sa_service_type == SA_AUTHENTICATED_ENCRYPTION))
            {
                // TODO: More robust calculation of this location
                // uint16 output_loc = TC_FRAME_PRIMARYHEADER_SIZE + 1 + 2 + temp_SA.shivf_len + temp_SA.shsnf_len + temp_SA.shplf_len;
                #ifdef TC_DEBUG
                    OS_printf("Encrypted bytes output_loc is %d\n", index);
                    OS_printf("tf_payload_len is %d\n", tf_payload_len);
                    OS_printf(KYEL "Printing TC Frame prior to encryption:\n\t");
                    for(int i=0; i < *p_enc_frame_len; i++)
                    {
                        OS_printf("%02X", *(p_new_enc_frame + i));
                    }
                    OS_printf("\n");
                #endif

                gcry_error = gcry_cipher_encrypt(
                    tmp_hd,
                    &p_new_enc_frame[index],                              // ciphertext output
                    tf_payload_len,		 		                    // length of data
                    (p_in_frame + TC_FRAME_PRIMARYHEADER_SIZE),       // plaintext input TODO: Determine if Segment header exists, assuming yes (+1) for now
                    tf_payload_len                                  // in data length
                );
                if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                {
                    OS_printf(KRED "ERROR: gcry_cipher_encrypt error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                    status = OS_ERROR;
                    return status;
                }
            }

            if ((sa_service_type == SA_AUTHENTICATION) || \
                (sa_service_type == SA_AUTHENTICATED_ENCRYPTION))
            {
                // TODO - Know if FECF exists
                mac_loc = *p_enc_frame_len - sa_ptr->stmacf_len - FECF_SIZE;
                #ifdef MAC_DEBUG
                    OS_printf(KYEL "MAC location is: %d\n" RESET, mac_loc);
                    OS_printf(KYEL "MAC size is: %d\n" RESET, MAC_SIZE);
                #endif
                gcry_error = gcry_cipher_gettag(
                    tmp_hd,
                    &p_new_enc_frame[mac_loc],                             // tag output
                    MAC_SIZE                                         // tag size
                );
                if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                {
                    OS_printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                    status = OS_ERROR;
                    return status;
                }
            }
            // Zeroise any sensitive information
            if (sa_service_type != SA_PLAINTEXT)
            {
                gcry_cipher_close(tmp_hd);
            }
        }
        /*
        ** End Authentication / Encryption
        */

        // Set FECF Field if present
        // TODO: Determine is FECF is even present
        // on this particular channel
        // Calc new fecf, don't include old fecf in length
        #ifdef FECF_DEBUG
            OS_printf(KCYN "Calcing FECF over %d bytes\n" RESET, *p_enc_frame_len - 2);
        #endif
        new_fecf = Crypto_Calc_FECF(p_new_enc_frame, *p_enc_frame_len - 2);
        *(p_new_enc_frame + *p_enc_frame_len - 2) = (uint8) ((new_fecf & 0xFF00) >> 8);
        *(p_new_enc_frame + *p_enc_frame_len - 1) = (uint8) (new_fecf & 0x00FF);
        index += 2;

        #ifdef TC_DEBUG
            OS_printf(KYEL "Printing new TC Frame:\n\t");
            for(int i=0; i < *p_enc_frame_len; i++)
            {
                OS_printf("%02X", *(p_new_enc_frame + i));
            }
            OS_printf("\n\tThe returned length is: %d\n" RESET, *p_enc_frame_len);
        #endif

        *pp_in_frame = p_new_enc_frame;
    }

    status = sadb_routine->sadb_save_sa(sa_ptr);

    #ifdef DEBUG
        OS_printf(KYEL "----- Crypto_TC_ApplySecurity END -----\n" RESET);
    #endif

    return status;
}

int32 Crypto_TC_ProcessSecurity( char* ingest, int* len_ingest,TC_t* tc_sdls_processed_frame)
// Loads the ingest frame into the global tc_frame while performing decryption
{
    // Local Variables
    int32 status = OS_SUCCESS;
    int x = 0;
    int y = 0;
    gcry_cipher_hd_t tmp_hd;
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    SecurityAssociation_t* sa_ptr = NULL;

    #ifdef DEBUG
        OS_printf(KYEL "\n----- Crypto_TC_ProcessSecurity START -----\n" RESET);
    #endif

    int byte_idx = 0;
    // Primary Header
    tc_sdls_processed_frame->tc_header.tfvn   = ((uint8)ingest[byte_idx] & 0xC0) >> 6;
    tc_sdls_processed_frame->tc_header.bypass = ((uint8)ingest[byte_idx] & 0x20) >> 5;
    tc_sdls_processed_frame->tc_header.cc     = ((uint8)ingest[byte_idx] & 0x10) >> 4;
    tc_sdls_processed_frame->tc_header.spare  = ((uint8)ingest[byte_idx] & 0x0C) >> 2;
    tc_sdls_processed_frame->tc_header.scid   = ((uint8)ingest[byte_idx] & 0x03) << 8;
    byte_idx++;
    tc_sdls_processed_frame->tc_header.scid   = tc_sdls_processed_frame->tc_header.scid | (uint8)ingest[byte_idx];
    byte_idx++;
    tc_sdls_processed_frame->tc_header.vcid   = (((uint8)ingest[byte_idx] & 0xFC) >> 2) & VCID_BITMASK;
    tc_sdls_processed_frame->tc_header.fl     = ((uint8)ingest[byte_idx] & 0x03) << 8;
    byte_idx++;
    tc_sdls_processed_frame->tc_header.fl     = tc_sdls_processed_frame->tc_header.fl | (uint8)ingest[byte_idx];
    byte_idx++;
    tc_sdls_processed_frame->tc_header.fsn	  = (uint8)ingest[byte_idx];
    byte_idx++;

    // Security Header
    if(SEGMENTATION_HDR){
        tc_sdls_processed_frame->tc_sec_header.sh  = (uint8)ingest[byte_idx];
        byte_idx++;
    }
    tc_sdls_processed_frame->tc_sec_header.spi = ((uint8)ingest[byte_idx] << 8) | (uint8)ingest[byte_idx+1];
    byte_idx+=2;
    #ifdef TC_DEBUG
        OS_printf("vcid = %d \n", tc_sdls_processed_frame->tc_header.vcid );
        OS_printf("spi  = %d \n", tc_sdls_processed_frame->tc_sec_header.spi);
    #endif

    // Checks
    if (PUS_HDR && ((uint8)ingest[18] == 0x0B) && ((uint8)ingest[19] == 0x00) && (((uint8)ingest[20] & 0xF0) == 0x40))
    {   
        // User packet check only used for ESA Testing!
    }
    else
    {   // Update last spi used
        report.lspiu = tc_sdls_processed_frame->tc_sec_header.spi;

        // Verify 
        if (tc_sdls_processed_frame->tc_header.scid != (SCID & 0x3FF))
        {
            OS_printf(KRED "Error: SCID incorrect! \n" RESET);
            status = OS_ERROR;
        }
        else
        {   
            switch (report.lspiu)
            {	// Invalid SPIs fall through to trigger flag in FSR
                case 0x0000:
                case 0xFFFF:
                    status = OS_ERROR;
                    report.ispif = 1;
                    OS_printf(KRED "Error: SPI invalid! \n" RESET);
                    break;
                default:
                    break;
            }
        }


        if ((report.lspiu > NUM_SA) && (status == OS_SUCCESS))
        {
            report.ispif = 1;
            OS_printf(KRED "Error: SPI value greater than NUM_SA! \n" RESET);
            status = OS_ERROR;
        }
        if (status == OS_SUCCESS)
        {
            if(sadb_routine->sadb_get_sa_from_spi(report.lspiu,&sa_ptr) != OS_SUCCESS){
                //TODO - Error handling
                status = OS_ERROR; //Error -- unable to get SA from SPI.
            }
        }
        if (status == OS_SUCCESS)
        {
            if (sa_ptr->gvcid_tc_blk.mapid != TYPE_TC)
            {	
                OS_printf(KRED "Error: SA invalid type! \n" RESET);
                status = OS_ERROR;
            }
        }
        // TODO: I don't think this is needed.
        //if (status == OS_SUCCESS)
        //{
        //    if (sa_ptr->gvcid_tc_blk.vcid != tc_sdls_processed_frame->tc_header.vcid)
        //    {	
        //        OS_printf(KRED "Error: VCID not mapped to provided SPI! \n" RESET);
        //        status = OS_ERROR;
        //    }
        //}
        if (status == OS_SUCCESS)
        {
            if (sa_ptr->sa_state != SA_OPERATIONAL)
            {
                OS_printf(KRED "Error: SA state not operational! \n" RESET);
                status = OS_ERROR;
            }
        }
        if (status != OS_SUCCESS)
        {
            report.af = 1;
            if (log_summary.rs > 0)
            {
                Crypto_increment((uint8*)&log_summary.num_se, 4);
                log_summary.rs--;
                log.blk[log_count].emt = SPI_INVALID_EID;
                log.blk[log_count].emv[0] = 0x4E;
                log.blk[log_count].emv[1] = 0x41;
                log.blk[log_count].emv[2] = 0x53;
                log.blk[log_count].emv[3] = 0x41;
                log.blk[log_count++].em_len = 4;
            }
            *len_ingest = 0;
            return status;
        }
    }
    if(sadb_routine->sadb_get_sa_from_spi(tc_sdls_processed_frame->tc_sec_header.spi,&sa_ptr) != OS_SUCCESS){
        //TODO - Error handling
        status = OS_ERROR; //Error -- unable to get SA from SPI.
        return status;
    }
    // Determine mode via SPI
    if ((sa_ptr->est == 1) &&
        (sa_ptr->ast == 1))
    {	// Authenticated Encryption
        #ifdef DEBUG
            OS_printf(KBLU "ENCRYPTED TC Received!\n" RESET);
        #endif
        #ifdef TC_DEBUG
            OS_printf("IV: \n");
        #endif
        for (x = byte_idx; x < (byte_idx + IV_SIZE); x++)
        {
            tc_sdls_processed_frame->tc_sec_header.iv[x-byte_idx] = (uint8)ingest[x];
            #ifdef TC_DEBUG
                OS_printf("\t iv[%d] = 0x%02x\n", x-byte_idx, tc_sdls_processed_frame->tc_sec_header.iv[x-byte_idx]);
            #endif
        }
        byte_idx += IV_SIZE;
        report.snval = tc_sdls_processed_frame->tc_sec_header.iv[IV_SIZE-1];

        #ifdef DEBUG
            OS_printf("\t tc_sec_header.iv[%d] = 0x%02x \n", IV_SIZE-1, tc_sdls_processed_frame->tc_sec_header.iv[IV_SIZE-1]);
            OS_printf("\t sa[%d].iv[%d] = 0x%02x \n", tc_sdls_processed_frame->tc_sec_header.spi, IV_SIZE-1, sa_ptr->iv[IV_SIZE-1]);
        #endif

        // Check IV is in ARCW
        if ( Crypto_window(tc_sdls_processed_frame->tc_sec_header.iv, sa_ptr->iv, IV_SIZE,
            sa_ptr->arcw[sa_ptr->arcw_len-1]) != OS_SUCCESS )
        {
            report.af = 1;
            report.bsnf = 1;
            if (log_summary.rs > 0)
            {
                Crypto_increment((uint8*)&log_summary.num_se, 4);
                log_summary.rs--;
                log.blk[log_count].emt = IV_WINDOW_ERR_EID;
                log.blk[log_count].emv[0] = 0x4E;
                log.blk[log_count].emv[1] = 0x41;
                log.blk[log_count].emv[2] = 0x53;
                log.blk[log_count].emv[3] = 0x41;
                log.blk[log_count++].em_len = 4;
            }
            OS_printf(KRED "Error: IV not in window! \n" RESET);
            #ifdef OCF_DEBUG
                Crypto_fsrPrint(&report);
            #endif
            status = OS_ERROR;
        }
        else 
        {
            if ( Crypto_compare_less_equal(tc_sdls_processed_frame->tc_sec_header.iv, sa_ptr->iv, IV_SIZE) == OS_SUCCESS )
            {   // Replay - IV value lower than expected
                report.af = 1;
                report.bsnf = 1;
                if (log_summary.rs > 0)
                {
                    Crypto_increment((uint8*)&log_summary.num_se, 4);
                    log_summary.rs--;
                    log.blk[log_count].emt = IV_REPLAY_ERR_EID;
                    log.blk[log_count].emv[0] = 0x4E;
                    log.blk[log_count].emv[1] = 0x41;
                    log.blk[log_count].emv[2] = 0x53;
                    log.blk[log_count].emv[3] = 0x41;
                    log.blk[log_count++].em_len = 4;
                }
                OS_printf(KRED "Error: IV replay! Value lower than expected! \n" RESET);
                #ifdef OCF_DEBUG
                    Crypto_fsrPrint(&report);
                #endif
                status = OS_ERROR;
            } 
            else
            {   // Adjust expected IV to acceptable received value
                for (int i = 0; i < (IV_SIZE); i++)
                {
                    sa_ptr->iv[i] = tc_sdls_processed_frame->tc_sec_header.iv[i];
                }
            }
        }
        
        if ( status == OS_ERROR )
        {   // Exit
            *len_ingest = 0;
            return status;
        }

        tc_sdls_processed_frame->tc_pdu_len = Crypto_Get_tcPayloadLength(tc_sdls_processed_frame);

        x = x + tc_sdls_processed_frame->tc_pdu_len;

        #ifdef TC_DEBUG
            OS_printf("TC: \n"); 
            for (int temp = 0; temp < tc_sdls_processed_frame->tc_pdu_len; temp++)
            {	
                OS_printf("\t ingest[%d] = 0x%02x \n", temp, (uint8)ingest[temp+20]);
            }
        #endif

        // Security Trailer
        #ifdef TC_DEBUG
            OS_printf("MAC: \n");
        #endif
        for (y = x; y < (x + MAC_SIZE); y++)
        {
            tc_sdls_processed_frame->tc_sec_trailer.mac[y-x]  = (uint8)ingest[y];
            #ifdef TC_DEBUG
                OS_printf("\t mac[%d] = 0x%02x\n", y-x, tc_sdls_processed_frame->tc_sec_trailer.mac[y-x]);
            #endif
        }
        x = x + MAC_SIZE;

        // FECF
        tc_sdls_processed_frame->tc_sec_trailer.fecf = ((uint8)ingest[x] << 8) | ((uint8)ingest[x+1]);
        Crypto_FECF(tc_sdls_processed_frame->tc_sec_trailer.fecf, ingest, (tc_sdls_processed_frame->tc_header.fl - 2),tc_sdls_processed_frame);

        // Initialize the key
        //itc_gcm128_init(&sa[tc_sdls_processed_frame->tc_sec_header.spi].gcm_ctx, (const unsigned char*) &ek_ring[sa[sa_ptr->ekid]);

        gcry_error = gcry_cipher_open(
            &(tmp_hd),
            GCRY_CIPHER_AES256, 
            GCRY_CIPHER_MODE_GCM, 
            GCRY_CIPHER_CBC_MAC
        );
        if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            OS_printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
            status = OS_ERROR;
            return status;
        }
        #ifdef DEBUG
            OS_printf("Key ID = %d, 0x", sa_ptr->ekid);
            for(int y = 0; y < KEY_SIZE; y++)
            {
                OS_printf("%02x", ek_ring[sa_ptr->ekid].value[y]);
            }
            OS_printf("\n");
        #endif
        gcry_error = gcry_cipher_setkey(
            tmp_hd,
            &(ek_ring[sa_ptr->ekid].value[0]),
            KEY_SIZE
        );
        if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            OS_printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
            status = OS_ERROR;
            return status;
        }
        gcry_error = gcry_cipher_setiv(
            tmp_hd,
            &(sa_ptr->iv[0]),
            sa_ptr->iv_len
        );
        if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            OS_printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
            status = OS_ERROR;
            return status;
        }
        #ifdef MAC_DEBUG
            OS_printf("AAD = 0x");
        #endif
        // Prepare additional authenticated data (AAD)
        for (y = 0; y < sa_ptr->abm_len; y++)
        {
            ingest[y] = (uint8) ((uint8)ingest[y] & (uint8)sa_ptr->abm[y]);
            #ifdef MAC_DEBUG
                OS_printf("%02x", (uint8) ingest[y]);
            #endif
        }
        #ifdef MAC_DEBUG
            OS_printf("\n");
        #endif

        gcry_error = gcry_cipher_decrypt(
            tmp_hd, 
            &(tc_sdls_processed_frame->tc_pdu[0]),                          // plaintext output
            tc_sdls_processed_frame->tc_pdu_len,			 		// length of data
            &(ingest[20]),                                  // ciphertext input
            tc_sdls_processed_frame->tc_pdu_len                    // in data length
        );
        if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            OS_printf(KRED "ERROR: gcry_cipher_decrypt error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
            status = OS_ERROR;
            return status;
        }
        gcry_error = gcry_cipher_checktag(
            tmp_hd, 
            &(tc_sdls_processed_frame->tc_sec_trailer.mac[0]),              // tag input
            MAC_SIZE                                        // tag size
        );
        if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            OS_printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
            
            OS_printf("Actual MAC   = 0x");
            for (int z = 0; z < MAC_SIZE; z++)
            {
                OS_printf("%02x",tc_sdls_processed_frame->tc_sec_trailer.mac[z]);
            }
            OS_printf("\n");
            
            gcry_error = gcry_cipher_gettag(
                tmp_hd,
                &(tc_sdls_processed_frame->tc_sec_trailer.mac[0]),          // tag output
                MAC_SIZE                                    // tag size
            );
            if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                OS_printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
            }

            OS_printf("Expected MAC = 0x");
            for (int z = 0; z < MAC_SIZE; z++)
            {
                OS_printf("%02x",tc_sdls_processed_frame->tc_sec_trailer.mac[z]);
            }
            OS_printf("\n");
            status = OS_ERROR;
            report.bmacf = 1;
            #ifdef OCF_DEBUG
                Crypto_fsrPrint(&report);
            #endif
            return status;
        }
        gcry_cipher_close(tmp_hd);
        
        // Increment the IV for next time
        #ifdef INCREMENT
            Crypto_increment(sa_ptr->iv, IV_SIZE);
        #endif
    }
    else
    {	// Clear
        #ifdef DEBUG
            OS_printf(KBLU "CLEAR TC Received!\n" RESET);
        #endif

        for (y = 10; y <= (tc_sdls_processed_frame->tc_header.fl - 2); y++) //tfhdr+seghdr+sechdr=5+1+6=12
        {	
            tc_sdls_processed_frame->tc_pdu[y - 10] = (uint8)ingest[y];
        }
        // FECF
        tc_sdls_processed_frame->tc_sec_trailer.fecf = ((uint8)ingest[y] << 8) | ((uint8)ingest[y+1]);
        Crypto_FECF((int) tc_sdls_processed_frame->tc_sec_trailer.fecf, ingest, (tc_sdls_processed_frame->tc_header.fl - 2),tc_sdls_processed_frame);
    }
    
    #ifdef TC_DEBUG
        Crypto_tcPrint(tc_sdls_processed_frame);
    #endif

    // Zero ingest
    for (x = 0; x < *len_ingest; x++)
    {
        ingest[x] = 0;
    }


    if(!TC_PROCESS_SDLS_PDUS) //If we don't want to process frame data for SDLS PDUs, only reverse security & return content.
    {
        // CCSDS Pass-through
        #ifdef DEBUG
        OS_printf(KGRN "CCSDS Pass-through \n" RESET);
        #endif
        if (PUS_HDR) {
            for (x = 0; x < (tc_sdls_processed_frame->tc_header.fl - 11); x++) {
                ingest[x] = tc_sdls_processed_frame->tc_pdu[x];
                #ifdef CCSDS_DEBUG
                OS_printf("tc_sdls_processed_frame->tc_pdu[%d] = 0x%02x\n", x, tc_sdls_processed_frame->tc_pdu[x]);
                #endif
                *len_ingest = x;
            }
        } else {
            for (x = 0; x < (tc_sdls_processed_frame->tc_header.fl); x++) { //with no PUS header, entire PDU is data
                ingest[x] = tc_sdls_processed_frame->tc_pdu[x];
                #ifdef CCSDS_DEBUG
                OS_printf("tc_sdls_processed_frame->tc_pdu[%d] = 0x%02x\n", x, tc_sdls_processed_frame->tc_pdu[x]);
                #endif
                *len_ingest = x;
            }
        }
    }
    else //Process SDLS PDU
    {
        if (PUS_HDR)
        {
            if ((tc_sdls_processed_frame->tc_pdu[0] == 0x18) && (tc_sdls_processed_frame->tc_pdu[1] == 0x80))
            // Crypto Lib Application ID
            {
                #ifdef DEBUG
                OS_printf(KGRN "Received SDLS command: " RESET);
                #endif
                // CCSDS Header
                sdls_frame.hdr.pvn = (tc_sdls_processed_frame->tc_pdu[0] & 0xE0) >> 5;
                sdls_frame.hdr.type = (tc_sdls_processed_frame->tc_pdu[0] & 0x10) >> 4;
                sdls_frame.hdr.shdr = (tc_sdls_processed_frame->tc_pdu[0] & 0x08) >> 3;
                sdls_frame.hdr.appID =
                        ((tc_sdls_processed_frame->tc_pdu[0] & 0x07) << 8) | tc_sdls_processed_frame->tc_pdu[1];
                sdls_frame.hdr.seq = (tc_sdls_processed_frame->tc_pdu[2] & 0xC0) >> 6;
                sdls_frame.hdr.pktid =
                        ((tc_sdls_processed_frame->tc_pdu[2] & 0x3F) << 8) | tc_sdls_processed_frame->tc_pdu[3];
                sdls_frame.hdr.pkt_length = (tc_sdls_processed_frame->tc_pdu[4] << 8) | tc_sdls_processed_frame->tc_pdu[5];

                // CCSDS PUS
                sdls_frame.pus.shf = (tc_sdls_processed_frame->tc_pdu[6] & 0x80) >> 7;
                sdls_frame.pus.pusv = (tc_sdls_processed_frame->tc_pdu[6] & 0x70) >> 4;
                sdls_frame.pus.ack = (tc_sdls_processed_frame->tc_pdu[6] & 0x0F);
                sdls_frame.pus.st = tc_sdls_processed_frame->tc_pdu[7];
                sdls_frame.pus.sst = tc_sdls_processed_frame->tc_pdu[8];
                sdls_frame.pus.sid = (tc_sdls_processed_frame->tc_pdu[9] & 0xF0) >> 4;
                sdls_frame.pus.spare = (tc_sdls_processed_frame->tc_pdu[9] & 0x0F);

                // SDLS TLV PDU
                sdls_frame.pdu.type = (tc_sdls_processed_frame->tc_pdu[10] & 0x80) >> 7;
                sdls_frame.pdu.uf = (tc_sdls_processed_frame->tc_pdu[10] & 0x40) >> 6;
                sdls_frame.pdu.sg = (tc_sdls_processed_frame->tc_pdu[10] & 0x30) >> 4;
                sdls_frame.pdu.pid = (tc_sdls_processed_frame->tc_pdu[10] & 0x0F);
                sdls_frame.pdu.pdu_len = (tc_sdls_processed_frame->tc_pdu[11] << 8) | tc_sdls_processed_frame->tc_pdu[12];
                for (x = 13; x < (13 + sdls_frame.hdr.pkt_length); x++) {
                    sdls_frame.pdu.data[x - 13] = tc_sdls_processed_frame->tc_pdu[x];
                }

                #ifdef CCSDS_DEBUG
                Crypto_ccsdsPrint(&sdls_frame);
                #endif

                // Determine type of PDU
                *len_ingest = Crypto_PDU(ingest, tc_sdls_processed_frame);
            }
        }
        else if (tc_sdls_processed_frame->tc_header.vcid == TC_SDLS_EP_VCID) //TC SDLS PDU with no packet layer
        {
            #ifdef DEBUG
            OS_printf(KGRN "Received SDLS command: " RESET);
            #endif
            // No Packet HDR or PUS in these frames
            // SDLS TLV PDU
            sdls_frame.pdu.type = (tc_sdls_processed_frame->tc_pdu[0] & 0x80) >> 7;
            sdls_frame.pdu.uf = (tc_sdls_processed_frame->tc_pdu[0] & 0x40) >> 6;
            sdls_frame.pdu.sg = (tc_sdls_processed_frame->tc_pdu[0] & 0x30) >> 4;
            sdls_frame.pdu.pid = (tc_sdls_processed_frame->tc_pdu[0] & 0x0F);
            sdls_frame.pdu.pdu_len = (tc_sdls_processed_frame->tc_pdu[1] << 8) | tc_sdls_processed_frame->tc_pdu[2];
            for (x = 3; x < (3 + tc_sdls_processed_frame->tc_header.fl); x++) {
                //Todo - Consider how this behaves with large OTAR PDUs that are larger than 1 TC in size. Most likely fails. Must consider Uplink Sessions (sequence numbers).
                sdls_frame.pdu.data[x - 3] = tc_sdls_processed_frame->tc_pdu[x];
            }

            #ifdef CCSDS_DEBUG
            Crypto_ccsdsPrint(&sdls_frame);
            #endif

            // Determine type of PDU
            *len_ingest = Crypto_PDU(ingest, tc_sdls_processed_frame);
        }
        else {
            //TODO - Process SDLS PDU with Packet Layer without PUS_HDR
        }
    }//End Process SDLS PDU

    #ifdef OCF_DEBUG
        Crypto_fsrPrint(&report);
    #endif
    
    #ifdef DEBUG
        OS_printf(KYEL "----- Crypto_TC_ProcessSecurity END -----\n" RESET);
    #endif

    return status;
}

int32 Crypto_TM_ApplySecurity( char* ingest, int* len_ingest)
// Accepts CCSDS message in ingest, and packs into TM before encryption
{
    int32 status = ITC_GCM128_SUCCESS;
    int count = 0;
    int pdu_loc = 0;
    int pdu_len = *len_ingest - TM_MIN_SIZE;
    int pad_len = 0;
    int mac_loc = 0;
    int fecf_loc = 0;
    uint8 tempTM[TM_SIZE];
    int x = 0;
    int y = 0;
    uint8 aad[20];
    uint16 spi = tm_frame.tm_sec_header.spi;
    uint16 spp_crc = 0x0000;
    SecurityAssociation_t* sa_ptr;
    SecurityAssociation_t sa;

    gcry_cipher_hd_t tmp_hd;
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    CFE_PSP_MemSet(&tempTM, 0, TM_SIZE);
    
    #ifdef DEBUG
        OS_printf(KYEL "\n----- Crypto_TM_ApplySecurity START -----\n" RESET);
    #endif

    // Check for idle frame trigger
    if (((uint8)ingest[0] == 0x08) && ((uint8)ingest[1] == 0x90))
    {   // Zero ingest
        for (x = 0; x < *len_ingest; x++)
        {
            ingest[x] = 0;
        }
        // Update TM First Header Pointer
        tm_frame.tm_header.fhp = 0xFE;
    }   
    else
    {   // Update the length of the ingest from the CCSDS header
        *len_ingest = (ingest[4] << 8) | ingest[5];
        ingest[5] = ingest[5] - 5;
        // Remove outgoing secondary space packet header flag
        ingest[0] = 0x00;
        // Change sequence flags to 0xFFFF
        ingest[2] = 0xFF;
        ingest[3] = 0xFF;
        // Add 2 bytes of CRC to space packet
        spp_crc = Crypto_Calc_CRC16((char*) ingest, *len_ingest);
        ingest[*len_ingest] = (spp_crc & 0xFF00) >> 8;
        ingest[*len_ingest+1] = (spp_crc & 0x00FF);
        *len_ingest = *len_ingest + 2;
        // Update TM First Header Pointer
        tm_frame.tm_header.fhp = tm_offset;
        #ifdef TM_DEBUG
            OS_printf("tm_offset = %d \n", tm_offset);
        #endif
    }             

    // Update Current Telemetry Frame in Memory
        // Counters
        tm_frame.tm_header.mcfc++;
        tm_frame.tm_header.vcfc++;
        // Operational Control Field 
        Crypto_TM_updateOCF();
        // Payload Data Unit
        Crypto_TM_updatePDU(ingest, *len_ingest);

        if(sadb_routine->sadb_get_sa_from_spi(spi,&sa_ptr) != OS_SUCCESS){
            //TODO - Error handling
            return OS_ERROR; //Error -- unable to get SA from SPI.
        }


    // Check test flags
        if (badSPI == 1)
        {
            tm_frame.tm_sec_header.spi++; 
        }
        if (badIV == 1)
        {
            sa_ptr->iv[IV_SIZE-1]++;
        }
        if (badMAC == 1)
        {
            tm_frame.tm_sec_trailer.mac[MAC_SIZE-1]++;
        }

    // Initialize the temporary TM frame
        // Header
        tempTM[count++] = (uint8) ((tm_frame.tm_header.tfvn << 6) | ((tm_frame.tm_header.scid & 0x3F0) >> 4));
        tempTM[count++] = (uint8) (((tm_frame.tm_header.scid & 0x00F) << 4) | (tm_frame.tm_header.vcid << 1) | (tm_frame.tm_header.ocff));
        tempTM[count++] = (uint8) (tm_frame.tm_header.mcfc);
        tempTM[count++] = (uint8) (tm_frame.tm_header.vcfc);
        tempTM[count++] = (uint8) ((tm_frame.tm_header.tfsh << 7) | (tm_frame.tm_header.sf << 6) | (tm_frame.tm_header.pof << 5) | (tm_frame.tm_header.slid << 3) | ((tm_frame.tm_header.fhp & 0x700) >> 8));
        tempTM[count++] = (uint8) (tm_frame.tm_header.fhp & 0x0FF);
        //	tempTM[count++] = (uint8) ((tm_frame.tm_header.tfshvn << 6) | tm_frame.tm_header.tfshlen);
        // Security Header
        tempTM[count++] = (uint8) ((spi & 0xFF00) >> 8);
        tempTM[count++] = (uint8) ((spi & 0x00FF));
        CFE_PSP_MemCpy(tm_frame.tm_sec_header.iv, sa_ptr->iv, IV_SIZE);

        // Padding Length
            pad_len = Crypto_Get_tmLength(*len_ingest) - TM_MIN_SIZE + IV_SIZE + TM_PAD_SIZE - *len_ingest;
        
        // Only add IV for authenticated encryption 
        if ((sa_ptr->est == 1) &&
            (sa_ptr->ast == 1))
        {	// Initialization Vector
            #ifdef INCREMENT
                Crypto_increment(sa_ptr->iv, IV_SIZE);
            #endif
            if ((sa_ptr->est == 1) || (sa_ptr->ast == 1))
            {	for (x = 0; x < IV_SIZE; x++)
                {
                    tempTM[count++] = sa_ptr->iv[x];
                }
            }
            pdu_loc = count;
            pad_len = pad_len - IV_SIZE - TM_PAD_SIZE + OCF_SIZE;
            pdu_len = *len_ingest + pad_len;
        }
        else	
        {	// Include padding length bytes - hard coded per ESA testing
            tempTM[count++] = 0x00;  // pad_len >> 8; 
            tempTM[count++] = 0x1A;  // pad_len
            pdu_loc = count;
            pdu_len = *len_ingest + pad_len;
        }
        
        // Payload Data Unit
        for (x = 0; x < (pdu_len); x++)	
        {
            tempTM[count++] = (uint8) tm_frame.tm_pdu[x];
        }
        // Message Authentication Code
        mac_loc = count;
        for (x = 0; x < MAC_SIZE; x++)
        {
            tempTM[count++] = 0x00;
        }
        // Operational Control Field
        for (x = 0; x < OCF_SIZE; x++)
        {
            tempTM[count++] = (uint8) tm_frame.tm_sec_trailer.ocf[x];
        }
        // Frame Error Control Field
        fecf_loc = count;
        tm_frame.tm_sec_trailer.fecf = Crypto_Calc_FECF((char*) tempTM, count);	
        tempTM[count++] = (uint8) ((tm_frame.tm_sec_trailer.fecf & 0xFF00) >> 8);
        tempTM[count++] = (uint8) (tm_frame.tm_sec_trailer.fecf & 0x00FF);

    // Determine Mode
        // Clear
        if ((sa_ptr->est == 0) &&
            (sa_ptr->ast == 0))
        {
            #ifdef DEBUG
                OS_printf(KBLU "Creating a TM - CLEAR! \n" RESET);
            #endif
            // Copy temporary frame to ingest
            CFE_PSP_MemCpy(ingest, tempTM, count);
        }
        // Authenticated Encryption
        else if ((sa_ptr->est == 1) &&
                 (sa_ptr->ast == 1))
        {
            #ifdef DEBUG
                OS_printf(KBLU "Creating a TM - AUTHENTICATED ENCRYPTION! \n" RESET);
            #endif

            // Copy TM to ingest
            CFE_PSP_MemCpy(ingest, tempTM, pdu_loc);
            
            #ifdef MAC_DEBUG
                OS_printf("AAD = 0x");
            #endif
            // Prepare additional authenticated data
            for (y = 0; y < sa_ptr->abm_len; y++)
            {
                aad[y] = ingest[y] & sa_ptr->abm[y];
                #ifdef MAC_DEBUG
                    OS_printf("%02x", aad[y]);
                #endif
            }
            #ifdef MAC_DEBUG
                OS_printf("\n");
            #endif

            gcry_error = gcry_cipher_open(
                &(tmp_hd), 
                GCRY_CIPHER_AES256, 
                GCRY_CIPHER_MODE_GCM, 
                GCRY_CIPHER_CBC_MAC
            );
            if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                OS_printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                status = OS_ERROR;
                return status;
            }
            gcry_error = gcry_cipher_setkey(
                tmp_hd, 
                &(ek_ring[sa_ptr->ekid].value[0]),
                KEY_SIZE
            );
            if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                OS_printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                status = OS_ERROR;
                return status;
            }
            gcry_error = gcry_cipher_setiv(
                tmp_hd, 
                &(sa_ptr->iv[0]),
                sa_ptr->iv_len
            );
            if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                OS_printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                status = OS_ERROR;
                return status;
            }
            gcry_error = gcry_cipher_encrypt(
                tmp_hd,
                &(ingest[pdu_loc]),                             // ciphertext output
                pdu_len,			 		                    // length of data
                &(tempTM[pdu_loc]),                             // plaintext input
                pdu_len                                         // in data length
            );
            if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                OS_printf(KRED "ERROR: gcry_cipher_decrypt error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                status = OS_ERROR;
                return status;
            }
            gcry_error = gcry_cipher_authenticate(
                tmp_hd,
                &(aad[0]),                                      // additional authenticated data
                sa_ptr->abm_len       		                        // length of AAD
            );
            if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                OS_printf(KRED "ERROR: gcry_cipher_authenticate error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                status = OS_ERROR;
                return status;
            }
            gcry_error = gcry_cipher_gettag(
                tmp_hd,
                &(ingest[mac_loc]),                             // tag output
                MAC_SIZE                                        // tag size
            );
            if((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                OS_printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET,gcry_error & GPG_ERR_CODE_MASK);
                status = OS_ERROR;
                return status;
            }

            #ifdef MAC_DEBUG
                OS_printf("MAC = 0x");
                for(x = 0; x < MAC_SIZE; x++)
                {
                    OS_printf("%02x", (uint8) ingest[x + mac_loc]);
                }
                OS_printf("\n");
            #endif

            // Update OCF
            y = 0;
            for (x = OCF_SIZE; x > 0; x--)
            {
                ingest[fecf_loc - x] = tm_frame.tm_sec_trailer.ocf[y++];
            }

            // Update FECF
            tm_frame.tm_sec_trailer.fecf = Crypto_Calc_FECF((char*) ingest, fecf_loc - 1);
            ingest[fecf_loc] = (uint8) ((tm_frame.tm_sec_trailer.fecf & 0xFF00) >> 8);
            ingest[fecf_loc + 1] = (uint8) (tm_frame.tm_sec_trailer.fecf & 0x00FF); 
        }
        // Authentication
        else if ((sa_ptr->est == 0) &&
                 (sa_ptr->ast == 1))
        {
            #ifdef DEBUG
                OS_printf(KBLU "Creating a TM - AUTHENTICATED! \n" RESET);
            #endif
            // TODO: Future work. Operationally same as clear.
            CFE_PSP_MemCpy(ingest, tempTM, count);
        }
        // Encryption
        else if ((sa_ptr->est == 1) &&
                 (sa_ptr->ast == 0))
        {
            #ifdef DEBUG
                OS_printf(KBLU "Creating a TM - ENCRYPTED! \n" RESET);
            #endif
            // TODO: Future work. Operationally same as clear.
            CFE_PSP_MemCpy(ingest, tempTM, count);
        }

    #ifdef TM_DEBUG
        Crypto_tmPrint(&tm_frame);		
    #endif	
    
    #ifdef DEBUG
        OS_printf(KYEL "----- Crypto_TM_ApplySecurity END -----\n" RESET);
    #endif

    *len_ingest = count;
    return status;    
}

int32 Crypto_TM_ProcessSecurity(char* ingest, int* len_ingest)
{
    // Local Variables
    int32 status = OS_SUCCESS;

    #ifdef DEBUG
        OS_printf(KYEL "\n----- Crypto_TM_ProcessSecurity START -----\n" RESET);
    #endif

    // TODO: This whole function!
    len_ingest = len_ingest;
    ingest[0] = ingest[0];

    #ifdef DEBUG
        OS_printf(KYEL "----- Crypto_TM_ProcessSecurity END -----\n" RESET);
    #endif

    return status;
}

int32 Crypto_AOS_ApplySecurity(char* ingest, int* len_ingest)
{
    // Local Variables
    int32 status = OS_SUCCESS;

    #ifdef DEBUG
        OS_printf(KYEL "\n----- Crypto_AOS_ApplySecurity START -----\n" RESET);
    #endif

    // TODO: This whole function!
    len_ingest = len_ingest;
    ingest[0] = ingest[0];

    #ifdef DEBUG
        OS_printf(KYEL "----- Crypto_AOS_ApplySecurity END -----\n" RESET);
    #endif

    return status;
}

int32 Crypto_AOS_ProcessSecurity(char* ingest, int* len_ingest)
{
    // Local Variables
    int32 status = OS_SUCCESS;

    #ifdef DEBUG
        OS_printf(KYEL "\n----- Crypto_AOS_ProcessSecurity START -----\n" RESET);
    #endif

    // TODO: This whole function!
    len_ingest = len_ingest;
    ingest[0] = ingest[0];

    #ifdef DEBUG
        OS_printf(KYEL "----- Crypto_AOS_ProcessSecurity END -----\n" RESET);
    #endif

    return status;
}

int32 Crypto_ApplySecurity(char* ingest, int* len_ingest)
{
    // Local Variables
    int32 status = OS_SUCCESS;

    #ifdef DEBUG
        OS_printf(KYEL "\n----- Crypto_ApplySecurity START -----\n" RESET);
    #endif

    // TODO: This whole function!
    len_ingest = len_ingest;
    ingest[0] = ingest[0];

    #ifdef DEBUG
        OS_printf(KYEL "----- Crypto_ApplySecurity END -----\n" RESET);
    #endif

    return status;
}

int32 Crypto_ProcessSecurity(char* ingest, int* len_ingest)
{
    // Local Variables
    int32 status = OS_SUCCESS;

    #ifdef DEBUG
        OS_printf(KYEL "\n----- Crypto_ProcessSecurity START -----\n" RESET);
    #endif

    // TODO: This whole function!
    len_ingest = len_ingest;
    ingest[0] = ingest[0];

    #ifdef DEBUG
        OS_printf(KYEL "----- Crypto_ProcessSecurity END -----\n" RESET);
    #endif

    return status;
}

#endif