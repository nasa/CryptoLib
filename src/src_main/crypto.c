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

/*
** Includes
*/
#include "crypto.h"

/*
** Static Library Declaration
*/
#ifdef BUILD_STATIC
CFS_MODULE_DECLARE_LIB(crypto);
#endif

/*
** Global Variables
*/
SadbRoutine sadb_routine = NULL;
// Security
crypto_key_t ek_ring[NUM_KEYS] = {0};
// crypto_key_t ak_ring[NUM_KEYS];
CCSDS_t sdls_frame;
TM_t tm_frame;
CryptoConfig_t *crypto_config = NULL;
SadbMariaDBConfig_t *sadb_mariadb_config = NULL;
GvcidManagedParameters_t *gvcid_managed_parameters = NULL;
GvcidManagedParameters_t *current_managed_parameters = NULL;
// OCF
uint8_t ocf = 0;
SDLS_FSR_t report;
TM_FrameCLCW_t clcw;
// Flags
SDLS_MC_LOG_RPLY_t log_summary;
SDLS_MC_DUMP_BLK_RPLY_t mc_log;
uint8_t log_count = 0;
uint16_t tm_offset = 0;
// ESA Testing - 0 = disabled, 1 = enabled
uint8_t badSPI = 0;
uint8_t badIV = 0;
uint8_t badMAC = 0;
uint8_t badFECF = 0;
//  CRC
uint32_t crc32Table[256];
uint16_t crc16Table[256];

/*
** Initialization Functions
*/

/**
 * @brief Function: Crypto_Init_Unit_test
 * @return int32: status
 **/
int32_t Crypto_Init_Unit_Test(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS);
    status = Crypto_Init();
    return status;
}

/**
 * @brief Function: Crypto_Init_With_Configs
 * @param crypto_config_p: CryptoConfig_t*
 * @param gvcid_managed_parameters_p: GvcidManagedParameters_t*
 * @param sadb_mariadb_config_p: SadbMariaDBConfig_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_Init_With_Configs(CryptoConfig_t *crypto_config_p, GvcidManagedParameters_t *gvcid_managed_parameters_p,
                                 SadbMariaDBConfig_t *sadb_mariadb_config_p)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    crypto_config = crypto_config_p;
    gvcid_managed_parameters = gvcid_managed_parameters_p;
    sadb_mariadb_config = sadb_mariadb_config_p;
    status = Crypto_Init();
    return status;
}

/**
 * @brief Function Crypto_Init
 * Initializes libgcrypt, Security Associations
 **/
int32_t Crypto_Init(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (crypto_config == NULL)
    {
        status = CRYPTO_CONFIGURATION_NOT_COMPLETE;
        printf(KRED "ERROR: CryptoLib must be configured before intializing!\n" RESET);
        return status; // No configuration set -- return!
    }
    if (gvcid_managed_parameters == NULL)
    {
        status = CRYPTO_MANAGED_PARAM_CONFIGURATION_NOT_COMPLETE;
        printf(KRED "ERROR: CryptoLib  Managed Parameters must be configured before intializing!\n" RESET);
        return status; // No Managed Parameter configuration set -- return!
    }

#ifdef TC_DEBUG
    Crypto_mpPrint(gvcid_managed_parameters, 1);
#endif

    // Prepare SADB type from config
    if (crypto_config->sadb_type == SADB_TYPE_INMEMORY)
    {
        sadb_routine = get_sadb_routine_inmemory();
    }
    else if (crypto_config->sadb_type == SADB_TYPE_MARIADB)
    {
        if (sadb_mariadb_config == NULL)
        {
            status = CRYPTO_MARIADB_CONFIGURATION_NOT_COMPLETE;
            printf(KRED "ERROR: CryptoLib MariaDB must be configured before intializing!\n" RESET);
            return status; // MariaDB connection specified but no configuration exists, return!
        }
        sadb_routine = get_sadb_routine_mariadb();
    }
    else
    {
        status = SADB_INVALID_SADB_TYPE;
        return status;
    } // TODO: Error stack

    // Initialize libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION))
    {
        fprintf(stderr, "Gcrypt Version: %s", GCRYPT_VERSION);
        printf(KRED "\tERROR: gcrypt version mismatch! \n" RESET);
    }
    if (gcry_control(GCRYCTL_SELFTEST) != GPG_ERR_NO_ERROR)
    {
        printf(KRED "ERROR: gcrypt self test failed\n" RESET);
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
    printf(KBLU "Crypto Lib Intialized.  Version %d.%d.%d.%d\n" RESET, CRYPTO_LIB_MAJOR_VERSION,
           CRYPTO_LIB_MINOR_VERSION, CRYPTO_LIB_REVISION, CRYPTO_LIB_MISSION_REV);

    return status;
}

/**
 * @brief Function: Crypto_Shutdown
 * Free memory objects & restore pointers to NULL for re-initialization
 * @return int32: Success/Failure
 **/
int32_t Crypto_Shutdown(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (crypto_config != NULL)
    {
        free(crypto_config);
        crypto_config = NULL;
    }
    if (sadb_mariadb_config != NULL)
    {
        free(sadb_mariadb_config);
        sadb_mariadb_config = NULL;
    }
    current_managed_parameters = NULL;

    if (gvcid_managed_parameters != NULL)
    {
        Crypto_Free_Managed_Parameters(gvcid_managed_parameters);
        gvcid_managed_parameters = NULL;
    }

    return status;
}

/**
 * @brief Function: Crypto_Config_CryptoLib
 * @param sadb_type: uint8
 * @param crypto_create_fecf: uint8
 * @param process_sdls_pdus: uint8
 * @param has_pus_hdr: uint8
 * @param ignore_sa_state: uint8
 * @param ignore_anti_replay: uint8
 * @param unique_sa_per_mapid: uint8
 * @param crypto_check_fecf: uint8
 * @param vcid_bitmask: uint8
 * @return int32: Success/Failure
 **/
int32_t Crypto_Config_CryptoLib(uint8_t sadb_type, uint8_t crypto_create_fecf, uint8_t process_sdls_pdus,
                                uint8_t has_pus_hdr, uint8_t ignore_sa_state, uint8_t ignore_anti_replay,
                                uint8_t unique_sa_per_mapid, uint8_t crypto_check_fecf, uint8_t vcid_bitmask)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    crypto_config = (CryptoConfig_t *)calloc(1, CRYPTO_CONFIG_SIZE);
    crypto_config->sadb_type = sadb_type;
    crypto_config->crypto_create_fecf = crypto_create_fecf;
    crypto_config->process_sdls_pdus = process_sdls_pdus;
    crypto_config->has_pus_hdr = has_pus_hdr;
    crypto_config->ignore_sa_state = ignore_sa_state;
    crypto_config->ignore_anti_replay = ignore_anti_replay;
    crypto_config->unique_sa_per_mapid = unique_sa_per_mapid;
    crypto_config->crypto_check_fecf = crypto_check_fecf;
    crypto_config->vcid_bitmask = vcid_bitmask;
    return status;
}

/**
 * @brief Function: Crypto_Config_MariaDB
 * @param mysql_username: uint8_t*
 * @param mysql_password: uint8_t*
 * @param mysql_hostname: uint8_t*
 * @param mysql_database: uint8_t*
 * @param mysql_port: uint16
 * @return int32: Success/Failure
 **/
int32_t Crypto_Config_MariaDB(uint8_t *mysql_username, uint8_t *mysql_password, uint8_t *mysql_hostname,
                              uint8_t *mysql_database, uint16_t mysql_port)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    sadb_mariadb_config = (SadbMariaDBConfig_t *)calloc(1, SADB_MARIADB_CONFIG_SIZE);
    sadb_mariadb_config->mysql_username = mysql_username;
    sadb_mariadb_config->mysql_password = mysql_password;
    sadb_mariadb_config->mysql_hostname = mysql_hostname;
    sadb_mariadb_config->mysql_database = mysql_database;
    sadb_mariadb_config->mysql_port = mysql_port;
    return status;
}

/**
 * @brief Function: Crypto_Config_Add_Gvcid_Managed_Parameter
 * @param tfvn: uint8
 * @param scid: uint16
 * @param vcid: uint8
 * @param has_fecf: uint8
 * @param has_segmentation_hdr: uint8
 * @return int32: Success/Failure
 **/
int32_t Crypto_Config_Add_Gvcid_Managed_Parameter(uint8_t tfvn, uint16_t scid, uint8_t vcid, uint8_t has_fecf,
                                                  uint8_t has_segmentation_hdr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (gvcid_managed_parameters == NULL)
    { // case: Global Root Node not Set
        gvcid_managed_parameters = (GvcidManagedParameters_t *)calloc(1, GVCID_MANAGED_PARAMETERS_SIZE);
        gvcid_managed_parameters->tfvn = tfvn;
        gvcid_managed_parameters->scid = scid;
        gvcid_managed_parameters->vcid = vcid;
        gvcid_managed_parameters->has_fecf = has_fecf;
        gvcid_managed_parameters->has_segmentation_hdr = has_segmentation_hdr;
        gvcid_managed_parameters->next = NULL;
        return status;
    }
    else
    { // Recurse through nodes and add at end
        return crypto_config_add_gvcid_managed_parameter_recursion(tfvn, scid, vcid, has_fecf, has_segmentation_hdr,
                                                                   gvcid_managed_parameters);
    }
}

/**
 * @brief Function: crypto_config_add_gvcid_managed_parameter_recursion
 * @param tfvn: uint8
 * @param scid: uint16
 * @param vcid: uint8
 * @param has_fecf: uint8
 * @param has_segmentation_hdr: uint8
 * @param managed_parameter: GvcidManagedParameters_t*
 * @return int32: Success/Failure
 **/
int32_t crypto_config_add_gvcid_managed_parameter_recursion(uint8_t tfvn, uint16_t scid, uint8_t vcid,
                                                                   uint8_t has_fecf, uint8_t has_segmentation_hdr,
                                                                   GvcidManagedParameters_t *managed_parameter)
{
    if (managed_parameter->next != NULL)
    {
        return crypto_config_add_gvcid_managed_parameter_recursion(tfvn, scid, vcid, has_fecf, has_segmentation_hdr,
                                                                   managed_parameter->next);
    }
    else
    {
        managed_parameter->next = (GvcidManagedParameters_t *)calloc(1, GVCID_MANAGED_PARAMETERS_SIZE);
        managed_parameter->next->tfvn = tfvn;
        managed_parameter->next->scid = scid;
        managed_parameter->next->vcid = vcid;
        managed_parameter->next->has_fecf = has_fecf;
        managed_parameter->next->has_segmentation_hdr = has_segmentation_hdr;
        managed_parameter->next->next = NULL;
        return CRYPTO_LIB_SUCCESS;
    }
}

/**
 * @brief Function: Crypto_Local_Config
 * Initalizes TM Configuration, Log, and Keyrings
 **/
void Crypto_Local_Config(void)
{
    // Initial TM configuration
    tm_frame.tm_sec_header.spi = 1;

    // Initialize Log
    log_summary.num_se = 2;
    log_summary.rs = LOG_SIZE;
    // Add a two messages to the log
    log_summary.rs--;
    mc_log.blk[log_count].emt = STARTUP;
    mc_log.blk[log_count].emv[0] = 0x4E;
    mc_log.blk[log_count].emv[1] = 0x41;
    mc_log.blk[log_count].emv[2] = 0x53;
    mc_log.blk[log_count].emv[3] = 0x41;
    mc_log.blk[log_count++].em_len = 4;
    log_summary.rs--;
    mc_log.blk[log_count].emt = STARTUP;
    mc_log.blk[log_count].emv[0] = 0x4E;
    mc_log.blk[log_count].emv[1] = 0x41;
    mc_log.blk[log_count].emv[2] = 0x53;
    mc_log.blk[log_count].emv[3] = 0x41;
    mc_log.blk[log_count++].em_len = 4;

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
    ek_ring[135].key_state = KEY_DEACTIVATED;
}

/**
 * @brief Function: Crypto_Local_Init
 * Initalize TM Frame, CLCW
 **/
void Crypto_Local_Init(void)
{

    // Initialize TM Frame
    // TM Header
    tm_frame.tm_header.tfvn = 0; // Shall be 00 for TM-/TC-SDLP
    tm_frame.tm_header.scid = SCID & 0x3FF;
    tm_frame.tm_header.vcid = 0;
    tm_frame.tm_header.ocff = 1;
    tm_frame.tm_header.mcfc = 1;
    tm_frame.tm_header.vcfc = 1;
    tm_frame.tm_header.tfsh = 0;
    tm_frame.tm_header.sf = 0;
    tm_frame.tm_header.pof = 0;  // Shall be set to 0
    tm_frame.tm_header.slid = 3; // Shall be set to 11
    tm_frame.tm_header.fhp = 0;
    // TM Security Header
    tm_frame.tm_sec_header.spi = 0x0000;
    for (int x = 0; x < IV_SIZE; x++)
    { // Initialization Vector
        *(tm_frame.tm_sec_header.iv + x) = 0x00;
    }
    // TM Payload Data Unit
    for (int x = 0; x < TM_FRAME_DATA_SIZE; x++)
    { // Zero TM PDU
        tm_frame.tm_pdu[x] = 0x00;
    }
    // TM Security Trailer
    for (int x = 0; x < MAC_SIZE; x++)
    { // Zero TM Message Authentication Code
        tm_frame.tm_sec_trailer.mac[x] = 0x00;
    }
    for (int x = 0; x < OCF_SIZE; x++)
    { // Zero TM Operational Control Field
        tm_frame.tm_sec_trailer.ocf[x] = 0x00;
    }
    tm_frame.tm_sec_trailer.fecf = 0xFECF;

    // Initialize CLCW
    clcw.cwt = 0;    // Control Word Type "0"
    clcw.cvn = 0;    // CLCW Version Number "00"
    clcw.sf = 0;     // Status Field
    clcw.cie = 1;    // COP In Effect
    clcw.vci = 0;    // Virtual Channel Identification
    clcw.spare0 = 0; // Reserved Spare
    clcw.nrfa = 0;   // No RF Avaliable Flag
    clcw.nbl = 0;    // No Bit Lock Flag
    clcw.lo = 0;     // Lock-Out Flag
    clcw.wait = 0;   // Wait Flag
    clcw.rt = 0;     // Retransmit Flag
    clcw.fbc = 0;    // FARM-B Counter
    clcw.spare1 = 0; // Reserved Spare
    clcw.rv = 0;     // Report Value

    // Initialize Frame Security Report
    report.cwt = 1;   // Control Word Type "0b1""
    report.vnum = 4;  // FSR Version "0b100""
    report.af = 0;    // Alarm Field
    report.bsnf = 0;  // Bad SN Flag
    report.bmacf = 0; // Bad MAC Flag
    report.ispif = 0; // Invalid SPI Flag
    report.lspiu = 0; // Last SPI Used
    report.snval = 0; // SN Value (LSB)
}

/**
 * @brief Function: Crypto_Calc_CRC_Init_Table
 * Initialize CRC Table
 **/
void Crypto_Calc_CRC_Init_Table(void)
{
    uint16_t val;
    uint32_t poly = 0xEDB88320;
    uint32_t crc;

    // http://create.stephan-brumme.com/crc32/
    for (unsigned int i = 0; i <= 0xFF; i++)
    {
        crc = i;
        for (unsigned int j = 0; j < 8; j++)
        {
            crc = (crc >> 1) ^ (-(int)(crc & 1) & poly);
        }
        crc32Table[i] = crc;
        // printf("crc32Table[%d] = 0x%08x \n", i, crc32Table[i]);
    }

    // Code provided by ESA
    for (int i = 0; i < 256; i++)
    {
        val = 0;
        if ((i & 1) != 0)
            val ^= 0x1021;
        if ((i & 2) != 0)
            val ^= 0x2042;
        if ((i & 4) != 0)
            val ^= 0x4084;
        if ((i & 8) != 0)
            val ^= 0x8108;
        if ((i & 16) != 0)
            val ^= 0x1231;
        if ((i & 32) != 0)
            val ^= 0x2462;
        if ((i & 64) != 0)
            val ^= 0x48C4;
        if ((i & 128) != 0)
            val ^= 0x9188;
        crc16Table[i] = val;
        // printf("crc16Table[%d] = 0x%04x \n", i, crc16Table[i]);
    }
}

/*
** Assisting Functions
*/
/**
 * @brief Function: Crypto_Get_tcPayloadLength
 * Returns the payload length of current tc_frame in BYTES!
 * @param tc_frame: TC_t*
 * @param sa_ptr: SecurityAssociation_t
 * @return int32, Length of TCPayload
 **/
/*
int32_t Crypto_Get_tcPayloadLength(TC_t* tc_frame, SecurityAssociation_t *sa_ptr)
{
    int tf_hdr = 5;
    int seg_hdr = 0;if(current_managed_parameters->has_segmentation_hdr==TC_HAS_SEGMENT_HDRS){seg_hdr=1;}
    int fecf = 0;if(current_managed_parameters->has_fecf==TC_HAS_FECF){fecf=FECF_SIZE;}
    int spi = 2;
    int iv_size = sa_ptr->shivf_len;
    int mac_size = sa_ptr->stmacf_len;

    #ifdef TC_DEBUG
        printf("Get_tcPayloadLength Debug [byte lengths]:\n");
        printf("\thdr.fl\t%d\n", tc_frame->tc_header.fl);
        printf("\ttf_hdr\t%d\n",tf_hdr);
        printf("\tSeg hdr\t%d\t\n",seg_hdr);
        printf("\tspi \t%d\n",spi);
        printf("\tiv_size\t%d\n",iv_size);
        printf("\tmac\t%d\n",mac_size);
        printf("\tfecf \t%d\n",fecf);
        printf("\tTOTAL LENGTH: %d\n", (tc_frame->tc_header.fl - (tf_hdr + seg_hdr + spi + iv_size ) - (mac_size +
fecf))); #endif

    return (tc_frame->tc_header.fl + 1 - (tf_hdr + seg_hdr + spi + iv_size ) - (mac_size + fecf) );
}
*/

/**
 * @brief Function: Crypto_Get_tmLength
 * Returns the total length of the current tm_frame in BYTES!
 * @param len: int
 * @return int32_t Length of TM
 **/
int32_t Crypto_Get_tmLength(int len)
{
#ifdef FILL
    len = TM_FILL_SIZE;
#else
    len = TM_FRAME_PRIMARYHEADER_SIZE + TM_FRAME_SECHEADER_SIZE + len + TM_FRAME_SECTRAILER_SIZE + TM_FRAME_CLCW_SIZE;
#endif

    return len;
}

/**
 * @brief Function: Crypto_Is_AEAD_Algorithm
 * Looks up cipher suite ID and determines if it's an AEAD algorithm. Returns 1 if true, 0 if false;
 * @param cipher_suite_id: uint32
 **/
uint8_t Crypto_Is_AEAD_Algorithm(uint32_t cipher_suite_id)
{
    // CryptoLib only supports AES-GCM, which is an AEAD (Authenticated Encryption with Associated Data) algorithm, so
    // return true/1.
    // TODO - Add cipher suite mapping to which algorithms are AEAD and which are not.
    cipher_suite_id = cipher_suite_id;

    return CRYPTO_TRUE;
}

/**
 * @brief Function: Crypto_Prepare_TC_AAD
 * Callocs and returns pointer to buffer where AAD is created & bitwise-anded with bitmask!
 * Note: Function caller is responsible for freeing the returned buffer!
 * @param buffer: uint8_t*
 * @param len_aad: uint16_t
 * @param abm_buffer: uint8_t*
 **/
uint8_t *Crypto_Prepare_TC_AAD(uint8_t *buffer, uint16_t len_aad, uint8_t *abm_buffer)
{
    uint8_t *aad = (uint8_t *)calloc(1, len_aad * sizeof(uint8_t));

    for (int i = 0; i < len_aad; i++)
    {
        aad[i] = buffer[i] & abm_buffer[i];
    }

#ifdef MAC_DEBUG
    printf(KYEL "Preparing AAD:\n");
    printf("\tUsing AAD Length of %d\n\t", len_aad);
    for (int i = 0; i < len_aad; i++)
    {
        printf("%02x", aad[i]);
    }
    printf("\n" RESET);
#endif

    return aad;
}

/**
 * @brief Function: Crypto_TM_updatePDU
 * Update the Telemetry Payload Data Unit
 * @param ingest: uint8_t*
 * @param len_ingest: int
 **/
void Crypto_TM_updatePDU(uint8_t *ingest, int len_ingest)
{ // Copy ingest to PDU
    int x = 0;
    int fill_size = 0;
    SecurityAssociation_t *sa_ptr;

    if (sadb_routine->sadb_get_sa_from_spi(tm_frame.tm_sec_header.spi, &sa_ptr) != CRYPTO_LIB_SUCCESS)
    {
        // TODO - Error handling
        return; // Error -- unable to get SA from SPI.
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
        { // Fill
            tm_frame.tm_pdu[x] = (uint8_t)ingest[x];
        }
        else
        { // Zero
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
        // printf("ingest[x - tm_offset] = 0x%02x \n", (uint8_t)ingest[x - tm_offset]);
        tm_frame.tm_pdu[x] = (uint8_t)ingest[x - tm_offset];
        x++;
    }
#ifdef TM_IDLE_FILL
    // Check for idle frame trigger
    if (((uint8_t)ingest[0] == 0x08) && ((uint8_t)ingest[1] == 0x90))
    {
        // Don't fill idle frames
    }
    else
    {
        while (x < (fill_size - 64))
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
/**
 * @brief Function: Crypto_TM_updateOCF
 * Update the TM OCF
 **/
void Crypto_TM_updateOCF(void)
{
    if (ocf == 0)
    { // CLCW
        clcw.vci = tm_frame.tm_header.vcid;

        tm_frame.tm_sec_trailer.ocf[0] = (clcw.cwt << 7) | (clcw.cvn << 5) | (clcw.sf << 2) | (clcw.cie);
        tm_frame.tm_sec_trailer.ocf[1] = (clcw.vci << 2) | (clcw.spare0);
        tm_frame.tm_sec_trailer.ocf[2] = (clcw.nrfa << 7) | (clcw.nbl << 6) | (clcw.lo << 5) | (clcw.wait << 4) |
                                         (clcw.rt << 3) | (clcw.fbc << 1) | (clcw.spare1);
        tm_frame.tm_sec_trailer.ocf[3] = (clcw.rv);
        // Alternate OCF
        ocf = 1;
#ifdef OCF_DEBUG
        Crypto_clcwPrint(&clcw);
#endif
    }
    else
    { // FSR
        tm_frame.tm_sec_trailer.ocf[0] = (report.cwt << 7) | (report.vnum << 4) | (report.af << 3) |
                                         (report.bsnf << 2) | (report.bmacf << 1) | (report.ispif);
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

// TODO - Review this. Not sure it quite works how we think
/**
 * @brief Function: Crypto_increment
 * Increments the bytes within a uint8_t array
 * @param num: uint8*
 * @param length: int
 * @return int32: Success/Failure
 **/
int32_t Crypto_increment(uint8_t *num, int length)
{
    int i;
    /* go from right (least significant) to left (most signifcant) */
    for (i = length - 1; i >= 0; --i)
    {
        ++(num[i]); /* increment current byte */

        if (num[i] != 0) /* if byte did not overflow, we're done! */
            break;
    }

    if (i < 0) /* this means num[0] was incremented and overflowed */
        return CRYPTO_LIB_ERROR;
    else
        return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_window
 * Determines if a value is within the expected window of values
 * @param actual: uint8*
 * @param expected: uint8*
 * @param length: int
 * @param window: int
 * @return int32: Success/Failure
 **/
int32_t Crypto_window(uint8_t *actual, uint8_t *expected, int length, int window)
{
    int status = CRYPTO_LIB_ERR_BAD_ANTIREPLAY_WINDOW;
    int result = 0;
    uint8_t temp[length];

    memcpy(temp, expected, length);

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
            status = CRYPTO_LIB_SUCCESS;
            break;
        }
        Crypto_increment(&temp[0], length);
    }
    return status;
}

/**
 * @brief Function: Crypto_compare_less_equal
 * @param actual: uint8*
 * @param expected: uint8*
 * @param length: int
 * @return int32: Success/Failure
 **/
/*
int32_t Crypto_compare_less_equal(uint8_t *actual, uint8_t *expected, int length)
{
    int status = CRYPTO_LIB_ERROR;

    for(int i = 0; i < length - 1; i++)
    {
        if (actual[i] > expected[i])
        {
            status = CRYPTO_LIB_SUCCESS;
            break;
        }
        else if (actual[i] < expected[i])
        {
            status = CRYPTO_LIB_ERROR;
            break;
        }
    }
    return status;
}
*/

/**
 * @brief Function: Crypto_Prep_Reply
 * Assumes that both the pkt_length and pdu_len are set properly
 * @param ingest: uint8_t*
 * @param appID: uint8
 * @return uint8: Count
 **/
uint8_t Crypto_Prep_Reply(uint8_t *ingest, uint8_t appID)
{
    uint8_t count = 0;

    // Prepare CCSDS for reply
    sdls_frame.hdr.pvn = 0;
    sdls_frame.hdr.type = 0;
    sdls_frame.hdr.shdr = 1;
    sdls_frame.hdr.appID = appID;

    sdls_frame.pdu.type = 1;

    // Fill ingest with reply header
    ingest[count++] = (sdls_frame.hdr.pvn << 5) | (sdls_frame.hdr.type << 4) | (sdls_frame.hdr.shdr << 3) |
                      ((sdls_frame.hdr.appID & 0x700 >> 8));
    ingest[count++] = (sdls_frame.hdr.appID & 0x00FF);
    ingest[count++] = (sdls_frame.hdr.seq << 6) | ((sdls_frame.hdr.pktid & 0x3F00) >> 8);
    ingest[count++] = (sdls_frame.hdr.pktid & 0x00FF);
    ingest[count++] = (sdls_frame.hdr.pkt_length & 0xFF00) >> 8;
    ingest[count++] = (sdls_frame.hdr.pkt_length & 0x00FF);

    // Fill ingest with PUS
    // ingest[count++] = (sdls_frame.pus.shf << 7) | (sdls_frame.pus.pusv << 4) | (sdls_frame.pus.ack);
    // ingest[count++] = (sdls_frame.pus.st);
    // ingest[count++] = (sdls_frame.pus.sst);
    // ingest[count++] = (sdls_frame.pus.sid << 4) | (sdls_frame.pus.spare);

    // Fill ingest with Tag and Length
    ingest[count++] =
        (sdls_frame.pdu.type << 7) | (sdls_frame.pdu.uf << 6) | (sdls_frame.pdu.sg << 4) | (sdls_frame.pdu.pid);
    ingest[count++] = (sdls_frame.pdu.pdu_len & 0xFF00) >> 8;
    ingest[count++] = (sdls_frame.pdu.pdu_len & 0x00FF);

    return count;
}

/**
 * @brief Function Crypto_FECF
 * Calculate the Frame Error Control Field (FECF), also known as a cyclic redundancy check (CRC)
 * @param fecf: int
 * @param ingest: uint8_t*
 * @param len_ingest: int
 * @param tc_frame: TC_t*
 * @return int32: Success/Failure
 **/
/*
int32_t Crypto_FECF(int fecf, uint8_t* ingest, int len_ingest,TC_t* tc_frame)
{
    int32_t result = CRYPTO_LIB_SUCCESS;
    uint16_t calc_fecf = Crypto_Calc_FECF(ingest, len_ingest);

    if ( (fecf & 0xFFFF) != calc_fecf )
        {
            if (((uint8_t)ingest[18] == 0x0B) && ((uint8_t)ingest[19] == 0x00) && (((uint8_t)ingest[20] & 0xF0) ==
0x40))
            {
                // User packet check only used for ESA Testing!
            }
            else
            {   // TODO: Error Correction
                printf(KRED "Error: FECF incorrect!\n" RESET);
                if (log_summary.rs > 0)
                {
                    Crypto_increment((uint8_t*)&log_summary.num_se, 4);
                    log_summary.rs--;
                    mc_log.blk[log_count].emt = FECF_ERR_EID;
                    mc_log.blk[log_count].emv[0] = 0x4E;
                    mc_log.blk[log_count].emv[1] = 0x41;
                    mc_log.blk[log_count].emv[2] = 0x53;
                    mc_log.blk[log_count].emv[3] = 0x41;
                    mc_log.blk[log_count++].em_len = 4;
                }
                #ifdef FECF_DEBUG
                    printf("\t Calculated = 0x%04x \n\t Received   = 0x%04x \n", calc_fecf,
tc_frame->tc_sec_trailer.fecf); #endif result = CRYPTO_LIB_ERROR;
            }
        }

    return result;
}
*/

/**
 * @brief Function Crypto_Calc_FECF
 * Calculate the Frame Error Control Field (FECF), also known as a cyclic redundancy check (CRC)
 * @param ingest: uint8_t*
 * @param len_ingest: int
 * @return uint16: FECF
 **/
uint16_t Crypto_Calc_FECF(uint8_t *ingest, int len_ingest)
{
    uint16_t fecf = 0xFFFF;
    uint16_t poly = 0x1021; // TODO: This polynomial is (CRC-CCITT) for ESA testing, may not match standard protocol
    uint8_t bit;
    uint8_t c15;

    for (int i = 0; i < len_ingest; i++)
    { // Byte Logic
        for (int j = 0; j < 8; j++)
        { // Bit Logic
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
    printf(KCYN "Crypto_Calc_FECF: 0x%02x%02x%02x%02x%02x, len_ingest = %d\n" RESET, ingest[0], ingest[1], ingest[2],
           ingest[3], ingest[4], len_ingest);
    printf(KCYN "0x" RESET);
    for (int x = 0; x < len_ingest; x++)
    {
        printf(KCYN "%02x" RESET, (uint8_t) * (ingest + x));
    }
    printf(KCYN "\n" RESET);
    printf(KCYN "In Crypto_Calc_FECF! fecf = 0x%04x\n" RESET, fecf);
#endif

    return fecf;
}

/**
 * @brief Function: Crypto_Calc_CRC16
 * Calculates CRC16
 * @param data: uint8_t*
 * @param size: int
 * @return uint16: CRC
 **/
uint16_t Crypto_Calc_CRC16(uint8_t *data, int size)
{ // Code provided by ESA
    uint16_t crc = 0xFFFF;

    for (; size > 0; size--)
    {
        // printf("*data = 0x%02x \n", (uint8_t) *data);
        crc = ((crc << 8) & 0xFF00) ^ crc16Table[(crc >> 8) ^ *data++];
    }

    return crc;
}

/**
 * @brief Function: Crypto_User_IdleTrigger
 * @param ingest: uint8_t*
 * @return int32: count
 **/
int32_t Crypto_User_IdleTrigger(uint8_t *ingest)
{
    uint8_t count = 0;

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 0;
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 144);

    return count;
}

/**
 * @brief Function: Crypto_User_BadSPI
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_BadSPI(void)
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

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_BadMAC
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_BadMAC(void)
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

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_BadIV
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_BadIV(void)
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

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_BadFECF
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_BadFECF(void)
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

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_ModifyKey
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_ModifyKey(void)
{
    // Local variables
    uint16_t kid = ((uint8_t)sdls_frame.pdu.data[0] << 8) | ((uint8_t)sdls_frame.pdu.data[1]);
    uint8_t mod = (uint8_t)sdls_frame.pdu.data[2];

    switch (mod)
    {
    case 1: // Invalidate Key
        ek_ring[kid].value[KEY_SIZE - 1]++;
        printf("Key %d value invalidated! \n", kid);
        break;
    case 2: // Modify key state
        ek_ring[kid].key_state = (uint8_t)sdls_frame.pdu.data[3] & 0x0F;
        printf("Key %d state changed to %d! \n", kid, mod);
        break;
    default:
        // Error
        break;
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_ModifyActiveTM
 * Modifies tm_sec_header.spi based on sdls_frame.pdu.data[0]
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_ModifyActiveTM(void)
{
    tm_frame.tm_sec_header.spi = (uint8_t)sdls_frame.pdu.data[0];
    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_ModifyVCID
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_ModifyVCID(void)
{
    tm_frame.tm_header.vcid = (uint8_t)sdls_frame.pdu.data[0];
    SecurityAssociation_t *sa_ptr;

    for (int i = 0; i < NUM_GVCID; i++)
    {
        if (sadb_routine->sadb_get_sa_from_spi(i, &sa_ptr) != CRYPTO_LIB_SUCCESS)
        {
            // TODO - Error handling
            return CRYPTO_LIB_ERROR; // Error -- unable to get SA from SPI.
        }
        for (int j = 0; j < NUM_SA; j++)
        {

            if (sa_ptr->gvcid_tm_blk[j].mapid == TYPE_TM)
            {
                if (sa_ptr->gvcid_tm_blk[j].vcid == tm_frame.tm_header.vcid)
                {
                    tm_frame.tm_sec_header.spi = i;
                    printf("TM Frame SPI changed to %d \n", i);
                    break;
                }
            }
        }
    }

    return CRYPTO_LIB_SUCCESS;
}

/*
** Procedures Specifications
*/
/**
 * @brief Function: Crypto_PDU
 * @param ingest: uint8_t*
 * @param tc_frame: TC_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_PDU(uint8_t *ingest, TC_t *tc_frame)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    switch (sdls_frame.pdu.type)
    {
    case 0: // Command
        switch (sdls_frame.pdu.uf)
        {
        case 0: // CCSDS Defined Command
            switch (sdls_frame.pdu.sg)
            {
            case SG_KEY_MGMT: // Key Management Procedure
                switch (sdls_frame.pdu.pid)
                {
                case PID_OTAR:
#ifdef PDU_DEBUG
                    printf(KGRN "Key OTAR\n" RESET);
#endif
                    status = Crypto_Key_OTAR();
                    break;
                case PID_KEY_ACTIVATION:
#ifdef PDU_DEBUG
                    printf(KGRN "Key Activate\n" RESET);
#endif
                    status = Crypto_Key_update(KEY_ACTIVE);
                    break;
                case PID_KEY_DEACTIVATION:
#ifdef PDU_DEBUG
                    printf(KGRN "Key Deactivate\n" RESET);
#endif
                    status = Crypto_Key_update(KEY_DEACTIVATED);
                    break;
                case PID_KEY_VERIFICATION:
#ifdef PDU_DEBUG
                    printf(KGRN "Key Verify\n" RESET);
#endif
                    status = Crypto_Key_verify(ingest, tc_frame);
                    break;
                case PID_KEY_DESTRUCTION:
#ifdef PDU_DEBUG
                    printf(KGRN "Key Destroy\n" RESET);
#endif
                    status = Crypto_Key_update(KEY_DESTROYED);
                    break;
                case PID_KEY_INVENTORY:
#ifdef PDU_DEBUG
                    printf(KGRN "Key Inventory\n" RESET);
#endif
                    status = Crypto_Key_inventory(ingest);
                    break;
                default:
                    printf(KRED "Error: Crypto_PDU failed interpreting Key Management Procedure Identification Field! "
                                "\n" RESET);
                    break;
                }
                break;
            case SG_SA_MGMT: // Security Association Management Procedure
                switch (sdls_frame.pdu.pid)
                {
                case PID_CREATE_SA:
#ifdef PDU_DEBUG
                    printf(KGRN "SA Create\n" RESET);
#endif
                    status = sadb_routine->sadb_sa_create();
                    break;
                case PID_DELETE_SA:
#ifdef PDU_DEBUG
                    printf(KGRN "SA Delete\n" RESET);
#endif
                    status = sadb_routine->sadb_sa_delete();
                    break;
                case PID_SET_ARSNW:
#ifdef PDU_DEBUG
                    printf(KGRN "SA setARSNW\n" RESET);
#endif
                    status = sadb_routine->sadb_sa_setARSNW();
                    break;
                case PID_REKEY_SA:
#ifdef PDU_DEBUG
                    printf(KGRN "SA Rekey\n" RESET);
#endif
                    status = sadb_routine->sadb_sa_rekey();
                    break;
                case PID_EXPIRE_SA:
#ifdef PDU_DEBUG
                    printf(KGRN "SA Expire\n" RESET);
#endif
                    status = sadb_routine->sadb_sa_expire();
                    break;
                case PID_SET_ARSN:
#ifdef PDU_DEBUG
                    printf(KGRN "SA SetARSN\n" RESET);
#endif
                    status = sadb_routine->sadb_sa_setARSN();
                    break;
                case PID_START_SA:
#ifdef PDU_DEBUG
                    printf(KGRN "SA Start\n" RESET);
#endif
                    status = sadb_routine->sadb_sa_start(tc_frame);
                    break;
                case PID_STOP_SA:
#ifdef PDU_DEBUG
                    printf(KGRN "SA Stop\n" RESET);
#endif
                    status = sadb_routine->sadb_sa_stop();
                    break;
                case PID_READ_ARSN:
#ifdef PDU_DEBUG
                    printf(KGRN "SA readARSN\n" RESET);
#endif
                    status = Crypto_SA_readARSN(ingest);
                    break;
                case PID_SA_STATUS:
#ifdef PDU_DEBUG
                    printf(KGRN "SA Status\n" RESET);
#endif
                    status = sadb_routine->sadb_sa_status(ingest);
                    break;
                default:
                    printf(KRED "Error: Crypto_PDU failed interpreting SA Procedure Identification Field! \n" RESET);
                    break;
                }
                break;
            case SG_SEC_MON_CTRL: // Security Monitoring & Control Procedure
                switch (sdls_frame.pdu.pid)
                {
                case PID_PING:
#ifdef PDU_DEBUG
                    printf(KGRN "MC Ping\n" RESET);
#endif
                    status = Crypto_MC_ping(ingest);
                    break;
                case PID_LOG_STATUS:
#ifdef PDU_DEBUG
                    printf(KGRN "MC Status\n" RESET);
#endif
                    status = Crypto_MC_status(ingest);
                    break;
                case PID_DUMP_LOG:
#ifdef PDU_DEBUG
                    printf(KGRN "MC Dump\n" RESET);
#endif
                    status = Crypto_MC_dump(ingest);
                    break;
                case PID_ERASE_LOG:
#ifdef PDU_DEBUG
                    printf(KGRN "MC Erase\n" RESET);
#endif
                    status = Crypto_MC_erase(ingest);
                    break;
                case PID_SELF_TEST:
#ifdef PDU_DEBUG
                    printf(KGRN "MC Selftest\n" RESET);
#endif
                    status = Crypto_MC_selftest(ingest);
                    break;
                case PID_ALARM_FLAG:
#ifdef PDU_DEBUG
                    printf(KGRN "MC Reset Alarm\n" RESET);
#endif
                    status = Crypto_MC_resetalarm();
                    break;
                default:
                    printf(KRED "Error: Crypto_PDU failed interpreting MC Procedure Identification Field! \n" RESET);
                    break;
                }
                break;
            default: // ERROR
                printf(KRED "Error: Crypto_PDU failed interpreting Service Group! \n" RESET);
                break;
            }
            break;

        case 1: // User Defined Command
            switch (sdls_frame.pdu.sg)
            {
            default:
                switch (sdls_frame.pdu.pid)
                {
                case 0: // Idle Frame Trigger
#ifdef PDU_DEBUG
                    printf(KMAG "User Idle Trigger\n" RESET);
#endif
                    status = Crypto_User_IdleTrigger(ingest);
                    break;
                case 1: // Toggle Bad SPI
#ifdef PDU_DEBUG
                    printf(KMAG "User Toggle Bad SPI\n" RESET);
#endif
                    status = Crypto_User_BadSPI();
                    break;
                case 2: // Toggle Bad IV
#ifdef PDU_DEBUG
                    printf(KMAG "User Toggle Bad IV\n" RESET);
#endif
                    status = Crypto_User_BadIV();
                    break;
                case 3: // Toggle Bad MAC
#ifdef PDU_DEBUG
                    printf(KMAG "User Toggle Bad MAC\n" RESET);
#endif
                    status = Crypto_User_BadMAC();
                    break;
                case 4: // Toggle Bad FECF
#ifdef PDU_DEBUG
                    printf(KMAG "User Toggle Bad FECF\n" RESET);
#endif
                    status = Crypto_User_BadFECF();
                    break;
                case 5: // Modify Key
#ifdef PDU_DEBUG
                    printf(KMAG "User Modify Key\n" RESET);
#endif
                    status = Crypto_User_ModifyKey();
                    break;
                case 6: // Modify ActiveTM
#ifdef PDU_DEBUG
                    printf(KMAG "User Modify Active TM\n" RESET);
#endif
                    status = Crypto_User_ModifyActiveTM();
                    break;
                case 7: // Modify TM VCID
#ifdef PDU_DEBUG
                    printf(KMAG "User Modify VCID\n" RESET);
#endif
                    status = Crypto_User_ModifyVCID();
                    break;
                default:
                    printf(KRED "Error: Crypto_PDU received user defined command! \n" RESET);
                    break;
                }
            }
            break;
        }
        break;

    case 1: // Reply
        printf(KRED "Error: Crypto_PDU failed interpreting PDU Type!  Received a Reply!?! \n" RESET);
        break;
    }

#ifdef CCSDS_DEBUG
    if (status > 0)
    {
        printf(KMAG "CCSDS message put on software bus: 0x" RESET);
        for (int x = 0; x < status; x++)
        {
            printf(KMAG "%02x" RESET, (uint8_t)ingest[x]);
        }
        printf("\n");
    }
#endif

    return status;
}

/**
 * @brief Function: Crypto_Get_Managed_Parameters_For_Gvcid
 * @param tfvn: uint8
 * @param scid: uint16
 * @param vcid: uint8
 * @param managed_parameters_in: GvcidManagedParameters_t*
 * @param managed_parameters_out: GvcidManagedParameters_t**
 * @return int32: Success/Failure
 **/
int32_t Crypto_Get_Managed_Parameters_For_Gvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid,
                                                       GvcidManagedParameters_t *managed_parameters_in,
                                                       GvcidManagedParameters_t **managed_parameters_out)
{
    int32_t status = MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND;

    if (managed_parameters_in != NULL)
    {
        if (managed_parameters_in->tfvn == tfvn && managed_parameters_in->scid == scid &&
            managed_parameters_in->vcid == vcid)
        {
            *managed_parameters_out = managed_parameters_in;
            status = CRYPTO_LIB_SUCCESS;
            return status;
        }
        else
        {
            return Crypto_Get_Managed_Parameters_For_Gvcid(tfvn, scid, vcid, managed_parameters_in->next,
                                                           managed_parameters_out);
        }
    }
    else
    {
        printf(KRED "Error: Managed Parameters for GVCID(TFVN: %d, SCID: %d, VCID: %d) not found. \n" RESET, tfvn, scid,
               vcid);
        return status;
    }
}

/**
 * @brief Function: Crypto_Free_Managed_Parameters
 * Managed parameters are expected to live the duration of the program, this may not be necessary.
 * @param managed_parameters: GvcidManagedParameters_t*
 **/
void Crypto_Free_Managed_Parameters(GvcidManagedParameters_t *managed_parameters)
{
    if (managed_parameters == NULL)
    {
        return; // Nothing to free, just return!
    }
    if (managed_parameters->next != NULL)
    {
        Crypto_Free_Managed_Parameters(managed_parameters->next);
    }
    free(managed_parameters);
}

/**
 * @brief Function: Crypto_Process_Extended_Procedure_Pdu
 * @param tc_sdls_processed_frame: TC_t*
 * @param ingest: uint8_t*
 * @note TODO - Actually update based on variable config
 * */
int32_t Crypto_Process_Extended_Procedure_Pdu(TC_t *tc_sdls_processed_frame, uint8_t *ingest)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (crypto_config->has_pus_hdr == TC_HAS_PUS_HDR)
    {
        if ((tc_sdls_processed_frame->tc_pdu[0] == 0x18) && (tc_sdls_processed_frame->tc_pdu[1] == 0x80))
        // Crypto Lib Application ID
        {
#ifdef DEBUG
            printf(KGRN "Received SDLS command: " RESET);
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
            for (int x = 13; x < (13 + sdls_frame.hdr.pkt_length); x++)
            {
                sdls_frame.pdu.data[x - 13] = tc_sdls_processed_frame->tc_pdu[x];
            }

#ifdef CCSDS_DEBUG
            Crypto_ccsdsPrint(&sdls_frame);
#endif

            // Determine type of PDU
            status = Crypto_PDU(ingest, tc_sdls_processed_frame);
        }
    }
    else if (tc_sdls_processed_frame->tc_header.vcid == TC_SDLS_EP_VCID) // TC SDLS PDU with no packet layer
    {
#ifdef DEBUG
        printf(KGRN "Received SDLS command: " RESET);
#endif
        // No Packet HDR or PUS in these frames
        // SDLS TLV PDU
        sdls_frame.pdu.type = (tc_sdls_processed_frame->tc_pdu[0] & 0x80) >> 7;
        sdls_frame.pdu.uf = (tc_sdls_processed_frame->tc_pdu[0] & 0x40) >> 6;
        sdls_frame.pdu.sg = (tc_sdls_processed_frame->tc_pdu[0] & 0x30) >> 4;
        sdls_frame.pdu.pid = (tc_sdls_processed_frame->tc_pdu[0] & 0x0F);
        sdls_frame.pdu.pdu_len = (tc_sdls_processed_frame->tc_pdu[1] << 8) | tc_sdls_processed_frame->tc_pdu[2];
        for (int x = 3; x < (3 + tc_sdls_processed_frame->tc_header.fl); x++)
        {
            // Todo - Consider how this behaves with large OTAR PDUs that are larger than 1 TC in size. Most likely
            // fails. Must consider Uplink Sessions (sequence numbers).
            sdls_frame.pdu.data[x - 3] = tc_sdls_processed_frame->tc_pdu[x];
        }

#ifdef CCSDS_DEBUG
        Crypto_ccsdsPrint(&sdls_frame);
#endif

        // Determine type of PDU
        status = Crypto_PDU(ingest, tc_sdls_processed_frame);
    }
    else
    {
        // TODO - Process SDLS PDU with Packet Layer without PUS_HDR
    }

    return status;
} // End Process SDLS PDU