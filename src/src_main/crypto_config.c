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
** Global Variables
*/
SadbRoutine sadb_routine = NULL;
CryptographyInterface cryptography_if = NULL;
CryptoConfig_t *crypto_config = NULL;
SadbMariaDBConfig_t *sadb_mariadb_config = NULL;
CryptographyKmcCryptoServiceConfig_t *cryptography_kmc_crypto_config = NULL;
GvcidManagedParameters_t *gvcid_managed_parameters = NULL;
GvcidManagedParameters_t *current_managed_parameters = NULL;

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
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
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
                                 SadbMariaDBConfig_t *sadb_mariadb_config_p, CryptographyKmcCryptoServiceConfig_t *cryptography_kmc_crypto_config_p)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    crypto_config = crypto_config_p;
    gvcid_managed_parameters = gvcid_managed_parameters_p;
    sadb_mariadb_config = sadb_mariadb_config_p;
    cryptography_kmc_crypto_config = cryptography_kmc_crypto_config_p;
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

    // Prepare Cryptographic Library from config
    if(crypto_config->cryptography_type == CRYPTOGRAPHY_TYPE_LIBGCRYPT)
    {
        cryptography_if = get_cryptography_interface_libgcrypt();
    }
    else if (crypto_config->cryptography_type == CRYPTOGRAPHY_TYPE_KMCCRYPTO)
    {
        if (cryptography_kmc_crypto_config == NULL)
        {
            status = CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIGURATION_NOT_COMPLETE;
            printf(KRED "ERROR: CryptoLib KMC Crypto Service Interface must be configured before intializing!\n" RESET);
            return status;
        }
        cryptography_if = get_cryptography_interface_kmc_crypto_service();
    }
    else
    {
        status = CRYPTOGRAPHY_INVALID_CRYPTO_INTERFACE_TYPE;
        return status;
    }

    // Initialize the cryptography library.
    status = cryptography_if->cryptography_init();
    if(status != CRYPTO_LIB_SUCCESS){
        fprintf(stderr, "Fatal Error: Unable to initialize Cryptography Interface.\n");
        return status;
    }

    // Configure the cryptography library.
    status = cryptography_if->cryptography_config();

    if(status != CRYPTO_LIB_SUCCESS){
        fprintf(stderr, "Fatal Error: Unable to configure Cryptography Interface.\n");
        return status;
    }


    // Init Security Associations
    status = sadb_routine->sadb_init();
    if (status==CRYPTO_LIB_SUCCESS)
    {
        status = sadb_routine->sadb_config();

        Crypto_Local_Init();
        Crypto_Local_Config();

        // TODO - Add error checking

        // Init table for CRC calculations
        Crypto_Calc_CRC_Init_Table();

        // cFS Standard Initialized Message
        printf(KBLU "Crypto Lib Intialized.  Version %d.%d.%d.%d\n" RESET, CRYPTO_LIB_MAJOR_VERSION,
               CRYPTO_LIB_MINOR_VERSION, CRYPTO_LIB_REVISION, CRYPTO_LIB_MISSION_REV);
        }
    else
    {
        printf(KBLU "Error, Crypto Lib NOT Intialized, sadb_init() returned error:%d.  Version .%d.%d.%d\n" RESET, CRYPTO_LIB_MAJOR_VERSION,
           CRYPTO_LIB_MINOR_VERSION, CRYPTO_LIB_REVISION, CRYPTO_LIB_MISSION_REV); 
    }

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

    if (cryptography_if != NULL)
    {
        cryptography_if->cryptography_shutdown();
        cryptography_if = NULL;
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
int32_t Crypto_Config_CryptoLib(uint8_t sadb_type, uint8_t cryptography_type, uint8_t crypto_create_fecf, uint8_t process_sdls_pdus,
                                uint8_t has_pus_hdr, uint8_t ignore_sa_state, uint8_t ignore_anti_replay,
                                uint8_t unique_sa_per_mapid, uint8_t crypto_check_fecf, uint8_t vcid_bitmask)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    crypto_config = (CryptoConfig_t *)calloc(1, CRYPTO_CONFIG_SIZE);
    crypto_config->sadb_type = sadb_type;
    crypto_config->cryptography_type = cryptography_type;
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
 * @param mysql_username: char*
 * @param mysql_password: char*
 * @param mysql_hostname: char*
 * @param mysql_database: char*
 * @param mysql_port: uint16
 * @return int32: Success/Failure 
 **/
/*set parameters for an encrypted TLS connection*/
int32_t Crypto_Config_MariaDB(char* mysql_username, char* mysql_password, char* mysql_hostname, char* mysql_database, uint16_t mysql_port, uint8_t encrypted_connection, char* ssl_cert, char* ssl_key, char* ssl_ca, char* ssl_capath)
{
    int32_t status = CRYPTO_LIB_ERROR;
    sadb_mariadb_config = (SadbMariaDBConfig_t*)calloc(1, SADB_MARIADB_CONFIG_SIZE);
    if (NULL!=sadb_mariadb_config)
    {
        sadb_mariadb_config->mysql_username=mysql_username;
        sadb_mariadb_config->mysql_password=mysql_password;
        sadb_mariadb_config->mysql_hostname=mysql_hostname;
        sadb_mariadb_config->mysql_database=mysql_database;
        sadb_mariadb_config->mysql_port=mysql_port;
        /*start - encrypted connection related parameters*/
        sadb_mariadb_config->encrypted_connection = encrypted_connection; 
        sadb_mariadb_config->ssl_cert = ssl_cert; 
        sadb_mariadb_config->ssl_key = ssl_key; 
        sadb_mariadb_config->ssl_ca = ssl_ca; 
        sadb_mariadb_config->ssl_capath = ssl_capath; 
        /*end - encrypted connection related parameters*/
        status = CRYPTO_LIB_SUCCESS; 
    }
    return status;
}

extern int32_t Crypto_Config_Kmc_Crypto_Service(char* protocol, char *kmc_crypto_hostname, uint16_t kmc_crypto_port, char *kmc_crypto_app_uri, char *mtls_client_cert_path, char *mtls_client_cert_type,
                                                char *mtls_client_key_path,char *mtls_client_key_pass,char *mtls_ca_bundle, char *mtls_ca_path, char *mtls_issuer_cert,
                                                uint8_t ignore_ssl_hostname_validation)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    cryptography_kmc_crypto_config = (CryptographyKmcCryptoServiceConfig_t *)calloc(1, CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIG_SIZE);
    cryptography_kmc_crypto_config->protocol = protocol;
    cryptography_kmc_crypto_config->kmc_crypto_hostname = kmc_crypto_hostname;
    cryptography_kmc_crypto_config->kmc_crypto_port = kmc_crypto_port;
    if(kmc_crypto_app_uri != NULL){
        cryptography_kmc_crypto_config->kmc_crypto_app_uri = kmc_crypto_app_uri;
    } else{
        cryptography_kmc_crypto_config->kmc_crypto_app_uri = "crypto-service";
    }

    cryptography_kmc_crypto_config->mtls_client_cert_path = mtls_client_cert_path;
    cryptography_kmc_crypto_config->mtls_client_cert_type = mtls_client_cert_type;
    cryptography_kmc_crypto_config->mtls_client_key_path = mtls_client_key_path;
    cryptography_kmc_crypto_config->mtls_client_key_pass = mtls_client_key_pass;
    cryptography_kmc_crypto_config->mtls_ca_bundle = mtls_ca_bundle;
    cryptography_kmc_crypto_config->mtls_ca_path = mtls_ca_path;
    cryptography_kmc_crypto_config->mtls_issuer_cert = mtls_issuer_cert;
    cryptography_kmc_crypto_config->ignore_ssl_hostname_validation = ignore_ssl_hostname_validation;
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
        if(gvcid_managed_parameters != NULL)
        {
            gvcid_managed_parameters->tfvn = tfvn;
            gvcid_managed_parameters->scid = scid;
            gvcid_managed_parameters->vcid = vcid;
            gvcid_managed_parameters->has_fecf = has_fecf;
            gvcid_managed_parameters->has_segmentation_hdr = has_segmentation_hdr;
            gvcid_managed_parameters->next = NULL;
            return status;
        }
        else
        {
            // calloc failed - return error
            status = CRYPTO_LIB_ERR_NULL_BUFFER;
            return status;
        }
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
int32_t crypto_config_add_gvcid_managed_parameter_recursion(uint8_t tfvn, uint16_t scid, uint8_t vcid, uint8_t has_fecf,
                                                            uint8_t has_segmentation_hdr,
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
