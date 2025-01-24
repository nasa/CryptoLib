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
#include <string.h>
#include "crypto.h"

/*
** Global Variables
*/
CryptographyInterface cryptography_if = NULL;
KeyInterface          key_if          = NULL;
McInterface           mc_if           = NULL;
SaInterface           sa_if           = NULL;

SadbMariaDBConfig_t *sa_mariadb_config = NULL;

CryptoConfig_t crypto_config;

CryptographyKmcCryptoServiceConfig_t *cryptography_kmc_crypto_config = NULL;
CamConfig_t                          *cam_config                     = NULL;

GvcidManagedParameters_t gvcid_managed_parameters_array[GVCID_MAN_PARAM_SIZE];
int                      gvcid_counter                     = 0;
GvcidManagedParameters_t gvcid_null_struct                 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
GvcidManagedParameters_t current_managed_parameters_struct = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// GvcidManagedParameters_t* gvcid_managed_parameters = NULL;
//  GvcidManagedParameters_t* current_managed_parameters = NULL;

// Free all configuration structs
int32_t crypto_free_config_structs(void);

/*
** Initialization Functions
*/

/**
 * @brief Function: Crypto_Init_TC_Unit_Test
 * @return int32: status
 **/
int32_t Crypto_SC_Init(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // TC
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 4, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    TC_UT_Managed_Parameters.vcid = 4;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);

    // TM
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TM_HAS_FECF, TM_SEGMENT_HDRS_NA, TM_HAS_OCF, 1786,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TM_UT_Managed_Parameters = {
        0, 0x0003, 1, TM_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TM_SEGMENT_HDRS_NA, 1786, TM_HAS_OCF, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TM_UT_Managed_Parameters);
    status = Crypto_Init();
    return status;
}

/**
 * @brief Function: Crypto_Init_TC_Unit_Test
 * @return int32: status
 **/
int32_t Crypto_Init_TC_Unit_Test(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // TC Tests
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 4;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 4, TC_HAS_FECF,
    // TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    status = Crypto_Init();
    return status;
}

/**
 * @brief Function: Crypto_Init_TM_Unit_Test
 * @return int32: status
 **/
int32_t Crypto_Init_TM_Unit_Test(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TM_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TM_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // TM Tests
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TM_HAS_FECF, TM_SEGMENT_HDRS_NA, TM_NO_OCF, 1786,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TM_UT_Managed_Parameters = {
        0, 0x0003, 0, TM_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TM_SEGMENT_HDRS_NA, 1786, TM_NO_OCF, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TM_UT_Managed_Parameters);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002c, 0, TM_NO_FECF, TM_SEGMENT_HDRS_NA, TM_NO_OCF, 1786,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    TM_UT_Managed_Parameters.scid     = 0x002c;
    TM_UT_Managed_Parameters.has_fecf = TM_NO_FECF;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TM_UT_Managed_Parameters);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0042, 0, TM_NO_FECF, TM_SEGMENT_HDRS_NA, TM_HAS_OCF, 1786,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    TM_UT_Managed_Parameters.scid    = 0x0042;
    TM_UT_Managed_Parameters.has_ocf = TM_HAS_OCF;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TM_UT_Managed_Parameters);

    status = Crypto_Init();
    return status;
}

/**
 * @brief Function: Crypto_Init_AOS_Unit_Test
 * @return int32: status
 **/
int32_t Crypto_Init_AOS_Unit_Test(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_AOS_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            AOS_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // AOS Tests
    // Crypto_Config_Add_Gvcid_Managed_Parameter(1, 0x0003, 0, AOS_HAS_FECF, AOS_SEGMENT_HDRS_NA, AOS_NO_OCF, 1786,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t AOS_UT_Managed_Parameters = {
        1, 0x0003, 0, AOS_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, AOS_SEGMENT_HDRS_NA, 1786, AOS_NO_OCF, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(AOS_UT_Managed_Parameters);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(1, 0x002c, 0, AOS_NO_FECF, AOS_SEGMENT_HDRS_NA, AOS_NO_OCF, 1786,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    AOS_UT_Managed_Parameters.scid     = 0x002c;
    AOS_UT_Managed_Parameters.has_fecf = AOS_NO_FECF;
    Crypto_Config_Add_Gvcid_Managed_Parameters(AOS_UT_Managed_Parameters);

    // Crypto_Config_Add_Gvcid_Managed_Parameter(1, 0x0042, 0, AOS_NO_FECF, AOS_SEGMENT_HDRS_NA, AOS_HAS_OCF, 1786,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    AOS_UT_Managed_Parameters.scid    = 0x0042;
    AOS_UT_Managed_Parameters.has_ocf = AOS_HAS_OCF;
    Crypto_Config_Add_Gvcid_Managed_Parameters(AOS_UT_Managed_Parameters);
    status = Crypto_Init();
    return status;
}

/**
 * @brief Function: Crypto_Init_With_Configs
 * @param crypto_config_p: CryptoConfig_t*
 * @param gvcid_managed_parameters_p: GvcidManagedParameters_t*
 * @param sa_mariadb_config_p: SadbMariaDBConfig_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_Init_With_Configs(CryptoConfig_t *crypto_config_p, GvcidManagedParameters_t *gvcid_managed_parameters_p,
                                 SadbMariaDBConfig_t                  *sa_mariadb_config_p,
                                 CryptographyKmcCryptoServiceConfig_t *cryptography_kmc_crypto_config_p)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (crypto_config_p != NULL)
    {
        memcpy(&crypto_config, crypto_config_p, CRYPTO_CONFIG_SIZE);
        crypto_config.init_status = INITIALIZED;
    }
    gvcid_managed_parameters_array[0] = *gvcid_managed_parameters_p;
    sa_mariadb_config                 = sa_mariadb_config_p;
    cryptography_kmc_crypto_config    = cryptography_kmc_crypto_config_p;
    status                            = Crypto_Init();
    return status;
}

/**
 * @brief Function Crypto_Init
 * Initializes libgcrypt, Security Associations
 **/
int32_t Crypto_Init(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (crypto_config.init_status == UNITIALIZED)
    {
        status = CRYPTO_CONFIGURATION_NOT_COMPLETE;
        printf(KRED "ERROR: CryptoLib must be configured before intializing!\n" RESET);
        return status; // No configuration set -- return!
    }
    if (gvcid_managed_parameters_array[0].set_flag == 0)
    {
        status = CRYPTO_MANAGED_PARAM_CONFIGURATION_NOT_COMPLETE;
        printf(KRED "ERROR: CryptoLib  Managed Parameters must be configured before intializing!\n" RESET);
        return status; // No Managed Parameter configuration set -- return!
    }

    // #ifdef TC_DEBUG
    // Crypto_mpPrint(gvcid_managed_parameters, 1);
    // #endif
    /* Key Interface */
    if (key_if == NULL)
    {
        if (crypto_config.key_type == KEY_TYPE_CUSTOM)
        {
            key_if = get_key_interface_custom();
        }
        else if (crypto_config.key_type == KEY_TYPE_INTERNAL)
        {
            key_if = get_key_interface_internal();
        }
        else // KEY_TYPE_KMC
        {
            key_if = get_key_interface_kmc();
        }
    }
    key_if->key_init();
    // TODO: Check and return status on error
    /* MC Interface */
    if (mc_if == NULL)
    {
        if (crypto_config.mc_type == MC_TYPE_CUSTOM)
        {
            mc_if = get_mc_interface_custom();
        }
        else if (crypto_config.mc_type == MC_TYPE_DISABLED)
        {
            mc_if = get_mc_interface_disabled();
        }
        else // MC_TYPE_INTERNAL
        {
            mc_if = get_mc_interface_internal();
        }
    }
    mc_if->mc_initialize();
    // TODO: Check and return status on error
    /* SA Interface */
    if (sa_if == NULL)
    {
        // Prepare SA type from config
        if (crypto_config.sa_type == SA_TYPE_CUSTOM)
        {
            sa_if = get_sa_interface_custom();
        }
        else if (crypto_config.sa_type == SA_TYPE_INMEMORY)
        {
            sa_if = get_sa_interface_inmemory();
        }
        else if (crypto_config.sa_type == SA_TYPE_MARIADB)
        {
            if (sa_mariadb_config == NULL)
            {
                status = CRYPTO_MARIADB_CONFIGURATION_NOT_COMPLETE;
                printf(KRED "ERROR: CryptoLib MariaDB must be configured before intializing!\n" RESET);
                return status; // MariaDB connection specified but no configuration exists, return!
            }
            sa_if = get_sa_interface_mariadb();
        }
        else
        {
            status = SADB_INVALID_SADB_TYPE;
            return status;
        } // TODO: Error stack
    }

    /* Crypto Interface */
    // Determine which cryptographic module is in use
    if (cryptography_if == NULL)
    {
        cryptography_if = get_cryptography_interface_libgcrypt();
        if (cryptography_if == NULL)
        {
            cryptography_if = get_cryptography_interface_wolfssl();
        }
        if (cryptography_if == NULL)
        {
            cryptography_if = get_cryptography_interface_custom();
        }
        if (cryptography_if == NULL)
        { // Note this needs to be the last option in the chain due to addition configuration required
            if (cryptography_kmc_crypto_config != NULL)
            {
                cryptography_if = get_cryptography_interface_kmc_crypto_service();
            }
        }
        if (cryptography_if == NULL)
        {
#ifdef DEBUG
            printf("Fatal Error: Unable to identify Cryptography Interface!\n");
#endif
            status = CRYPTOGRAPHY_INVALID_CRYPTO_INTERFACE_TYPE;
        }
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
        // Initialize the cryptography library.
        status = cryptography_if->cryptography_init();
        if (status != CRYPTO_LIB_SUCCESS)
        {
#ifdef DEBUG
            fprintf(stderr, "Fatal Error: Unable to initialize Cryptography Interface.\n");
#endif
        }
        if (status == CRYPTO_LIB_SUCCESS)
        {
            // Configure the cryptography library.
            status = cryptography_if->cryptography_config();
        }

        if (status != CRYPTO_LIB_SUCCESS)
        {
#ifdef DEBUG
            fprintf(stderr, "Fatal Error: Unable to configure Cryptography Interface.\n");
#endif
        }
        if (status == CRYPTO_LIB_SUCCESS)
        {
            // Init Security Associations
            status = sa_if->sa_init();
            if (status == CRYPTO_LIB_SUCCESS)
            {
                status = sa_if->sa_config();

                Crypto_Local_Init();
                Crypto_Local_Config();

                // TODO - Add error checking

                // Init table for CRC calculations
                Crypto_Calc_CRC_Init_Table();

                // cFS Standard Initialized Message
#ifdef DEBUG
                printf(KBLU "Crypto Lib Intialized.  Version %d.%d.%d.%d\n" RESET, CRYPTO_LIB_MAJOR_VERSION,
                       CRYPTO_LIB_MINOR_VERSION, CRYPTO_LIB_REVISION, CRYPTO_LIB_MISSION_REV);
#endif
            }
            else
            {
#ifdef DEBUG
                printf(KBLU "Error, Crypto Lib NOT Intialized, sa_init() returned error:%d.  Version .%d.%d.%d\n" RESET,
                       CRYPTO_LIB_MAJOR_VERSION, CRYPTO_LIB_MINOR_VERSION, CRYPTO_LIB_REVISION, CRYPTO_LIB_MISSION_REV);
#endif
            }
        }
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

    crypto_free_config_structs();

    // current_managed_parameters = NULL;
    current_managed_parameters_struct = gvcid_null_struct;
    for (int i = 0; i <= gvcid_counter; i++)
    {
        gvcid_managed_parameters_array[i] = gvcid_null_struct;
    }

    gvcid_counter = 0;

    if (key_if != NULL)
    {
        key_if->key_shutdown();
        key_if = NULL;
    }

    if (mc_if != NULL)
    {
        mc_if->mc_shutdown();
        mc_if = NULL;
    }

    if (sa_if != NULL)
    {
        sa_if->sa_close();
        sa_if = NULL;
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
 * @param key_type: uint8
 * @param sa_type: uint8
 * @param iv_type: uint8
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
int32_t Crypto_Config_CryptoLib(uint8_t key_type, uint8_t mc_type, uint8_t sa_type, uint8_t cryptography_type,
                                uint8_t iv_type, uint8_t crypto_create_fecf, uint8_t process_sdls_pdus,
                                uint8_t has_pus_hdr, uint8_t ignore_sa_state, uint8_t ignore_anti_replay,
                                uint8_t unique_sa_per_mapid, uint8_t crypto_check_fecf, uint8_t vcid_bitmask,
                                uint8_t crypto_increment_nontransmitted_iv)
{
    int32_t status                                   = CRYPTO_LIB_SUCCESS;
    crypto_config.init_status                        = INITIALIZED;
    crypto_config.key_type                           = key_type;
    crypto_config.mc_type                            = mc_type;
    crypto_config.sa_type                            = sa_type;
    crypto_config.cryptography_type                  = cryptography_type;
    crypto_config.iv_type                            = iv_type;
    crypto_config.crypto_create_fecf                 = crypto_create_fecf;
    crypto_config.process_sdls_pdus                  = process_sdls_pdus;
    crypto_config.has_pus_hdr                        = has_pus_hdr;
    crypto_config.ignore_sa_state                    = ignore_sa_state;
    crypto_config.ignore_anti_replay                 = ignore_anti_replay;
    crypto_config.unique_sa_per_mapid                = unique_sa_per_mapid;
    crypto_config.crypto_check_fecf                  = crypto_check_fecf;
    crypto_config.vcid_bitmask                       = vcid_bitmask;
    crypto_config.crypto_increment_nontransmitted_iv = crypto_increment_nontransmitted_iv;
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
int32_t Crypto_Config_MariaDB(char *mysql_hostname, char *mysql_database, uint16_t mysql_port,
                              uint8_t mysql_require_secure_transport, uint8_t mysql_tls_verify_server,
                              char *mysql_tls_ca, char *mysql_tls_capath, char *mysql_mtls_cert, char *mysql_mtls_key,
                              char *mysql_mtls_client_key_password, char *mysql_username, char *mysql_password)
{
    int32_t status    = CRYPTO_LIB_ERROR;
    sa_mariadb_config = (SadbMariaDBConfig_t *)calloc(1, SADB_MARIADB_CONFIG_SIZE);
    if (sa_mariadb_config != NULL)
    {
        sa_mariadb_config->mysql_username = crypto_deep_copy_string(mysql_username);
        sa_mariadb_config->mysql_password = crypto_deep_copy_string(mysql_password);
        sa_mariadb_config->mysql_hostname = crypto_deep_copy_string(mysql_hostname);
        sa_mariadb_config->mysql_database = crypto_deep_copy_string(mysql_database);
        sa_mariadb_config->mysql_port     = mysql_port;
        /*start - encrypted connection related parameters*/
        sa_mariadb_config->mysql_mtls_cert                = crypto_deep_copy_string(mysql_mtls_cert);
        sa_mariadb_config->mysql_mtls_key                 = crypto_deep_copy_string(mysql_mtls_key);
        sa_mariadb_config->mysql_mtls_ca                  = crypto_deep_copy_string(mysql_tls_ca);
        sa_mariadb_config->mysql_mtls_capath              = crypto_deep_copy_string(mysql_tls_capath);
        sa_mariadb_config->mysql_tls_verify_server        = mysql_tls_verify_server;
        sa_mariadb_config->mysql_mtls_client_key_password = crypto_deep_copy_string(mysql_mtls_client_key_password);
        sa_mariadb_config->mysql_require_secure_transport = mysql_require_secure_transport;
        /*end - encrypted connection related parameters*/
        status = CRYPTO_LIB_SUCCESS;
    }
    return status;
}

int32_t Crypto_Config_Kmc_Crypto_Service(char *protocol, char *kmc_crypto_hostname, uint16_t kmc_crypto_port,
                                         char *kmc_crypto_app, char *kmc_tls_ca_bundle, char *kmc_tls_ca_path,
                                         uint8_t kmc_ignore_ssl_hostname_validation, char *mtls_client_cert_path,
                                         char *mtls_client_cert_type, char *mtls_client_key_path,
                                         char *mtls_client_key_pass, char *mtls_issuer_cert)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    cryptography_kmc_crypto_config =
        (CryptographyKmcCryptoServiceConfig_t *)calloc(1, CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIG_SIZE);
    cryptography_kmc_crypto_config->protocol            = crypto_deep_copy_string(protocol);
    cryptography_kmc_crypto_config->kmc_crypto_hostname = crypto_deep_copy_string(kmc_crypto_hostname);
    cryptography_kmc_crypto_config->kmc_crypto_port     = kmc_crypto_port;
    if (kmc_crypto_app != NULL)
    {
        cryptography_kmc_crypto_config->kmc_crypto_app_uri = crypto_deep_copy_string(kmc_crypto_app);
    }
    else
    {
        char *crypto_service_tmp                           = (char *)"crypto-service";
        cryptography_kmc_crypto_config->kmc_crypto_app_uri = crypto_deep_copy_string(crypto_service_tmp);
    }

    cryptography_kmc_crypto_config->mtls_client_cert_path          = crypto_deep_copy_string(mtls_client_cert_path);
    cryptography_kmc_crypto_config->mtls_client_cert_type          = crypto_deep_copy_string(mtls_client_cert_type);
    cryptography_kmc_crypto_config->mtls_client_key_path           = crypto_deep_copy_string(mtls_client_key_path);
    cryptography_kmc_crypto_config->mtls_client_key_pass           = crypto_deep_copy_string(mtls_client_key_pass);
    cryptography_kmc_crypto_config->mtls_ca_bundle                 = crypto_deep_copy_string(kmc_tls_ca_bundle);
    cryptography_kmc_crypto_config->mtls_ca_path                   = crypto_deep_copy_string(kmc_tls_ca_path);
    cryptography_kmc_crypto_config->mtls_issuer_cert               = crypto_deep_copy_string(mtls_issuer_cert);
    cryptography_kmc_crypto_config->ignore_ssl_hostname_validation = kmc_ignore_ssl_hostname_validation;
    return status;
}

/**
 * @brief Function: Crypto_Config_Cam
 * @param cam_enabled: uint8_t
 * @param cookie_file_path: char*
 * @param keytab_file_path: char*
 * @param login_method: uint8_t
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_Config_Cam(uint8_t cam_enabled, char *cookie_file_path, char *keytab_file_path, uint8_t login_method,
                          char *access_manager_uri, char *username, char *cam_home)
{
    int32_t status                 = CRYPTO_LIB_SUCCESS;
    cam_config                     = (CamConfig_t *)calloc(1, CAM_CONFIG_SIZE);
    cam_config->cam_enabled        = cam_enabled;
    cam_config->cookie_file_path   = crypto_deep_copy_string(cookie_file_path);
    cam_config->keytab_file_path   = crypto_deep_copy_string(keytab_file_path);
    cam_config->login_method       = login_method;
    cam_config->access_manager_uri = crypto_deep_copy_string(access_manager_uri);
    cam_config->username           = crypto_deep_copy_string(username);
    cam_config->cam_home           = crypto_deep_copy_string(cam_home);

    return status;
}

int32_t Crypto_Config_Add_Gvcid_Managed_Parameters(GvcidManagedParameters_t gvcid_managed_parameters_struct)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (gvcid_counter > GVCID_MAN_PARAM_SIZE)
    {
        status = CRYPTO_LIB_ERR_EXCEEDS_MANAGED_PARAMETER_MAX_LIMIT;
    }
    else
    {
        gvcid_managed_parameters_array[gvcid_counter] = gvcid_managed_parameters_struct;
        gvcid_counter++;
    }

    return status;
}

/**
 * @brief Function: Crypto_Config_Add_Gvcid_Managed_Parameter
 * @param tfvn: uint8
 * @param scid: uint16
 * @param vcid: uint8
 * @param has_fecf: uint8
 * @param has_segmentation_hdr: uint8
 * @param has_ocf: uint8
 * @param max_frame_size: uint16
 * @param aos_has_fhec: uint8
 * @param aos_has_iz: uint8
 * @param aos_iz_len: uint16
 * @return int32: Success/Failure
 **/
// int32_t Crypto_Config_Add_Gvcid_Managed_Parameter(uint8_t tfvn, uint16_t scid, uint8_t vcid, uint8_t has_fecf,
//                                                   uint8_t has_segmentation_hdr, uint8_t has_ocf, uint16_t
//                                                   max_frame_size, uint8_t aos_has_fhec, uint8_t aos_has_iz, uint16_t
//                                                   aos_iz_len)
// {
//     int32_t status = CRYPTO_LIB_SUCCESS;

//     if (gvcid_managed_parameters == NULL)
//     { // case: Global Root Node not Set
//         gvcid_managed_parameters = (GvcidManagedParameters_t* )calloc(1, GVCID_MANAGED_PARAMETERS_SIZE);
//         if(gvcid_managed_parameters != NULL)
//         {
//             gvcid_managed_parameters->tfvn = tfvn;
//             gvcid_managed_parameters->scid = scid;
//             gvcid_managed_parameters->vcid = vcid;
//             gvcid_managed_parameters->has_fecf = has_fecf;
//             gvcid_managed_parameters->has_segmentation_hdr = has_segmentation_hdr;
//             gvcid_managed_parameters->has_ocf = has_ocf;
//             gvcid_managed_parameters->max_frame_size = max_frame_size;
//             gvcid_managed_parameters->aos_has_fhec = aos_has_fhec;
//             gvcid_managed_parameters->aos_has_iz = aos_has_iz;
//             gvcid_managed_parameters->aos_iz_len = aos_iz_len;
//             gvcid_managed_parameters->next = NULL;
//             return status;
//         }
//         else
//         {
//             // calloc failed - return error
//             status = CRYPTO_LIB_ERR_NULL_BUFFER;
//             return status;
//         }
//     }
//     else
//     { // Recurse through nodes and add at end
//         return crypto_config_add_gvcid_managed_parameter_recursion(tfvn, scid, vcid, has_fecf, has_segmentation_hdr,
//         has_ocf,
//                                                                    max_frame_size, aos_has_fhec, aos_has_iz,
//                                                                    aos_iz_len, gvcid_managed_parameters);
//     }
// }

int32_t crypto_free_config_structs(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (crypto_config.init_status == UNITIALIZED)
    {
        status = CRYPTO_LIB_SUCCESS;
    }
    else
    {
        // free(crypto_config); //no strings in this struct, just free it.
        crypto_config.init_status = UNITIALIZED;

        // Config structs with char* types that are malloc'd and must be freed individually.
        if (sa_mariadb_config != NULL)
        {
            free(sa_mariadb_config->mysql_username);
            free(sa_mariadb_config->mysql_password);
            free(sa_mariadb_config->mysql_hostname);
            free(sa_mariadb_config->mysql_database);
            free(sa_mariadb_config->mysql_mtls_cert);
            free(sa_mariadb_config->mysql_mtls_key);
            free(sa_mariadb_config->mysql_mtls_ca);
            free(sa_mariadb_config->mysql_mtls_capath);
            free(sa_mariadb_config->mysql_mtls_client_key_password);
            free(sa_mariadb_config);
            sa_mariadb_config = NULL;
        }
        if (cryptography_kmc_crypto_config != NULL)
        {
            free(cryptography_kmc_crypto_config->kmc_crypto_hostname);
            free(cryptography_kmc_crypto_config->protocol);
            free(cryptography_kmc_crypto_config->kmc_crypto_app_uri);
            free(cryptography_kmc_crypto_config->mtls_client_cert_path);
            free(cryptography_kmc_crypto_config->mtls_client_cert_type);
            free(cryptography_kmc_crypto_config->mtls_client_key_path);
            free(cryptography_kmc_crypto_config->mtls_client_key_pass);
            free(cryptography_kmc_crypto_config->mtls_ca_bundle);
            free(cryptography_kmc_crypto_config->mtls_ca_path);
            free(cryptography_kmc_crypto_config->mtls_issuer_cert);
            free(cryptography_kmc_crypto_config);
            cryptography_kmc_crypto_config = NULL;
        }
        if (cam_config != NULL)
        {
            free(cam_config->cookie_file_path);
            free(cam_config->keytab_file_path);
            free(cam_config->access_manager_uri);
            free(cam_config->username);
            free(cam_config->cam_home);
            free(cam_config);
            cam_config = NULL;
        }
    }
    return status;
}

/**
 * @brief Function: crypto_deep_copy_string
 *  Used to malloc a local copy of an externally referenced string. The string MUST BE null-terminated.
 * @param src_string: Pointer to externally-memory-managed string.
 * @return char*: Pointer to locally-memory-managed string copy.
 **/

char *crypto_deep_copy_string(char *src_string)
{
    if (src_string == NULL)
    {
        return NULL;
    }
    // Note that the strlen() function doesn't count the null character \0 while calculating the length.
    char *deep_copied_str = malloc((strlen(src_string) + 1) * sizeof(char));
    memcpy(deep_copied_str, src_string, strlen(src_string) + 1);
    return deep_copied_str;
}

/**
 * @brief Function: crypto_config_add_gvcid_managed_parameter_recursion
 * @param tfvn: uint8
 * @param scid: uint16
 * @param vcid: uint8
 * @param has_fecf: uint8
 * @param has_segmentation_hdr: uint8
 * @param max_frame_size: uint16
 * @param managed_parameter: GvcidManagedParameters_t*
 * @return int32: Success/Failure
 **/
// int32_t crypto_config_add_gvcid_managed_parameter_recursion(uint8_t tfvn, uint16_t scid, uint8_t vcid, uint8_t
// has_fecf,
//                                                             uint8_t has_segmentation_hdr, uint8_t has_ocf, uint16_t
//                                                             max_frame_size, uint8_t aos_has_fhec, uint8_t aos_has_iz,
//                                                             uint16_t aos_iz_len, GvcidManagedParameters_t*
//                                                             managed_parameter)
// {
//     if (managed_parameter->next != NULL)
//     {
//         return crypto_config_add_gvcid_managed_parameter_recursion(tfvn, scid, vcid, has_fecf, has_segmentation_hdr,
//         has_ocf,
//                                                                    max_frame_size, aos_has_fhec, aos_has_iz,
//                                                                    aos_iz_len, managed_parameter->next);
//     }
//     else
//     {
//         managed_parameter->next = (GvcidManagedParameters_t* )calloc(1, GVCID_MANAGED_PARAMETERS_SIZE);
//         managed_parameter->next->tfvn = tfvn;
//         managed_parameter->next->scid = scid;
//         managed_parameter->next->vcid = vcid;
//         managed_parameter->next->has_fecf = has_fecf;
//         managed_parameter->next->has_segmentation_hdr = has_segmentation_hdr;
//         managed_parameter->next->has_ocf = has_ocf;
//         managed_parameter->next->max_frame_size = max_frame_size;
//         managed_parameter->next->next = NULL;
//         return CRYPTO_LIB_SUCCESS;
//     }
// }

/**
 * @brief Function: Crypto_Local_Config
 * Initalizes TM Configuration, Log, and Keyrings
 **/
void Crypto_Local_Config(void)
{
    // Initial TM configuration
    // tm_frame.tm_sec_header.spi = 1;

    if (log_count == 0)
    {
        // Initialize Log
        log_summary.num_se = 2;
        log_summary.rs     = LOG_SIZE;
        // Add a two messages to the log
        log_summary.rs--;
        mc_log.blk[log_count].emt      = STARTUP_EID;
        mc_log.blk[log_count].emv[0]   = 0x4E;
        mc_log.blk[log_count].emv[1]   = 0x41;
        mc_log.blk[log_count].emv[2]   = 0x53;
        mc_log.blk[log_count].emv[3]   = 0x41;
        mc_log.blk[log_count++].em_len = 4;
        log_summary.rs--;
        mc_log.blk[log_count].emt      = STARTUP_EID;
        mc_log.blk[log_count].emv[0]   = 0x4E;
        mc_log.blk[log_count].emv[1]   = 0x41;
        mc_log.blk[log_count].emv[2]   = 0x53;
        mc_log.blk[log_count].emv[3]   = 0x41;
        mc_log.blk[log_count++].em_len = 4;
    }
}

/**
 * @brief Function: Crypto_Local_Init
 * Initalize TM Frame, CLCW
 **/
void Crypto_Local_Init(void)
{
    // int x;

    // Possibly just zero out the entire frame here
    // since copying in entire test frame

    /***
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
    for (x = 0; x < IV_SIZE; x++)
    { // Initialization Vector
        *(tm_frame.tm_sec_header.iv + x) = 0x00;
    }
    // TM Payload Data Unit
    for (x = 0; x < TM_FRAME_DATA_SIZE; x++)
    { // Zero TM PDU
        tm_frame.tm_pdu[x] = 0x00;
    }
    // TM Security Trailer
    for (x = 0; x < MAC_SIZE; x++)
    { // Zero TM Message Authentication Code
        tm_frame.tm_sec_trailer.mac[x] = 0x00;
    }
    for (x = 0; x < OCF_SIZE; x++)
    { // Zero TM Operational Control Field
        tm_frame.tm_sec_trailer.ocf[x] = 0x00;
    }
    tm_frame.tm_sec_trailer.fecf = 0xFECF;
    **/

    // Initialize CLCW
    clcw.cwt    = 0; // Control Word Type "0"
    clcw.cvn    = 0; // CLCW Version Number "00"
    clcw.sf     = 0; // Status Field
    clcw.cie    = 1; // COP In Effect
    clcw.vci    = 0; // Virtual Channel Identification
    clcw.spare0 = 0; // Reserved Spare
    clcw.nrfaf  = 0; // No RF Avaliable Flag
    clcw.nblf   = 0; // No Bit Lock Flag
    clcw.lof    = 0; // Lock-Out Flag
    clcw.waitf  = 0; // Wait Flag
    clcw.rtf    = 0; // Retransmit Flag
    clcw.fbc    = 0; // FARM-B Counter
    clcw.spare1 = 0; // Reserved Spare
    clcw.rv     = 0; // Report Value

    // Initialize Frame Security Report
    report.cwt   = 1; // Control Word Type "0b1""
    report.fvn   = 4; // FSR Version "0b100""
    report.af    = 0; // Alarm Field
    report.bsnf  = 0; // Bad SN Flag
    report.bmacf = 0; // Bad MAC Flag
    report.bsaf  = 0; // Invalid SPI Flag
    report.lspi  = 0; // Last SPI Used
    report.snval = 0; // SN Value (LSB)
}

/**
 * @brief Function: Crypto_Calc_CRC_Init_Table
 * Initialize CRC Table
 **/
void Crypto_Calc_CRC_Init_Table(void)
{
    uint16_t     val;
    uint32_t     poly = 0xEDB88320;
    uint32_t     crc;
    unsigned int i;
    unsigned int j;

    // http://create.stephan-brumme.com/crc32/
    for (i = 0; i <= 0xFF; i++)
    {
        crc = i;
        for (j = 0; j < 8; j++)
        {
            crc = (crc >> 1) ^ (-(int)(crc & 1) & poly);
        }
        crc32Table[i] = crc;
        // printf("crc32Table[%d] = 0x%08x \n", i, crc32Table[i]);
    }

    // Code provided by ESA
    for (i = 0; i < 256; i++)
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
