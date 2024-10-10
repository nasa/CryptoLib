/* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration.
   All Foreign Rights are Reserved to the U.S. Government.

This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including,
but not limited to, any warranty that the software will conform to, specifications any implied warranties of
merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty that the
documentation will conform to the program, or any warranty that the software will be error free.

In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
consequential damages, arising out of, resulting from, or in any way connected with the software or its documentation.
Whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was sustained from, or arose
out of the results of, or use of, the software, documentation or services provided hereunder

ITC Team
NASA IV&V
ivv-itc@lists.nasa.gov
*/
#ifndef CRYPTO_CONFIG_STRUCTS_H
#define CRYPTO_CONFIG_STRUCTS_H

#include "crypto_config.h"

#ifdef NOS3 // NOS3/cFS build is ready
#include "common_types.h"
#else // Assume build outside of NOS3/cFS infrastructure
#include <stdint.h>
#endif

// main config enums
typedef enum
{
    UNITIALIZED = 0,
    INITIALIZED
} InitStatus;
typedef enum
{
    KEY_TYPE_UNITIALIZED = 0,
    KEY_TYPE_CUSTOM,
    KEY_TYPE_INTERNAL,
    KEY_TYPE_KMC
} KeyType;
typedef enum
{
    MC_TYPE_UNITIALIZED = 0,
    MC_TYPE_CUSTOM,
    MC_TYPE_DISABLED,
    MC_TYPE_INTERNAL
} McType;
typedef enum
{
    SA_TYPE_UNITIALIZED = 0,
    SA_TYPE_CUSTOM,
    SA_TYPE_INMEMORY,
    SA_TYPE_MARIADB
} SadbType;
typedef enum
{
    CRYPTOGRAPHY_TYPE_UNITIALIZED = 0,
    CRYPTOGRAPHY_TYPE_LIBGCRYPT,
    CRYPTOGRAPHY_TYPE_KMCCRYPTO,
    CRYPTOGRAPHY_TYPE_WOLFSSL,
    CRYPTOGRAPHY_TYPE_CUSTOM
} CryptographyType;
/***************************************
** GVCID Managed Parameter enums
****************************************/
typedef enum
{
    IV_INTERNAL,
    IV_CRYPTO_MODULE
} IvType;
typedef enum
{
    TC_NO_FECF,
    TC_HAS_FECF,
    TM_NO_FECF,
    TM_HAS_FECF,
    AOS_NO_FECF,
    AOS_HAS_FECF
} FecfPresent;
typedef enum
{
    CRYPTO_TC_CREATE_FECF_FALSE,
    CRYPTO_TC_CREATE_FECF_TRUE,
    CRYPTO_TM_CREATE_FECF_FALSE,
    CRYPTO_TM_CREATE_FECF_TRUE,
    CRYPTO_AOS_CREATE_FECF_FALSE,
    CRYPTO_AOS_CREATE_FECF_TRUE
} CreateFecfBool;
typedef enum
{
    AOS_FHEC_NA=0,
    AOS_NO_FHEC,
    AOS_HAS_FHEC
} AosFhecPresent;
typedef enum
{
    AOS_IZ_NA,
    AOS_NO_IZ,
    AOS_HAS_IZ
} AosInsertZonePresent;
typedef enum
{
    TC_CHECK_FECF_FALSE,
    TC_CHECK_FECF_TRUE,
    TM_CHECK_FECF_FALSE,
    TM_CHECK_FECF_TRUE,
    AOS_CHECK_FECF_FALSE,
    AOS_CHECK_FECF_TRUE
} CheckFecfBool;
typedef enum
{
    AOS_NO_OCF,
    AOS_HAS_OCF,
    TC_OCF_NA,
    TM_NO_OCF,
    TM_HAS_OCF
} OcfPresent;
/***************************************
** TC specific enums
****************************************/
typedef enum
{
    TC_NO_SEGMENT_HDRS,
    TC_HAS_SEGMENT_HDRS,
    TM_SEGMENT_HDRS_NA, // Invalid for TM
    AOS_SEGMENT_HDRS_NA // Invalid for AOS
} TcSegmentHdrsPresent;
typedef enum
{
    TC_PROCESS_SDLS_PDUS_FALSE,
    TC_PROCESS_SDLS_PDUS_TRUE
} TcProcessSdlsPdus;
typedef enum
{
    TC_NO_PUS_HDR,
    TC_HAS_PUS_HDR
} TcPusHdrPresent;
typedef enum
{
    TC_IGNORE_SA_STATE_FALSE,
    TC_IGNORE_SA_STATE_TRUE
} TcIgnoreSaState;
typedef enum
{
    TC_IGNORE_ANTI_REPLAY_FALSE,
    TC_IGNORE_ANTI_REPLAY_TRUE
} TcIgnoreAntiReplay;
typedef enum
{
    TC_UNIQUE_SA_PER_MAP_ID_FALSE,
    TC_UNIQUE_SA_PER_MAP_ID_TRUE
} TcUniqueSaPerMapId;
typedef enum
{
    SA_INCREMENT_NONTRANSMITTED_IV_FALSE,
    SA_INCREMENT_NONTRANSMITTED_IV_TRUE
} SaIncrementNonTransmittedIvPortion;
/***************************************
** Telemetry specific enums
****************************************/
typedef enum
{
    TM_NO_SECONDARY_HDR,
    TM_HAS_SECONDARY_HDR
} TmSecondaryHdrPresent;
typedef enum
{
    CAM_ENABLED_FALSE,
    CAM_ENABLED_TRUE
} CamEnabledBool;

typedef enum
{
    CAM_LOGIN_NONE, // Using already populated cam_cookie_file
    CAM_LOGIN_KERBEROS, // Using already logged-in Kerberos to generate CAM cookies
    CAM_LOGIN_KEYTAB_FILE // using keytab file to login and generate CAM cookies
} CamLoginMethod;
/*
**  Used for selecting supported algorithms
*/
typedef enum
{
    CRYPTO_MAC_NONE,
    CRYPTO_MAC_CMAC_AES256,
    CRYPTO_MAC_HMAC_SHA256,
    CRYPTO_MAC_HMAC_SHA512
} AuthCipherSuite;
typedef enum
{
    CRYPTO_CIPHER_NONE,
    CRYPTO_CIPHER_AES256_GCM,
    CRYPTO_CIPHER_AES256_GCM_SIV,
    CRYPTO_CIPHER_AES256_CBC,
    CRYPTO_CIPHER_AES256_CBC_MAC,
    CRYPTO_CIPHER_AES256_CCM
} EncCipherSuite;

/*
** Main Crypto Configuration Block
*/
typedef struct
{
    InitStatus init_status;
    KeyType key_type;
    McType mc_type;
    SadbType sa_type;
    CryptographyType cryptography_type;
    IvType iv_type; // Whether or not CryptoLib should generate the IV
    CreateFecfBool crypto_create_fecf; // Whether or not CryptoLib is expected to calculate TC FECFs and return
                                         // payloads with the FECF
    TcProcessSdlsPdus process_sdls_pdus; // Config to process SDLS extended procedure PDUs in CryptoLib
    TcPusHdrPresent has_pus_hdr;
    TcIgnoreSaState ignore_sa_state; // TODO - add logic that uses this configuration
    TcIgnoreAntiReplay ignore_anti_replay;
    TcUniqueSaPerMapId unique_sa_per_mapid;
    CheckFecfBool crypto_check_fecf;
    uint8_t vcid_bitmask;
    uint8_t crypto_increment_nontransmitted_iv; // Whether or not CryptoLib increments the non-transmitted portion of the IV field
} CryptoConfig_t;
#define CRYPTO_CONFIG_SIZE (sizeof(CryptoConfig_t))

typedef struct _GvcidManagedParameters_t GvcidManagedParameters_t;
struct _GvcidManagedParameters_t
{
    uint8_t tfvn : 4;   // Transfer Frame Version Number
    uint16_t scid : 10; // SpacecraftID
    uint8_t vcid : 6;   // Virtual Channel ID
    FecfPresent has_fecf;
    AosFhecPresent aos_has_fhec;
    AosInsertZonePresent aos_has_iz;
    uint16_t aos_iz_len;
    TcSegmentHdrsPresent has_segmentation_hdr;
    uint16_t max_frame_size; // Maximum TC/TM Frame Length with headers
    OcfPresent has_ocf;
    int set_flag;
};
#define GVCID_MANAGED_PARAMETERS_SIZE (sizeof(GvcidManagedParameters_t))

/*
** SaDB MariaDB Configuration Block
*/
typedef struct
{
    char* mysql_username;
    char* mysql_password;
    char* mysql_hostname;
    char* mysql_database;
    uint16_t mysql_port;
    char* mysql_mtls_cert;
    char* mysql_mtls_key;
    char* mysql_mtls_ca;
    char* mysql_mtls_capath;
    uint8_t mysql_tls_verify_server;
    char* mysql_mtls_client_key_password;
    uint8_t mysql_require_secure_transport;

} SadbMariaDBConfig_t;
#define SADB_MARIADB_CONFIG_SIZE (sizeof(SadbMariaDBConfig_t))

/*
** KMC Cryptography Service Configuration Block
*/
typedef struct
{
    char* kmc_crypto_hostname;
    char* protocol;
    uint16_t kmc_crypto_port;
    char* kmc_crypto_app_uri;
    char* mtls_client_cert_path;
    char* mtls_client_cert_type; // default "PEM", supports "P12" and "DER"
    char* mtls_client_key_path;
    char* mtls_client_key_pass;
    char* mtls_ca_bundle;
    char* mtls_ca_path;
    char* mtls_issuer_cert;
    uint8_t ignore_ssl_hostname_validation;

} CryptographyKmcCryptoServiceConfig_t;
#define CRYPTOGRAPHY_KMC_CRYPTO_SERVICE_CONFIG_SIZE (sizeof(CryptographyKmcCryptoServiceConfig_t))

/*
** Common Access Manager (CAM) Configuration Block
*/
typedef struct
{
    uint8_t cam_enabled;
    char* cookie_file_path;
    char* keytab_file_path;
    char* access_manager_uri;
    char* username;
    char* cam_home;
    uint8_t login_method;

} CamConfig_t;
#define CAM_CONFIG_SIZE (sizeof(CamConfig_t))

#endif //CRYPTO_CONFIG_STRUCTS_H