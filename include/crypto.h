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

#ifndef CRYPTO_H
#define CRYPTO_H

/*
** Crypto Includes
*/
#ifdef NOS3 // NOS3/cFS build is ready
#include "cfe.h"
#else // Assume build outside of NOS3/cFS infrastructure
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <string.h>
#include "crypto_config.h"
#include "crypto_config_structs.h"
#include "crypto_error.h"
#include "crypto_events.h"
#include "crypto_print.h"
#include "crypto_structs.h"
#include "sa_interface.h"
#include "cryptography_interface.h"
#include "key_interface.h"
#include "mc_interface.h"
#include "sa_interface.h"

/*
** Crypto Version
*/
#define CRYPTO_LIB_MAJOR_VERSION 1
#define CRYPTO_LIB_MINOR_VERSION 2
#define CRYPTO_LIB_REVISION 2
#define CRYPTO_LIB_MISSION_REV 0

/*
** SAVE FILE NAME/LOCATION
*/
#define CRYPTO_SA_SAVE "sa_save_file.bin"

/*
** TC_BLOCK_SIZE
*/
#define TC_BLOCK_SIZE 16

/*
** User Prototypes
*/

// Crypto Library Configuration functions
extern int32_t Crypto_Config_CryptoLib(uint8_t key_type, uint8_t mc_type, uint8_t sa_type, uint8_t cryptography_type, 
                                       uint8_t iv_type, uint8_t crypto_create_fecf, uint8_t process_sdls_pdus, 
                                       uint8_t has_pus_hdr, uint8_t ignore_sa_state, uint8_t ignore_anti_replay,
                                       uint8_t unique_sa_per_mapid, uint8_t crypto_check_fecf, uint8_t vcid_bitmask, 
                                       uint8_t crypto_increment_nontransmitted_iv);
extern int32_t Crypto_Config_MariaDB(char* mysql_hostname, char* mysql_database, uint16_t mysql_port,
                                     uint8_t mysql_require_secure_transport, uint8_t mysql_tls_verify_server,
                                     char* mysql_tls_ca, char* mysql_tls_capath, char* mysql_mtls_cert,
                                     char* mysql_mtls_key,
                                     char* mysql_mtls_client_key_password, char* mysql_username, char* mysql_password);
extern int32_t Crypto_Config_Kmc_Crypto_Service(char* protocol, char* kmc_crypto_hostname, uint16_t kmc_crypto_port,
                                                char* kmc_crypto_app, char* kmc_tls_ca_bundle, char* kmc_tls_ca_path,
                                                uint8_t kmc_ignore_ssl_hostname_validation, char* mtls_client_cert_path,
                                                char* mtls_client_cert_type, char* mtls_client_key_path,
                                                char* mtls_client_key_pass, char* mtls_issuer_cert);
extern int32_t Crypto_Config_Cam(uint8_t cam_enabled, char* cookie_file_path, char* keytab_file_path, uint8_t login_method, char* access_manager_uri, char* username, char* cam_home);
extern int32_t Crypto_Config_Add_Gvcid_Managed_Parameter(uint8_t tfvn, uint16_t scid, uint8_t vcid, uint8_t has_fecf,
                                                         uint8_t has_segmentation_hdr, uint16_t max_frame_size, uint8_t aos_has_fhec,
                                                         uint8_t aos_has_iz, uint16_t aos_iz_len);

// Initialization
extern int32_t Crypto_Init(void); // Initialize CryptoLib After Configuration Calls
extern int32_t Crypto_Init_With_Configs(
    CryptoConfig_t* crypto_config_p, GvcidManagedParameters_t* gvcid_managed_parameters_p,
    SadbMariaDBConfig_t* sa_mariadb_config_p,
    CryptographyKmcCryptoServiceConfig_t* cryptography_kmc_crypto_config_p); // Initialize CryptoLib With Application Defined Configuration
extern int32_t Crypto_TC_Init(void);
extern int32_t Crypto_Init_TC_Unit_Test(void);      // Initialize CryptoLib with unit test default Configurations
extern int32_t Crypto_Init_TM_Unit_Test(void);      // Initialize CryptoLib with unit test default Configurations
extern int32_t Crypto_Init_AOS_Unit_Test(void);      // Initialize CryptoLib with unit test default Configurations

// Cleanup
extern int32_t Crypto_Shutdown(void); // Free all allocated memory

// Telecommand (TC)
extern int32_t Crypto_TC_ApplySecurity(const uint8_t* p_in_frame, const uint16_t in_frame_length,
                                       uint8_t** pp_enc_frame, uint16_t* p_enc_frame_len);
extern int32_t Crypto_TC_ProcessSecurity(uint8_t* ingest, int *len_ingest, TC_t* tc_sdls_processed_frame);
extern int32_t Crypto_TC_ApplySecurity_Cam(const uint8_t* p_in_frame, const uint16_t in_frame_length,
                                       uint8_t** pp_enc_frame, uint16_t* p_enc_frame_len, char* cam_cookies);
extern int32_t Crypto_TC_ProcessSecurity_Cam(uint8_t* ingest, int *len_ingest, TC_t* tc_sdls_processed_frame, char* cam_cookies);

int32_t Crypto_TC_Get_SA_Service_Type(uint8_t* sa_service_type, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TC_Parse_Check_FECF(uint8_t* ingest, int* len_ingest, TC_t* tc_sdls_processed_frame);
int32_t Crypto_TC_Nontransmitted_IV_Increment(SecurityAssociation_t* sa_ptr, TC_t* tc_sdls_processed_frame);
int32_t Crypto_TC_Nontransmitted_SN_Increment(SecurityAssociation_t* sa_ptr, TC_t* tc_sdls_processed_frame);
int32_t Crypto_TC_Check_ACS_Keylen(crypto_key_t* akp, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TC_Check_ECS_Keylen(crypto_key_t* ekp, SecurityAssociation_t* sa_ptr);
void Crypto_TC_Safe_Free_Ptr(uint8_t* ptr);
int32_t Crypto_TC_Do_Decrypt(uint8_t sa_service_type, uint8_t ecs_is_aead_algorithm, crypto_key_t* ekp, SecurityAssociation_t* sa_ptr, uint8_t* aad, TC_t* tc_sdls_processed_frame, uint8_t* ingest, uint16_t tc_enc_payload_start_index, uint16_t aad_len, char* cam_cookies, crypto_key_t* akp, uint8_t segment_hdr_len);
int32_t Crypto_TC_Process_Sanity_Check(int* len_ingest);
int32_t Crypto_TC_Prep_AAD(TC_t* tc_sdls_processed_frame, uint8_t fecf_len,  uint8_t sa_service_type, uint8_t ecs_is_aead_algorithm, uint16_t* aad_len, SecurityAssociation_t* sa_ptr, uint8_t segment_hdr_len, uint8_t* ingest, uint8_t** aad);
int32_t Crypto_TC_Get_Keys(crypto_key_t** ekp, crypto_key_t** akp, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TC_Check_IV_ARSN(SecurityAssociation_t* sa_ptr,TC_t* tc_sdls_processed_frame);
uint32_t Crypto_TC_Sanity_Validations(TC_t* tc_sdls_processed_frame, SecurityAssociation_t** sa_ptr);
void Crypto_TC_Get_Ciper_Mode_TCP(uint8_t sa_service_type, uint32_t* encryption_cipher, uint8_t* ecs_is_aead_algorithm, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TC_Get_Ciper_Mode_TCA(uint8_t sa_service_type, uint32_t* encryption_cipher, uint8_t* ecs_is_aead_algorithm, SecurityAssociation_t* sa_ptr);
void Crypto_TC_Calc_Lengths(uint8_t* fecf_len, uint8_t* segment_hdr_len);
void Crypto_TC_Set_Segment_Header(TC_t* tc_sdls_processed_frame, uint8_t* ingest, int* byte_idx);
int32_t Crypto_TC_Check_CMD_Frame_Flag(uint8_t header_cc);
int32_t Crypto_TC_Validate_SA_Service_Type(uint8_t sa_service_type);
int32_t Crypto_TC_Handle_Enc_Padding(uint8_t sa_service_type, uint32_t* pkcs_padding, uint16_t* p_enc_frame_len, uint16_t* new_enc_frame_header_field_length, uint16_t tf_payload_len, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TC_Frame_Validation(uint16_t* p_enc_frame_len);
int32_t Crypto_TC_Accio_Buffer(uint8_t** p_new_enc_frame, uint16_t* p_enc_frame_len);
int32_t Crypto_TC_ACS_Algo_Check(SecurityAssociation_t* sa_ptr);
int32_t Crypto_TC_Check_IV_Setup(SecurityAssociation_t* sa_ptr, uint8_t* p_new_enc_frame, uint16_t *index);
int32_t Crypto_TC_Do_Encrypt_PLAINTEXT(uint8_t sa_service_type, SecurityAssociation_t* sa_ptr, uint16_t* mac_loc, uint16_t tf_payload_len, uint8_t segment_hdr_len, uint8_t* p_new_enc_frame, crypto_key_t* ekp, uint8_t** aad, uint8_t ecs_is_aead_algorithm, uint16_t *index_p, const uint8_t* p_in_frame, char* cam_cookies, uint32_t pkcs_padding);
void Crypto_TC_Do_Encrypt_NONPLAINTEXT(uint8_t sa_service_type, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TC_Do_Encrypt(uint8_t sa_service_type, SecurityAssociation_t* sa_ptr, uint16_t* mac_loc, uint16_t tf_payload_len, uint8_t segment_hdr_len, uint8_t* p_new_enc_frame, crypto_key_t* ekp, uint8_t** aad, uint8_t ecs_is_aead_algorithm, uint16_t *index_p, const uint8_t* p_in_frame, char* cam_cookies, uint32_t pkcs_padding, uint16_t new_enc_frame_header_field_length, uint16_t* new_fecf);
int32_t Crypto_TC_Check_Init_Setup(uint16_t in_frame_length);
int32_t Crypto_TC_Sanity_Setup(const uint8_t* p_in_frame, const uint16_t in_frame_length);
int32_t Crytpo_TC_Validate_TC_Temp_Header(const uint16_t in_frame_length, TC_FramePrimaryHeader_t temp_tc_header, const uint8_t* p_in_frame, uint8_t* map_id, uint8_t* segmentation_hdr, SecurityAssociation_t** sa_ptr);
int32_t Crypto_TC_Finalize_Frame_Setup(uint8_t sa_service_type, uint32_t* pkcs_padding, uint16_t* p_enc_frame_len, uint16_t* new_enc_frame_header_field_length, uint16_t tf_payload_len, SecurityAssociation_t** sa_ptr, uint8_t** p_new_enc_frame);
void Crypto_TC_Handle_Padding(uint32_t pkcs_padding, SecurityAssociation_t* sa_ptr, uint8_t* p_new_enc_frame, uint16_t* index);
int32_t Crypto_TC_Set_IV(SecurityAssociation_t* sa_ptr, uint8_t* p_new_enc_frame, uint16_t* index);




// Telemetry (TM)
extern int32_t Crypto_TM_ApplySecurity(uint8_t* pTfBuffer);
extern int32_t Crypto_TM_ProcessSecurity(uint8_t* p_ingest, uint16_t len_ingest, uint8_t** pp_processed_frame, uint16_t *p_decrypted_length);
// Advanced Orbiting Systems (AOS)
extern int32_t Crypto_AOS_ApplySecurity(uint8_t* pTfBuffer);
extern int32_t Crypto_AOS_ProcessSecurity(uint8_t* p_ingest, uint16_t len_ingest, uint8_t** pp_processed_frame, uint16_t* p_decrypted_length);


// Crypo Error Support Functions
extern char* Crypto_Get_Error_Code_Enum_String(int32_t crypto_error_code);

/*
** Internal Prototypes
*/
// Telemetry (TM)
int32_t Crypto_TM_Sanity_Check(uint8_t* pTfBuffer);
int32_t Crypto_TM_Determine_SA_Service_Type(uint8_t* sa_service_type, SecurityAssociation_t* sa_ptr);
void Crypto_TM_Check_For_Secondary_Header(uint8_t* pTfBuffer, uint16_t* idx);
int32_t Crypto_TM_IV_Sanity_Check(uint8_t* sa_service_type, SecurityAssociation_t* sa_ptr);
void Crypto_TM_PKCS_Padding(uint32_t* pkcs_padding, SecurityAssociation_t* sa_ptr, uint8_t* pTfBuffer, uint16_t* idx_p);
void Crypto_TM_Handle_Managed_Parameter_Flags(uint16_t* pdu_len);
int32_t Crypto_TM_Get_Keys(crypto_key_t** ekp, crypto_key_t** akp, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TM_Do_Encrypt_NONPLAINTEXT(uint8_t sa_service_type, uint16_t* aad_len, int* mac_loc, uint16_t* idx_p, uint16_t pdu_len, uint8_t* pTfBuffer, uint8_t* aad, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TM_Do_Encrypt_NONPLAINTEXT_AEAD_Logic(uint8_t sa_service_type, uint8_t ecs_is_aead_algorithm, uint8_t* pTfBuffer, uint16_t pdu_len, uint16_t data_loc, crypto_key_t* ekp, crypto_key_t* akp, uint32_t pkcs_padding, int* mac_loc, uint16_t* aad_len, uint8_t* aad, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TM_Do_Encrypt_Handle_Increment(uint8_t sa_service_type, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TM_Do_Encrypt(uint8_t sa_service_type, SecurityAssociation_t* sa_ptr, uint16_t* aad_len, int* mac_loc, uint16_t* idx_p, uint16_t pdu_len, uint8_t* pTfBuffer, uint8_t* aad, uint8_t ecs_is_aead_algorithm, uint16_t data_loc, crypto_key_t* ekp, crypto_key_t* akp, uint32_t pkcs_padding, uint16_t* new_fecf);
void Crypto_TM_ApplySecurity_Debug_Print(uint16_t idx, uint16_t pdu_len, SecurityAssociation_t* sa_ptr);
int32_t Crypto_TM_Process_Setup(uint16_t len_ingest, uint16_t* byte_idx, uint8_t* p_ingest, uint8_t* secondary_hdr_len);
int32_t Crypto_TM_Determine_Cipher_Mode(uint8_t sa_service_type, SecurityAssociation_t* sa_ptr, uint32_t* encryption_cipher, uint8_t* ecs_is_aead_algorithm);
int32_t Crypto_TM_FECF_Setup(uint8_t* p_ingest, uint16_t len_ingest);
int32_t Crypto_TM_Parse_Mac_Prep_AAD(uint8_t sa_service_type, uint8_t* p_ingest, int mac_loc, SecurityAssociation_t* sa_ptr, uint16_t* aad_len, uint16_t byte_idx, uint8_t* aad);
int32_t Crypto_TM_Do_Decrypt_AEAD(uint8_t sa_service_type, uint8_t* p_ingest, uint8_t* p_new_dec_frame, uint16_t byte_idx, uint16_t pdu_len, crypto_key_t* ekp, SecurityAssociation_t* sa_ptr, uint8_t iv_loc, int mac_loc, uint16_t aad_len, uint8_t* aad);
int32_t Crypto_TM_Do_Decrypt_NONAEAD(uint8_t sa_service_type, uint16_t pdu_len, uint8_t* p_new_dec_frame, uint16_t byte_idx, uint8_t* p_ingest, crypto_key_t* akp, crypto_key_t* ekp, SecurityAssociation_t* sa_ptr, uint8_t iv_loc, int mac_loc, uint16_t aad_len, uint8_t* aad);
void Crypto_TM_Calc_PDU_MAC(uint16_t* pdu_len, uint16_t byte_idx, SecurityAssociation_t* sa_ptr, int* mac_loc);
int32_t Crypto_TM_Do_Decrypt(uint8_t sa_service_type, SecurityAssociation_t* sa_ptr, uint8_t ecs_is_aead_algorithm, uint16_t byte_idx, uint8_t* p_new_dec_frame, uint16_t pdu_len, uint8_t* p_ingest, crypto_key_t* ekp, crypto_key_t* akp, uint8_t iv_loc, int mac_loc, uint16_t aad_len, uint8_t* aad, uint8_t** pp_processed_frame, uint16_t* p_decrypted_length);
void Crypto_TM_Process_Debug_Print(uint16_t byte_idx, uint16_t pdu_len, SecurityAssociation_t* sa_ptr);


extern uint8_t Crypto_Prep_Reply(uint8_t* ingest, uint8_t appID);
extern int32_t Crypto_increment(uint8_t* num, int length);
// int32_t  Crypto_Get_tcPayloadLength(TC_t* tc_frame, SecurityAssociation_t* sa_ptr);
int32_t Crypto_Get_tmLength(int len);
uint8_t Crypto_Is_AEAD_Algorithm(uint32_t cipher_suite_id);
void Crypto_TM_updatePDU(uint8_t* ingest, int len_ingest);
void Crypto_TM_updateOCF(void);
uint8_t* Crypto_Prepare_TC_AAD(uint8_t* buffer, uint16_t len_aad, uint8_t* abm_buffer);
uint32_t Crypto_Prepare_TM_AAD(const uint8_t* buffer, uint16_t len_aad, const uint8_t* abm_buffer, uint8_t* aad);
uint32_t Crypto_Prepare_AOS_AAD(const uint8_t* buffer, uint16_t len_aad, const uint8_t* abm_buffer, uint8_t* aad);
void Crypto_Local_Config(void);
void Crypto_Local_Init(void);
// int32_t  Crypto_gcm_err(int gcm_err);
int32_t Crypto_window(uint8_t* actual, uint8_t* expected, int length, int window);
// int32_t Crypto_compare_less_equal(uint8_t* actual, uint8_t* expected, int length);
// int32_t  Crypto_FECF(int fecf, uint8_t* ingest, int len_ingest,TC_t* tc_frame);
uint16_t Crypto_Calc_FECF(const uint8_t* ingest, int len_ingest);
void Crypto_Calc_CRC_Init_Table(void);
uint16_t Crypto_Calc_CRC16(uint8_t* data, int size);
int32_t Crypto_Check_Anti_Replay(SecurityAssociation_t *sa_ptr, uint8_t *arsn, uint8_t *iv);
int32_t Crypto_Get_ECS_Algo_Keylen(uint8_t algo);
int32_t Crypto_Get_ACS_Algo_Keylen(uint8_t algo);

int32_t Crypto_Check_Anti_Replay_Verify_Pointers(SecurityAssociation_t* sa_ptr, uint8_t* arsn, uint8_t* iv);
int32_t Crypto_Check_Anti_Replay_ARSNW(SecurityAssociation_t* sa_ptr, uint8_t* arsn, int8_t* arsn_valid);
int32_t Crypto_Check_Anti_Replay_GCM(SecurityAssociation_t* sa_ptr, uint8_t* iv, int8_t* iv_valid);

// Key Management Functions
int32_t Crypto_Key_OTAR(void);
int32_t Crypto_Key_update(uint8_t state);
int32_t Crypto_Key_inventory(uint8_t* );
int32_t Crypto_Key_verify(uint8_t* , TC_t* tc_frame);

// Security Monitoring & Control Procedure
int32_t Crypto_MC_ping(uint8_t* ingest);
int32_t Crypto_MC_status(uint8_t* ingest);
int32_t Crypto_MC_dump(uint8_t* ingest);
int32_t Crypto_MC_erase(uint8_t* ingest);
int32_t Crypto_MC_selftest(uint8_t* ingest);
int32_t Crypto_SA_readARSN(uint8_t* ingest);
int32_t Crypto_MC_resetalarm(void);

// User Functions
int32_t Crypto_User_IdleTrigger(uint8_t* ingest);
int32_t Crypto_User_BadSPI(void);
int32_t Crypto_User_BadIV(void);
int32_t Crypto_User_BadMAC(void);
int32_t Crypto_User_BadFECF(void);
int32_t Crypto_User_ModifyKey(void);
int32_t Crypto_User_ModifyActiveTM(void);
int32_t Crypto_User_ModifyVCID(void);

// SA Save Functions
int32_t sa_perform_save(SecurityAssociation_t* sa);

// Determine Payload Data Unit
int32_t Crypto_Process_Extended_Procedure_Pdu(TC_t* tc_sdls_processed_frame, uint8_t* ingest);
int32_t Crypto_PDU(uint8_t* ingest, TC_t* tc_frame);

// Helper length functions
int32_t Crypto_Get_Security_Header_Length(SecurityAssociation_t* sa_ptr);
int32_t Crypto_Get_Security_Trailer_Length(SecurityAssociation_t* sa_ptr);

// Managed Parameter Functions
int32_t Crypto_Get_Managed_Parameters_For_Gvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid,
                                                       GvcidManagedParameters_t* managed_parameters_in,
                                                       GvcidManagedParameters_t** managed_parameters_out);
int32_t crypto_config_add_gvcid_managed_parameter_recursion(uint8_t tfvn, uint16_t scid, uint8_t vcid,
                                                                   uint8_t has_fecf, uint8_t has_segmentation_hdr,
                                                                   uint16_t max_frame_size, uint8_t aos_has_fhec,
                                                                   uint8_t aos_has_iz, uint16_t aos_iz_len,
                                                                   GvcidManagedParameters_t* managed_parameter);
void Crypto_Free_Managed_Parameters(GvcidManagedParameters_t* managed_parameters);

// Project-wide support functions
extern char* crypto_deep_copy_string(char* src_string);

/*
** Extern Global Variables
*/ 
// Data stores used in multiple components
extern CCSDS_t sdls_frame;
// extern TM_t tm_frame;
extern uint8_t tm_frame[1786];
extern TM_FramePrimaryHeader_t tm_frame_pri_hdr; 
extern TM_FrameSecurityHeader_t tm_frame_sec_hdr; // Used to reduce bit math duplication
// exterm AOS_t aos_frame
extern AOS_FramePrimaryHeader_t aos_frame_pri_hdr; 
extern AOS_FrameSecurityHeader_t aos_frame_sec_hdr; // Used to reduce bit math duplication

// Global configuration structs
extern CryptoConfig_t crypto_config;
extern SadbMariaDBConfig_t* sa_mariadb_config;
extern CryptographyKmcCryptoServiceConfig_t* cryptography_kmc_crypto_config;
extern CamConfig_t* cam_config;
extern GvcidManagedParameters_t* gvcid_managed_parameters;
extern GvcidManagedParameters_t* current_managed_parameters;
extern KeyInterface key_if;
extern McInterface mc_if;
extern SaInterface sa_if;
extern CryptographyInterface cryptography_if;

// extern crypto_key_t ak_ring[NUM_KEYS];
extern CCSDS_t sdls_frame;
extern SadbMariaDBConfig_t* sa_mariadb_config;
extern GvcidManagedParameters_t* gvcid_managed_parameters;
extern GvcidManagedParameters_t* current_managed_parameters;
// OCF
extern uint8_t ocf;
extern SDLS_FSR_t report;
extern Telemetry_Frame_Clcw_t clcw;
// Flags
extern SDLS_MC_LOG_RPLY_t log_summary;
extern SDLS_MC_DUMP_BLK_RPLY_t mc_log;
extern uint8_t log_count;
extern uint16_t tm_offset;
// ESA Testing - 0 = disabled, 1 = enabled
extern uint8_t badSPI;
extern uint8_t badIV;
extern uint8_t badMAC;
extern uint8_t badFECF;
//  CRC
extern uint32_t crc32Table[256];
extern uint16_t crc16Table[256];

#endif //CRYPTO_H