/* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory, including, but not
   limited to, any warranty that the software will conform to specifications, any implied warranties of merchantability, fitness
   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
   any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
   arising out of, resulting from, or in any way connected with the software or its documentation, whether or not based upon warranty,
   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
   documentation or services provided hereunder.

   ITC Team
   NASA IV&V
   jstar-development-team@mail.nasa.gov
*/

#ifndef _crypto_h_
#define _crypto_h_

/*
** Crypto Includes
*/

#ifdef NOS3 //NOS3/cFS build is ready
#include "cfe.h"
#else //Assume build outside of NOS3/cFS infrastructure
#include <stdint.h>
#include "osapi_minimum.h"
#endif

#include "crypto_structs.h"
#include "crypto_config_structs.h"

#define CRYPTO_LIB_MAJOR_VERSION    1
#define CRYPTO_LIB_MINOR_VERSION    2
#define CRYPTO_LIB_REVISION         0
#define CRYPTO_LIB_MISSION_REV      0

/*
** Prototypes
*/

// Crypto Library Configuration functions
extern int32_t Crypto_Config_CryptoLib(uint8_t sadb_type, uint8_t crypto_create_fecf, uint8_t process_sdls_pdus, uint8_t has_pus_hdr, uint8_t ignore_sa_state, uint8_t ignore_anti_replay, uint8_t unique_sa_per_mapid, uint8_t crypto_check_fecf, uint8_t vcid_bitmask);
extern int32_t Crypto_Config_MariaDB(uint8_t* mysql_username, uint8_t* mysql_password, uint8_t* mysql_hostname, uint8_t* mysql_database, uint16_t mysql_port);
extern int32_t Crypto_Config_Add_Gvcid_Managed_Parameter(uint8_t tfvn, uint16_t scid, uint8_t vcid, uint8_t has_fecf, uint8_t has_segmentation_hdr);

// Initialization
extern int32_t Crypto_Init(void); // Initialize CryptoLib After Configuration Calls
extern int32_t Crypto_Init_With_Configs(CryptoConfig_t* crypto_config_p,GvcidManagedParameters_t* gvcid_managed_parameters_p,SadbMariaDBConfig_t* sadb_mariadb_config_p); // Initialize CryptoLib With Application Defined Configuration
extern int32_t Crypto_Init_Unit_Test(void); // Initialize CryptoLib with unit test default Configurations

// Cleanup
extern int32_t Crypto_Shutdown(void); // Free all allocated memory

// Telecommand (TC)
extern int32_t Crypto_TC_ApplySecurity(const uint8_t* p_in_frame, const uint16_t in_frame_length, \
                                      uint8_t **pp_enc_frame, uint16_t *p_enc_frame_len);
extern int32_t Crypto_TC_ProcessSecurity(uint8_t* ingest, int*  len_ingest, TC_t* tc_sdls_processed_frame);
// Telemetry (TM)
extern int32_t Crypto_TM_ApplySecurity(uint8_t* ingest, int* len_ingest);
extern int32_t Crypto_TM_ProcessSecurity(uint8_t* ingest, int* len_ingest);
// Advanced Orbiting Systems (AOS)
extern int32_t Crypto_AOS_ApplySecurity(uint8_t* ingest, int* len_ingest);
extern int32_t Crypto_AOS_ProcessSecurity(uint8_t* ingest, int* len_ingest);
// Security Functions
extern int32_t Crypto_ApplySecurity(uint8_t* ingest, int* len_ingest);
extern int32_t Crypto_ProcessSecurity(uint8_t* ingest, int* len_ingest);

// Data stores used in multiple components
extern CCSDS_t sdls_frame;
extern TM_t tm_frame;
extern crypto_key_t ek_ring[NUM_KEYS];
// Assisting functions used in multiple components
extern uint8_t Crypto_Prep_Reply(uint8_t* ingest, uint8_t appID);
extern int32_t Crypto_increment(uint8_t *num, int length);

//Global configuration structs
extern CryptoConfig_t* crypto_config;
extern SadbMariaDBConfig_t* sadb_mariadb_config;
extern GvcidManagedParameters_t* gvcid_managed_parameters;
extern GvcidManagedParameters_t* current_managed_parameters;

#endif