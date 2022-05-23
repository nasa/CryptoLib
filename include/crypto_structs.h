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

#ifndef _crypto_structs_h_
#define _crypto_structs_h_

#include "crypto_config.h"

#ifdef NOS3 // NOS3/cFS build is ready
#include "common_types.h"
#else // Assume build outside of NOS3/cFS infrastructure
#include <stdint.h>
#endif

/*
** Key Definitions
*/
typedef struct
{
    uint8_t value[KEY_SIZE];
    uint32_t key_len;
    uint8_t key_state : 4;
} crypto_key_t;
#define CRYPTO_KEY_SIZE (sizeof(crypto_key_t))

typedef struct
{                       // Global Virtual Channel ID / Global MAP ID
    uint8_t tfvn : 4;   // Transfer Frame Version Number
    uint16_t scid : 16; // Spacecraft ID
    uint16_t vcid : 6;  // Virtual Channel ID
    uint8_t mapid : 6;  // Multiplexer Access Point ID
} crypto_gvcid_t;
#define CRYPTO_GVCID_SIZE (sizeof(crypto_gvcid_t))

/*
** Security Association
*/
typedef struct
{
    // Status
    uint16_t spi;  // Security Parameter Index
    uint16_t ekid; // Encryption Key ID  (Used with numerically indexed keystores, EG inmemory keyring)
    uint16_t akid; // Authentication Key ID
    char*    ek_ref; // Encryption Key Reference (Used with string-referenced keystores,EG-PKCS12 keystores, KMC crypto)
    char*    ak_ref; // Authentication Key Reference (Used with string-referenced keystores,EG-PKCS12 keystores, KMC crypto)
    uint8_t sa_state : 2;
    crypto_gvcid_t gvcid_tc_blk;
    crypto_gvcid_t gvcid_tm_blk[NUM_GVCID];
    uint8_t lpid;

    // Configuration
    uint8_t est : 1;        // Encryption Service Type
    uint8_t ast : 1;        // Authentication Service Type
    uint8_t shivf_len : 6;  // Sec. Header Transmitted IV Field Length
    uint8_t shsnf_len : 6;  // Sec. Header SN Field Length
    uint8_t shplf_len : 2;  // Sec. Header PL Field Length
    uint8_t stmacf_len : 8; // Sec. Trailer MAC Field Length
    uint8_t* ecs;           // Encryption Cipher Suite (algorithm / mode ID)
    uint8_t ecs_len : 8;    // Encryption Cipher Suite Length
    uint8_t* iv;            // Initialization Vector
    uint8_t iv_len;         // Length of entire IV
    uint8_t acs_len : 8;    // Authentication Cipher Suite Length
    uint8_t* acs;        // Authentication Cipher Suite (algorithm / mode ID)
    uint16_t abm_len : 16;  // Authentication Bit Mask Length
    uint8_t* abm;           // Authentication Bit Mask (Primary Hdr. through Security Hdr.)
    uint8_t arsn_len : 8;    // Anti-Replay Seq Num Length
    uint8_t* arsn;           // Anti-Replay Seq Num
    uint8_t arsnw_len : 8;   // Anti-Replay Seq Num Window Length
    uint16_t arsnw;          // Anti-Replay Seq Num Window

} SecurityAssociation_t;
#define SA_SIZE (sizeof(SecurityAssociation_t))

/*
** SDLS Definitions
*/
typedef struct
{
    uint8_t cwt : 1;     // Control Word Type
    uint8_t vnum : 3;    // FSR Version Number
    uint8_t af : 1;      // Alarm Field
    uint8_t bsnf : 1;    // Bad SN Flag
    uint8_t bmacf : 1;   // Bad MAC Flag
    uint8_t ispif : 1;   // Invalid SPI Flag
    uint16_t lspiu : 16; // Last SPI Used
    uint8_t snval : 8;   // SN Value (LSB)
} SDLS_FSR_t;
#define SDLS_FSR_SIZE (sizeof(SDLS_FSR_t))

typedef struct
{
    uint8_t type : 1;      // Procedure Type Flag
    uint8_t uf : 1;        // User Flag
    uint8_t sg : 2;        // Service Group Field
    uint8_t pid : 4;       // Procedure Identification Field
    uint16_t pdu_len : 16; // EP Data Field Length - BITS
    uint8_t data[TLV_DATA_SIZE];
} SDLS_TLV_t;
#define SDLS_TLV_SIZE (sizeof(SDLS_TLV_t))

typedef struct
{
    uint16_t ekid;        // Encrypted Key ID
    uint8_t ek[KEY_SIZE]; // Encrypted Key
    // uint8_t	ekcrc[4];			// Encrypted Key CRC
} SDLS_EKB_t;
#define SDLS_EKB_SIZE (sizeof(SDLS_EKB_t))

typedef struct
{
    uint16_t mkid;         // Master Key ID
    uint8_t iv[IV_SIZE];   // Initialization Vector
    SDLS_EKB_t EKB[30];    // Encrypted Key Block
    uint8_t mac[MAC_SIZE]; // Message Authentication Code
} SDLS_OTAR_t;
#define SDLS_OTAR_SIZE (sizeof(SDLS_OTAR_t))

typedef struct
{
    uint16_t kid : 16; // Key ID
} SDLS_KEY_t;
#define SDLS_KEY_SIZE (sizeof(SDLS_KEY_t))

typedef struct
{
    SDLS_KEY_t kblk[98]; // Key ID Block
} SDLS_KEY_BLK_t;
#define SDLS_KEY_BLK_SIZE (sizeof(SDLS_KEY_BLK_t))

typedef struct
{
    uint16_t kid_first : 16; // First Key ID
    uint16_t kid_last : 16;  // Last Key ID
} SDLS_KEY_INVENTORY_t;
#define SDLS_KEY_INVENTORY_SIZE (sizeof(SDLS_KEY_INVENTORY_t))

typedef struct
{
    uint16_t kid : 16;                 // Key ID
    uint8_t challenge[CHALLENGE_SIZE]; // Key Challenge
} SDLS_KEYV_CMD_BLK_t;
#define SDLS_KEYV_CMD_BLK_SIZE (sizeof(SDLS_KEYV_CMD_BLK_t))

typedef struct
{
    SDLS_KEYV_CMD_BLK_t blk[29]; // Key Verification Command Block
} SDLS_KEYV_CMD_t;
#define SDLS_KEYV_CMD_SIZE (sizeof(SDLS_KEYV_CMD_t))

typedef struct
{
    uint16_t kid : 16;                  // Key ID
    uint8_t iv[IV_SIZE];                // Key Initialization Vector
    uint8_t challenged[CHALLENGE_SIZE]; // Encrypted Challenge
    uint8_t cmac[CHALLENGE_MAC_SIZE];   // Challenge Message Authentication Code
} SDLS_KEYV_RPLY_BLK_t;
#define SDLS_KEYV_RPLY_BLK_SIZE (sizeof(SDLS_KEYV_RPLY_BLK_t))

typedef struct
{
    SDLS_KEYV_RPLY_BLK_t blk[29]; // Key Verification Reply Block
} SDLS_KEYV_RPLY_t;
#define SDLS_KEYV_RPLY_SIZE (sizeof(SDLS_KEYV_RPLY_t))

typedef struct
{
    uint16_t kid : 16; // Key ID
    uint8_t challenged[10];
} SDLS_KEYDB_CMD_t;
#define SDLS_KEYDB_CMD_SIZE (sizeof(SDLS_KEYDB_CMD_t))

typedef struct
{
    uint16_t kid : 16;      // Key ID
    uint8_t iv[IV_SIZE];    // Initialization Vector
    uint8_t challenged[10]; // Encrypted Challenge
    uint8_t cmac[4];        // Challenge Message Authentication Code
} SDLS_KEYDB_RPLY_t;
#define SDLS_KEYDB_RPLY_SIZE (sizeof(SDLS_KEYDB_RPLY_t))

typedef struct
{
    uint16_t spi : 16; // Security Parameter Index
    uint8_t lpid : 8;  // Procedure ID from Last State Transition
} SDLS_SA_STATUS_RPLY_t;
#define SDLS_SA_STATUS_RPLY_SIZE (sizeof(SDLS_SA_STATUS_RPLY_t))

typedef struct
{
    uint16_t num_se; // Number of Security Events
    uint16_t rs;     // Remaining Space
} SDLS_MC_LOG_RPLY_t;
#define SDLS_MC_LOG_RPLY_SIZE (sizeof(SDLS_MC_LOG_RPLY_t))

typedef struct
{
    uint8_t emt : 8;       // Event Message Tag
    uint16_t em_len : 16;  // Event Message Length
    uint8_t emv[EMV_SIZE]; // Event Message Value
} SDLS_MC_DUMP_RPLY_t;
#define SDLS_MC_DUMP_RPLY_SIZE (sizeof(SDLS_MC_DUMP_RPLY_t))

typedef struct
{
    SDLS_MC_DUMP_RPLY_t blk[LOG_SIZE]; // Dump Log PDU
} SDLS_MC_DUMP_BLK_RPLY_t;
#define SDLS_MC_DUMP_BLK_RPLY_SIZE (sizeof(SDLS_MC_DUMP_BLK_RPLY_t))

typedef struct
{
    uint8_t str : 8; // Self-Test Result
} SDLS_MC_ST_RPLY_t;
#define SDLS_MC_ST_RPLY_SIZE (sizeof(SDLS_MC_ST_RPLY_t))

typedef struct
{
    uint8_t snv[SN_SIZE]; // Sequence Number Value
} SDLS_MC_SN_RPLY_t;
#define SDLS_MC_SN_RPLY_SIZE (sizeof(SDLS_MC_SN_RPLY_t))

/*
** Telecommand (TC) Definitions
*/
// typedef struct __attribute__ ((packed)) //__attribute__ ((packed)) is not easily supported in CFFI python. Only add
// when CFFI properly supports packed & nonpacked structs.
typedef struct
{
    uint8_t tfvn : 2;   // Transfer Frame Version Number
    uint8_t bypass : 1; // Bypass
                        // 0 = Type A: Sequence Check, Acknowledgement
                        // 1 = Type B: Checks are bypassed
    uint8_t cc : 1;     // Control Command
                        // 0 = Type D: Transfer Frame is Data Unit
                        // 1 = Type C: Contron Command (for COP)
    uint8_t spare : 2;  // Reserved Spare - Shall be 00
    uint16_t scid : 10; // Spacecraft ID
                        // Master Channel ID (MCID) = TFVN + SCID
    uint8_t vcid : 6;   // Virtual Channel ID
    uint16_t fl : 10;   // The whole transfer frame length (max 1024)
    uint8_t fsn : 8;    // Frame sequence number, also N(S), zeroed on Type-B frames
} TC_FramePrimaryHeader_t;
#define TC_FRAME_PRIMARYHEADER_STRUCT_SIZE (sizeof(TC_FramePrimaryHeader_t))
#define TC_FRAME_HEADER_SIZE 5

typedef struct
{
    uint8_t sh : TC_SH_SIZE;  // Segment Header
    uint16_t spi;             // Security Parameter Index
    uint8_t* iv;      // Initialization Vector for encryption
    uint8_t iv_field_len;
    uint8_t* sn;   // Sequence Number for anti-replay
    uint8_t sn_field_len;
    uint8_t* pad; // Count of the used fill Bytes
    uint8_t pad_field_len;
} TC_FrameSecurityHeader_t;
#define TC_FRAME_SECHEADER_SIZE (sizeof(TC_FrameSecurityHeader_t))

typedef struct
{
    uint8_t* mac; // Message Authentication Code
    uint8_t mac_field_len;
    uint16_t fecf;         // Frame Error Control Field
} TC_FrameSecurityTrailer_t;
#define TC_FRAME_SECTRAILER_SIZE (sizeof(TC_FrameSecurityTrailer_t))

typedef struct
{
    TC_FramePrimaryHeader_t tc_header;
    TC_FrameSecurityHeader_t tc_sec_header;
    uint8_t tc_pdu[TC_FRAME_DATA_SIZE];
    uint16_t tc_pdu_len;
    TC_FrameSecurityTrailer_t tc_sec_trailer;
} TC_t;
#define TC_SIZE (sizeof(TC_t))

/*
** CCSDS Definitions
*/
typedef struct
{
    uint8_t pvn : 3;          // Packet Version Number
    uint8_t type : 1;         // Type = 1
    uint8_t shdr : 1;         // Data Field Header Flag
    uint16_t appID : 11;      // Application ID
    uint8_t seq : 2;          // Sequence Flags
    uint16_t pktid : 14;      // Sequence Count
    uint16_t pkt_length : 16; // Packet Length
} CCSDS_HDR_t;
#define CCSDS_HDR_SIZE (sizeof(CCSDS_HDR_t))

typedef struct
{
    uint8_t shf : 1;  // Secondary Header Flag
    uint8_t pusv : 3; // TC Packet PUS Version Number
    uint8_t ack : 4;  // Acknowledgement
    uint8_t st : 8;   // Service Type
    uint8_t sst : 8;  // Service Subtype
    uint8_t sid : 4;  // Source ID
    uint8_t spare : 4;
} CCSDS_PUS_t;
#define CCSDS_PUS_SIZE (sizeof(CCSDS_PUS_t))

/* unused?
typedef struct
{
  uint8_t    CmdHeader[CFE_SB_CMD_HDR_SIZE];

} Crypto_NoArgsCmd_t;
*/

typedef struct
{
    CCSDS_HDR_t hdr;
    CCSDS_PUS_t pus;
    // CCSDS_2HDR_t	cmd;
    SDLS_TLV_t pdu;
} CCSDS_t;
#define CCSDS_SIZE (sizeof(CCSDS_t))

/*
** Telemetry (TM) Definitions
*/
typedef struct
{
    uint8_t tfvn : 2;   // Transfer Frame Version Number
    uint16_t scid : 10; // Spacecraft ID
    uint8_t vcid : 3;   // Virtual Channel ID
    uint8_t ocff : 1;   // Describes wether OCF is present or not
    uint8_t mcfc : 8;   // Master Channel Frame Count (modulo-256)
    uint8_t vcfc : 8;   // Virtual Channel Frame Count (modulo-256)
    uint8_t tfsh : 1;   // Transfer Frame Secondary Header
    uint8_t sf : 1;     // Sync Flag
                        // 0 = Payload is either idle data or octet synchronized forward-ordered packets
                        // 1 = Data is a virtual channel access data unit
    uint8_t pof : 1;    // Packet Order Flag
                        // 0 = Shall be set to 0
                        // Sync Flag 1 = Undefined
    uint8_t slid : 2;   // Segment Length ID
                        // Sync Flag 0 = Shall be 11
                        // Sync Flag 1 = Undefined
    uint16_t fhp : 11;  // First Header Pointer
                        // Sync Flag 0 = Contains position of the first byte of the first packet in the data field
                        // Sync Flag 1 = undefined
    // uint8_t	tfshvn	:2;			// Transfer Frame Secondary Header Version Number - shall be 00
    // uint8_t	tfshlen	:6;			// TFSH Length (max 64 Bytes)
} TM_FramePrimaryHeader_t;
#define TM_FRAME_PRIMARYHEADER_SIZE (sizeof(TM_FramePrimaryHeader_t))

typedef struct
{
    uint16_t spi;        // Security Parameter Index
    uint8_t iv[IV_SIZE]; // Initialization Vector for encryption
    // uint8_t	sn[TM_SN_SIZE]; 	// Sequence Number for anti-replay
    // uint8_t	pad[TM_PAD_SIZE]; 	// Count of the used fill Bytes
} TM_FrameSecurityHeader_t;
#define TM_FRAME_SECHEADER_SIZE (sizeof(TM_FrameSecurityHeader_t))

typedef struct
{
    uint8_t mac[MAC_SIZE]; // Message Authentication Code
    uint8_t ocf[OCF_SIZE]; // Operational Control Field
    uint16_t fecf;         // Frame Error Control Field
} TM_FrameSecurityTrailer_t;
#define TM_FRAME_SECTRAILER_SIZE (sizeof(TM_FrameSecurityTrailer_t))

typedef struct
{
    uint8_t cwt : 1;    // Control Word Type "0"
    uint8_t cvn : 2;    // CLCW Version Number "00"
    uint8_t sf : 3;     // Status Field
    uint8_t cie : 2;    // COP In Effect
    uint8_t vci : 6;    // Virtual Channel Identification
    uint8_t spare0 : 2; // Reserved Spare
    uint8_t nrfa : 1;   // No RF Avaliable Flag
    uint8_t nbl : 1;    // No Bit Lock Flag
    uint8_t lo : 1;     // Lock-Out Flag
    uint8_t wait : 1;   // Wait Flag
    uint8_t rt : 1;     // Retransmit Flag
    uint8_t fbc : 2;    // FARM-B Counter
    uint8_t spare1 : 1; // Reserved Spare
    uint8_t rv : 8;     // Report Value
} TM_FrameCLCW_t;
#define TM_FRAME_CLCW_SIZE (sizeof(TM_FrameCLCW_t))

typedef struct
{
    TM_FramePrimaryHeader_t tm_header;
    TM_FrameSecurityHeader_t tm_sec_header;
    uint8_t tm_pdu[TM_FRAME_DATA_SIZE];
    TM_FrameSecurityTrailer_t tm_sec_trailer;
} TM_t;
#define TM_SIZE (sizeof(TM_t))

#define TM_MIN_SIZE                                                                                                    \
    (TM_FRAME_PRIMARYHEADER_SIZE + TM_FRAME_SECHEADER_SIZE + TM_FRAME_SECTRAILER_SIZE + TM_FRAME_CLCW_SIZE)

#endif