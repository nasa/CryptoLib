/* Copyright (C) 2009 - 2017 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
any warranty that the software will be error free.

In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
arising out of, resulting from, or in any way connected with the software or its documentation.  Whether or not based upon warranty,
contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
documentation or services provided hereunder

ITC Team
NASA IV&V
ivv-itc@lists.nasa.gov
*/
#ifndef _crypto_structs_h_
#define _crypto_structs_h_

#include "crypto_config.h"

#ifdef NOS3 //NOS3/cFS build is ready
#include "common_types.h"
#else //Assume build outside of NOS3/cFS infrastructure
#include "common_types_minimum.h"
#endif

/*
** Key Definitions
*/
typedef struct
{
    uint8 value[KEY_SIZE];
    uint8 key_state:4;
} crypto_key_t;
#define CRYPTO_KEY_SIZE     (sizeof(crypto_key_t))

typedef struct
{   // Global Virtual Channel ID / Global MAP ID
    uint8  tfvn  :  4;  // Transfer Frame Version Number
    uint16 scid  : 16;  // Spacecraft ID
    uint16 vcid  :  6;  // Virtual Channel ID
    uint8  mapid :  6;  // Multiplexer Access Point ID
} crypto_gvcid_t;
#define CRYPTO_GVCID_SIZE 	(sizeof(crypto_gvcid_t))

/*
** Security Association
*/
typedef struct
{
    // Status
    uint16                      spi;     //Security Parameter Index
    uint16 						ekid;    // Encryption Key ID
    uint16                      akid;    // Authentication Key ID
    uint8						sa_state:2;
    crypto_gvcid_t				gvcid_tc_blk;
    crypto_gvcid_t				gvcid_tm_blk[NUM_GVCID];
    uint8                       lpid;

    // Configuration
    uint8		est		:1;			// Encryption Service Type
    uint8		ast		:1;			// Authentication Service Type
    uint8		shivf_len:6;		// Sec. Header IV Field Length
    uint8		shsnf_len:6;		// Sec. Header SN Field Length
    uint8		shplf_len:2;		// Sec. Header PL Field Length
    uint8		stmacf_len:8;		// Sec. Trailer MAC Field Length
    uint8		ecs_len	:8;			// Encryption Cipher Suite Length
    uint8		ecs[ECS_SIZE];		// Encryption Cipher Suite (algorithm / mode ID)
    uint8		iv_len	:8;			// Initialization Vector Length
    uint8		iv[IV_SIZE];		// Initialization Vector
    uint8		acs_len	:8;			// Authentication Cipher Suite Length
    uint8		acs		:8;			// Authentication Cipher Suite (algorithm / mode ID)
    uint16		abm_len	:16;		// Authentication Bit Mask Length
    uint8		abm[ABM_SIZE];		// Authentication Bit Mask (Primary Hdr. through Security Hdr.)
    uint8		arc_len	:8;			// Anti-Replay Counter Length
    uint8		arc[ARC_SIZE];		// Anti-Replay Counter
    uint8		arcw_len:8;			// Anti-Replay Counter Window Length
    uint8		arcw[ARCW_SIZE];	// Anti-Replay Counter Window
    
} SecurityAssociation_t;
#define SA_SIZE	(sizeof(SecurityAssociation_t))

/*
** SDLS Definitions
*/	
typedef struct
{
    uint8	cwt		:1;			// Control Word Type
    uint8	vnum	:3;			// FSR Version Number
    uint8	af		:1;			// Alarm Field
    uint8	bsnf	:1;			// Bad SN Flag
    uint8	bmacf	:1;			// Bad MAC Flag
    uint8	ispif	:1;			// Invalid SPI Flag
    uint16	lspiu	:16;		// Last SPI Used
    uint8	snval	:8;			// SN Value (LSB)
} SDLS_FSR_t;
#define SDLS_FSR_SIZE	(sizeof(SDLS_FSR_t))

typedef struct
{
    uint8	type	:1;			// Procedure Type Flag
    uint8	uf		:1;			// User Flag
    uint8	sg		:2;			// Service Group Field
    uint8	pid		:4;			// Procedure Identification Field
    uint16	pdu_len	:16;		// EP Data Field Length - BITS
    uint8	data[TLV_DATA_SIZE];	
} SDLS_TLV_t;
#define SDLS_TLV_SIZE	(sizeof(SDLS_TLV_t))

typedef struct
{
    uint16	ekid;				// Encrypted Key ID
    uint8	ek[KEY_SIZE];		// Encrypted Key
    //uint8	ekcrc[4];			// Encrypted Key CRC
} SDLS_EKB_t;
#define SDLS_EKB_SIZE	(sizeof(SDLS_EKB_t))

typedef struct
{
    uint16		mkid;				// Master Key ID
    uint8		iv[IV_SIZE];		// Initialization Vector
    SDLS_EKB_t	EKB[30];			// Encrypted Key Block
    uint8   	mac[MAC_SIZE];		// Message Authentication Code
} SDLS_OTAR_t;
#define SDLS_OTAR_SIZE	(sizeof(SDLS_OTAR_t))

typedef struct
{
    uint16		kid		:16;		// Key ID
} SDLS_KEY_t;
#define SDLS_KEY_SIZE	(sizeof(SDLS_KEY_t))

typedef struct
{
    SDLS_KEY_t	kblk[98];			// Key ID Block
} SDLS_KEY_BLK_t;
#define SDLS_KEY_BLK_SIZE	(sizeof(SDLS_KEY_BLK_t))

typedef struct
{
    uint16      kid_first   :16;            // First Key ID
    uint16      kid_last    :16;            // Last Key ID
} SDLS_KEY_INVENTORY_t;
#define SDLS_KEY_INVENTORY_SIZE (sizeof(SDLS_KEY_INVENTORY_t))

typedef struct
{
    uint16		kid		:16;		        // Key ID
    uint8       challenge[CHALLENGE_SIZE];  // Key Challenge
} SDLS_KEYV_CMD_BLK_t;
#define SDLS_KEYV_CMD_BLK_SIZE	(sizeof(SDLS_KEYV_CMD_BLK_t))

typedef struct
{
    SDLS_KEYV_CMD_BLK_t	blk[29];	// Key Verification Command Block
} SDLS_KEYV_CMD_t;
#define SDLS_KEYV_CMD_SIZE	(sizeof(SDLS_KEYV_CMD_t))

typedef struct
{
    uint16		kid		:16;		        // Key ID
    uint8       iv[IV_SIZE];                // Key Initialization Vector
    uint8       challenged[CHALLENGE_SIZE]; // Encrypted Challenge
    uint8       cmac[CHALLENGE_MAC_SIZE];   // Challenge Message Authentication Code
} SDLS_KEYV_RPLY_BLK_t;
#define SDLS_KEYV_RPLY_BLK_SIZE	(sizeof(SDLS_KEYV_RPLY_BLK_t))

typedef struct
{
    SDLS_KEYV_RPLY_BLK_t blk[29];		// Key Verification Reply Block	
} SDLS_KEYV_RPLY_t;
#define SDLS_KEYV_RPLY_SIZE	(sizeof(SDLS_KEYV_RPLY_t))

typedef struct
{
    uint16		kid		:16;		// Key ID
    uint8		challenged[10];		
} SDLS_KEYDB_CMD_t;
#define SDLS_KEYDB_CMD_SIZE	(sizeof(SDLS_KEYDB_CMD_t))

typedef struct
{
    uint16		kid		:16;		// Key ID
    uint8		iv[IV_SIZE];		// Initialization Vector
    uint8		challenged[10];		// Encrypted Challenge
    uint8		cmac[4];			// Challenge Message Authentication Code		
} SDLS_KEYDB_RPLY_t;
#define SDLS_KEYDB_RPLY_SIZE	(sizeof(SDLS_KEYDB_RPLY_t))

typedef struct
{
    uint16		spi		:16;		// Security Parameter Index
    uint8		lpid	:8;			// Procedure ID from Last State Transition
} SDLS_SA_STATUS_RPLY_t;
#define SDLS_SA_STATUS_RPLY_SIZE (sizeof(SDLS_SA_STATUS_RPLY_t))

typedef struct
{
    uint16		num_se;				// Number of Security Events
    uint16		rs;					// Remaining Space
} SDLS_MC_LOG_RPLY_t;
#define SDLS_MC_LOG_RPLY_SIZE (sizeof(SDLS_MC_LOG_RPLY_t))

typedef struct
{
    uint8		emt		:8;			// Event Message Tag
    uint16		em_len	:16;		// Event Message Length
    uint8		emv[EMV_SIZE];		// Event Message Value
} SDLS_MC_DUMP_RPLY_t;
#define SDLS_MC_DUMP_RPLY_SIZE (sizeof(SDLS_MC_DUMP_RPLY_t))

typedef struct
{
    SDLS_MC_DUMP_RPLY_t blk[LOG_SIZE];	// Dump Log PDU
} SDLS_MC_DUMP_BLK_RPLY_t;
#define SDLS_MC_DUMP_BLK_RPLY_SIZE (sizeof(SDLS_MC_DUMP_BLK_RPLY_t))

typedef struct
{
    uint8		str		:8;			// Self-Test Result
} SDLS_MC_ST_RPLY_t;
#define SDLS_MC_ST_RPLY_SIZE (sizeof(SDLS_MC_ST_RPLY_t))

typedef struct
{
    uint8		snv[SN_SIZE];		// Sequence Number Value
} SDLS_MC_SN_RPLY_t;
#define SDLS_MC_SN_RPLY_SIZE (sizeof(SDLS_MC_SN_RPLY_t))


/*
** Telecommand (TC) Definitions
*/
typedef struct __attribute__ ((packed))
{
    uint8 	tfvn	:2;			// Transfer Frame Version Number
    uint8 	bypass	:1;			// Bypass
                                    // 0 = Type A: Sequence Check, Acknowledgement
                                    // 1 = Type B: Checks are bypassed
    uint8 	cc		:1;			// Control Command
                                    // 0 = Type D: Transfer Frame is Data Unit
                                    // 1 = Type C: Contron Command (for COP)
    uint8	spare	:2;			// Reserved Spare - Shall be 00
    uint16	scid	:10;		// Spacecraft ID
                                    // Master Channel ID (MCID) = TFVN + SCID
    uint8 	vcid	:6;			// Virtual Channel ID
    uint16	fl		:10;		// The whole transfer frame length (max 1024)
    uint8	fsn		:8;			// Frame sequence number, also N(S), zeroed on Type-B frames
} TC_FramePrimaryHeader_t;
#define TC_FRAME_PRIMARYHEADER_SIZE     (sizeof(TC_FramePrimaryHeader_t))

typedef struct
{
    uint8   sh:TC_SH_SIZE;		// Segment Header
    uint16	spi;				// Security Parameter Index
    uint8	iv[IV_SIZE]; 	    // Initialization Vector for encryption
    //uint8	sn[TC_SN_SIZE]; 	// Sequence Number for anti-replay
    //uint8	pad[TC_PAD_SIZE]; 	// Count of the used fill Bytes
} TC_FrameSecurityHeader_t;
#define TC_FRAME_SECHEADER_SIZE     (sizeof(TC_FrameSecurityHeader_t))

typedef struct
{
    uint8   mac[MAC_SIZE];	// Message Authentication Code
    uint16	fecf;				// Frame Error Control Field
} TC_FrameSecurityTrailer_t;
#define TC_FRAME_SECTRAILER_SIZE     (sizeof(TC_FrameSecurityTrailer_t))

typedef struct
{
    TC_FramePrimaryHeader_t		tc_header;
    TC_FrameSecurityHeader_t	tc_sec_header;
    uint8 						tc_pdu[TC_FRAME_DATA_SIZE];
    uint16                      tc_pdu_len;
    TC_FrameSecurityTrailer_t	tc_sec_trailer;
} TC_t;
#define TC_SIZE     (sizeof(TC_t))

/*
** CCSDS Definitions
*/
typedef struct
{
    uint8		pvn					:3;			// Packet Version Number
    uint8		type				:1;			// Type = 1
    uint8		shdr				:1;			// Data Field Header Flag
    uint16		appID				:11;		// Application ID
    uint8		seq					:2;			// Sequence Flags
    uint16		pktid				:14;		// Sequence Count
    uint16		pkt_length			:16;		// Packet Length
} CCSDS_HDR_t;
#define CCSDS_HDR_SIZE (sizeof(CCSDS_HDR_t))

typedef struct
{
    uint8		shf					:1;			// Secondary Header Flag
    uint8		pusv				:3;			// TC Packet PUS Version Number
    uint8		ack					:4;			// Acknowledgement
    uint8		st					:8;			// Service Type
    uint8		sst					:8;			// Service Subtype
    uint8		sid					:4;			// Source ID
    uint8		spare				:4;			
} CCSDS_PUS_t;
#define CCSDS_PUS_SIZE (sizeof(CCSDS_PUS_t))

/* unused?
typedef struct
{
  uint8    CmdHeader[CFE_SB_CMD_HDR_SIZE];

} Crypto_NoArgsCmd_t;
*/

typedef struct
{
    CCSDS_HDR_t		hdr;
    CCSDS_PUS_t		pus;
    //CCSDS_2HDR_t	cmd;
    SDLS_TLV_t		pdu;
} CCSDS_t;
#define CCSDS_SIZE	(sizeof(CCSDS_t))

/*
** Telemetry (TM) Definitions
*/
typedef struct
{
    uint8	tfvn	:2;			// Transfer Frame Version Number
    uint16	scid	:10;		// Spacecraft ID
    uint8	vcid	:3;			// Virtual Channel ID
    uint8	ocff	:1;			// Describes wether OCF is present or not
    uint8	mcfc	:8;			// Master Channel Frame Count (modulo-256)
    uint8	vcfc	:8;			// Virtual Channel Frame Count (modulo-256)
    uint8	tfsh	:1;			// Transfer Frame Secondary Header
    uint8	sf		:1;			// Sync Flag
                                    // 0 = Payload is either idle data or octet synchronized forward-ordered packets
                                    // 1 = Data is a virtual channel access data unit
    uint8	pof		:1;			// Packet Order Flag
                                    // 0 = Shall be set to 0
                                    // Sync Flag 1 = Undefined
    uint8	slid	:2;			// Segment Length ID
                                    // Sync Flag 0 = Shall be 11
                                    // Sync Flag 1 = Undefined
    uint16	fhp		:11;		// First Header Pointer
                                    // Sync Flag 0 = Contains position of the first byte of the first packet in the data field
                                    // Sync Flag 1 = undefined
    //uint8	tfshvn	:2;			// Transfer Frame Secondary Header Version Number - shall be 00
    //uint8	tfshlen	:6;			// TFSH Length (max 64 Bytes)
} TM_FramePrimaryHeader_t;
#define TM_FRAME_PRIMARYHEADER_SIZE     (sizeof(TM_FramePrimaryHeader_t))

typedef struct
{
    uint16	spi;				// Security Parameter Index
    uint8	iv[IV_SIZE]; 	    // Initialization Vector for encryption
    //uint8	sn[TM_SN_SIZE]; 	// Sequence Number for anti-replay
    //uint8	pad[TM_PAD_SIZE]; 	// Count of the used fill Bytes
} TM_FrameSecurityHeader_t;
#define TM_FRAME_SECHEADER_SIZE     (sizeof(TM_FrameSecurityHeader_t))

typedef struct
{
    uint8   mac[MAC_SIZE];		// Message Authentication Code
    uint8	ocf[OCF_SIZE];		// Operational Control Field
    uint16	fecf;				// Frame Error Control Field
} TM_FrameSecurityTrailer_t;
#define TM_FRAME_SECTRAILER_SIZE     (sizeof(TM_FrameSecurityTrailer_t))

typedef struct
{
    uint8 	cwt		:1;			// Control Word Type "0"
    uint8 	cvn		:2;			// CLCW Version Number "00"
    uint8	sf		:3;			// Status Field
    uint8	cie		:2;			// COP In Effect
    uint8	vci		:6;			// Virtual Channel Identification
    uint8	spare0	:2;			// Reserved Spare
    uint8	nrfa	:1;			// No RF Avaliable Flag
    uint8 	nbl		:1;			// No Bit Lock Flag
    uint8	lo		:1;			// Lock-Out Flag
    uint8 	wait	:1;			// Wait Flag
    uint8	rt		:1;			// Retransmit Flag
    uint8	fbc		:2;			// FARM-B Counter
    uint8	spare1	:1;			// Reserved Spare
    uint8	rv		:8;			// Report Value
} TM_FrameCLCW_t;
#define TM_FRAME_CLCW_SIZE (sizeof(TM_FrameCLCW_t))

typedef struct
{
    TM_FramePrimaryHeader_t		tm_header;
    TM_FrameSecurityHeader_t	tm_sec_header;
    uint8 						tm_pdu[TM_FRAME_DATA_SIZE];
    TM_FrameSecurityTrailer_t	tm_sec_trailer;
} TM_t;
#define TM_SIZE     (sizeof(TM_t))

#define TM_MIN_SIZE (TM_FRAME_PRIMARYHEADER_SIZE + TM_FRAME_SECHEADER_SIZE + TM_FRAME_SECTRAILER_SIZE + TM_FRAME_CLCW_SIZE)

#endif