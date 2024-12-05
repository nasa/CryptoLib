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
#ifndef CRYPTO_CONFIG_H
#define CRYPTO_CONFIG_H

// Debug Colors
#ifdef DEBUG
#define CRYPTO_DEBUG printf("%s:%s: %d", __FILE__, __FUNCTION__, __LINE__);
#define KRED         "\x1B[31m"
#define KGRN         "\x1B[32m"
#define KYEL         "\x1B[33m"
#define KBLU         "\x1B[34m"
#define KMAG         "\x1B[35m"
#define KCYN         "\x1B[36m"
#define RESET        "\033[0m"
#else
#define CRYPTO_DEBUG
#define KRED
#define RED
#define KGRN
#define GREEN
#define KYEL
#define KBLU
#define KMAG
#define KCYN
#define RESET
#endif

// Managed Parameters Size
#define GVCID_MAN_PARAM_SIZE 250

// Max Frame Size
#define TC_MAX_FRAME_SIZE  1024
#define TM_MAX_FRAME_SIZE  1786
#define AOS_MAX_FRAME_SIZE 1786

// Spacecraft Defines
#define SCID 0x0003

// Functionality Defines
#define INCREMENT
#define FILL
// TM Fill Types - select 1
//#define TM_ZERO_FILL
#define TM_IDLE_FILL

// GVCID Defines
#define NUM_GVCID 64
#define TYPE_TC   0
#define TYPE_MAP  1
#define TYPE_TM   2
#define TYPE_AOS  3

// Specific to Authentication
#define SA_NONE        0
#define SA_UNKEYED     1
#define SA_KEYED       2
#define SA_OPERATIONAL 3
// SA State Transitions
#define SA_CREATE 5
#define SA_REKEY  6
#define SA_START  7
#define SA_STOP   2
#define SA_EXPIRE 1
#define SA_DELETE 0
// SA Additional Directives
#define SA_STATUS   8
#define SA_SETARSN  9
#define SA_SETARSNW 10

// Key State Defines
#define KEY_PREACTIVE   0
#define KEY_ACTIVE      1
#define KEY_DEACTIVATED 2
#define KEY_DESTROYED   3
#define KEY_CORRUPTED   4

// Key Length Defines
// ECS
#define AES256_GCM_KEYLEN     32
#define AES256_GCM_SIV_KEYLEN 32
#define AES256_CBC_KEYLEN     32
#define AES256_CCM_KEYLEN     32
// ACS
#define CMAC_AES256_KEYLEN 32
#define HMAC_SHA256_KEYLEN 32
#define HMAC_SHA512_KEYLEN 64

// SA Service Types
#define SA_PLAINTEXT                0
#define SA_AUTHENTICATION           1
#define SA_ENCRYPTION               2
#define SA_AUTHENTICATED_ENCRYPTION 3

// Generic Defines
#define NUM_SA              64
#define SPI_LEN             2   /* bytes */
#define SPI_MIN             0
#define SPI_MAX             NUM_SA - 1
#define KEY_SIZE            512 /* bytes */
#define KEY_ID_SIZE         8
#define MKID_MAX            128
#define NUM_KEYS            256
#define DISABLED            0
#define ENABLED             1
#define IV_SIZE             16 /* TM IV size bytes */
#define IV_SIZE_TC          4  /* TC IV size bytes */
#define REF_SIZE            250
#define OCF_SIZE            4
#define MAC_SIZE            16 /* bytes */
#define FECF_SIZE           2
#define TC_SEGMENT_HDR_SIZE 1
#define ECS_SIZE            4    /* bytes */
#define ABM_SIZE            1786 /* bytes */
#define ARSN_SIZE           20   /* total messages */
#define ARSNW_SIZE          1    /* bytes */
#define SN_SIZE             16   /* bytes */
#define PAD_SIZE            32   /* bytes */
#define CHALLENGE_SIZE      16   /* bytes */
#define CHALLENGE_MAC_SIZE  16   /* bytes */
#define BYTE_LEN            8    /* bits */
#define CRYPTOLIB_APPID    128

// Monitoring and Control Defines
#define EMV_SIZE 4  /* bytes */
#define LOG_SIZE 50 /* packets */
#define ST_OK    0x00
#define ST_NOK   0xFF

// Protocol Data Unit (PDU)
// PDU Type
#define PDU_TYPE_COMMAND 0
#define PDU_TYPE_REPLY   1
// PDU User Flag
#define PDU_USER_FLAG_TRUE  1
#define PDU_USER_FLAG_FALSE 0

// Procedure Identification (PID) - CCSDS Defined Commands
// Service Group - Key Management
#define SG_KEY_MGMT          0x00 // 0b00
#define PID_OTAR             0x01 // 0b0001
#define PID_KEY_ACTIVATION   0x02 // 0b0010
#define PID_KEY_DEACTIVATION 0x03 // 0b0011
#define PID_KEY_VERIFICATION 0x04 // 0b0100
#define PID_KEY_DESTRUCTION  0x06 // 0b0110
#define PID_KEY_INVENTORY    0x07 // 0b0111
// Service Group - Security Association Management
#define SG_SA_MGMT    0x01 // 0b01
#define PID_CREATE_SA 0x01 // 0b0001
#define PID_REKEY_SA  0x06 // 0b0110
#define PID_START_SA  0x0B // 0b1011
#define PID_STOP_SA   0x0E // 0b1110
#define PID_EXPIRE_SA 0x09 // 0b1001
#define PID_DELETE_SA 0x04 // 0b0100
#define PID_SET_ARSN  0x0A // 0b1010
#define PID_SET_ARSNW 0x05 // 0b0101
#define PID_READ_ARSN 0x00 // 0b0000
#define PID_SA_STATUS 0x0F // 0b1111
// Service Group - Security Monitoring & Control
#define SG_SEC_MON_CTRL 0x03 // 0b11
#define PID_PING        0x01 // 0b0001
#define PID_LOG_STATUS  0x02 // 0b0010
#define PID_DUMP_LOG    0x03 // 0b0011
#define PID_ERASE_LOG   0x04 // 0b0100
#define PID_SELF_TEST   0x05 // 0b0101
#define PID_ALARM_FLAG  0x07 // 0b0111

// Procedure Identification (PID) - User Defined Commands
#define PID_IDLE_FRAME_TRIGGER 0
#define PID_TOGGLE_BAD_SPI     1
#define PID_TOGGLE_BAD_IV      2
#define PID_TOGGLE_BAD_MAC     3
#define PID_TOGGLE_BAD_FECF    4
#define PID_MODIFY_KEY         5
#define PID_MODIFY_ACTIVE_TM   6
#define PID_MODIFY_VCID        7

// TC Defines
#define TC_SH_SIZE         8 /* bits */
#define TC_SN_SIZE         2
#define TC_SN_WINDOW       10               /* +/- value */
#define TC_FRAME_DATA_SIZE 1019 /* bytes */ // 1024 - 5byte header
#define TC_CADU_ASM_SIZE   4

// CCSDS PUS Defines
#define TLV_DATA_SIZE 494 /* bytes */

// TM Defines
#define TM_FRAME_DATA_SIZE 1786 /* bytes */
#define TM_FILL_SIZE       1145 /* bytes */
#define TM_PAD_SIZE        2    /* bytes */

// AOS Defines
#define AOS_FRAME_DATA_SIZE 1786 /* bytes */
#define AOS_FILL_SIZE       1145 /* bytes */

// SDLS Behavior Defines
#define SDLS_OTAR_IV_OFFSET  2
#define SDLS_KEYV_MAX_KEYS   21 /* keys */
#define SDLS_IV_LEN          12 /* bytes */
#define SDLS_KEYV_KEY_ID_LEN 2  /* bytes */
#define SDLS_KEY_LEN         32 /* bytes */
#define SDLS_KEYID_LEN       2  /* bytes */

// TC Behavior Defines
#define TC_SDLS_EP_VCID \
    4 // VCID which has SDLS PDUs (JPL uses VCIDs to determine TC type, there is no space packet layer with APIDs). Set
      // to -1 if uses SP APIDs.

// TM Behavior Defines
#define TM_CADU_HAS_ASM 1 // Skip 0x1acffc1d at beginning of each frame
// TM CADU based on ASM, currently only holds non-turbo ASM
#ifdef TM_CADU_HAS_ASM
#define TM_CADU_SIZE (TM_FRAME_DATA_SIZE + TC_CADU_ASM_SIZE)
#else
#define TM_CADU_SIZE TM_FRAME_DATA_SIZE
#endif

// Logic Behavior Defines
#define CRYPTO_FALSE 0
#define CRYPTO_TRUE  1

/*
** SAVE FILE NAME/LOCATION
*/
#define CRYPTO_SA_SAVE "sa_save_file.bin"

/*
** TC_BLOCK_SIZE
*/
#define TC_BLOCK_SIZE 16

#endif // CRYPTO_CONFIG_H
