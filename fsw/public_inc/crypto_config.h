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
#ifndef _crypto_config_h_
#define _crypto_config_h_

// Build Defines
    //#define BUILD_STATIC

// Debug Defines -- Use CMAKE options
    //#define ARC_DEBUG
    //#define CCSDS_DEBUG
    //#define DEBUG //(CMAKE option, not hardcoded)
    //#define FECF_DEBUG
    //#define MAC_DEBUG
    //#define OCF_DEBUG
    //#define PDU_DEBUG
    //#define SA_DEBUG
    //#define TC_DEBUG
    //#define TM_DEBUG

// Debug Colors
    #ifdef DEBUG
        #define KRED  "\x1B[31m"
        #define KGRN  "\x1B[32m"
        #define KYEL  "\x1B[33m"
        #define KBLU  "\x1B[34m"
        #define KMAG  "\x1B[35m"
        #define KCYN  "\x1B[36m"
        #define RESET "\033[0m"
    #else
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

// Spacecraft Defines
    #define SCID                        0x0003 // 0xC3D2

// Functionality Defines
    #define INCREMENT
    #define FILL
    // TM Fill Types - select 1
        //#define TM_ZERO_FILL
        #define TM_IDLE_FILL

// GVCID Defines
    #define NUM_GVCID                   64
    #define TYPE_TC                     0
    #define TYPE_MAP                    1
    #define TYPE_TM                     2

// Specific to Authentication
    #define SA_NONE						0
    #define SA_UNKEYED				    1
    #define SA_KEYED					2
    #define SA_OPERATIONAL			    3
// SA State Transitions
    #define SA_CREATE                   5
    #define SA_REKEY                    6
    #define SA_START                    7
    #define SA_STOP                     2
    #define SA_EXPIRE                   1
    #define SA_DELETE                   0
// SA Additional Directives
    #define SA_STATUS                   8
    #define SA_SETARC                   9
    #define SA_SETARCW                  10						

// Key State Defines
    #define KEY_PREACTIVE               0
    #define KEY_ACTIVE                  1
    #define KEY_DEACTIVATED             2
    #define KEY_DESTROYED               3
    #define KEY_CORRUPTED               4

// SA Service Types
    #define SA_PLAINTEXT                0
    #define SA_AUTHENTICATION           1
    #define SA_ENCRYPTION               2
    #define SA_AUTHENTICATED_ENCRYPTION 3

// Generic Defines
    #define NUM_SA						64
    #define KEY_SIZE					32
    #define KEY_ID_SIZE					8
    #define NUM_KEYS					256
    #define DISABLED					0
    #define ENABLED						1
    #define IV_SIZE						12      /* TM IV size bytes */
    #define IV_SIZE_TC                  4       /* TC IV size bytes */
    #define OCF_SIZE                    4
    #define MAC_SIZE                    16      /* bytes */
    #define FECF_SIZE                   2
    #define ECS_SIZE                    4       /* bytes */
    #define ABM_SIZE                    20      /* bytes */
    #define ARC_SIZE                    20      /* total messages */
    #define ARCW_SIZE                   1       /* bytes */
    #define SN_SIZE                     0
    #define CHALLENGE_SIZE              16      /* bytes */
    #define CHALLENGE_MAC_SIZE          16      /* bytes */

// Monitoring and Control Defines
    #define EMV_SIZE                    4       /* bytes */ 
    #define LOG_SIZE                    50     /* packets */
    #define ST_OK                       0x00
    #define ST_NOK                      0xFF

// Procedure Identification (PID)
    // Service Group - Key Management
    #define SG_KEY_MGMT                 0b00
    #define PID_OTAR                    0b0001
    #define PID_KEY_ACTIVATION          0b0010
    #define PID_KEY_DEACTIVATION        0b0011
    #define PID_KEY_VERIFICATION        0b0100
    #define PID_KEY_DESTRUCTION         0b0110
    #define PID_KEY_INVENTORY           0b0111
    // Service Group - Security Association Management
    #define SG_SA_MGMT                  0b01
    #define PID_CREATE_SA               0b0001
    #define PID_REKEY_SA                0b0110
    #define PID_START_SA                0b1011
    #define PID_STOP_SA                 0b1110
    #define PID_EXPIRE_SA               0b1001
    #define PID_DELETE_SA               0b0100
    #define PID_SET_ARSN                0b1010
    #define PID_SET_ARSNW               0b0101
    #define PID_READ_ARSN               0b0000
    #define PID_SA_STATUS               0b1111
    // Service Group - Security Monitoring & Control
    #define SG_SEC_MON_CTRL             0b11
    #define PID_PING                    0b0001
    #define PID_LOG_STATUS              0b0010
    #define PID_DUMP_LOG                0b0011
    #define PID_ERASE_LOG               0b0100
    #define PID_SELF_TEST               0b0101
    #define PID_ALARM_FLAG              0b0111

// TC Defines
    #define TC_SH_SIZE					8       /* bits */
    #define TC_SN_SIZE					0
    #define TC_SN_WINDOW				10		/* +/- value */
    #define	TC_PAD_SIZE					0
    #define	TC_FRAME_DATA_SIZE			1740 	/* bytes */

// CCSDS PUS Defines
    #define TLV_DATA_SIZE               494     /* bytes */
    #define PUS_HDR                     1 //(1=true,0=false)

// TM Defines
    #define TM_FRAME_DATA_SIZE          1740 	/* bytes */
    #define TM_FILL_SIZE                1145    /* bytes */
    #define TM_PAD_SIZE                 2       /* bytes */

// TC Behavior Defines
    #define TC_PROCESS_SDLS_PDUS        1 //(1=true,0=false)
    #define TC_SDLS_EP_VCID             4 //VCID which has SDLS PDUs (JPL uses VCIDs to determine TC type, there is no space packet layer with APIDs). Set to -1 if uses SP APIDs.
    #define VCID_BITMASK                0b111111 //Some JPL missions do not use the entire CCSDS 6 bit field for VCID.
    #define SEGMENTATION_HDR            1 //(1=true,0=false)
    #define HAS_FECF                    1 //(1=true,0=false)

// MySQL - MariaDB Defines (will be dynamically loaded properties in the future)
    #define MYSQL_USER                  "sadb_user"
    #define MYSQL_PASS                  "sadb_password"
    #define MYSQL_HOST                  "localhost"
    #define MYSQL_DB                    "sadb"
    #define MYSQL_PORT                  0
#endif