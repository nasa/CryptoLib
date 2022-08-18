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
#include <string.h>

/*
** Static Library Declaration
*/
#ifdef BUILD_STATIC
CFS_MODULE_DECLARE_LIB(crypto);
#endif

/*
** Global Variables
*/
// crypto_key_t ak_ring[NUM_KEYS];
CCSDS_t sdls_frame;
TM_t tm_frame;
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
** Assisting Functions
*/

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
    if(cipher_suite_id == CRYPTO_CIPHER_AES256_GCM)
    {
        return CRYPTO_TRUE;
    }
    else
    {
        return CRYPTO_FALSE;
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
int32_t Crypto_increment(uint8_t* num, int length)
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
    {
        for(i=0; i<length; i++)
        {
            num[i] = 0;
        }
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_window
 * Determines if a value is within the expected positive window of values
 * @param actual: uint8*
 * @param expected: uint8*
 * @param length: int
 * @param window: int
 * @return int32: Success/Failure
 **/
int32_t Crypto_window(uint8_t* actual, uint8_t* expected, int length, int window)
{
    int status = CRYPTO_LIB_ERROR;
    int result = 0;
    uint8_t temp[length];
    int i;
    int j;

    // Check Null Pointers
    if (actual == NULL)
    {
#ifdef DEBUG
        printf("Crypto_Window expected ptr is NULL\n");
#endif
        return status;        
    }
    if (expected == NULL)
    {
#ifdef DEBUG
        printf("Crypto_Window expected ptr is NULL\n");
#endif
        return status;
    }
    // Check for special case where received value is all 0's and expected is all 0's (won't have -1 in sa!)
    // Received ARSN is: 00000000, SA ARSN is: 00000000
    uint8_t zero_case = CRYPTO_TRUE;
    for(i = 0; i < length; i++)
    {
        if (actual[i] != 0 || expected[i] != 0 )
        {
            zero_case = CRYPTO_FALSE;
        }
    }
    if(zero_case == CRYPTO_TRUE)
    {
        status = CRYPTO_LIB_SUCCESS;
        return status;
    }

    memcpy(temp, expected, length);
    for (i = 0; i < window; i++)
    {
        // Recall - the stored IV or ARSN is the last valid one received, check against next expected
        Crypto_increment(&temp[0], length);

#ifdef DEBUG
        printf("Checking Frame Against Incremented Window:\n");
        Crypto_hexprint(temp,length);
#endif
        
        result = 0;
        /* go from right (least significant) to left (most signifcant) */
        for (j = length - 1; j >= 0; --j)
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
int32_t Crypto_compare_less_equal(uint8_t* actual, uint8_t* expected, int length)
{
    int status = CRYPTO_LIB_ERROR;
    int i;

    for(i = 0; i < length - 1; i++)
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
uint8_t Crypto_Prep_Reply(uint8_t* ingest, uint8_t appID)
{
    uint8_t count = 0;
    if(ingest == NULL) return count;
    
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
uint16_t Crypto_Calc_FECF(uint8_t* ingest, int len_ingest)
{
    uint16_t fecf = 0xFFFF;
    uint16_t poly = 0x1021; // TODO: This polynomial is (CRC-CCITT) for ESA testing, may not match standard protocol
    uint8_t bit;
    uint8_t c15;
    int i;
    int j;

    for (i = 0; i < len_ingest; i++)
    { // Byte Logic
        for (j = 0; j < 8; j++)
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
    int x;
    printf(KCYN "Crypto_Calc_FECF: 0x%02x%02x%02x%02x%02x, len_ingest = %d\n" RESET, ingest[0], ingest[1], ingest[2],
           ingest[3], ingest[4], len_ingest);
    printf(KCYN "0x" RESET);
    for (x = 0; x < len_ingest; x++)
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
uint16_t Crypto_Calc_CRC16(uint8_t* data, int size)
{ // Code provided by ESA
    uint16_t crc = 0xFFFF;

    for (; size > 0; size--)
    {
        // printf("*data = 0x%02x \n", (uint8_t) *data);
        crc = ((crc << 8) & 0xFF00) ^ crc16Table[(crc >> 8) ^ *data++];
    }

    return crc;
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
int32_t Crypto_PDU(uint8_t* ingest, TC_t* tc_frame)
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
    int x;
    if ((status > 0) && (ingest != NULL))
    {
        printf(KMAG "CCSDS message put on software bus: 0x" RESET);
        for (x = 0; x < status; x++)
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
                                                GvcidManagedParameters_t* managed_parameters_in,
                                                GvcidManagedParameters_t** managed_parameters_out)
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
void Crypto_Free_Managed_Parameters(GvcidManagedParameters_t* managed_parameters)
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
 **/
int32_t Crypto_Process_Extended_Procedure_Pdu(TC_t* tc_sdls_processed_frame, uint8_t* ingest)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    int x;

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
            for (x = 13; x < (13 + sdls_frame.hdr.pkt_length); x++)
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
        for (x = 3; x < (3 + tc_sdls_processed_frame->tc_header.fl); x++)
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

/*
** @brief: Check IVs and ARSNs to ensure within valid positive window if applicable
*/
int32_t Crypto_Check_Anti_Replay(SecurityAssociation_t *sa_ptr, uint8_t *arsn, uint8_t *iv)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    // Check for NULL pointers
    if (arsn == NULL)
    {
        return CRYPTO_LIB_ERR_NULL_ARSN;
    }
    if (iv == NULL)
    {
        return CRYPTO_LIB_ERR_NULL_IV;
    }
    if (sa_ptr == NULL)
    {
        return CRYPTO_LIB_ERR_NULL_SA;
    }
    // If sequence number field is greater than zero, check for replay
    if (sa_ptr->shsnf_len > 0)
    {
        // Check Sequence Number is in ARSNW
        status = Crypto_window(arsn, sa_ptr->arsn, sa_ptr->arsn_len, sa_ptr->arsnw);
#ifdef DEBUG
        printf("Received ARSN is\n\t");
        for (int i = 0; i < sa_ptr->arsn_len; i++)
        {
            printf("%02x", *(arsn + i));
        }
        printf("\nSA ARSN is\n\t");
        for (int i = 0; i < sa_ptr->arsn_len; i++)
        {
            printf("%02x", *(sa_ptr->arsn + i));
        }
        printf("\nARSNW is: %d\n", sa_ptr->arsnw);
        printf("Status from Crypto_Window is: %d\n", status);
#endif
        if (status != CRYPTO_LIB_SUCCESS)
        {
            return CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW;
        }
        // Valid ARSN received, increment stored value
        else
        {
            memcpy(sa_ptr->arsn, arsn, sa_ptr->arsn_len);
        }
    }
    // If IV is greater than zero (and arsn isn't used), check for replay
    else if (sa_ptr->iv_len > 0)
    {
        // Check IV is in ARSNW
        if(crypto_config->crypto_increment_nontransmitted_iv == SA_INCREMENT_NONTRANSMITTED_IV_TRUE)
        {
            status = Crypto_window(iv, sa_ptr->iv, sa_ptr->iv_len, sa_ptr->arsnw);
        } else // SA_INCREMENT_NONTRANSMITTED_IV_FALSE
        {
            // Whole IV gets checked in MAC validation previously, this only verifies transmitted portion is what we expect.
            status = Crypto_window(iv, sa_ptr->iv + (sa_ptr->iv_len - sa_ptr->shivf_len), sa_ptr->shivf_len, sa_ptr->arsnw);
        }


#ifdef DEBUG
        printf("Received IV is\n\t");
        for (int i = 0; i < sa_ptr->iv_len; i++)
        {
            printf("%02x", *(iv + i));
        }
        printf("\nSA IV is\n\t");
        for (int i = 0; i < sa_ptr->iv_len; i++)
        {
            printf("%02x", *(sa_ptr->iv + i));
        }
        printf("\nARSNW is: %d\n", sa_ptr->arsnw);
        printf("Crypto_Window return status is: %d\n", status);
#endif
        if (status != CRYPTO_LIB_SUCCESS)
        {
            return CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW;
        }
        // Valid IV received, increment stored value
        else
        {
            memcpy(sa_ptr->iv, iv, sa_ptr->iv_len);
        }
    }
    return status;
}

/*
** @brief: For a given algorithm, return the associated key length in bytes
** @param: algo
*/
int32_t Crypto_Get_ECS_Algo_Keylen(uint8_t algo)
{
    int32_t retval= -1;

    switch(algo){
        case CRYPTO_CIPHER_AES256_GCM:
            retval = 32;
            break;
        case CRYPTO_CIPHER_AES256_CBC:
            retval = 32;
        default:
            break;
    }

    return retval;
}


/*
** @brief: For a given algorithm, return the associated key length in bytes
** @param: algo
*/
int32_t Crypto_Get_ACS_Algo_Keylen(uint8_t algo)
{
    int32_t retval= -1;

    switch(algo){
        case CRYPTO_MAC_CMAC_AES256:
            retval = 32;
            break;
        case CRYPTO_MAC_HMAC_SHA256:
            retval = 32;
            break;
        case CRYPTO_MAC_HMAC_SHA512:
            retval = 64;
            break;
        default:
            break;
    }

    return retval;
}