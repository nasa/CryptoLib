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

/**
 * CCSDS Compliance Reference:
 * This file implements security features compliant with:
 * - CCSDS 232.0-B-3 (TC Space Data Link Protocol)
 * - CCSDS 132.0-B-3 (TM Space Data Link Protocol)
 * - CCSDS 732.0-B-4 (AOS Space Data Link Protocol)
 * - CCSDS 355.0-B-2 (Space Data Link Security Protocol)
 */

/*
** Static Library Declaration
*/
#ifdef BUILD_STATIC
CFS_MODULE_DECLARE_LIB(crypto);
#endif

/*
** Global Variables
*/
// SDLS Replies
SDLS_KEYV_RPLY_t sdls_ep_keyv_reply; // Reply block for challenged keys
uint8_t          sdls_ep_reply[TC_MAX_FRAME_SIZE];
CCSDS_t          sdls_frame;
// TM
uint8_t                  tm_frame[TM_MAX_FRAME_SIZE]; // TM Global Frame
TM_FramePrimaryHeader_t  tm_frame_pri_hdr;            // Used to reduce bit math duplication
TM_FrameSecurityHeader_t tm_frame_sec_hdr;            // Used to reduce bit math duplication
// AOS
uint8_t                   aos_frame[AOS_MAX_FRAME_SIZE]; // AOS Global Frame
AOS_FramePrimaryHeader_t  aos_frame_pri_hdr;             // Used to reduce bit math duplication
AOS_FrameSecurityHeader_t aos_frame_sec_hdr;             // Used to reduce bit math duplication
// OCF
uint8_t                    ocf = 0;
Telemetry_Frame_Ocf_Fsr_t  report;
Telemetry_Frame_Ocf_Clcw_t clcw;
// Flags
SDLS_MC_LOG_RPLY_t      log_summary;
SDLS_MC_DUMP_BLK_RPLY_t mc_log;
uint8_t                 log_count = 0;
uint16_t                tm_offset = 0;
// ESA Testing - 0 = disabled, 1 = enabled
uint8_t badSPI  = 0;
uint8_t badIV   = 0;
uint8_t badMAC  = 0;
uint8_t badFECF = 0;
// FHECF
uint8_t parity[RS_PARITY];
//  CRC
uint32_t crc32Table[CRC32TBL_SIZE];
uint16_t crc16Table[CRC16TBL_SIZE];

/*
** Assisting Functions
*/

/**
 * @brief Function: clean_ekref
 * Null terminates the entire array for EKREF
 * @param sa: SecurityAssocation_t*
 **/
void clean_ekref(SecurityAssociation_t *sa)
{
    for (int y = 0; y < REF_SIZE; y++)
    {
        sa->ek_ref[y] = '\0';
    }
}

/**
 * @brief Function: clean_akref
 * Null terminates the entire array for AKREF
 * @param sa: SecurityAssocation_t*
 **/
void clean_akref(SecurityAssociation_t *sa)
{
    for (int y = 0; y < REF_SIZE; y++)
    {
        sa->ak_ref[y] = '\0';
    }
}

/**
 * @brief Function: Crypto_Is_AEAD_Algorithm
 * Looks up cipher suite ID and determines if it's an AEAD algorithm. Returns 1 if true, 0 if false;
 * @param cipher_suite_id: uint32
 * @return int: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.2 (Cryptographic Algorithms)
 **/
uint8_t Crypto_Is_AEAD_Algorithm(uint32_t cipher_suite_id)
{
    int status = CRYPTO_FALSE;

    // Determine if AEAD Algorithm
    if ((cipher_suite_id == CRYPTO_CIPHER_AES256_GCM) || (cipher_suite_id == CRYPTO_CIPHER_AES256_CBC_MAC) ||
        (cipher_suite_id == CRYPTO_CIPHER_AES256_GCM_SIV))
    {
#ifdef DEBUG
        printf(KYEL "CRYPTO IS AEAD? : TRUE\n" RESET);
#endif
        status = CRYPTO_TRUE;
    }
    else
    {
#ifdef DEBUG
        printf(KYEL "CRYPTO IS AEAD? : FALSE\n" RESET);
#endif
        status = CRYPTO_FALSE;
    }
    return status;
}

/**
 * @brief Function: Crypto_Is_ACS_Only_Algo
 * Looks up cipher suite ID and determines if it's an ACS algorithm. Returns 1 if true, 0 if false;
 * @param cipher_suite_id: uint8_t
 * @return int: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.2 (Cryptographic Algorithms)
 **/
uint8_t Crypto_Is_ACS_Only_Algo(uint8_t algo)
{
    if (algo > 0 && algo <= CRYPTO_ACS_MAX)
    {
        return CRYPTO_TRUE;
    }
    return CRYPTO_FALSE;
}

/**
 * @brief Function: Crypto_increment
 * Increments the bytes within a uint8_t array
 * @param num: uint8*
 * @param length: int
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
int32_t Crypto_increment(uint8_t *num, int length)
{
    int status = CRYPTO_LIB_SUCCESS;
    int i;
    if (num == NULL)
    {
        status = CRYPTO_LIB_ERR_NULL_BUFFER;
    }
    if (status == CRYPTO_LIB_SUCCESS)
    {
        /* go from right (least significant) to left (most signifcant) */
        for (i = length - 1; i >= 0; --i)
        {
            ++(num[i]); /* increment current byte */

            if (num[i] != 0) /* if byte did not overflow, we're done! */
                break;
        }

        if (i < 0) /* this means num[0] was incremented and overflowed */
        {
            for (i = 0; i < length; i++)
            {
                num[i] = 0;
            }
        }
    }

    return status;
}

/**
 * @brief Function: Crypto_window
 * Determines if a value is within the expected positive window of values
 * @param actual: uint8*
 * @param expected: uint8*
 * @param length: int
 * @param window: int
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
int32_t Crypto_window(uint8_t *actual, uint8_t *expected, int length, int window)
{
    int     status      = CRYPTO_LIB_ERROR;
    int     return_code = 0;
    int     result      = 0;
    uint8_t temp[length];
    int     i;
    int     j;

    // Check Null Pointers
    if (actual == NULL)
    {
#ifdef DEBUG
        printf("Crypto_Window expected ptr is NULL\n");
#endif
        status      = CRYPTO_LIB_ERROR;
        return_code = 1;
    }
    if (expected == NULL)
    {
#ifdef DEBUG
        printf("Crypto_Window expected ptr is NULL\n");
#endif
        status      = CRYPTO_LIB_ERROR;
        return_code = 1;
    }
    // Check for special case where received value is all 0's and expected is all 0's (won't have -1 in sa!)
    // Received ARSN is: 00000000, SA ARSN is: 00000000
    uint8_t zero_case = CRYPTO_TRUE;
    for (i = 0; i < length; i++)
    {
        if (actual[i] != 0 || expected[i] != 0)
        {
            zero_case = CRYPTO_FALSE;
        }
    }
    if (zero_case == CRYPTO_TRUE)
    {
        status      = CRYPTO_LIB_SUCCESS;
        return_code = 1;
    }
    if (return_code != 1)
    {
        memcpy(temp, expected, length);
        for (i = 0; i < window; i++)
        {
            // Recall - the stored IV or ARSN is the last valid one received, check against next expected
            Crypto_increment(&temp[0], length);

#ifdef DEBUG
            printf("Checking Frame Against Incremented Window:\n");
            Crypto_hexprint(temp, length);
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
    }
    return status;
}

/**
 * @brief Function: Crypto_Prep_Reply
 * Assumes that both the pkt_length and pdu_len are set properly
 * @param reply: uint8_t*
 * @param appID: uint8
 * @return uint8: Count
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 7.4 (Management)
 **/
uint8_t Crypto_Prep_Reply(uint8_t *reply, uint8_t appID)
{
    uint8_t count = 0;
    if (reply == NULL)
        return count;

    // Prepare CCSDS for reply
    sdls_frame.hdr.pvn   = 0;
    sdls_frame.hdr.type  = 0;
    sdls_frame.hdr.shdr  = 1;
    sdls_frame.hdr.appID = appID;

    sdls_frame.tlv_pdu.hdr.type = 1;

    // Fill reply with reply header
    reply[count++] = (sdls_frame.hdr.pvn << 5) | (sdls_frame.hdr.type << 4) | (sdls_frame.hdr.shdr << 3) |
                     ((sdls_frame.hdr.appID & 0x700 >> 8));
    reply[count++] = (sdls_frame.hdr.appID & 0x00FF);
    reply[count++] = (sdls_frame.hdr.seq << 6) | ((sdls_frame.hdr.pktid & 0x3F00) >> 8);
    reply[count++] = (sdls_frame.hdr.pktid & 0x00FF);
    reply[count++] = (sdls_frame.hdr.pkt_length & 0xFF00) >> 8;
    reply[count++] = (sdls_frame.hdr.pkt_length & 0x00FF);

    if (crypto_config.has_pus_hdr == TC_HAS_PUS_HDR)
    {
        // Fill reply with PUS
        reply[count++] = (sdls_frame.pus.shf << 7) | (sdls_frame.pus.pusv << 4) | (sdls_frame.pus.ack);
        reply[count++] = (sdls_frame.pus.st);
        reply[count++] = (sdls_frame.pus.sst);
        reply[count++] = (sdls_frame.pus.sid << 4) | (sdls_frame.pus.spare);
    }

    // Fill reply with Tag and Length
    reply[count++] = (sdls_frame.tlv_pdu.hdr.type << 7) | (sdls_frame.tlv_pdu.hdr.uf << 6) |
                     (sdls_frame.tlv_pdu.hdr.sg << 4) | (sdls_frame.tlv_pdu.hdr.pid);
    reply[count++] = (sdls_frame.tlv_pdu.hdr.pdu_len & 0xFF00) >> 8;
    reply[count++] = (sdls_frame.tlv_pdu.hdr.pdu_len & 0x00FF);

    sdls_frame.tlv_pdu.hdr.type = 0;
    return count;
}

/**
 * @brief Function: Crypto_Get_Sdls_Ep_Reply
 * Retrieves SDLS EP Reply
 * @param buffer: uint8_t*
 * @param length: uint16_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.2 (Protocol Description)
 **/
int32_t Crypto_Get_Sdls_Ep_Reply(uint8_t *buffer, uint16_t *length)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    // Length to be pulled from packet header
    uint16_t pkt_length = 0;

    // Check for NULL Inputs
    if (buffer == NULL || length == NULL)
    {
        status = CRYPTO_LIB_ERR_NULL_BUFFER;
        return status;
    }

    pkt_length = sdls_frame.hdr.pkt_length + 1;

    // Sanity Check on length
    if (pkt_length > TC_MAX_FRAME_SIZE)
    {
        status = CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_SPEC_LIMIT;
        return status;
    }
    // Copy our length, which will fit in the buffer
    memcpy(buffer, sdls_ep_reply, (size_t)pkt_length);

    // Update length externally
    *length = pkt_length;

    return status;
}

/**
 * @brief Function Crypto_Calc_FECF
 * Calculate the Frame Error Control Field (FECF), also known as a cyclic redundancy check (CRC)
 * @param ingest: uint8_t*
 * @param len_ingest: int
 * @return uint16: FECF
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1.4 (Error Control Field)
 **/
uint16_t Crypto_Calc_FECF(const uint8_t *ingest, int len_ingest)
{
    uint16_t fecf = 0xFFFF;
    uint16_t poly = 0x1021; // This polynomial is (CRC-CCITT) for ESA testing, may not match standard protocol
    uint8_t  bit;
    uint8_t  c15;
    int      i;
    int      j;

    for (i = 0; i < len_ingest; i++)
    { // Byte Logic
        for (j = 0; j < BYTE_LEN; j++)
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
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1.4 (Error Control Field)
 **/
uint16_t Crypto_Calc_CRC16(uint8_t *data, int size)
{ // Code provided by ESA
    uint16_t crc = 0xFFFF;

    for (; size > 0; size--)
    {
        crc = ((crc << BYTE_LEN) & 0xFF00) ^ crc16Table[(crc >> BYTE_LEN) ^ *data++];
    }

    return crc;
}

uint8_t gf_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0)
    {
        return 0;
    }
    else
    {
        return gf_exp[(gf_log[a] + gf_log[b]) % (GF_SIZE - 1)];
    }
}

/**
 * @brief Function: Crypto_Calc_FHECF
 * Frame Header Error Control Field
 * @param data: uint8_t*
 * @return uint16: FHECF
 *
 * CCSDS Compliance: CCSDS 732.0-B-4 Section 4.1.2.6 (Frame Header Error Control Field)
 **/
uint16_t Crypto_Calc_FHECF(uint8_t *data)
{
    uint8_t  feedback = 0;
    uint16_t result   = 0;
    int      i        = 0;
    int      j        = 0;

    // RS encoding
    memset(parity, 0, RS_PARITY);
    for (i = 0; i < RS_DATA; i++)
    {
        feedback = (data[i] ^ parity[0]) % (GF_SIZE - 1);
        for (j = 0; j < RS_PARITY - 1; j++)
        {
            parity[j] = parity[j + 1];
        }
        parity[RS_PARITY - 1] = 0;

        for (j = 0; j < RS_PARITY; j++)
        {
            parity[j] ^= gf_mul(feedback, gen_poly[j + 1]);
        }
    }
#ifdef AOS_DEBUG
    for (i = 0; i < RS_PARITY; i++)
    {
        printf("Parity[%d] = 0x%02x\n", i, parity[i]);
    }
#endif
    result = (parity[0] << 12) | (parity[1] << 8) | (parity[2] << 4) | (parity[3] << 0);
    return result;
}

/*
** Procedures Specifications
*/
/**
 * @brief Function: Crypto_PDU
 * Parses PDU and directs to other function based on type/flags/sg
 * @param ingest: uint8_t*
 * @param tc_frame: TC_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.3 (Procedure Type)
 **/
int32_t Crypto_PDU(uint8_t *ingest, TC_t *tc_frame)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Check null pointer
    if (tc_frame == NULL)
    {
        status = CRYPTO_LIB_ERR_NULL_BUFFER;
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
        switch (sdls_frame.tlv_pdu.hdr.type)
        {
            case PDU_TYPE_COMMAND:
                switch (sdls_frame.tlv_pdu.hdr.uf)
                {
                    case PDU_USER_FLAG_FALSE: // CCSDS Defined Command
                        switch (sdls_frame.tlv_pdu.hdr.sg)
                        {
                            case SG_KEY_MGMT: // Key Management Procedure
                                status = Crypto_SG_KEY_MGMT(ingest, tc_frame);
                                break;
                            case SG_SA_MGMT: // Security Association Management Procedure
                                status = Crypto_SG_SA_MGMT(ingest, tc_frame);
                                break;
                            case SG_SEC_MON_CTRL: // Security Monitoring & Control Procedure
                                status = Crypto_SEC_MON_CTRL(ingest);
                                break;
                            default: // ERROR
#ifdef PDU_DEBUG
                                printf(KRED "Error: Crypto_PDU failed interpreting Service Group! \n" RESET);
#endif
                                break;
                        }
                        break;

                    case PDU_USER_FLAG_TRUE: // User Defined Command
                        switch (sdls_frame.tlv_pdu.hdr.sg)
                        {
                            default:
                                status = Crypto_USER_DEFINED_CMD(ingest);
                                break;
                        }
                        break;
                }
                break;

            case PDU_TYPE_REPLY:
#ifdef PDU_DEBUG
                printf(KRED "Error: Crypto_PDU failed interpreting PDU Type!  Received a Reply!?! \n" RESET);
#endif
                break;
        }
    }
    return status;
}

/**
 * @brief Function: Crypto_SG_KEY_MGMT
 * Handles key management procedures
 * @param ingest: uint8_t*
 * @param tc_frame: TC_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.2 (Key Management)
 **/
int32_t Crypto_SG_KEY_MGMT(uint8_t *ingest, TC_t *tc_frame)
{
    int status = CRYPTO_LIB_SUCCESS;
    switch (sdls_frame.tlv_pdu.hdr.pid)
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
            status = Crypto_Key_verify(tc_frame);
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
#ifdef PDU_DEBUG
            printf(KRED
                   "Error: Crypto_PDU failed interpreting Key Management Procedure Identification Field! \n" RESET);
#endif
            break;
    }
    return status;
}

/**
 * @brief Function: Crypto_SG_SA_MGMT
 * Handles security association management procedures
 * @param ingest: uint8_t*
 * @param tc_frame: TC_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 7.2 (Security Association Management)
 **/
int32_t Crypto_SG_SA_MGMT(uint8_t *ingest, TC_t *tc_frame)
{
    int status = CRYPTO_LIB_SUCCESS;
    switch (sdls_frame.tlv_pdu.hdr.pid)
    {
        case PID_CREATE_SA:
#ifdef PDU_DEBUG
            printf(KGRN "SA Create\n" RESET);
#endif
            status = sa_if->sa_create(tc_frame);
            break;
        case PID_DELETE_SA:
#ifdef PDU_DEBUG
            printf(KGRN "SA Delete\n" RESET);
#endif
            status = sa_if->sa_delete(tc_frame);
            break;
        case PID_SET_ARSNW:
#ifdef PDU_DEBUG
            printf(KGRN "SA setARSNW\n" RESET);
#endif
            status = sa_if->sa_setARSNW(tc_frame);
            break;
        case PID_REKEY_SA:
#ifdef PDU_DEBUG
            printf(KGRN "SA Rekey\n" RESET);
#endif
            status = sa_if->sa_rekey(tc_frame);
            break;
        case PID_EXPIRE_SA:
#ifdef PDU_DEBUG
            printf(KGRN "SA Expire\n" RESET);
#endif
            status = sa_if->sa_expire(tc_frame);
            break;
        case PID_SET_ARSN:
#ifdef PDU_DEBUG
            printf(KGRN "SA SetARSN\n" RESET);
#endif
            status = sa_if->sa_setARSN(tc_frame);
            break;
        case PID_START_SA:
#ifdef PDU_DEBUG
            printf(KGRN "SA Start\n" RESET);
#endif
            status = sa_if->sa_start(tc_frame);
            break;
        case PID_STOP_SA:
#ifdef PDU_DEBUG
            printf(KGRN "SA Stop\n" RESET);
#endif
            status = sa_if->sa_stop(tc_frame);
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
            status = sa_if->sa_status(ingest);
            break;
        default:
#ifdef PDU_DEBUG
            printf(KRED "Error: Crypto_PDU failed interpreting SA Procedure Identification Field! \n" RESET);
#endif
            break;
    }
    return status;
}

/**
 * @brief Function: Crypto_SEC_MON_CTRL
 * Handles security monitoring and control procedures
 * @param ingest: uint8_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 7.3 (Security Monitoring and Control)
 **/
int32_t Crypto_SEC_MON_CTRL(uint8_t *ingest)
{
    int status = CRYPTO_LIB_SUCCESS;
    switch (sdls_frame.tlv_pdu.hdr.pid)
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
#ifdef PDU_DEBUG
            printf(KRED "Error: Crypto_PDU failed interpreting MC Procedure Identification Field! \n" RESET);
#endif
            break;
    }
    return status;
}

/**
 * @brief Function: Crypto_USER_DEFINED_CMD
 * Parses User Defined Procedure from PID
 * @param ingest: uint8_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.3.3 (User-Defined Procedures)
 **/
int32_t Crypto_USER_DEFINED_CMD(uint8_t *ingest)
{
    int status = CRYPTO_LIB_SUCCESS;
    switch (sdls_frame.tlv_pdu.hdr.pid)
    {
        case PID_IDLE_FRAME_TRIGGER:
#ifdef PDU_DEBUG
            printf(KMAG "User Idle Trigger\n" RESET);
#endif
            status = Crypto_User_IdleTrigger(ingest);
            break;
        case PID_TOGGLE_BAD_SPI:
#ifdef PDU_DEBUG
            printf(KMAG "User Toggle Bad SPI\n" RESET);
#endif
            status = Crypto_User_BadSPI();
            break;
        case PID_TOGGLE_BAD_IV:
#ifdef PDU_DEBUG
            printf(KMAG "User Toggle Bad IV\n" RESET);
#endif
            status = Crypto_User_BadIV();
            break;
        case PID_TOGGLE_BAD_MAC:
#ifdef PDU_DEBUG
            printf(KMAG "User Toggle Bad MAC\n" RESET);
#endif
            status = Crypto_User_BadMAC();
            break;
        case PID_TOGGLE_BAD_FECF:
#ifdef PDU_DEBUG
            printf(KMAG "User Toggle Bad FECF\n" RESET);
#endif
            status = Crypto_User_BadFECF();
            break;
        case PID_MODIFY_KEY:
#ifdef PDU_DEBUG
            printf(KMAG "User Modify Key\n" RESET);
#endif
            status = Crypto_User_ModifyKey();
            break;
        case PID_MODIFY_ACTIVE_TM:
#ifdef PDU_DEBUG
            printf(KMAG "User Modify Active TM\n" RESET);
#endif
            status = Crypto_User_ModifyActiveTM();
            break;
        case PID_MODIFY_VCID:
#ifdef PDU_DEBUG
            printf(KMAG "User Modify VCID\n" RESET);
#endif
            status = Crypto_User_ModifyVCID();
            break;
        default:
#ifdef PDU_DEBUG
            printf(KRED "Error: Crypto_PDU received user defined command! \n" RESET);
#endif
            break;
    }
    return status;
}

/**
 * @brief Function: Crypto_Get_Managed_Parameters_For_Gvcid
 * @param tfvn: uint8_t
 * @param scid: uint16_t
 * @param vcid: uint8_t
 * @param managed_parameters_in: GvcidManagedParameters_t*
 * @param managed_parameters_out: GvcidManagedParameters_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 2.4 (Managed Parameters)
 **/
int32_t Crypto_Get_Managed_Parameters_For_Gvcid(uint8_t tfvn, uint16_t scid, uint8_t vcid,
                                                GvcidManagedParameters_t *managed_parameters_in,
                                                GvcidManagedParameters_t *managed_parameters_out)
{
    int32_t status = MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND;
    // Check gvcid counter against a max
    if (gvcid_counter > NUM_GVCID)
    {
        status = CRYPTO_LIB_ERR_EXCEEDS_MANAGED_PARAMETER_MAX_LIMIT;
    }
    if (status != CRYPTO_LIB_ERR_EXCEEDS_MANAGED_PARAMETER_MAX_LIMIT)
    {
        for (int i = 0; i < gvcid_counter; i++)
        {
            if (managed_parameters_in[i].tfvn == tfvn && managed_parameters_in[i].scid == scid &&
                managed_parameters_in[i].vcid == vcid)
            {
                *managed_parameters_out = managed_parameters_in[i];
                status                  = CRYPTO_LIB_SUCCESS;
                break;
            }
        }

        if (status != CRYPTO_LIB_SUCCESS)
        {
#ifdef DEBUG
            printf(KRED "Error: Managed Parameters for GVCID(TFVN: %d, SCID: %d, VCID: %d) not found. \n" RESET, tfvn,
                   scid, vcid);
#endif
        }
    }
    return status;
}

/**
 * @brief Function: Crypto_Process_Extended_Procedure_Pdu
 * @param tc_sdls_processed_frame: TC_t*
 * @param ingest: uint8_t*
 * @param len_ingest: uint16_t
 * @return int32: Success/Failure
 * @note TODO - Actually update based on variable config
 * @note Allows EPs to be processed one of two ways.
 * @note - 1) By using a packet layer with APID 0x1980
 * @note - 2) By using a defined Virtual Channel ID
 * @note Requires this to happen on either SPI_MIN (0) or SPI_MAX (configurable)
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.2 (Protocol Description)
 **/
int32_t Crypto_Process_Extended_Procedure_Pdu(TC_t *tc_sdls_processed_frame, uint8_t *ingest, uint16_t len_ingest)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    ingest         = ingest;     // Suppress unused variable error depending on build
    len_ingest     = len_ingest; // suppress error for now

    // Check for null pointers
    if (tc_sdls_processed_frame == NULL)
    {
        status = CRYPTO_LIB_ERR_NULL_BUFFER;
    }
    // Validate correct SA for EPs
    uint8_t valid_ep_sa = CRYPTO_FALSE;
    if ((tc_sdls_processed_frame->tc_sec_header.spi == SPI_MIN) ||
        (tc_sdls_processed_frame->tc_sec_header.spi == SPI_MAX))
    {
        valid_ep_sa = CRYPTO_TRUE;
    }
    if (status == CRYPTO_LIB_SUCCESS)
    {
        // Check for specific App ID for EPs - the CryptoLib Apid in this case
        if ((tc_sdls_processed_frame->tc_pdu[0] == 0x19) && (tc_sdls_processed_frame->tc_pdu[1] == 0x80))
        {

#ifdef CRYPTO_EPROC
            // Check validity of SAs used for EP
            if (valid_ep_sa == CRYPTO_TRUE)
            {
#ifdef DEBUG
                printf(KGRN "Received SDLS command w/ packet header:\n\t " RESET);
#endif
                // CCSDS Header
                sdls_frame.hdr.pvn  = (tc_sdls_processed_frame->tc_pdu[0] & 0xE0) >> 5;
                sdls_frame.hdr.type = (tc_sdls_processed_frame->tc_pdu[0] & 0x10) >> 4;
                sdls_frame.hdr.shdr = (tc_sdls_processed_frame->tc_pdu[0] & 0x08) >> 3;
                sdls_frame.hdr.appID =
                    ((tc_sdls_processed_frame->tc_pdu[0] & 0x07) << 8) | tc_sdls_processed_frame->tc_pdu[1];
                sdls_frame.hdr.seq = (tc_sdls_processed_frame->tc_pdu[2] & 0xC0) >> 6;
                sdls_frame.hdr.pktid =
                    ((tc_sdls_processed_frame->tc_pdu[2] & 0x3F) << 8) | tc_sdls_processed_frame->tc_pdu[3];
                sdls_frame.hdr.pkt_length =
                    (tc_sdls_processed_frame->tc_pdu[4] << 8) | tc_sdls_processed_frame->tc_pdu[5];

                // Using PUS Header
                if (crypto_config.has_pus_hdr == TC_HAS_PUS_HDR)
                {
                    // If ECSS PUS Header is being used
                    sdls_frame.pus.shf   = (tc_sdls_processed_frame->tc_pdu[6] & 0x80) >> 7;
                    sdls_frame.pus.pusv  = (tc_sdls_processed_frame->tc_pdu[6] & 0x70) >> 4;
                    sdls_frame.pus.ack   = (tc_sdls_processed_frame->tc_pdu[6] & 0x0F);
                    sdls_frame.pus.st    = tc_sdls_processed_frame->tc_pdu[7];
                    sdls_frame.pus.sst   = tc_sdls_processed_frame->tc_pdu[8];
                    sdls_frame.pus.sid   = (tc_sdls_processed_frame->tc_pdu[9] & 0xF0) >> 4;
                    sdls_frame.pus.spare = (tc_sdls_processed_frame->tc_pdu[9] & 0x0F);

                    // SDLS TLV PDU
                    sdls_frame.tlv_pdu.hdr.type = (tc_sdls_processed_frame->tc_pdu[10] & 0x80) >> 7;
                    sdls_frame.tlv_pdu.hdr.uf   = (tc_sdls_processed_frame->tc_pdu[10] & 0x40) >> 6;
                    sdls_frame.tlv_pdu.hdr.sg   = (tc_sdls_processed_frame->tc_pdu[10] & 0x30) >> 4;
                    sdls_frame.tlv_pdu.hdr.pid  = (tc_sdls_processed_frame->tc_pdu[10] & 0x0F);
                    sdls_frame.tlv_pdu.hdr.pdu_len =
                        (tc_sdls_processed_frame->tc_pdu[11] << 8) | tc_sdls_processed_frame->tc_pdu[12];

                    // Subtract headers from total frame length
                    uint16_t derived_tlv =
                        (tc_sdls_processed_frame->tc_pdu_len - CCSDS_HDR_SIZE - ECSS_PUS_SIZE - SDLS_TLV_HDR_SIZE);
#ifdef CCSDS_DEBUG
                    printf("Printing lengths for sanity check:\n");
                    printf("\t TC Frame Header Length (bytes): %d \n", tc_sdls_processed_frame->tc_header.fl);
                    printf("\t TC Frame Actual Length (bytes): %d \n", tc_sdls_processed_frame->tc_header.fl + 1);
                    printf("\t TC Frame Space Pkt Length (bytes): %d \n", tc_sdls_processed_frame->tc_pdu_len);
                    printf("\t Received TLV Length (bits): %d \n", sdls_frame.tlv_pdu.hdr.pdu_len);
                    printf("\t Derived TLV Length (bytes): %d \n", derived_tlv);
                    printf("\t Received TLV Length (bytes): %f \n", sdls_frame.tlv_pdu.hdr.pdu_len / 8.0);
#endif
                    // Sanity check - does the length of the pdu header match the number of bytes we have?
                    // CODE REVIEW - PDUs allow lengths in bits, it is plausible that only a few bits of a byte are
                    // needed but would require a full byte for transmission. I can't find anything atm in docs to
                    // dispute this
                    if ((double)(sdls_frame.tlv_pdu.hdr.pdu_len / 8.0) != derived_tlv)
                    {
#ifdef PDU_DEBUG
                        printf(KRED "Packet PDU_LEN Not Equal To Derived PDU Len\n" RESET);
#endif
                        return CRYPTO_LIB_ERR_BAD_TLV_LENGTH;
                    }

                    if (sdls_frame.tlv_pdu.hdr.pdu_len % 8 != 0)
                    {
#ifdef PDU_DEBUG
                        printf(KRED "Packet PDU_LEN Not multiple of 8 bits\n" RESET);
#endif
                        return CRYPTO_LIB_ERR_BAD_TLV_LENGTH;
                    }

                    if (sdls_frame.hdr.pkt_length <= TLV_DATA_SIZE)
                    {
                        for (int x = 13; x < (13 + sdls_frame.hdr.pkt_length); x++)
                        {
                            sdls_frame.tlv_pdu.data[x - 13] = tc_sdls_processed_frame->tc_pdu[x];
                        }
                    }
                    else
                    {
#ifdef PDU_DEBUG
                        printf(KRED "Packet Header Length GT TLV_DATA_SIZE\n" RESET);
#endif
                        status = CRYPTO_LIB_ERR_BAD_TLV_LENGTH;
                        return status;
                    }
                }
                // Not using PUS Header
                else
                {
                    // SDLS TLV PDU
                    sdls_frame.tlv_pdu.hdr.type = (tc_sdls_processed_frame->tc_pdu[6] & 0x80) >> 7;
                    sdls_frame.tlv_pdu.hdr.uf   = (tc_sdls_processed_frame->tc_pdu[6] & 0x40) >> 6;
                    sdls_frame.tlv_pdu.hdr.sg   = (tc_sdls_processed_frame->tc_pdu[6] & 0x30) >> 4;
                    sdls_frame.tlv_pdu.hdr.pid  = (tc_sdls_processed_frame->tc_pdu[6] & 0x0F);
                    sdls_frame.tlv_pdu.hdr.pdu_len =
                        (tc_sdls_processed_frame->tc_pdu[7] << 8) | tc_sdls_processed_frame->tc_pdu[8];

                    // Make sure TLV isn't larger than we have allocated, and it is sane given total frame length
                    uint16_t max_tlv = tc_sdls_processed_frame->tc_header.fl - CCSDS_HDR_SIZE - SDLS_TLV_HDR_SIZE;
                    len_ingest       = len_ingest; // suppress error for now
#ifdef PDU_DEBUG
                    printf("PDU_LEN: %d\n", sdls_frame.tlv_pdu.hdr.pdu_len);
#endif
                    if ((sdls_frame.tlv_pdu.hdr.pdu_len / 8) > max_tlv)
                    {
#ifdef PDU_DEBUG
                        printf(KRED "PDU_LEN GT MAX_TLV\n" RESET);
#endif
                        return CRYPTO_LIB_ERR_BAD_TLV_LENGTH;
                    }
                    if ((sdls_frame.hdr.pkt_length < TLV_DATA_SIZE) && (sdls_frame.hdr.pkt_length < max_tlv))
                    {
                        for (int x = 9; x < (9 + sdls_frame.hdr.pkt_length); x++)
                        {
                            sdls_frame.tlv_pdu.data[x - 9] = tc_sdls_processed_frame->tc_pdu[x];
                        }
                    }
                    else
                    {
                        status = CRYPTO_LIB_ERR_BAD_TLV_LENGTH;
                        return status;
                    }
                }

#ifdef CCSDS_DEBUG
                Crypto_ccsdsPrint(&sdls_frame);
#endif

                // Determine type of PDU
                status = Crypto_PDU(ingest, tc_sdls_processed_frame);
            }
            // Received EP PDU on invalid SA
            else
            {
#ifdef CCSDS_DEBUG
                printf(KRED "Received EP PDU on invalid SA! SPI %d\n" RESET,
                       tc_sdls_processed_frame->tc_sec_header.spi);
#endif
                status = CRYPTO_LIB_ERR_SDLS_EP_WRONG_SPI;
            }

#else  // Received an EP command without EPs being built
            if (valid_ep_sa)
            {
                status = CRYPTO_LIB_ERR_SDLS_EP_NOT_BUILT;
                return status;
            }
            valid_ep_sa = valid_ep_sa; // Suppress build error
            status      = CRYPTO_LIB_SUCCESS;
#endif // CRYPTO_EPROC
        }

        // If not a specific APID, check if using VCIDs for SDLS PDUs with no packet layer
        else if (tc_sdls_processed_frame->tc_header.vcid == TC_SDLS_EP_VCID)
        {
#ifdef CRYPTO_EPROC
            // Check validity of SAs used for EP
            if (valid_ep_sa == CRYPTO_TRUE)
            {
#ifdef CCSDS_DEBUG
                printf(KGRN "Received SDLS command (No Packet Header or PUS): " RESET);
#endif
                // No Packet HDR or PUS in these frames
                // SDLS TLV PDU
                sdls_frame.hdr.type        = (tc_sdls_processed_frame->tc_pdu[0] & 0x80) >> 7;
                sdls_frame.tlv_pdu.hdr.uf  = (tc_sdls_processed_frame->tc_pdu[0] & 0x40) >> 6;
                sdls_frame.tlv_pdu.hdr.sg  = (tc_sdls_processed_frame->tc_pdu[0] & 0x30) >> 4;
                sdls_frame.tlv_pdu.hdr.pid = (tc_sdls_processed_frame->tc_pdu[0] & 0x0F);
                sdls_frame.tlv_pdu.hdr.pdu_len =
                    (tc_sdls_processed_frame->tc_pdu[1] << 8) | tc_sdls_processed_frame->tc_pdu[2];
                for (int x = 3; x < (3 + tc_sdls_processed_frame->tc_header.fl); x++)
                {
                    // Todo - Consider how this behaves with large OTAR PDUs that are larger than 1 TC in size. Most
                    // likely fails. Must consider Uplink Sessions (sequence numbers).
                    sdls_frame.tlv_pdu.data[x - 3] = tc_sdls_processed_frame->tc_pdu[x];
                }

#ifdef CCSDS_DEBUG
                Crypto_ccsdsPrint(&sdls_frame);
#endif

                // Determine type of PDU
                status = Crypto_PDU(ingest, tc_sdls_processed_frame);
            }
#else // Received an EP command without EPs being built
#ifdef CCSDS_DEBUG
            printf(KRED "PDU DEBUG %s %d\n" RESET, __FILE__, __LINE__);
#endif
            valid_ep_sa = valid_ep_sa; // Suppress build error
            status      = CRYPTO_LIB_ERR_SDLS_EP_NOT_BUILT;
#endif // CRYPTO_EPROC
        }
    }
    return status;
} // End Process SDLS PDU

/**
 * @brief Function: Crypto_Check_Anti_Replay_Verify_Pointers
 * Sanity Check, validates passed in pointers
 * @param sa_ptr: SecurityAssociation_t*
 * @param arsn: uint8_t*
 * @param iv: uint8_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
int32_t Crypto_Check_Anti_Replay_Verify_Pointers(SecurityAssociation_t *sa_ptr, uint8_t *arsn, uint8_t *iv)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (sa_ptr == NULL) // #177 - Modification made per suggestion of 'Spicydll' - prevents null dereference
    {
        status = CRYPTO_LIB_ERR_NULL_SA;
        return status;
    }
    if (arsn == NULL && sa_ptr->arsn_len > 0)
    {
        status = CRYPTO_LIB_ERR_NULL_ARSN;
        return status;
    }
    if (iv == NULL && sa_ptr->shivf_len > 0 && crypto_config.cryptography_type != CRYPTOGRAPHY_TYPE_KMCCRYPTO)
    {
        status = CRYPTO_LIB_ERR_NULL_IV;
        return status;
    }
    return status;
}

/**
 * @brief Function: Crypto_Check_Anti_Replay_ARSNW
 * Sanity Check, validates ARSN within window
 * @param sa_ptr: SecurityAssociation_t*
 * @param arsn: uint8_t*
 * @param arsn_valid: uint8_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
int32_t Crypto_Check_Anti_Replay_ARSNW(SecurityAssociation_t *sa_ptr, uint8_t *arsn, int8_t *arsn_valid)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Check for null pointers
    if (sa_ptr == NULL || arsn == NULL || arsn_valid == NULL)
    {
        status = CRYPTO_LIB_ERR_NULL_BUFFER;
    }

    if (status == CRYPTO_LIB_SUCCESS)
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
                *arsn_valid = CRYPTO_TRUE;
            }
        }
    return status;
}

/**
 * @brief Function: Crypto_Check_Anti_Replay_GCM
 * Sanity Check, validates IV within window
 * @param sa_ptr: SecurityAssociation_t*
 * @param iv: uint8_t*
 * @param iv_valid: uint8_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
int32_t Crypto_Check_Anti_Replay_GCM(SecurityAssociation_t *sa_ptr, uint8_t *iv, int8_t *iv_valid)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if ((sa_ptr->iv_len > 0) && (sa_ptr->ecs == CRYPTO_CIPHER_AES256_GCM))
    {
        // Check IV Length
        if (sa_ptr->iv_len > IV_SIZE)
        {
            status = CRYPTO_LIB_ERR_IV_GREATER_THAN_MAX_LENGTH;
        }
        if (status == CRYPTO_LIB_SUCCESS)
        {
            // Check IV is in ARSNW
            if (crypto_config.crypto_increment_nontransmitted_iv == SA_INCREMENT_NONTRANSMITTED_IV_TRUE)
            {
                status = Crypto_window(iv, sa_ptr->iv, sa_ptr->iv_len, sa_ptr->arsnw);
            }
            else // SA_INCREMENT_NONTRANSMITTED_IV_FALSE
            {
                // Whole IV gets checked in MAC validation previously, this only verifies transmitted portion is what we
                // expect.
                status = Crypto_window(iv, sa_ptr->iv + (sa_ptr->iv_len - sa_ptr->shivf_len), sa_ptr->shivf_len,
                                       sa_ptr->arsnw);
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
                *iv_valid = CRYPTO_TRUE;
            }
        }
    }
    return status;
}

/**
 * @brief Function: Crypto_Check_Anti_Replay
 * Verifies data within window.
 * @param sa_ptr: SecurityAssociation_t*
 * @param arsn: uint8_t*
 * @param iv: uint8_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
int32_t Crypto_Check_Anti_Replay(SecurityAssociation_t *sa_ptr, uint8_t *arsn, uint8_t *iv)
{
    int32_t status     = CRYPTO_LIB_SUCCESS;
    int8_t  iv_valid   = -1;
    int8_t  arsn_valid = -1;

    // Check for NULL pointers
    status = Crypto_Check_Anti_Replay_Verify_Pointers(sa_ptr, arsn, iv);

    // If sequence number field is greater than zero, check for replay
    if (status == CRYPTO_LIB_SUCCESS)
    {
        status = Crypto_Check_Anti_Replay_ARSNW(sa_ptr, arsn, &arsn_valid);
    }

    // If IV is greater than zero and using GCM, check for replay
    if (status == CRYPTO_LIB_SUCCESS)
    {
        status = Crypto_Check_Anti_Replay_GCM(sa_ptr, iv, &iv_valid);
    }

    // For GCM specifically, if have a valid IV...
    if ((sa_ptr->ecs == CRYPTO_CIPHER_AES256_GCM || sa_ptr->ecs == CRYPTO_CIPHER_AES256_GCM_SIV) &&
        (iv_valid == CRYPTO_TRUE))
    {
        // Using ARSN? Need to be valid to increment both
        if (sa_ptr->arsn_len > 0 && arsn_valid == CRYPTO_TRUE)
        {
            memcpy(sa_ptr->iv, iv, sa_ptr->iv_len);
            memcpy(sa_ptr->arsn, arsn, sa_ptr->arsn_len);
        }
        // Not using ARSN? IV Valid and good to go
        if (sa_ptr->arsn_len == 0)
        {
            memcpy(sa_ptr->iv, iv, sa_ptr->iv_len);
        }
    }

    // If not GCM, and ARSN is valid - can incrmeent it
    if ((sa_ptr->ecs != CRYPTO_CIPHER_AES256_GCM && sa_ptr->ecs != CRYPTO_CIPHER_AES256_GCM_SIV) &&
        arsn_valid == CRYPTO_TRUE)
    {
        memcpy(sa_ptr->arsn, arsn, sa_ptr->arsn_len);
    }

    if (status != CRYPTO_LIB_SUCCESS)
    {
        // Log error if it happened
        mc_if->mc_log(status);
    }

    return status;
}

/**
 * @brief: Function: Crypto_Get_ECS_Algo_Keylen
 * For a given ECS algorithm, return the associated key length in bytes
 * @param algo: uint8_t
 * @return int32: Key Length
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.2 (Cryptographic Algorithms)
 **/
int32_t Crypto_Get_ECS_Algo_Keylen(uint8_t algo)
{
    int32_t retval = -1;

    switch (algo)
    {
        case CRYPTO_CIPHER_AES256_GCM:
            retval = AES256_GCM_KEYLEN;
            break;
        case CRYPTO_CIPHER_AES256_GCM_SIV:
            retval = AES256_GCM_SIV_KEYLEN;
            break;
        case CRYPTO_CIPHER_AES256_CBC:
            retval = AES256_CBC_KEYLEN;
            break;
        case CRYPTO_CIPHER_AES256_CCM:
            retval = AES256_CCM_KEYLEN;
            break;
        default:
            break;
    }

    return retval;
}

/**
 * @brief: Function: Crypto_Get_ACS_Algo_Keylen
 * For a given ACS algorithm, return the associated key length in bytes
 * @param algo: uint8_t
 * @return int32: Key Length
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.2 (Cryptographic Algorithms)
 **/
int32_t Crypto_Get_ACS_Algo_Keylen(uint8_t algo)
{
    int32_t retval = -1;

    switch (algo)
    {
        case CRYPTO_MAC_CMAC_AES256:
            retval = CMAC_AES256_KEYLEN;
            break;
        case CRYPTO_MAC_HMAC_SHA256:
            retval = HMAC_SHA256_KEYLEN;
            break;
        case CRYPTO_MAC_HMAC_SHA512:
            retval = HMAC_SHA512_KEYLEN;
            break;
        default:
            break;
    }

    return retval;
}

/**
 * @brief: Function: Crypto_Get_Security_Header_Length
 * Return Security Header Length
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32: Security Header Length
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.3.2 (Security Header)
 **/
int32_t Crypto_Get_Security_Header_Length(SecurityAssociation_t *sa_ptr)
{
    /* Narrator's Note: Leaving this here for future work
    ** eventually we need a way to reconcile cryptolib managed parameters with TO managed parameters
    GvcidManagedParameters_t* temp_current_managed_parameters = NULL;
    Crypto_Get_Managed_Parameters_For_Gvcid(tfvn, scid, vcid,
                                            gvcid_managed_parameters, temp_current_managed_parameters);
    */

    if (!sa_ptr)
    {
#ifdef DEBUG
        printf(KRED "Get_Security_Header_Length passed Null SA!\n" RESET);
#endif
        return CRYPTO_LIB_ERR_NULL_SA;
    }
    uint16_t securityHeaderLength = 2; // Start with SPI

    securityHeaderLength += sa_ptr->shivf_len + sa_ptr->shsnf_len + sa_ptr->shplf_len;

    return securityHeaderLength;
}

/**
 * @brief: Function: Crypto_Get_Security_Trailer_Length
 * Return Security Trailer Length
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32: Security Trailer Length
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.3.3 (Security Trailer)
 **/
int32_t Crypto_Get_Security_Trailer_Length(SecurityAssociation_t *sa_ptr)
{
    if (!sa_ptr)
    {
#ifdef DEBUG
        printf(KRED "Get_Trailer_Trailer_Length passed Null SA!\n" RESET);
#endif
        return CRYPTO_LIB_ERR_NULL_SA;
    }
    uint16_t securityTrailerLength = 0;

    securityTrailerLength = sa_ptr->stmacf_len;

    return securityTrailerLength;
}

/**
 * @brief: Function: Crypto_Set_FSR
 * Sets the Frame Security Report
 * @param p_ingest: uint8_t*
 * @param byte_idx: uint16_t
 * @param pdu_len: uint16_t
 * @param sa_ptr: SecurityAssociation_t*
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.5.2 (Alarms Reporting)
 **/
void Crypto_Set_FSR(uint8_t *p_ingest, uint16_t byte_idx, uint16_t pdu_len, SecurityAssociation_t *sa_ptr)
{
    if (current_managed_parameters_struct.has_ocf == TM_HAS_OCF ||
        current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        Telemetry_Frame_Ocf_Fsr_t temp_report;
        byte_idx += (pdu_len + sa_ptr->stmacf_len);
        temp_report.cwt   = (p_ingest[byte_idx] >> 7) & 0x01;
        temp_report.fvn   = (p_ingest[byte_idx] >> 4) & 0x07;
        temp_report.af    = (p_ingest[byte_idx] >> 3) & 0x01;
        temp_report.bsnf  = (p_ingest[byte_idx] >> 2) & 0x01;
        temp_report.bmacf = (p_ingest[byte_idx] >> 1) & 0x01;
        temp_report.bsaf  = (p_ingest[byte_idx] & 0x01);
        byte_idx += 1;
        temp_report.lspi = (p_ingest[byte_idx] << 8) | (p_ingest[byte_idx + 1]);
        byte_idx += 2;
        temp_report.snval = (p_ingest[byte_idx]);
        byte_idx++;
        report = temp_report;
#ifdef DEBUG
        Crypto_fsrPrint(&report);
#endif
    }
}

/**
 * @brief: Function: Crypto_Get_FSR
 * Gets the Frame Security Report
 * @return uint32: FSR
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.5.2 (Alarms Reporting)
 **/
uint32_t Crypto_Get_FSR(void)
{
    uint32_t fsr;
    fsr = (report.cwt << 31) |   // bit(s) 1
          (report.fvn << 28) |   // bit(s) 2-4
          (report.af << 27) |    // bit(s) 5
          (report.bsnf << 26) |  // bit(s) 6
          (report.bmacf << 25) | // bit(s) 7
          (report.bsaf << 24) |  // bit(s) 8
          (report.lspi << 8) |   // bit(s) 9-24
          (report.snval << 0);   // bit(s) 25-32
    return fsr;
}


int32_t Crypto_Check_Padding_Length(SecurityAssociation_t *sa_ptr)
{
    int status = CRYPTO_LIB_SUCCESS;

    if ((sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC || sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC_MAC) &&
        sa_ptr->shplf_len == 0)
    {
        status = CRYPTO_LIB_ERR_SHPLF_LEN_LESS_THAN_MIN_PAD_SIZE;
    }

    return status;
}
