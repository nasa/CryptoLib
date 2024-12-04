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

/*
** Key Management Services
*/
/**
 * @brief Function: Crypto_Key_OTAR
 * The OTAR Rekeying procedure shall have the following Service Parameters:
 * a- Key ID of the Master Key (Integer, unmanaged)
 * b- Size of set of Upload Keys (Integer, managed)
 * c- Set of Upload Keys (Integer[Session Key]; managed)
 * NOTE- The size of the session keys is mission specific.
 * a- Set of Key IDs of Upload Keys (Integer[Key IDs]; managed)
 * b- Set of Encrypted Upload Keys (Integer[Size of set of Key ID]; unmanaged)
 * c- Agreed Cryptographic Algorithm (managed)
 * @return int32: Success/Failure
 **/
int32_t Crypto_Key_OTAR(void)
{
    // Local variables
    SDLS_OTAR_t packet;
    int         count = 0;
    int         x     = 0;
    int         y;
    int32_t     status = CRYPTO_LIB_SUCCESS;
    // uint16_t pdu_len = (uint16_t) sdls_frame.pdu.hdr.pdu_len[1] << 8 | sdls_frame.pdu.hdr.pdu_len[0];
    int           pdu_keys = (sdls_frame.pdu.hdr.pdu_len - SDLS_KEYID_LEN - SDLS_IV_LEN - MAC_SIZE) / (SDLS_KEYID_LEN + SDLS_KEY_LEN);
    int           w;
    crypto_key_t *ekp = NULL;

    // Master Key ID
    packet.mkid = (sdls_frame.pdu.data[0] << BYTE_LEN) | (sdls_frame.pdu.data[1]);
#ifdef DEBUG
    printf("# PDU Keys: %d\n", pdu_keys);
    printf("MKID: %d\n", packet.mkid);
#endif
    if (packet.mkid >= MKID_MAX)
    {
        report.af = 1;
        if (log_summary.rs > 0)
        {
            Crypto_increment((uint8_t *)&log_summary.num_se, 4);
            log_summary.rs--;
            mc_log.blk[log_count].emt      = MKID_INVALID_EID;
            mc_log.blk[log_count].emv[0]   = 0x4E;
            mc_log.blk[log_count].emv[1]   = 0x41;
            mc_log.blk[log_count].emv[2]   = 0x53;
            mc_log.blk[log_count].emv[3]   = 0x41;
            mc_log.blk[log_count++].em_len = 4;
        }
#ifdef DEBUG
        printf(KRED "Error: MKID is not valid! \n" RESET);
#endif
        status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
        return status;
    }

    for (count = SDLS_OTAR_IV_OFFSET; count < (SDLS_OTAR_IV_OFFSET + SDLS_IV_LEN); count++)
    { // Initialization Vector
        packet.iv[count - SDLS_OTAR_IV_OFFSET] = sdls_frame.pdu.data[count];
#ifdef DEBUG
        printf("packet.iv[%d] = 0x%02x\n", count - SDLS_OTAR_IV_OFFSET, packet.iv[count - SDLS_OTAR_IV_OFFSET]);
#endif
    }

    count = sdls_frame.pdu.hdr.pdu_len - MAC_SIZE;
    for (w = 0; w < MAC_SIZE; w++)
    { // MAC
        packet.mac[w] = sdls_frame.pdu.data[count + w];
#ifdef DEBUG
        printf("packet.mac[%d] = 0x%02x\n", w, packet.mac[w]);
#endif
    }

    // Try to get key
    ekp = key_if->get_key(packet.mkid);
    if (ekp == NULL)
    {
        return CRYPTO_LIB_ERR_KEY_ID_ERROR;
    }

    // Check key state
    if(ekp->key_state != KEY_ACTIVE)
    {
        return CRYPTO_LIB_ERR_KEY_STATE_INVALID;
    }

    uint8_t ecs = CRYPTO_CIPHER_AES256_GCM; // Per SDLS baseline
    status      = cryptography_if->cryptography_aead_decrypt(&(sdls_frame.pdu.data[14]), // plaintext output
                                                             (size_t)(pdu_keys * (SDLS_KEYID_LEN + SDLS_KEY_LEN)), // length of data
                                                             NULL,             // in place decryption
                                                             0,                // in data length
                                                             &(ekp->value[0]), // key
                                                             ekp->key_len,     // key length
                                                             NULL,             // SA reference
                                                             &(packet.iv[0]),  // IV
                                                             SDLS_IV_LEN,      // IV length
                                                             &(packet.mac[0]), // tag input
                                                             MAC_SIZE,         // tag size
                                                             NULL,             // AAD
                                                             0,                // AAD Length
                                                             CRYPTO_TRUE,      // decrypt
                                                             CRYPTO_TRUE,      // authenticate
                                                             CRYPTO_FALSE,     // AAD Bool
                                                             &ecs,             // encryption cipher
                                                             NULL,             // authentication cipher
                                                             NULL              // cam_cookies
         );

    // If decryption errors, return
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef DEBUG
        printf(KRED "Error: OTAR AEAD Decryption failed with error %d \n" RESET, status);
#endif
        return status;
    }

    // Read in Decrypted Data
    for (count = 14; x < pdu_keys; x++)
    { // Encrypted Key Blocks
        packet.EKB[x].ekid = (sdls_frame.pdu.data[count] << BYTE_LEN) | (sdls_frame.pdu.data[count + 1]);
        if (packet.EKB[x].ekid < MKID_MAX)
        {
            report.af = 1;
            if (log_summary.rs > 0)
            {
                Crypto_increment((uint8_t *)&log_summary.num_se, 4);
                log_summary.rs--;
                mc_log.blk[log_count].emt      = OTAR_MK_ERR_EID;
                mc_log.blk[log_count].emv[0]   = 0x4E; // N
                mc_log.blk[log_count].emv[1]   = 0x41; // A
                mc_log.blk[log_count].emv[2]   = 0x53; // S
                mc_log.blk[log_count].emv[3]   = 0x41; // A
                mc_log.blk[log_count++].em_len = 4;
            }
#ifdef DEBUG
            printf(KRED "Error: Cannot OTAR master key! \n" RESET);
#endif
            status = CRYPTO_LIB_ERROR;
            return status;
        }
        else
        {
            ekp = key_if->get_key(packet.EKB[x].ekid);
            if (ekp == NULL)
            {
                return CRYPTO_LIB_ERR_KEY_ID_ERROR;
            }

            count = count + 2;
            for (y = count; y < (SDLS_KEY_LEN + count); y++)
            {
                // Encrypted Key
                packet.EKB[x].ek[y - count] = sdls_frame.pdu.data[y];
#ifdef SA_DEBUG
                printf("\t packet.EKB[%d].ek[%d] = 0x%02x\n", x, y - count, packet.EKB[x].ek[y - count]);
#endif
                // Setup Key Ring
                ekp->value[y - count] = sdls_frame.pdu.data[y];
            }
            count = count + SDLS_KEY_LEN;

            // Set state to PREACTIVE
            ekp->key_state = KEY_PREACTIVE;
        }
    }

#ifdef PDU_DEBUG
    printf("Received %d keys via master key %d: \n", pdu_keys, packet.mkid);
    for (x = 0; x < pdu_keys; x++)
    {
        printf("%d) Key ID = %d, 0x", x + 1, packet.EKB[x].ekid);
        for (y = 0; y < SDLS_KEY_LEN; y++)
        {
            printf("%02x", packet.EKB[x].ek[y]);
        }
        printf("\n");
    }
#endif

    return CRYPTO_LIB_SUCCESS;
}
/**
 * @brief Function: Crypto_Key_update
 * Updates the state of the all keys in the received SDLS EP PDU
 * @param state: uint8
 * @return uint32: Success/Failure
 **/
int32_t Crypto_Key_update(uint8_t state)
{ // Local variables
    SDLS_KEY_BLK_t packet;
    int            count    = 0;
    int            pdu_keys = sdls_frame.pdu.hdr.pdu_len / 2;
    int32_t        status;
    crypto_key_t  *ekp = NULL;
    int            x;

    if (key_if == NULL)
    {
        status = CRYPTOGRAPHY_UNSUPPORTED_OPERATION_FOR_KEY_RING;
        return status;
    }

#ifdef PDU_DEBUG
    printf("Keys ");
#endif
    // Read in PDU
    for (x = 0; x < pdu_keys; x++)
    {
        packet.kblk[x].kid = (sdls_frame.pdu.data[count] << BYTE_LEN) | (sdls_frame.pdu.data[count + 1]);
        count              = count + 2;
#ifdef PDU_DEBUG
        if (x != (pdu_keys - 1))
        {
            printf("%d, ", packet.kblk[x].kid);
        }
        else
        {
            printf("and %d ", packet.kblk[x].kid);
        }
#endif
    }
#ifdef PDU_DEBUG
    printf("changed to state ");
    switch (state)
    {
        case KEY_PREACTIVE:
            printf("PREACTIVE. \n");
            break;
        case KEY_ACTIVE:
            printf("ACTIVE. \n");
            break;
        case KEY_DEACTIVATED:
            printf("DEACTIVATED. \n");
            break;
        case KEY_DESTROYED:
            printf("DESTROYED. \n");
            break;
        case KEY_CORRUPTED:
            printf("CORRUPTED. \n");
            break;
        default:
            printf("ERROR. \n");
            break;
    }
#endif
    // Update Key State
    for (x = 0; x < pdu_keys; x++)
    {
        if (packet.kblk[x].kid < MKID_MAX)
        {
            report.af = 1;
            if (log_summary.rs > 0)
            {
                Crypto_increment((uint8_t *)&log_summary.num_se, 4);
                log_summary.rs--;
                mc_log.blk[log_count].emt      = MKID_STATE_ERR_EID;
                mc_log.blk[log_count].emv[0]   = 0x4E;
                mc_log.blk[log_count].emv[1]   = 0x41;
                mc_log.blk[log_count].emv[2]   = 0x53;
                mc_log.blk[log_count].emv[3]   = 0x41;
                mc_log.blk[log_count++].em_len = 4;
            }
#ifdef PDU_DEBUG
            printf(KRED "Error: MKID state cannot be changed! \n" RESET);
#endif
            return CRYPTO_LIB_ERR_KEY_ID_ERROR;
        }

        ekp = key_if->get_key(packet.kblk[x].kid);
        if (ekp == NULL)
        {
            return CRYPTO_LIB_ERR_KEY_ID_ERROR;
        }

        if (ekp->key_state == (state - 1))
        {
            ekp->key_state = state;
        }
        else
        {
            if (log_summary.rs > 0)
            {
                Crypto_increment((uint8_t *)&log_summary.num_se, 4);
                log_summary.rs--;
                mc_log.blk[log_count].emt      = KEY_TRANSITION_ERR_EID;
                mc_log.blk[log_count].emv[0]   = 0x4E;
                mc_log.blk[log_count].emv[1]   = 0x41;
                mc_log.blk[log_count].emv[2]   = 0x53;
                mc_log.blk[log_count].emv[3]   = 0x41;
                mc_log.blk[log_count++].em_len = 4;
            }
#ifdef PDU_DEBUG
            printf(KRED "Error: Key %d cannot transition to desired state! \n" RESET, packet.kblk[x].kid);
#endif
            return CRYPTO_LIB_ERR_KEY_STATE_TRANSITION_ERROR;
        }
    }
    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_Key_inventory
 * @param ingest: uint8_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_Key_inventory(uint8_t *ingest)
{
    // Local variables
    SDLS_KEY_INVENTORY_CMD_t packet;
    uint16_t                 range  = 0;
    uint8_t                  count  = 0;
    int32_t                  status = CRYPTO_LIB_SUCCESS;
    crypto_key_t            *ekp    = NULL;
    uint16_t                 x;

    if ((key_if == NULL) || (ingest == NULL))
    {
        status = CRYPTOGRAPHY_UNSUPPORTED_OPERATION_FOR_KEY_RING;
        return status;
    }

    // Read in PDU
    packet.kid_first = ((uint8_t)sdls_frame.pdu.data[count] << BYTE_LEN) | ((uint8_t)sdls_frame.pdu.data[count + 1]);
    count            = count + 2;
    packet.kid_last  = ((uint8_t)sdls_frame.pdu.data[count] << BYTE_LEN) | ((uint8_t)sdls_frame.pdu.data[count + 1]);
    count            = count + 2;

    // Prepare for Reply
    range                      = packet.kid_last - packet.kid_first + 1;
    sdls_frame.pdu.hdr.pdu_len = (SDLS_KEY_INVENTORY_RPLY_SIZE * (range)) * BYTE_LEN;
    sdls_frame.hdr.pkt_length =
        CCSDS_HDR_SIZE + CCSDS_PUS_SIZE + SDLS_TLV_HDR_SIZE + (sdls_frame.pdu.hdr.pdu_len / BYTE_LEN) - 1 + 2; // 2 = Num Keys Returned Field (2 Bytes)
    count = Crypto_Prep_Reply(sdls_ep_reply, CRYPTOLIB_APPID);

    sdls_ep_reply[count++] = ((range & 0xFF00) >> BYTE_LEN);
    sdls_ep_reply[count++] = (range & 0x00FF);
    for (x = packet.kid_first; x <= packet.kid_last; x++)
    {
        // Key ID
        sdls_ep_reply[count++] = ((x & 0xFF00) >> BYTE_LEN);
        sdls_ep_reply[count++] = (x & 0x00FF);
        // Get Key
        ekp = key_if->get_key(x);
        if (ekp == NULL)
        {
            return CRYPTO_LIB_ERR_KEY_ID_ERROR;
        }
        // Key State
        sdls_ep_reply[count++] = ekp->key_state;
    }
#ifdef DEBUG
    printf("Key Inv. Reply:    0x");
    for (x = 0; x < count; x++)
    {
        printf("%02X", sdls_ep_reply[x]);
    }
    printf("\n\n");
#endif
    return status;
}

/**
 * @brief Function: Crypto_Key_verify
 * @param tc_frame: TC_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_Key_verify(TC_t *tc_frame)
{
    // Local variables
    SDLS_KEYV_CMD_t packet;
    int             pdu_keys = sdls_frame.pdu.hdr.pdu_len / SDLS_KEYV_CMD_BLK_SIZE;
    int             x;
    int             y;
    uint8_t         count  = 0;
    int32_t         status = CRYPTO_LIB_SUCCESS;
    crypto_key_t   *ekp    = NULL;
    tc_frame               = tc_frame;

    if (key_if == NULL)
    {
        status = CRYPTOGRAPHY_UNSUPPORTED_OPERATION_FOR_KEY_RING;
        return status;
    }

#ifdef PDU_DEBUG
    printf("Crypto_Key_verify: Requested %d key(s) to verify \n", pdu_keys);
#endif

    // Read in PDU
    for (x = 0; x < pdu_keys; x++)
    {
        // Key ID
        packet.blk[x].kid = ((uint8_t)sdls_frame.pdu.data[count] << BYTE_LEN) | ((uint8_t)sdls_frame.pdu.data[count + 1]);
        count += 2;
#ifdef PDU_DEBUG
        printf("\tCrypto_Key_verify: Block %d Key ID is %d ", x, packet.blk[x].kid);
#endif
        // Key Challenge
        for (y = 0; y < CHALLENGE_SIZE; y++)
        {
            packet.blk[x].challenge[y] = sdls_frame.pdu.data[count];
            count += 1;
        }
#ifdef PDU_DEBUG
        printf("\n");
#endif
    }

    // Prepare for Reply
    sdls_frame.pdu.hdr.pdu_len =
        pdu_keys * (SDLS_KEYV_KEY_ID_LEN + SDLS_IV_LEN + CHALLENGE_SIZE + CHALLENGE_MAC_SIZE) * BYTE_LEN;

    // length = pdu_len + HDR + PUS - 1 (per CCSDS Convention)
    if (crypto_config.has_pus_hdr == TC_HAS_PUS_HDR)
    {
        sdls_frame.hdr.pkt_length =
            CCSDS_HDR_SIZE + CCSDS_PUS_SIZE + SDLS_TLV_HDR_SIZE + (sdls_frame.pdu.hdr.pdu_len / BYTE_LEN) - 1;
    }
    else
    {
        sdls_frame.hdr.pkt_length = CCSDS_HDR_SIZE + SDLS_TLV_HDR_SIZE + (sdls_frame.pdu.hdr.pdu_len / BYTE_LEN) - 1;
    }

    count                 = Crypto_Prep_Reply(sdls_ep_reply, CRYPTOLIB_APPID);
    uint16_t pdu_data_idx = count;

    for (x = 0; x < pdu_keys; x++)
    {
        // Key ID
        sdls_ep_keyv_reply.blk[x].kid = packet.blk[x].kid;

        sdls_frame.pdu.data[pdu_data_idx] = (packet.blk[x].kid & 0xFF00) >> BYTE_LEN;
        sdls_ep_reply[pdu_data_idx]       = (packet.blk[x].kid & 0xFF00) >> BYTE_LEN;
        pdu_data_idx += 1;

        sdls_frame.pdu.data[pdu_data_idx] = (packet.blk[x].kid & 0x00FF);
        sdls_ep_reply[pdu_data_idx]       = (packet.blk[x].kid & 0x00FF);
        pdu_data_idx += 1;
        count += 2;

        // Get Key
        ekp = key_if->get_key(sdls_ep_keyv_reply.blk[x].kid);
        if (ekp == NULL)
        {
            return CRYPTO_LIB_ERR_KEY_ID_ERROR;
        }

        // Initialization Vector
        for (y = 0; y < SDLS_IV_LEN; y++)
        {
            sdls_frame.pdu.data[pdu_data_idx] = 0x00; //= *(tc_frame->tc_sec_header.iv + y);
            sdls_ep_keyv_reply.blk[x].iv[y]   = 0x00; //= *(tc_frame->tc_sec_header.iv + y);
            sdls_ep_reply[pdu_data_idx]       = 0x00; //= *(tc_frame->tc_sec_header.iv + y);
            pdu_data_idx += 1;
            count += 1;
        }
        // ***** This increments the lowest bytes of the IVs so they aren't identical
        sdls_frame.pdu.data[pdu_data_idx - 1] = sdls_frame.pdu.data[pdu_data_idx - 1] + x + 1;
        sdls_ep_keyv_reply.blk[x].iv[11]      = sdls_ep_keyv_reply.blk[x].iv[SDLS_IV_LEN - 1] + x + 1;
        sdls_ep_reply[pdu_data_idx - 1]       = sdls_ep_reply[pdu_data_idx - 1] + x + 1;

        // Encrypt challenge
        uint8_t ecs = CRYPTO_CIPHER_AES256_GCM;
        status = cryptography_if->cryptography_aead_encrypt(&(sdls_ep_keyv_reply.blk[x].challenged[0]), // ciphertext output
                                                   (size_t)CHALLENGE_SIZE,                     // length of data
                                                   &(packet.blk[x].challenge[0]),              // plaintext input
                                                   (size_t)CHALLENGE_SIZE,                     // in data length
                                                   &(ekp->value[0]),                           // Key Index
                                                   SDLS_KEY_LEN,                               // Key Length
                                                   NULL,                                       // SA Reference for key
                                                   &(sdls_ep_keyv_reply.blk[x].iv[0]),         // IV
                                                   SDLS_IV_LEN,                                // IV Length
                                                   &(sdls_ep_keyv_reply.blk[x].mac[0]),        // MAC
                                                   CHALLENGE_MAC_SIZE,                         // MAC Size
                                                   NULL, 0,
                                                   CRYPTO_TRUE,  // Encrypt
                                                   CRYPTO_TRUE,  // Authenticate
                                                   CRYPTO_FALSE, // AAD
                                                   &ecs,         // encryption cipher
                                                   NULL,         // authentication cipher
                                                   NULL          // cam_cookies
        );

        // If encryption errors, capture something about it for testing
        // We need to continue on, other keys could be successful
        if (status != CRYPTO_LIB_SUCCESS)
        {
#ifdef DEBUG
        printf(KRED "Error: OTAR Key Verification encryption failed for new key index %d with error %d \n" RESET, x, status);
#endif
        }

        // Copy from the KEYV Blocks into the output PDU
        memcpy(&sdls_frame.pdu.data[pdu_data_idx], &(sdls_ep_keyv_reply.blk[x].challenged[0]), CHALLENGE_SIZE);
        memcpy(&sdls_ep_reply[pdu_data_idx], &(sdls_ep_keyv_reply.blk[x].challenged[0]), CHALLENGE_SIZE);
        pdu_data_idx += CHALLENGE_SIZE;

        memcpy(&sdls_frame.pdu.data[pdu_data_idx], &(sdls_ep_keyv_reply.blk[x].mac[0]), CHALLENGE_MAC_SIZE);
        memcpy(&sdls_ep_reply[pdu_data_idx], &(sdls_ep_keyv_reply.blk[x].mac[0]), CHALLENGE_MAC_SIZE);
        pdu_data_idx += CHALLENGE_MAC_SIZE;

        count += CHALLENGE_SIZE + CHALLENGE_MAC_SIZE; // Don't forget to increment count!
    }

#ifdef PDU_DEBUG

    /* Easy to read debug block for verified keys */
    for (int i = 0; i < pdu_keys; i++)
    {
        printf("\nKey Index %d Verification results:", i);
        printf("\n\tKID: %04X", sdls_ep_keyv_reply.blk[i].kid);
        printf("\n\tIV: ");
        for (int j = 0; j < SDLS_KEY_LEN; j++)
        {
            printf("%02X", sdls_ep_keyv_reply.blk[i].iv[j]);
        }
        printf("\n\tChallenged: ");
        for (int j = 0; j < CHALLENGE_SIZE; j++)
        {
            printf("%02X", sdls_ep_keyv_reply.blk[i].challenged[j]);
        }
        printf("\n\tMAC: ");
        for (int j = 0; j < CHALLENGE_MAC_SIZE; j++)
        {
            printf("%02X", sdls_ep_keyv_reply.blk[i].mac[j]);
        }
    }
    printf("\n\nCrypto_Key_Verify: Response is %d bytes \n", count);

    printf("\nPrinting NEW SDLS response packet:\n\t");
    for (uint16_t idx = 0; idx < count; idx++)
    {
        printf("%02X", sdls_ep_reply[idx]);
    }
    printf("\n");

#endif

    return status;
}