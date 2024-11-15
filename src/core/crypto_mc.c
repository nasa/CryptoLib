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
** Security Association Monitoring and Control
*/
/**
 * @brief Function: Crypto_MC_ping
 * @param ingest: uint8_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_MC_ping(uint8_t *ingest)
{
    uint8_t count = 0;
    count         = count;
    ingest        = ingest;

    // Prepare for Reply
    sdls_frame.pdu.hdr.pdu_len = 0;
    sdls_frame.hdr.pkt_length  = CCSDS_HDR_SIZE + CCSDS_PUS_SIZE + SDLS_TLV_HDR_SIZE + (sdls_frame.pdu.hdr.pdu_len / BYTE_LEN) - 1;
    count                      = Crypto_Prep_Reply(sdls_ep_reply, CRYPTOLIB_APPID);

#ifdef PDU_DEBUG
    printf("MC Ping Reply: \t   0x");
    for (int x = 0; x < count; x++)
    {
        printf("%02X", sdls_ep_reply[x]);
    }
    printf("\n\n");
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_MC_status
 * @param ingest: uint8_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_MC_status(uint8_t *ingest)
{
    if (ingest == NULL)
        return CRYPTO_LIB_ERROR;
    uint8_t count = 0;

    // Prepare for Reply
    sdls_frame.pdu.hdr.pdu_len = SDLS_MC_LOG_RPLY_SIZE * BYTE_LEN;
    sdls_frame.hdr.pkt_length  = CCSDS_HDR_SIZE + CCSDS_PUS_SIZE + SDLS_TLV_HDR_SIZE + (sdls_frame.pdu.hdr.pdu_len / BYTE_LEN) - 1;
    count                      = Crypto_Prep_Reply(sdls_ep_reply, CRYPTOLIB_APPID);
    // PDU
    sdls_ep_reply[count] = (log_summary.num_se & 0xFF00) >> BYTE_LEN;
    count++;
    sdls_ep_reply[count] = (log_summary.num_se & 0x00FF);
    count++;
    sdls_ep_reply[count] = (log_summary.rs & 0xFF00) >> BYTE_LEN;
    count++;
    sdls_ep_reply[count] = (log_summary.rs & 0x00FF);
    count++;

#ifdef PDU_DEBUG
    printf("MC Status Reply:   0x");
    for (int x = 0; x < count; x++)
    {
        printf("%02X", sdls_ep_reply[x]);
    }
    printf("\n");
    printf("log_summary.num_se = 0x%02x \n", log_summary.num_se);
    printf("log_summary.rs = 0x%02x \n", log_summary.rs);
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_MC_dump
 * @param ingest: uint8_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_MC_dump(uint8_t *ingest)
{
    if (ingest == NULL)
        return CRYPTO_LIB_ERROR;
    uint8_t count = 0;
    int     x;
    int     y;

    // Prepare for Reply
    sdls_frame.pdu.hdr.pdu_len = (SDLS_MC_DUMP_RPLY_SIZE * log_count) * BYTE_LEN;
    sdls_frame.hdr.pkt_length  = CCSDS_HDR_SIZE + CCSDS_PUS_SIZE + SDLS_TLV_HDR_SIZE + (sdls_frame.pdu.hdr.pdu_len / BYTE_LEN) - 1;
    count                      = Crypto_Prep_Reply(sdls_ep_reply, CRYPTOLIB_APPID);
    // PDU
    for (x = 0; x < log_count; x++)
    {
        sdls_ep_reply[count] = mc_log.blk[x].emt;
        count++;
        sdls_ep_reply[count] = (mc_log.blk[x].em_len & 0xFF00) >> BYTE_LEN;
        count++;
        sdls_ep_reply[count] = (mc_log.blk[x].em_len & 0x00FF);
        count++;
        for (y = 0; y < EMV_SIZE; y++)
        {
            sdls_ep_reply[count] = mc_log.blk[x].emv[y];
            count++;
        }
#ifdef PDU_DEBUG
        printf("Log %d emt: 0x%02x\n", x, mc_log.blk[x].emt);
        printf("Log %d em_len: 0x%04x\n", x, (mc_log.blk[x].em_len & 0xFFFF));
        printf("Log %d emv: 0x", x);
        for (y = 0; y < EMV_SIZE; y++)
        {
            printf("%02X", mc_log.blk[x].emv[y]);
        }
        printf("\n\n");
#endif
    }

#ifdef PDU_DEBUG
    printf("log_count = %d \n", log_count);
    printf("log_summary.num_se = 0x%02x \n", log_summary.num_se);
    printf("log_summary.rs = 0x%02x \n\n", log_summary.rs);
    printf("MC Dump Reply:     0x");
    for (int x = 0; x < count; x++)
    {
        printf("%02X", sdls_ep_reply[x]);
    }
    printf("\n");
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_MC_erase
 * @param ingest: uint8_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_MC_erase(uint8_t *ingest)
{
    if (ingest == NULL)
        return CRYPTO_LIB_ERROR;
    uint8_t count = 0;
    int     x;
    int     y;

    // Zero Logs
    for (x = 0; x < LOG_SIZE; x++)
    {
        mc_log.blk[x].emt    = 0;
        mc_log.blk[x].em_len = 0;
        for (y = 0; y < EMV_SIZE; y++)
        {
            mc_log.blk[x].emv[y] = 0;
        }
    }

    // Compute Summary
    log_count          = 0;
    log_summary.num_se = 0;
    log_summary.rs     = LOG_SIZE;

    // Prepare for Reply
    sdls_frame.pdu.hdr.pdu_len = SDLS_MC_LOG_RPLY_SIZE * BYTE_LEN; // 4
    sdls_frame.hdr.pkt_length  = CCSDS_HDR_SIZE + CCSDS_PUS_SIZE + SDLS_TLV_HDR_SIZE + (sdls_frame.pdu.hdr.pdu_len / BYTE_LEN) - 1;
    count                      = Crypto_Prep_Reply(sdls_ep_reply, CRYPTOLIB_APPID);
    // PDU
    sdls_ep_reply[count] = (log_summary.num_se & 0xFF00) >> BYTE_LEN;
    count++;
    sdls_ep_reply[count] = (log_summary.num_se & 0x00FF);
    count++;
    sdls_ep_reply[count] = (log_summary.rs & 0xFF00) >> BYTE_LEN;
    count++;
    sdls_ep_reply[count] = (log_summary.rs & 0x00FF);
    count++;

#ifdef PDU_DEBUG
    printf("log_count = %d \n", log_count);
    printf("log_summary.num_se = 0x%02x \n", log_summary.num_se);
    printf("log_summary.rs = 0x%02x \n", log_summary.rs);
    printf("MC Erase Reply:    0x");
    for (int x = 0; x < count; x++)
    {
        printf("%02X", sdls_ep_reply[x]);
    }
    printf("\n");
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_MC_selftest
 * @param ingest: uint8_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_MC_selftest(uint8_t *ingest)
{
    if (ingest == NULL)
        return CRYPTO_LIB_ERROR;
    uint8_t count  = 0;
    uint8_t result = ST_OK;

    // TODO: Perform test

    // Prepare for Reply
    sdls_frame.pdu.hdr.pdu_len = SDLS_MC_ST_RPLY_SIZE * BYTE_LEN;
    sdls_frame.hdr.pkt_length  = CCSDS_HDR_SIZE + CCSDS_PUS_SIZE + SDLS_TLV_HDR_SIZE + (sdls_frame.pdu.hdr.pdu_len / BYTE_LEN) - 1;
    sdls_frame.pdu.data[0]     = result;
    count                      = Crypto_Prep_Reply(sdls_ep_reply, CRYPTOLIB_APPID);

    sdls_ep_reply[count] = result;
    count++;

#ifdef PDU_DEBUG
    printf("MC SelfTest Reply: 0x");
    for (int x = 0; x < count; x++)
    {
        printf("%02X", sdls_ep_reply[x]);
    }
    printf("\n");
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_SA_readASRN
 * @param ingest: uint8_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_SA_readARSN(uint8_t *ingest)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (ingest == NULL)
    {
        status = CRYPTO_LIB_ERROR;
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
        // uint8_t count = 0;
        uint16_t               spi = 0x0000;
        SecurityAssociation_t *sa_ptr;
        int                    x;

        // Read ingest
        spi = ((uint8_t)sdls_frame.pdu.data[0] << BYTE_LEN) | (uint8_t)sdls_frame.pdu.data[1];

        if (sa_if->sa_get_from_spi(spi, &sa_ptr) != CRYPTO_LIB_SUCCESS)
        {
            // TODO - Error handling
            status = CRYPTO_LIB_ERR_SA_NOT_OPERATIONAL; // Error -- unable to get SA from SPI.
        }

        if (status == CRYPTO_LIB_SUCCESS)
        {
            // Prepare for Reply
            sdls_frame.pdu.hdr.pdu_len = (SPI_LEN + sa_ptr->arsn_len) * BYTE_LEN; // bits
            sdls_frame.hdr.pkt_length  = CCSDS_HDR_SIZE + CCSDS_PUS_SIZE + SDLS_TLV_HDR_SIZE + (sdls_frame.pdu.hdr.pdu_len / BYTE_LEN) - 1;
            uint8_t count              = Crypto_Prep_Reply(sdls_ep_reply, CRYPTOLIB_APPID);

            // Write SPI to reply
            sdls_ep_reply[count] = (spi & 0xFF00) >> BYTE_LEN;
            count++;
            sdls_ep_reply[count] = (spi & 0x00FF);
            count++;

            for (x = 0; x < sa_ptr->arsn_len; x++)
            {
                sdls_ep_reply[count] = *(sa_ptr->arsn + x);
                count++;
            }

            if (sa_ptr->shivf_len > 0 && sa_ptr->ecs == 1 && sa_ptr->acs == 1)
            { // Set IV - authenticated encryption
                for (x = 0; x < sa_ptr->shivf_len - 1; x++)
                {
                    sdls_ep_reply[count] = *(sa_ptr->iv + x);
                    count++;
                }

                // TODO: Do we need this?
                if (*(sa_ptr->iv + sa_ptr->shivf_len - 1) > 0)
                { // Adjust to report last received, not expected
                    sdls_ep_reply[count] = *(sa_ptr->iv + sa_ptr->shivf_len - 1) - 1;
                    count++;
                }
                else
                {
                    sdls_ep_reply[count] = *(sa_ptr->iv + sa_ptr->shivf_len - 1);
                    count++;
                }
            }
            else
            {
                // TODO
            }
#ifdef PDU_DEBUG
            printf("spi = %d \n", spi);
            printf("ARSN_LEN: %d\n", sa_ptr->arsn_len);
            if (sa_ptr->arsn_len > 0)
            {
                printf("ARSN = 0x");
                for (x = 0; x < sa_ptr->arsn_len; x++)
                {
                    printf("%02x", *(sa_ptr->arsn + x));
                }
                printf("\n");
            }
            printf("Read ARSN Reply:   0x");
            for (int x = 0; x < count; x++)
            {
                printf("%02X", sdls_ep_reply[x]);
            }
            printf("\n");
#endif
        }
    }

    return status;
}

/**
 * @brief Function: Crypto_MC_resetalarm
 * @return int32: Success/Failure
 **/
int32_t Crypto_MC_resetalarm(void)
{ // Reset all alarm flags
    report.af    = 0;
    report.bsnf  = 0;
    report.bmacf = 0;
    report.bsaf  = 0;
    return CRYPTO_LIB_SUCCESS;
}
