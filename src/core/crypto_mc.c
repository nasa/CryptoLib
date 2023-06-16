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
 * return int32: count
 **/
int32_t Crypto_MC_ping(uint8_t* ingest)
{
    int count = 0;

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 0;
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    return count;
}

/**
 * @brief Function: Crypto_MC_status
 * @param ingest: uint8_t*
 * @return int32: count
 **/
int32_t Crypto_MC_status(uint8_t* ingest)
{
    if(ingest == NULL) return CRYPTO_LIB_ERROR;
    int count = 0;

    // TODO: Update log_summary.rs;

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 2; // 4
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    // PDU
    // ingest[count++] = (log_summary.num_se & 0xFF00) >> 8;
    ingest[count++] = (log_summary.num_se & 0x00FF);
    // ingest[count++] = (log_summary.rs & 0xFF00) >> 8;
    ingest[count++] = (log_summary.rs & 0x00FF);

#ifdef PDU_DEBUG
    printf("log_summary.num_se = 0x%02x \n", log_summary.num_se);
    printf("log_summary.rs = 0x%02x \n", log_summary.rs);
#endif

    return count;
}

/**
 * @brief Function: Crypto_MC_dump
 * @param ingest: uint8_t*
 * @return int32: Count
 **/
int32_t Crypto_MC_dump(uint8_t* ingest)
{
    if(ingest == NULL) return CRYPTO_LIB_ERROR;
    int count = 0;
    int x;
    int y;

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = (log_count * 6); // SDLS_MC_DUMP_RPLY_SIZE
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    // PDU
    for (x = 0; x < log_count; x++)
    {
        ingest[count++] = mc_log.blk[x].emt;
        // ingest[count++] = (mc_log.blk[x].em_len & 0xFF00) >> 8;
        ingest[count++] = (mc_log.blk[x].em_len & 0x00FF);
        for (y = 0; y < EMV_SIZE; y++)
        {
            ingest[count++] = mc_log.blk[x].emv[y];
        }
    }

#ifdef PDU_DEBUG
    printf("log_count = %d \n", log_count);
    printf("log_summary.num_se = 0x%02x \n", log_summary.num_se);
    printf("log_summary.rs = 0x%02x \n", log_summary.rs);
#endif

    return count;
}

/**
 * @brief Function: Crypto_MC_erase
 * @param ingest: uint8_t*
 * @return int32: count
 **/
int32_t Crypto_MC_erase(uint8_t* ingest)
{
    if(ingest == NULL) return CRYPTO_LIB_ERROR;
    int count = 0;
    int x;
    int y;

    // Zero Logs
    for (x = 0; x < LOG_SIZE; x++)
    {
        mc_log.blk[x].emt = 0;
        mc_log.blk[x].em_len = 0;
        for (y = 0; y < EMV_SIZE; y++)
        {
            mc_log.blk[x].emv[y] = 0;
        }
    }

    // Compute Summary
    log_count = 0;
    log_summary.num_se = 0;
    log_summary.rs = LOG_SIZE;

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 2; // 4
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    // PDU
    // ingest[count++] = (log_summary.num_se & 0xFF00) >> 8;
    ingest[count++] = (log_summary.num_se & 0x00FF);
    // ingest[count++] = (log_summary.rs & 0xFF00) >> 8;
    ingest[count++] = (log_summary.rs & 0x00FF);

    return count;
}

/**
 * @brief Function: Crypto_MC_selftest
 * @param ingest: uint8_t*
 * @return int32: Count
 **/
int32_t Crypto_MC_selftest(uint8_t* ingest)
{
    if(ingest == NULL) return CRYPTO_LIB_ERROR;
    uint8_t count = 0;
    uint8_t result = ST_OK;

    // TODO: Perform test

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 1;
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    ingest[count++] = result;

    return count;
}

/**
 * @brief Function: Crypto_SA_readASRN
 * @param ingest: uint8_t*
 * @return int32: Count
 **/
int32_t Crypto_SA_readARSN(uint8_t* ingest)
{
    if(ingest == NULL) return CRYPTO_LIB_ERROR;
    uint8_t count = 0;
    uint16_t spi = 0x0000;
    SecurityAssociation_t* sa_ptr;
    int x;

    // Read ingest
    spi = ((uint8_t)sdls_frame.pdu.data[0] << 8) | (uint8_t)sdls_frame.pdu.data[1];

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 2 + IV_SIZE;
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 128);

    // Write SPI to reply
    ingest[count++] = (spi & 0xFF00) >> 8;
    ingest[count++] = (spi & 0x00FF);

    if (sadb_routine->sadb_get_sa_from_spi(spi, &sa_ptr) != CRYPTO_LIB_SUCCESS)
    {
        // TODO - Error handling
        return CRYPTO_LIB_ERROR; // Error -- unable to get SA from SPI.
    }
    if (sa_ptr->shivf_len > 0)
    { // Set IV - authenticated encryption
        for (x = 0; x < sa_ptr->shivf_len - 1; x++)
        {
            if(sa_ptr->iv == NULL)
            {
                return CRYPTO_LIB_ERROR;
            }
            ingest[count++] = *(sa_ptr->iv + x);
        }

        // TODO: Do we need this?
        if (*(sa_ptr->iv + sa_ptr->shivf_len - 1) > 0)
        { // Adjust to report last received, not expected
            ingest[count++] = *(sa_ptr->iv + sa_ptr->shivf_len - 1) - 1;
        }
        else
        {
            ingest[count++] = *(sa_ptr->iv + sa_ptr->shivf_len - 1);
        }
    }
    else
    {
        // TODO
    }
#ifdef PDU_DEBUG
    printf("spi = %d \n", spi);
    if (sa_ptr->shivf_len > 0)
    {
        printf("ARSN = 0x");
        for (x = 0; x < sa_ptr->shivf_len; x++)
        {
            printf("%02x", *(sa_ptr->iv + x));
        }
        printf("\n");
    }
#endif

    return count;
}

/**
 * @brief Function: Crypto_MC_resetalarm
 * @return int32: Success/Failure
 **/
int32_t Crypto_MC_resetalarm(void)
{ // Reset all alarm flags
    report.af = 0;
    report.bsnf = 0;
    report.bmacf = 0;
    report.ispif = 0;
    return CRYPTO_LIB_SUCCESS;
}
