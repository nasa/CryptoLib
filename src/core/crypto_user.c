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

/**
 * @brief Function: Crypto_User_IdleTrigger
 * @param ingest: uint8_t*
 * @return int32: count
 **/
int32_t Crypto_User_IdleTrigger(uint8_t* ingest)
{
    uint8_t count = 0;

    // Prepare for Reply
    sdls_frame.pdu.pdu_len = 0;
    sdls_frame.hdr.pkt_length = sdls_frame.pdu.pdu_len + 9;
    count = Crypto_Prep_Reply(ingest, 144);

    return count;
}

/**
 * @brief Function: Crypto_User_BadSPI
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_BadSPI(void)
{
    // Toggle Bad Sequence Number
    if (badSPI == 0)
    {
        badSPI = 1;
    }
    else
    {
        badSPI = 0;
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_BadMAC
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_BadMAC(void)
{
    // Toggle Bad MAC
    if (badMAC == 0)
    {
        badMAC = 1;
    }
    else
    {
        badMAC = 0;
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_BadIV
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_BadIV(void)
{
    // Toggle Bad MAC
    if (badIV == 0)
    {
        badIV = 1;
    }
    else
    {
        badIV = 0;
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_BadFECF
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_BadFECF(void)
{
    // Toggle Bad FECF
    if (badFECF == 0)
    {
        badFECF = 1;
    }
    else
    {
        badFECF = 0;
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_ModifyKey
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_ModifyKey(void)
{
    // Local variables
    uint16_t kid = ((uint8_t)sdls_frame.pdu.data[0] << 8) | ((uint8_t)sdls_frame.pdu.data[1]);
    uint8_t mod = (uint8_t)sdls_frame.pdu.data[2];

    crypto_key_t* ekp = NULL;

    ekp = key_if->get_key(kid);
    if (ekp == NULL)
    {
        return CRYPTO_LIB_ERR_KEY_ID_ERROR;
    }

    switch (mod)
    {
    case 1: // Invalidate Key
        ekp->value[KEY_SIZE - 1]++;
        printf("Key %d value invalidated! \n", kid);
        break;
    case 2: // Modify key state
        ekp->key_state = (uint8_t)sdls_frame.pdu.data[3] & 0x0F;
        printf("Key %d state changed to %d! \n", kid, mod);
        break;
    default:
        // Error
        break;
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_ModifyActiveTM
 * Modifies tm_sec_header.spi based on sdls_frame.pdu.data[0]
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_ModifyActiveTM(void)
{
    // TODO Check this
    tm_frame_sec_hdr.spi = (uint8_t)sdls_frame.pdu.data[0];
    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_User_ModifyVCID
 * @return int32: Success/Failure
 **/
int32_t Crypto_User_ModifyVCID(void)
{
    // tm_frame.tm_header.vcid = (uint8_t)sdls_frame.pdu.data[0];
    // Check this
    tm_frame_pri_hdr.vcid = (uint8_t)sdls_frame.pdu.data[0];
    SecurityAssociation_t* sa_ptr;
    int i;
    int j;

    for (i = 0; i < NUM_GVCID; i++)
    {
        if (sa_if->sa_get_from_spi(i, &sa_ptr) != CRYPTO_LIB_SUCCESS)
        {
            // TODO - Error handling
            return CRYPTO_LIB_ERROR; // Error -- unable to get SA from SPI.
        }
        for (j = 0; j < NUM_SA; j++)
        {

            if (sa_ptr->gvcid_blk.mapid == TYPE_TM)
            {
                
                if (sa_ptr->gvcid_blk.vcid == tm_frame_pri_hdr.vcid)//.tm_header.vcid)
                {
                    // TODO Check this
                    tm_frame_sec_hdr.spi = i;
                    printf("TM Frame SPI changed to %d \n", i);
                    break;
                }
            }
        }
    }

    return CRYPTO_LIB_SUCCESS;
}
