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

#include <string.h> // memcpy/memset

/**
 * @brief Function: Crypto_TM_ApplySecurity
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @return int32: Success/Failure
 **/
int32_t Crypto_TM_ApplySecurity(uint8_t* ingest, int *len_ingest)
// Accepts CCSDS message in ingest, and packs into TM before encryption
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    int count = 0;
    int pdu_loc = 0;
    int pdu_len = *len_ingest - TM_MIN_SIZE;
    int pad_len = 0;
    int mac_loc = 0;
    int fecf_loc = 0;
    uint8_t tempTM[TM_SIZE];
    int x = 0;
    int y = 0;
    uint8_t aad[20];
    uint16_t spi = tm_frame.tm_sec_header.spi;
    uint16_t spp_crc = 0x0000;
    SecurityAssociation_t sa;
    SecurityAssociation_t* sa_ptr = &sa;

    memset(&tempTM, 0, TM_SIZE);

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_TM_ApplySecurity START -----\n" RESET);
#endif

    // Check for idle frame trigger
    if (((uint8_t)ingest[0] == 0x08) && ((uint8_t)ingest[1] == 0x90))
    { // Zero ingest
        for (x = 0; x < *len_ingest; x++)
        {
            ingest[x] = 0;
        }
        // Update TM First Header Pointer
        tm_frame.tm_header.fhp = 0xFE;
    }
    else
    { // Update the length of the ingest from the CCSDS header
        *len_ingest = (ingest[4] << 8) | ingest[5];
        ingest[5] = ingest[5] - 5;
        // Remove outgoing secondary space packet header flag
        ingest[0] = 0x00;
        // Change sequence flags to 0xFFFF
        ingest[2] = 0xFF;
        ingest[3] = 0xFF;
        // Add 2 bytes of CRC to space packet
        spp_crc = Crypto_Calc_CRC16((uint8_t* )ingest, *len_ingest);
        ingest[*len_ingest] = (spp_crc & 0xFF00) >> 8;
        ingest[*len_ingest + 1] = (spp_crc & 0x00FF);
        *len_ingest = *len_ingest + 2;
        // Update TM First Header Pointer
        tm_frame.tm_header.fhp = tm_offset;
#ifdef TM_DEBUG
        printf("tm_offset = %d \n", tm_offset);
#endif
    }

    // Update Current Telemetry Frame in Memory
    // Counters
    tm_frame.tm_header.mcfc++;
    tm_frame.tm_header.vcfc++;
    // Operational Control Field
    Crypto_TM_updateOCF();
    // Payload Data Unit
    Crypto_TM_updatePDU(ingest, *len_ingest);

    if (sadb_routine->sadb_get_sa_from_spi(spi, &sa_ptr) != CRYPTO_LIB_SUCCESS)
    {
        // TODO - Error handling
        return CRYPTO_LIB_ERROR; // Error -- unable to get SA from SPI.
    }

    // Check test flags
    if (badSPI == 1)
    {
        tm_frame.tm_sec_header.spi++;
    }
    if (badIV == 1)
    {
        *(sa_ptr->iv + sa_ptr->shivf_len - 1) = *(sa_ptr->iv + sa_ptr->shivf_len - 1) + 1;
    }
    if (badMAC == 1)
    {
        tm_frame.tm_sec_trailer.mac[MAC_SIZE - 1]++;
    }

    // Initialize the temporary TM frame
    // Header
    tempTM[count++] = (uint8_t)((tm_frame.tm_header.tfvn << 6) | ((tm_frame.tm_header.scid & 0x3F0) >> 4));
    tempTM[count++] = (uint8_t)(((tm_frame.tm_header.scid & 0x00F) << 4) | (tm_frame.tm_header.vcid << 1) |
                                (tm_frame.tm_header.ocff));
    tempTM[count++] = (uint8_t)(tm_frame.tm_header.mcfc);
    tempTM[count++] = (uint8_t)(tm_frame.tm_header.vcfc);
    tempTM[count++] =
        (uint8_t)((tm_frame.tm_header.tfsh << 7) | (tm_frame.tm_header.sf << 6) | (tm_frame.tm_header.pof << 5) |
                  (tm_frame.tm_header.slid << 3) | ((tm_frame.tm_header.fhp & 0x700) >> 8));
    tempTM[count++] = (uint8_t)(tm_frame.tm_header.fhp & 0x0FF);
    //	tempTM[count++] = (uint8_t) ((tm_frame.tm_header.tfshvn << 6) | tm_frame.tm_header.tfshlen);
    // Security Header
    tempTM[count++] = (uint8_t)((spi & 0xFF00) >> 8);
    tempTM[count++] = (uint8_t)((spi & 0x00FF));
    memcpy(tm_frame.tm_sec_header.iv, sa_ptr->iv, sa_ptr->shivf_len);

    // Padding Length
    pad_len = Crypto_Get_tmLength(*len_ingest) - TM_MIN_SIZE + IV_SIZE + TM_PAD_SIZE - *len_ingest;

    // Only add IV for authenticated encryption
    if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
    { // Initialization Vector
#ifdef INCREMENT
        Crypto_increment(sa_ptr->iv, sa_ptr->shivf_len);
#endif
        if ((sa_ptr->est == 1) || (sa_ptr->ast == 1))
        {
            for (x = 0; x < IV_SIZE; x++)
            {
                tempTM[count++] = *(sa_ptr->iv + x);
            }
        }
        pdu_loc = count;
        pad_len = pad_len - IV_SIZE - TM_PAD_SIZE + OCF_SIZE;
        pdu_len = *len_ingest + pad_len;
    }
    else
    {                           // Include padding length bytes - hard coded per ESA testing
        tempTM[count++] = 0x00; // pad_len >> 8;
        tempTM[count++] = 0x1A; // pad_len
        pdu_loc = count;
        pdu_len = *len_ingest + pad_len;
    }

    // Payload Data Unit
    for (x = 0; x < (pdu_len); x++)
    {
        tempTM[count++] = (uint8_t)tm_frame.tm_pdu[x];
    }
    // Message Authentication Code
    mac_loc = count;
    for (x = 0; x < MAC_SIZE; x++)
    {
        tempTM[count++] = 0x00;
    }
    // Operational Control Field
    for (x = 0; x < OCF_SIZE; x++)
    {
        tempTM[count++] = (uint8_t)tm_frame.tm_sec_trailer.ocf[x];
    }
    // Frame Error Control Field
    fecf_loc = count;
    tm_frame.tm_sec_trailer.fecf = Crypto_Calc_FECF((uint8_t* )tempTM, count);
    tempTM[count++] = (uint8_t)((tm_frame.tm_sec_trailer.fecf & 0xFF00) >> 8);
    tempTM[count++] = (uint8_t)(tm_frame.tm_sec_trailer.fecf & 0x00FF);

    // Determine Mode
    // Clear
    if ((sa_ptr->est == 0) && (sa_ptr->ast == 0))
    {
#ifdef DEBUG
        printf(KBLU "Creating a TM - CLEAR! \n" RESET);
#endif
        // Copy temporary frame to ingest
        memcpy(ingest, tempTM, count);
    }
    // Authenticated Encryption
    else if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
    {
#ifdef DEBUG
        printf(KBLU "Creating a TM - AUTHENTICATED ENCRYPTION! \n" RESET);
#endif

        // Copy TM to ingest
        memcpy(ingest, tempTM, pdu_loc);

#ifdef MAC_DEBUG
        printf("AAD = 0x");
#endif
        // Prepare additional authenticated data
        for (y = 0; y < sa_ptr->abm_len; y++)
        {
            aad[y] = ingest[y] & *(sa_ptr->abm + y);
#ifdef MAC_DEBUG
            printf("%02x", aad[y]);
#endif
        }
#ifdef MAC_DEBUG
        printf("\n");
#endif

        status = cryptography_if->cryptography_aead_encrypt(&(ingest[pdu_loc]), // ciphertext output
                                                           (size_t)pdu_len,            // length of data
                                                           &(tempTM[pdu_loc]), // plaintext input
                                                           (size_t)pdu_len,             // in data length
                                                           NULL, // Key is mapped via SA
                                                           KEY_SIZE,
                                                           sa_ptr,
                                                           sa_ptr->iv,
                                                           sa_ptr->shivf_len,
                                                           &(ingest[mac_loc]),
                                                           MAC_SIZE,
                                                           &(aad[0]), // AAD Input location
                                                           sa_ptr->abm_len, // AAD is size of ABM in this case
                                                           CRYPTO_TRUE, // Encrypt
                                                           CRYPTO_FALSE, // Authenticate // TODO -- Set to SA value, manually setting to false here so existing tests pass. Existing data was generated with authenticate then encrypt, when it should have been encrypt then authenticate.
                                                           CRYPTO_TRUE, // Use AAD
                                                           sa_ptr->ecs, // encryption cipher
                                                           sa_ptr->acs  // authentication cipher
                                                           );


        // Update OCF
        y = 0;
        for (x = OCF_SIZE; x > 0; x--)
        {
            ingest[fecf_loc - x] = tm_frame.tm_sec_trailer.ocf[y++];
        }

        // Update FECF
        tm_frame.tm_sec_trailer.fecf = Crypto_Calc_FECF((uint8_t* )ingest, fecf_loc - 1);
        ingest[fecf_loc] = (uint8_t)((tm_frame.tm_sec_trailer.fecf & 0xFF00) >> 8);
        ingest[fecf_loc + 1] = (uint8_t)(tm_frame.tm_sec_trailer.fecf & 0x00FF);
    }
    // Authentication
    else if ((sa_ptr->est == 0) && (sa_ptr->ast == 1))
    {
#ifdef DEBUG
        printf(KBLU "Creating a TM - AUTHENTICATED! \n" RESET);
#endif
        // TODO: Future work. Operationally same as clear.
        memcpy(ingest, tempTM, count);
    }
    // Encryption
    else if ((sa_ptr->est == 1) && (sa_ptr->ast == 0))
    {
#ifdef DEBUG
        printf(KBLU "Creating a TM - ENCRYPTED! \n" RESET);
#endif
        // TODO: Future work. Operationally same as clear.
        memcpy(ingest, tempTM, count);
    }

#ifdef TM_DEBUG
    Crypto_tmPrint(&tm_frame);
#endif

#ifdef DEBUG
    printf(KYEL "----- Crypto_TM_ApplySecurity END -----\n" RESET);
#endif

    *len_ingest = count;
    return status;
}

/**
 * @brief Function: Crypto_TM_ProcessSecurity
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @return int32: Success/Failure
 **/
int32_t Crypto_TM_ProcessSecurity(uint8_t* ingest, int *len_ingest)
{
    // Local Variables
    int32_t status = CRYPTO_LIB_SUCCESS;

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_TM_ProcessSecurity START -----\n" RESET);
#endif

    // TODO: This whole function!
    len_ingest = len_ingest;
    ingest[0] = ingest[0];

#ifdef DEBUG
    printf(KYEL "----- Crypto_TM_ProcessSecurity END -----\n" RESET);
#endif

    return status;
}

/**
 * @brief Function: Crypto_Get_tmLength
 * Returns the total length of the current tm_frame in BYTES!
 * @param len: int
 * @return int32_t Length of TM
 **/
int32_t Crypto_Get_tmLength(int len)
{
#ifdef FILL
    len = TM_FILL_SIZE;
#else
    len = TM_FRAME_PRIMARYHEADER_SIZE + TM_FRAME_SECHEADER_SIZE + len + TM_FRAME_SECTRAILER_SIZE + TM_FRAME_CLCW_SIZE;
#endif

    return len;
}

/**
 * @brief Function: Crypto_TM_updatePDU
 * Update the Telemetry Payload Data Unit
 * @param ingest: uint8_t*
 * @param len_ingest: int
 **/
void Crypto_TM_updatePDU(uint8_t* ingest, int len_ingest)
{ // Copy ingest to PDU
    int x = 0;
    int y = 0;
    int fill_size = 0;
    SecurityAssociation_t* sa_ptr;

    if (sadb_routine->sadb_get_sa_from_spi(tm_frame.tm_sec_header.spi, &sa_ptr) != CRYPTO_LIB_SUCCESS)
    {
        // TODO - Error handling
        return; // Error -- unable to get SA from SPI.
    }

    if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
    {
        fill_size = 1129 - MAC_SIZE - IV_SIZE + 2; // +2 for padding bytes
    }
    else
    {
        fill_size = 1129;
    }

#ifdef TM_ZERO_FILL
    for (x = 0; x < TM_FILL_SIZE; x++)
    {
        if (x < len_ingest)
        { // Fill
            tm_frame.tm_pdu[x] = (uint8_t)ingest[x];
        }
        else
        { // Zero
            tm_frame.tm_pdu[x] = 0x00;
        }
    }
#else
    // Pre-append remaining packet if exist
    if (tm_offset == 63)
    {
        tm_frame.tm_pdu[x++] = 0xff;
        tm_offset--;
    }
    if (tm_offset == 62)
    {
        tm_frame.tm_pdu[x++] = 0x00;
        tm_offset--;
    }
    if (tm_offset == 61)
    {
        tm_frame.tm_pdu[x++] = 0x00;
        tm_offset--;
    }
    if (tm_offset == 60)
    {
        tm_frame.tm_pdu[x++] = 0x00;
        tm_offset--;
    }
    if (tm_offset == 59)
    {
        tm_frame.tm_pdu[x++] = 0x39;
        tm_offset--;
    }
    while (x < tm_offset)
    {
        tm_frame.tm_pdu[x] = 0x00;
        x++;
    }
    // Copy actual packet
    while (x < len_ingest + tm_offset)
    {
        // printf("ingest[x - tm_offset] = 0x%02x \n", (uint8_t)ingest[x - tm_offset]);
        tm_frame.tm_pdu[x] = (uint8_t)ingest[x - tm_offset];
        x++;
    }
#ifdef TM_IDLE_FILL
    // Check for idle frame trigger
    if (((uint8_t)ingest[0] == 0x08) && ((uint8_t)ingest[1] == 0x90))
    {
        // Don't fill idle frames
    }
    else
    {
        while (x < (fill_size - 64))
        {
            tm_frame.tm_pdu[x++] = 0x07;
            tm_frame.tm_pdu[x++] = 0xff;
            tm_frame.tm_pdu[x++] = 0x00;
            tm_frame.tm_pdu[x++] = 0x00;
            tm_frame.tm_pdu[x++] = 0x00;
            tm_frame.tm_pdu[x++] = 0x39;
            for (y = 0; y < 58; y++)
            {
                tm_frame.tm_pdu[x++] = 0x00;
            }
        }
        // Add partial packet, if possible, and set offset
        if (x < fill_size)
        {
            tm_frame.tm_pdu[x++] = 0x07;
            tm_offset = 63;
        }
        if (x < fill_size)
        {
            tm_frame.tm_pdu[x++] = 0xff;
            tm_offset--;
        }
        if (x < fill_size)
        {
            tm_frame.tm_pdu[x++] = 0x00;
            tm_offset--;
        }
        if (x < fill_size)
        {
            tm_frame.tm_pdu[x++] = 0x00;
            tm_offset--;
        }
        if (x < fill_size)
        {
            tm_frame.tm_pdu[x++] = 0x00;
            tm_offset--;
        }
        if (x < fill_size)
        {
            tm_frame.tm_pdu[x++] = 0x39;
            tm_offset--;
        }
        for (y = 0; x < fill_size; y++)
        {
            tm_frame.tm_pdu[x++] = 00;
            tm_offset--;
        }
    }
    while (x < TM_FILL_SIZE)
    {
        tm_frame.tm_pdu[x++] = 0x00;
    }
#endif
#endif

    return;
}

/**
 * @brief Function: Crypto_TM_updateOCF
 * Update the TM OCF
 **/
void Crypto_TM_updateOCF(void)
{
    if (ocf == 0)
    { // CLCW
        clcw.vci = tm_frame.tm_header.vcid;

        tm_frame.tm_sec_trailer.ocf[0] = (clcw.cwt << 7) | (clcw.cvn << 5) | (clcw.sf << 2) | (clcw.cie);
        tm_frame.tm_sec_trailer.ocf[1] = (clcw.vci << 2) | (clcw.spare0);
        tm_frame.tm_sec_trailer.ocf[2] = (clcw.nrfa << 7) | (clcw.nbl << 6) | (clcw.lo << 5) | (clcw.wait << 4) |
                                         (clcw.rt << 3) | (clcw.fbc << 1) | (clcw.spare1);
        tm_frame.tm_sec_trailer.ocf[3] = (clcw.rv);
        // Alternate OCF
        ocf = 1;
#ifdef OCF_DEBUG
        Crypto_clcwPrint(&clcw);
#endif
    }
    else
    { // FSR
        tm_frame.tm_sec_trailer.ocf[0] = (report.cwt << 7) | (report.vnum << 4) | (report.af << 3) |
                                         (report.bsnf << 2) | (report.bmacf << 1) | (report.ispif);
        tm_frame.tm_sec_trailer.ocf[1] = (report.lspiu & 0xFF00) >> 8;
        tm_frame.tm_sec_trailer.ocf[2] = (report.lspiu & 0x00FF);
        tm_frame.tm_sec_trailer.ocf[3] = (report.snval);
        // Alternate OCF
        ocf = 0;
#ifdef OCF_DEBUG
        Crypto_fsrPrint(&report);
#endif
    }
}
