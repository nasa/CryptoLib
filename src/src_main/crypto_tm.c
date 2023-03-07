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
 * 
 * The TM ApplySecurity Payload shall consist of the portion of the TM Transfer Frame (see
 * reference [1]) from the first octet of the Transfer Frame Primary Header to the last octet of
 * the Transfer Frame Data Field. 
 * NOTES
 * 1 The TM Transfer Frame is the fixed-length protocol data unit of the TM Space Data
 * Link Protocol. The length of any Transfer Frame transferred on a physical channel is
 * constant, and is established by management.
 * 2 The portion of the TM Transfer Frame contained in the TM ApplySecurity Payload
 * parameter includes the Security Header field. When the ApplySecurity Function is
 * called, the Security Header field is empty; i.e., the caller has not set any values in the
 * Security Header
 **/
// int32_t Crypto_TM_ApplySecurity(uint8_t* ingest, int *len_ingest)
int32_t Crypto_TM_ApplySecurity(SecurityAssociation_t *sa_ptr)
// Accepts CCSDS message in ingest, and packs into TM before encryption
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    // int count = 0;
    // int pdu_loc = 0;
    // int pdu_len = *len_ingest - TM_MIN_SIZE;
    // int pad_len = 0;
    // int mac_loc = 0;
    // int fecf_loc = 0;
    // uint8_t map_id = 0;
    // uint8_t tempTM[TM_SIZE];
    int i = 0;
    // int x = 0;
    // int y = 0;
    uint8_t sa_service_type = -1;
    // uint8_t aad[20];
    // uint16_t spi = tm_frame.tm_sec_header.spi;
    // uint16_t spp_crc = 0x0000;
    uint16_t data_loc = -1;
    uint16_t data_len = -1;
    // SecurityAssociation_t sa;
    // SecurityAssociation_t* sa_ptr = *sa_dblptr;
    // uint32_t encryption_cipher;
    // uint8_t ecs_is_aead_algorithm;

    // memset(&tempTM, 0, TM_SIZE);
    // Gotta figure out what  todo here if static is in flight
    // but could be various lengths. How to cast to correct setup?
    // tm_frame = *(TM_t *) ingest;

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_TM_ApplySecurity START -----\n" RESET);
#endif

    if (sa_ptr == NULL)
    {
        status = CRYPTO_LIB_ERR_NULL_SA;
        printf(KRED "Error: Input SA NULL! \n" RESET);
        return status; // Just return here, nothing can be done.
    }
#ifdef DEBUG

    status = Crypto_Get_Managed_Parameters_For_Gvcid(tm_frame_pri_hdr.tfvn, 
                                                    tm_frame_pri_hdr.scid,
                                                    tm_frame_pri_hdr.vcid, 
                                                    gvcid_managed_parameters, &current_managed_parameters);
    printf("Tried to get MPs for TVFN %d, SCID %d and VCID %d\n", tm_frame_pri_hdr.tfvn, tm_frame_pri_hdr.scid, tm_frame_pri_hdr.vcid);
    printf("Status was %d\n", status);
    printf("HELP\n");
    // current_managed_parameters->tc_max_frame_length = 1786;
    printf("TM DEBUG - Static TM Frame, Managed Param Size of %d bytes\n", current_managed_parameters->max_frame_size);
    printf("TM DEBUG - \n");
    for (i = 0; i < current_managed_parameters->max_frame_size; i++)
    {
        printf("%02X", ((uint8_t* )&tm_frame)[i]);
    }
    printf("\n");
#endif

    if (crypto_config == NULL)
    {
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        return status;  // return immediately so a NULL crypto_config is not dereferenced later
    }

    // TODO: Check if frame shorter than TM defined length for this channel
    // if (*len_ingest < TM_SIZE) // Frame length doesn't match managed parameter for channel -- error out.
    // {
    //     status = CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TC_STANDARD;
    //     return status;
    // }
    printf("TESTING: Printout tm_frame scid before doing anything:    %d\n", tm_frame_pri_hdr.scid);

    // **** TODO - THIS BLOCK MOVED INTO TO ****
    /**
    // Lookup-retrieve managed parameters for frame via gvcid:
    // status = Crypto_Get_Managed_Parameters_For_Gvcid(tm_frame.tm_header.tfvn, tm_frame.tm_header.scid, tm_frame.tm_header.vcid,
                                                    //  gvcid_managed_parameters, &current_managed_parameters);
    // if (status != CRYPTO_LIB_SUCCESS)
    // {
        // return status;
    // } // Unable to get necessary Managed Parameters for TM TF -- return with error.

    // Query SA DB for active SA / SDLS parameters
    if (sadb_routine == NULL) // This should not happen, but tested here for safety
    {
        printf(KRED "ERROR: SA DB Not initalized! -- CRYPTO_LIB_ERR_NO_INIT, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_INIT;
    }
    else
    {
        status = sadb_routine->sadb_get_operational_sa_from_gvcid(tm_frame.tm_header.tfvn, tm_frame.tm_header.scid,
                                                                    tm_frame.tm_header.vcid, map_id, &sa_ptr);
    }

    // If unable to get operational SA, can return
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }
    ***************/

#ifdef SA_DEBUG
        printf(KYEL "DEBUG - Printing SA Entry for current frame.\n" RESET);
        Crypto_saPrint(sa_ptr);
#endif

        // Determine SA Service Type
        if ((sa_ptr->est == 0) && (sa_ptr->ast == 0))
        {
            sa_service_type = SA_PLAINTEXT;
        }
        else if ((sa_ptr->est == 0) && (sa_ptr->ast == 1))
        {
            sa_service_type = SA_AUTHENTICATION;
        }
        else if ((sa_ptr->est == 1) && (sa_ptr->ast == 0))
        {
            sa_service_type = SA_ENCRYPTION;
        }
        else if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
        {
            sa_service_type = SA_AUTHENTICATED_ENCRYPTION;
        }
        else
        {
            // Probably unnecessary check
            // Leaving for now as it would be cleaner in SA to have an association enum returned I believe
            printf(KRED "Error: SA Service Type is not defined! \n" RESET);
            status = CRYPTO_LIB_ERROR;
            return status;
        }

// Determine Algorithm cipher & mode. // TODO - Parse authentication_cipher, and handle AEAD cases properly
        // if (sa_service_type != SA_PLAINTEXT)
        // {
        //     encryption_cipher =
        //         (sa_ptr->ecs[0] << 24) | (sa_ptr->ecs[1] << 16) | (sa_ptr->ecs[2] << 8) | sa_ptr->ecs[3];
        //     ecs_is_aead_algorithm = Crypto_Is_AEAD_Algorithm(encryption_cipher);
        // }

#ifdef TC_DEBUG
        switch (sa_service_type)
        {
        case SA_PLAINTEXT:
            printf(KBLU "Creating a TM - CLEAR!\n" RESET);
            break;
        case SA_AUTHENTICATION:
            printf(KBLU "Creating a TM - AUTHENTICATED!\n" RESET);
            break;
        case SA_ENCRYPTION:
            printf(KBLU "Creating a TM - ENCRYPTED!\n" RESET);
            break;
        case SA_AUTHENTICATED_ENCRYPTION:
            printf(KBLU "Creating a TM - AUTHENTICATED ENCRYPTION!\n" RESET);
            break;
        }
#endif

        // Calculate location of data within the frame
        // Note: Secondary headers are static only for a mission phase, not guaranteed static 
        // over the life of a mission Per CCSDS 132.0-B.3 Section 4.1.2.7.2.3
        // I'm interpeting this to mean at change of phase, it could be omitted, therefore
        // must check with the TF PriHdr to see if account for it, not necessarily the managed params
        data_loc = TM_FRAME_PRIMARYHEADER_SIZE + TM_FRAME_SECHEADER_SIZE;
        // if(tm_frame.tm_header.tfsh == 1)
        // {
        //     data_loc += current_managed_parameters->tm_frame_secondary_hdr_length;
        // }

        // Calculate length of data that will be encrypted
        // This length starts at data_loc, and does not include security trailer (if present) and Frame Trailer (if present)
        switch (sa_service_type)
        {
        case SA_PLAINTEXT:
            // Max frame length - data loc (includes spi and secondary header) - padding
            data_len = current_managed_parameters->max_frame_size - data_loc - sa_ptr->shplf_len;
            break;
        default:
            printf(KRED "Unknown SA Service Type Detected!" RESET);
            break;
        }
        
        if(current_managed_parameters->has_fecf == 1) //TM_NO_OCF) //TODO change back
        {
            data_len += 4;
        }
        if(current_managed_parameters->has_fecf == 1) //TM_NO_FECF)
        {
            data_len += 2;
        }

#ifdef TM_DEBUG
    printf(KYEL "Printing new TM frame:\n\t");
    printf("STUBBED OUT!\n");
    for(int i = 0; i < current_managed_parameters->max_frame_size; i++)
    {
        printf("%d %02X \n", i, tm_frame[i]);
    }
    printf("\n");
    // Crypto_tmPrint(tm_frame);
#endif

    status = sadb_routine->sadb_save_sa(sa_ptr);

#ifdef DEBUG
    printf(KYEL "----- Crypto_TM_ApplySecurity END -----\n" RESET);
#endif

    return status;
}


/*** Preserving for now
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
    printf("LINE: %d\n",__LINE__);
    // Update Current Telemetry Frame in Memory
    // Counters
    tm_frame.tm_header.mcfc++;
    tm_frame.tm_header.vcfc++;
    printf("LINE: %d\n",__LINE__);
    // Operational Control Field
    Crypto_TM_updateOCF();
    printf("LINE: %d\n",__LINE__);
    // Payload Data Unit
    Crypto_TM_updatePDU(ingest, *len_ingest);
    printf("LINE: %d\n",__LINE__);
    if (sadb_routine->sadb_get_sa_from_spi(spi, &sa_ptr) != CRYPTO_LIB_SUCCESS)
    {
        // TODO - Error handling
        return CRYPTO_LIB_ERROR; // Error -- unable to get SA from SPI.
    }
    printf("LINE: %d\n",__LINE__);
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
    printf("LINE: %d\n",__LINE__);
    // Initialize the temporary TM frame
    // Header
    tempTM[count++] = (uint8_t)((tm_frame.tm_header.tfvn << 6) | ((tm_frame.tm_header.scid & 0x3F0) >> 4));
    printf("LINE: %d\n",__LINE__);
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
    printf("LINE: %d\n",__LINE__);
    tempTM[count++] = (uint8_t)((spi & 0xFF00) >> 8);
    tempTM[count++] = (uint8_t)((spi & 0x00FF));
    if(sa_ptr->shivf_len > 0)
    {
        memcpy(tm_frame.tm_sec_header.iv, sa_ptr->iv, sa_ptr->shivf_len);
    }
    printf("LINE: %d\n",__LINE__);
    // TODO: Troubleshoot
    // Padding Length
    // pad_len = Crypto_Get_tmLength(*len_ingest) - TM_MIN_SIZE + IV_SIZE + TM_PAD_SIZE - *len_ingest;
    printf("LINE: %d\n",__LINE__);
    // Only add IV for authenticated encryption
    if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
    { // Initialization Vector
#ifdef INCREMENT
        printf("LINE: %d\n",__LINE__);
        Crypto_increment(sa_ptr->iv, sa_ptr->shivf_len);
#endif
        if ((sa_ptr->est == 1) || (sa_ptr->ast == 1))
        {
            printf("LINE: %d\n",__LINE__);
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
        printf("LINE: %d\n",__LINE__);
        tempTM[count++] = 0x00; // pad_len >> 8;
        tempTM[count++] = 0x1A; // pad_len
        pdu_loc = count;
        pdu_len = *len_ingest + pad_len;
    }
    printf("LINE: %d\n",__LINE__);
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
    printf("LINE: %d\n",__LINE__);
    // Operational Control Field
    for (x = 0; x < OCF_SIZE; x++)
    {
        tempTM[count++] = (uint8_t)tm_frame.tm_sec_trailer.ocf[x];
    }
    printf("LINE: %d\n",__LINE__);
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
                                                           sa_ptr->acs,  // authentication cipher
                                                           NULL // cam_cookies (not supported in TM functions yet)
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
}**/

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
    // int y = 0;
    // int fill_size = 0;
    SecurityAssociation_t* sa_ptr;
    printf("%s, Line: %d\n", __FILE__, __LINE__);
    // Consider a helper function here, or elsewhere, to do all the 'math' in one spot as a global accessible list of variables
    if (sadb_routine->sadb_get_sa_from_spi(tm_frame[0], &sa_ptr) != CRYPTO_LIB_SUCCESS) // modify
    {
        // TODO - Error handling
        printf(KRED"Update PRU Error!\n");
        return; // Error -- unable to get SA from SPI.
    }
    printf("%s, Line: %d\n", __FILE__, __LINE__);
    if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
    {
        // fill_size = 1129 - MAC_SIZE - IV_SIZE + 2; // +2 for padding bytes
    }
    else
    {
        // fill_size = 1129;
    }
    printf("%s, Line: %d\n", __FILE__, __LINE__);
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
    // if (tm_offset == 63)
    // {
    //     tm_frame.tm_pdu[x++] = 0xff;
    //     tm_offset--;
    // }
    // if (tm_offset == 62)
    // {
    //     tm_frame.tm_pdu[x++] = 0x00;
    //     tm_offset--;
    // }
    // if (tm_offset == 61)
    // {
    //     tm_frame.tm_pdu[x++] = 0x00;
    //     tm_offset--;
    // }
    // if (tm_offset == 60)
    // {
    //     tm_frame.tm_pdu[x++] = 0x00;
    //     tm_offset--;
    // }
    // if (tm_offset == 59)
    // {
    //     tm_frame.tm_pdu[x++] = 0x39;
    //     tm_offset--;
    // }
    // while (x < tm_offset)
    // {
    //     tm_frame.tm_pdu[x] = 0x00;
    //     x++;
    // }
    printf("%s, Line: %d\n", __FILE__, __LINE__);
    // Copy actual packet
    while (x < len_ingest + tm_offset)
    {
        // printf("%s, Line: %d\n", __FILE__, __LINE__);
        // printf("ingest[x - tm_offset] = 0x%02x \n", (uint8_t)ingest[x - tm_offset]);
        printf("%02X", (uint8_t)ingest[x - tm_offset]);
        // tm_frame.tm_pdu[x] = (uint8_t)ingest[x - tm_offset];
        x++;
    }
    printf("%s, Line: %d\n", __FILE__, __LINE__);
#ifdef TM_IDLE_FILL
    // Check for idle frame trigger
    if (((uint8_t)ingest[0] == 0x08) && ((uint8_t)ingest[1] == 0x90))
    {
        // Don't fill idle frames
    }
    else
    {
        printf("%s, Line: %d\n", __FILE__, __LINE__);
        // while (x < (fill_size - 64))
        // {
        //     tm_frame.tm_pdu[x++] = 0x07;
        //     tm_frame.tm_pdu[x++] = 0xff;
        //     tm_frame.tm_pdu[x++] = 0x00;
        //     tm_frame.tm_pdu[x++] = 0x00;
        //     tm_frame.tm_pdu[x++] = 0x00;
        //     tm_frame.tm_pdu[x++] = 0x39;
        //     for (y = 0; y < 58; y++)
        //     {
        //         tm_frame.tm_pdu[x++] = 0x00;
        //     }
        // }
        // Add partial packet, if possible, and set offset
        // if (x < fill_size)
        // {
        //     tm_frame.tm_pdu[x++] = 0x07;
        //     tm_offset = 63;
        // }
        // if (x < fill_size)
        // {
        //     tm_frame.tm_pdu[x++] = 0xff;
        //     tm_offset--;
        // }
        // if (x < fill_size)
        // {
        //     tm_frame.tm_pdu[x++] = 0x00;
        //     tm_offset--;
        // }
        // if (x < fill_size)
        // {
        //     tm_frame.tm_pdu[x++] = 0x00;
        //     tm_offset--;
        // }
        // if (x < fill_size)
        // {
        //     tm_frame.tm_pdu[x++] = 0x00;
        //     tm_offset--;
        // }
        // if (x < fill_size)
        // {
        //     tm_frame.tm_pdu[x++] = 0x39;
        //     tm_offset--;
        // }
        // for (y = 0; x < fill_size; y++)
        // {
        //     tm_frame.tm_pdu[x++] = 00;
        //     tm_offset--;
        // }
    }
    // while (x < TM_FILL_SIZE)
    // {
    //     tm_frame.tm_pdu[x++] = 0x00;
    // }
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
    // TODO
    /*
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
    **/
}
