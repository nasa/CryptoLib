/** Copyright (C) 2009 - 2022 National Aeronautics and Space Administration.
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
 **/

/**
 * Includes
 **/
#include "crypto.h"

/**
 * CCSDS Compliance Reference:
 * This file implements security features compliant with:
 * - CCSDS 732.0-B-4 (AOS Space Data Link Protocol)
 * - CCSDS 355.0-B-2 (Space Data Link Security Protocol)
 */

/**
 * @brief Function: Crypto_AOS_ProcessSecurity
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 5 (AOS Protocol), CCSDS 732.0-B-4
 **/
int32_t Crypto_AOS_ProcessSecurity(uint8_t *p_ingest, uint16_t len_ingest, uint8_t **pp_processed_frame,
                                   uint16_t *p_decrypted_length)
{
    // Local Variables
    int32_t                status = CRYPTO_LIB_SUCCESS;
    uint8_t                aad[1786];
    uint16_t               aad_len  = 0;
    uint16_t               byte_idx = 0;
    uint8_t                ecs_is_aead_algorithm;
    uint32_t               encryption_cipher = 0;
    uint8_t                iv_loc            = 0;
    int                    mac_loc           = 0;
    uint16_t               pdu_len           = 1;
    uint8_t               *p_new_dec_frame   = NULL;
    SecurityAssociation_t *sa_ptr            = NULL;
    uint8_t                sa_service_type   = -1;
    uint16_t               spi               = -1;
    uint8_t                aos_hdr_len       = 6;

    // Bit math to give concise access to values in the ingest
    aos_frame_pri_hdr.tfvn = ((uint8_t)p_ingest[0] & 0xC0) >> 6;
    aos_frame_pri_hdr.scid = (((uint16_t)p_ingest[0] & 0x3F) << 2) | (((uint16_t)p_ingest[1] & 0xC0) >> 6);
    aos_frame_pri_hdr.vcid = ((uint8_t)p_ingest[1] & 0x3F);

    if ((crypto_config.init_status == UNITIALIZED) || (mc_if == NULL) || (sa_if == NULL))
    {
#ifdef AOS_DEBUG
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
#endif
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        // Can't mc_log if it's not configured
        goto end_of_function;
    }
    
#ifdef DEBUG
    printf(KYEL "\n----- Crypto_AOS_ProcessSecurity START -----\n" RESET);
#endif

    #ifdef AOS_DEBUG
    printf(KGRN "AOS Process Using following parameters:\n\t" RESET);
    printf(KGRN "tvfn: %d\t scid: %d\t vcid: %d\n" RESET, aos_frame_pri_hdr.tfvn, aos_frame_pri_hdr.scid,
           aos_frame_pri_hdr.vcid);
#endif

    // Lookup-retrieve managed parameters for frame via gvcid:
    status =
        Crypto_Get_Managed_Parameters_For_Gvcid(aos_frame_pri_hdr.tfvn, aos_frame_pri_hdr.scid, aos_frame_pri_hdr.vcid,
                                                gvcid_managed_parameters_array, &current_managed_parameters_struct);
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef AOS_DEBUG
        printf(KRED "**NO LUCK WITH GVCID!\n" RESET);
#endif
        goto end_of_function;
    } // Unable to get necessary Managed Parameters for AOS TF -- return with error.

    status = Crypto_AOSP_Initial_Length_Checks(len_ingest, aos_hdr_len);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Increment to end of Primary Header start, depends on FHECF presence
    byte_idx = aos_hdr_len;

    Crypto_AOSP_Handle_FHEC(&p_ingest[0], &byte_idx, &aos_hdr_len);

    // Detect if optional variable length Insert Zone is present
    // Per CCSDS 732.0-B-4 Section 4.1.3, Insert Zone is optional but fixed length for a physical channel
    status = Crypto_AOSP_Handle_IZ(&byte_idx);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    /**
     * Begin Security Header Fields
     * Reference CCSDS SDLP 3550b1 4.1.1.1.3
     **/
    // Get SPI
    status = Crypto_AOSP_Get_SPI(&p_ingest[0], &byte_idx, &spi);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    status = sa_if->sa_get_from_spi(spi, &sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

#ifdef SA_DEBUG
    printf(KYEL "DEBUG - Printing SA Entry for current frame.\n" RESET);
    Crypto_saPrint(sa_ptr);
#endif

    // Determine SA Service Type
    status = Crypto_AOS_Get_SA_Service_Type(&sa_service_type, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }
    
    // Determine Algorithm cipher & mode. // TODO - Parse authentication_cipher, and handle AEAD cases properly
    if (sa_service_type != SA_PLAINTEXT)
    {
        if (sa_ptr->ecs != CRYPTO_CIPHER_NONE)
        {
            encryption_cipher = sa_ptr->ecs;
#ifdef TC_DEBUG
            printf(KYEL "SA Encryption Cipher: %d\n", encryption_cipher);
#endif
        }
        // If no pointer, must not be using ECS at all
        else
        {
            encryption_cipher = CRYPTO_CIPHER_NONE;
        }
        ecs_is_aead_algorithm = Crypto_Is_AEAD_Algorithm(encryption_cipher);
    }

    if (encryption_cipher == CRYPTO_CIPHER_NONE && sa_ptr->est == 1)
    {
        status = CRYPTO_LIB_ERR_NO_ECS_SET_FOR_ENCRYPTION_MODE;
        goto end_of_function;
    }

#ifdef AOS_DEBUG
    switch (sa_service_type)
    {
        case SA_PLAINTEXT:
            printf(KBLU "Processing a AOS - CLEAR!\n" RESET);
            break;
        case SA_AUTHENTICATION:
            printf(KBLU "Processing a AOS - AUTHENTICATED!\n" RESET);
            break;
        case SA_ENCRYPTION:
            printf(KBLU "Processing a AOS - ENCRYPTED!\n" RESET);
            break;
        case SA_AUTHENTICATED_ENCRYPTION:
            printf(KBLU "Processing a AOS - AUTHENTICATED ENCRYPTION!\n" RESET);
            break;
    }
#endif

    // Parse & Check FECF, if present, and update fecf length
    if (current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        uint16_t received_fecf = (((p_ingest[current_managed_parameters_struct.max_frame_size - 2] << 8) & 0xFF00) |
                                  (p_ingest[current_managed_parameters_struct.max_frame_size - 1] & 0x00FF));

        if (crypto_config.crypto_check_fecf == AOS_CHECK_FECF_TRUE)
        {
            // Calculate our own
            uint16_t calculated_fecf = Crypto_Calc_FECF(p_ingest, len_ingest - 2);
            // Compare FECFs
            // Invalid FECF
            if (received_fecf != calculated_fecf)
            {
#ifdef FECF_DEBUG
                printf("Received FECF is 0x%04X\n", received_fecf);
                printf("Calculated FECF is 0x%04X\n", calculated_fecf);
                printf("FECF was Calced over %d bytes\n", len_ingest - 2);
#endif
                status = CRYPTO_LIB_ERR_INVALID_FECF;
                goto end_of_function;
            }
            // Valid FECF, zero out the field
            else
            {
#ifdef FECF_DEBUG
                printf(KYEL "FECF CALC MATCHES! - GOOD\n" RESET);
#endif
            }
        }
    }
    // Needs to be AOS_HAS_FECF (checked above, or AOS_NO_FECF)
    else if (current_managed_parameters_struct.has_fecf != AOS_NO_FECF)
    {
#ifdef AOS_DEBUG
        printf(KRED "AOS_Process Error...tfvn: %d scid: 0x%04X vcid: 0x%02X fecf_enum: %d\n" RESET,
               current_managed_parameters_struct.tfvn, current_managed_parameters_struct.scid,
               current_managed_parameters_struct.vcid, current_managed_parameters_struct.has_fecf);
#endif
        status = CRYPTO_LIB_ERR_TC_ENUM_USED_FOR_AOS_CONFIG;
        goto end_of_function;
    }

    // Accio buffer
    p_new_dec_frame = (uint8_t *)calloc(1, (len_ingest) * sizeof(uint8_t));
    if (!p_new_dec_frame)
    {
#ifdef DEBUG
        printf(KRED "Error: Calloc for decrypted output buffer failed! \n" RESET);
#endif
        status = CRYPTO_LIB_ERROR;
        goto end_of_function;
    }

    // Copy over AOS Primary Header (6-8 bytes)
    memcpy(p_new_dec_frame, &p_ingest[0], aos_hdr_len);

    // Copy over insert zone data, if it exists
    if (current_managed_parameters_struct.aos_has_iz == AOS_HAS_IZ)
    {
        memcpy(p_new_dec_frame + aos_hdr_len, &p_ingest[aos_hdr_len], current_managed_parameters_struct.aos_iz_len);
#ifdef AOS_DEBUG
        printf("Copied over the following:\n\t");
        for (int i = 0; i < current_managed_parameters_struct.aos_iz_len; i++)
        {
            printf("%02X", p_ingest[aos_hdr_len + i]);
        }
        printf("\n");
#endif
    }

    // Byte_idx is still set to just past the SPI
    // If IV is present, note location
    if (sa_ptr->iv_len > 0)
    {
        iv_loc = byte_idx;
    }
    // Increment byte_idx past Security Header Fields based on SA values
    byte_idx += sa_ptr->shivf_len;
    byte_idx += (sa_ptr->arsn_len - sa_ptr->shsnf_len);
    byte_idx += sa_ptr->shplf_len;

#ifdef SA_DEBUG
    printf(KYEL "IV length of %d bytes\n" RESET, sa_ptr->shivf_len);
    printf(KYEL "ARSN length of %d bytes\n" RESET, sa_ptr->arsn_len - sa_ptr->shsnf_len);
    printf(KYEL "PAD length field of %d bytes\n" RESET, sa_ptr->shplf_len);
    printf(KYEL "First byte past Security Header is at index %d\n" RESET, byte_idx);
#endif

    /**
     * End Security Header Fields
     * byte_idx is now at start of pdu / encrypted data
     **/

    // Calculate size of the protocol data unit
    // NOTE: This size itself is not the length for authentication

    /*
    ** CCSDS 732.0-B-4 Section The AOS Transfer Frame Data Field
    ** The Data Field contains user data and occupies the central part of the Transfer Frame.
    ** The optional Operations Control Field and the Frame Error Control Field, if present,
    ** are not part of the Data Field.
    */
    pdu_len = current_managed_parameters_struct.max_frame_size - byte_idx - sa_ptr->stmacf_len;

    /*
    ** CCSDS 732.0-B-4 Section 4.1.5 - Operational Control Field (OCF)
    ** The OCF contains real-time Control Commands, reports, or status that may be required for
    ** the operation of the AOS Space Data Link Protocol.
    */
    if (current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        pdu_len -= 4;
    }

    /*
    ** CCSDS 732.0-B-4 Section 4.1.6 - Frame Error Control Field (FECF)
    ** The FECF shall contain a sequence of 16 parity bits for error detection.
    */
    if (current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        pdu_len -= 2;
    }

    // If MAC exists, comes immediately after pdu
    if (sa_ptr->stmacf_len > 0)
    {
        mac_loc = byte_idx + pdu_len;
    }
    Crypto_Set_FSR(p_ingest, byte_idx, pdu_len, sa_ptr);

#ifdef AOS_DEBUG
    printf(KYEL "Index / data location starts at: %d\n" RESET, byte_idx);
    printf(KYEL "Data size is: %d\n" RESET, pdu_len);
    if (current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        // If OCF exists, comes immediately after MAC
        printf(KYEL "OCF Location is: %d" RESET, byte_idx + pdu_len + sa_ptr->stmacf_len);
    }
    if (current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        // If FECF exists, comes just before end of the frame
        printf(KYEL "FECF Location is: %d\n" RESET, current_managed_parameters_struct.max_frame_size - 2);
    }
#endif

    // Get Key
    crypto_key_t *ekp = NULL;
    crypto_key_t *akp = NULL;

    if (sa_ptr->est == 1)
    {
        if (crypto_config.key_type != KEY_TYPE_KMC)
        {
            ekp = key_if->get_key(sa_ptr->ekid);
            if (ekp == NULL)
            {
                status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
                free(p_new_dec_frame);
                goto end_of_function;
            }
            if (ekp->key_state != KEY_ACTIVE)
            {
                status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
                free(p_new_dec_frame);
                goto end_of_function;
            }
        }
    }
    if (sa_ptr->ast == 1)
    {
        if (crypto_config.key_type != KEY_TYPE_KMC)
        {
            akp = key_if->get_key(sa_ptr->akid);
            if (akp == NULL)
            {
                status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
                free(p_new_dec_frame);
                goto end_of_function;
            }
            if (akp->key_state != KEY_ACTIVE)
            {
                status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
                free(p_new_dec_frame);
                goto end_of_function;
            }
        }
    }

    /**
     * Begin Authentication / Encryption
     * Reference CCSDS 355.0-B-2 Section 5.3 (AOS Security Processing)
     */

    // Parse MAC, prepare AAD
    if ((sa_service_type == SA_AUTHENTICATION) || (sa_service_type == SA_AUTHENTICATED_ENCRYPTION))
    {
#ifdef MAC_DEBUG
        printf("MAC Parsed from Frame:\n\t");
        Crypto_hexprint(p_ingest + mac_loc, sa_ptr->stmacf_len);
#endif
        if (sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
        {
            aad_len = byte_idx;
        }
        else
        {
            aad_len = mac_loc;
        }

        // CCSDS 355.0-B-2 Section 4.2.3.4 - Authentication bit mask must be sufficient for AAD
        if (sa_ptr->abm_len < aad_len)
        {
            free(p_new_dec_frame); // Add cleanup
            status = CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
#ifdef MAC_DEBUG
            printf(KRED "Error: ABM length %d is shorter than required AAD length %d\n" RESET, sa_ptr->abm_len,
                   aad_len);
#endif
            goto end_of_function;
        }

        // Use ingest and abm to create aad
        Crypto_Prepare_AOS_AAD(p_ingest, aad_len, sa_ptr->abm, &aad[0]);

#ifdef MAC_DEBUG
        printf("AAD Debug:\n\tAAD Length is %d\n\t AAD is: ", aad_len);
        for (int i = 0; i < aad_len; i++)
        {
            printf("%02X", aad[i]);
        }
        printf("\n");
#endif
    }

    // check sa state before decrypting
    if (sa_ptr->sa_state != SA_OPERATIONAL)
    {
#ifdef DEBUG
        printf(KRED "Error: SA Not Operational \n" RESET);
#endif
        free(p_new_dec_frame); // Add cleanup
        return CRYPTO_LIB_ERR_SA_NOT_OPERATIONAL;
    }

    if (sa_service_type != SA_PLAINTEXT && ecs_is_aead_algorithm == CRYPTO_TRUE)
    {

        if (sa_service_type == SA_ENCRYPTION)
        {
            status = cryptography_if->cryptography_decrypt(p_new_dec_frame + byte_idx, // plaintext output
                                                           pdu_len,                    // length of data
                                                           p_ingest + byte_idx,        // ciphertext input
                                                           pdu_len,                    // in data length
                                                           &(ekp->value[0]),           // Key
                                                           Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs),
                                                           sa_ptr,            // SA for key reference
                                                           p_ingest + iv_loc, // IV
                                                           sa_ptr->iv_len,    // IV Length
                                                           &sa_ptr->ecs,      // encryption cipher
                                                           &sa_ptr->acs,      // authentication cipher
                                                           NULL);
        }
        if (sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
        {
            status = cryptography_if->cryptography_aead_decrypt(p_new_dec_frame + byte_idx, // plaintext output
                                                                pdu_len,                    // length of data
                                                                p_ingest + byte_idx,        // ciphertext input
                                                                pdu_len,                    // in data length
                                                                &(ekp->value[0]),           // Key
                                                                Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs),
                                                                sa_ptr,             // SA for key reference
                                                                p_ingest + iv_loc,  // IV.
                                                                sa_ptr->iv_len,     // IV Length
                                                                p_ingest + mac_loc, // Frame Expected Tag
                                                                sa_ptr->stmacf_len, // tag size
                                                                aad,                // additional authenticated data
                                                                aad_len,            // length of AAD
                                                                (sa_ptr->est),      // Decryption Bool
                                                                (sa_ptr->ast),      // Authentication Bool
                                                                (sa_ptr->ast),      // AAD Bool
                                                                &sa_ptr->ecs,       // encryption cipher
                                                                &sa_ptr->acs,       // authentication cipher
                                                                NULL);
        }
    }

    else if (sa_service_type != SA_PLAINTEXT && ecs_is_aead_algorithm == CRYPTO_FALSE)
    {
        // TODO - implement non-AEAD algorithm logic
        if (sa_service_type == SA_AUTHENTICATION || sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
        {
            status =
                cryptography_if->cryptography_validate_authentication(p_new_dec_frame + byte_idx, // plaintext output
                                                                      pdu_len,                    // length of data
                                                                      p_ingest + byte_idx,        // ciphertext input
                                                                      pdu_len,                    // in data length
                                                                      &(akp->value[0]),           // Key
                                                                      Crypto_Get_ACS_Algo_Keylen(sa_ptr->acs),
                                                                      sa_ptr,             // SA for key reference
                                                                      p_ingest + iv_loc,  // IV
                                                                      sa_ptr->iv_len,     // IV Length
                                                                      p_ingest + mac_loc, // Frame Expected Tag
                                                                      sa_ptr->stmacf_len, // tag size
                                                                      aad,     // additional authenticated data
                                                                      aad_len, // length of AAD
                                                                      CRYPTO_CIPHER_NONE, // encryption cipher
                                                                      sa_ptr->acs,        // authentication cipher
                                                                      NULL);              // cam cookies
        }
        if (sa_service_type == SA_ENCRYPTION || sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
        {
            // Check that key length to be used emets the algorithm requirement
            if ((int32_t)ekp->key_len != Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs))
            {
                free(p_new_dec_frame); // Add cleanup
                status = CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
                goto end_of_function;
            }

            status = cryptography_if->cryptography_decrypt(p_new_dec_frame + byte_idx, // plaintext output
                                                           pdu_len,                    // length of data
                                                           p_ingest + byte_idx,        // ciphertext input
                                                           pdu_len,                    // in data length
                                                           &(ekp->value[0]),           // Key
                                                           Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs),
                                                           sa_ptr,            // SA for key reference
                                                           p_ingest + iv_loc, // IV
                                                           sa_ptr->iv_len,    // IV Length
                                                           &sa_ptr->ecs,      // encryption cipher
                                                           &sa_ptr->acs,      // authentication cipher
                                                           NULL);
        }
    }

    // If plaintext, copy byte by byte
    else if (sa_service_type == SA_PLAINTEXT)
    {
        memcpy(p_new_dec_frame + byte_idx, &(p_ingest[byte_idx]), pdu_len);
        // byte_idx += pdu_len; // byte_idx no longer read
    }

#ifdef AOS_DEBUG
    printf(KYEL "\nPrinting received frame:\n\t" RESET);
    for (int i = 0; i < current_managed_parameters_struct.max_frame_size; i++)
    {
        printf(KYEL "%02X", p_ingest[i]);
    }
    printf(KYEL "\nPrinting PROCESSED frame:\n\t" RESET);
    for (int i = 0; i < current_managed_parameters_struct.max_frame_size; i++)
    {
        printf(KYEL "%02X", p_new_dec_frame[i]);
    }
    printf("\n");
#endif

    *pp_processed_frame = p_new_dec_frame;
    // TODO maybe not just return this without doing the math ourselves
    *p_decrypted_length = current_managed_parameters_struct.max_frame_size;

#ifdef DEBUG
    printf(KYEL "----- Crypto_AOS_ProcessSecurity END -----\n" RESET);
#endif

end_of_function:
    if (mc_if != NULL)
    {
        mc_if->mc_log(status);
    }
    return status;
}


/**
 * @brief Function: Crypto_Prepare_AOS_AAD
 * Bitwise ANDs buffer with abm, placing results in aad buffer
 * @param buffer: uint8_t*
 * @param len_aad: uint16_t
 * @param abm_buffer: uint8_t*
 * @param aad: uint8_t*
 * @return status: uint32_t
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 7.2.3 (AAD Construction)
 **/
uint32_t Crypto_Prepare_AOS_AAD(const uint8_t *buffer, uint16_t len_aad, const uint8_t *abm_buffer, uint8_t *aad)
{
    uint32_t status = CRYPTO_LIB_SUCCESS;
    int      i;

    for (i = 0; i < len_aad; i++)
    {
        aad[i] = buffer[i] & abm_buffer[i];
    }

#ifdef MAC_DEBUG
    printf(KYEL "AAD before ABM Bitmask:\n\t");
    for (i = 0; i < len_aad; i++)
    {
        printf("%02x", buffer[i]);
    }
    printf("\n" RESET);
#endif

#ifdef MAC_DEBUG
    printf(KYEL "Preparing AAD:\n");
    printf("\tUsing AAD Length of %d\n\t", len_aad);
    for (i = 0; i < len_aad; i++)
    {
        printf("%02x", aad[i]);
    }
    printf("\n" RESET);
#endif

    return status;
}


int32_t Crypto_AOSP_Initial_Length_Checks(uint16_t len_ingest, uint8_t aos_hdr_len)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (len_ingest < aos_hdr_len) // Frame length doesn't even have enough bytes for header -- error out.
    {
        status = CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_AOS_STANDARD;
        goto end_of_function;
    }

    if (len_ingest != current_managed_parameters_struct.max_frame_size)
    {
#ifdef AOS_DEBUG
        printf("Received length of %d, but expected %d!\n", len_ingest, current_managed_parameters_struct.max_frame_size);
#endif
        status = CRYPTO_LIB_ERR_AOS_FL_LT_MAX_FRAME_SIZE;
        goto end_of_function;
    }

end_of_function: 
    return status;
}


int32_t Crypto_AOSP_Handle_FHEC(uint8_t *p_ingest, uint16_t *byte_idx, uint8_t *aos_hdr_len)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (current_managed_parameters_struct.aos_has_fhec == AOS_HAS_FHEC)
    {
        uint16_t recieved_fhecf = (((p_ingest[*aos_hdr_len] << 8) & 0xFF00) | (p_ingest[*aos_hdr_len + 1] & 0x00FF));
#ifdef AOS_DEBUG
        printf("Recieved FHECF: %04x\n", recieved_fhecf);
        printf(KYEL "Calculating FHECF...\n" RESET);
#endif
        uint16_t calculated_fhecf = Crypto_Calc_FHECF(p_ingest);

        if (recieved_fhecf != calculated_fhecf)
        {
            status = CRYPTO_LIB_ERR_INVALID_FHECF;
            goto end_of_function;
        }

        p_ingest[*byte_idx]     = (calculated_fhecf >> 8) & 0x00FF;
        p_ingest[*byte_idx + 1] = (calculated_fhecf)&0x00FF;
        *byte_idx               = 8;
        *aos_hdr_len            = *byte_idx;
    }

end_of_function:
    return status;
}


int32_t Crypto_AOSP_Handle_IZ(uint16_t *byte_idx)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (current_managed_parameters_struct.aos_has_iz == AOS_HAS_IZ)
    {
        // Section 4.1.3.2 - Validate Insert Zone length
        if (current_managed_parameters_struct.aos_iz_len <= 0)
        {
            status = CRYPTO_LIB_ERR_INVALID_AOS_IZ_LENGTH;
#ifdef AOS_DEBUG
            printf(KRED "Error: Invalid Insert Zone length %d. Must be between 1 and 65535 octets.\n" RESET,
                   current_managed_parameters_struct.aos_iz_len);
#endif
            goto end_of_function;
        }

// Section 4.1.3.2.3 - All bits of the Insert Zone shall be set by the sending end
// Based on the managed parameter configuration, we're not modifying the Insert Zone contents
#ifdef AOS_DEBUG
        printf(KYEL "Insert Zone present with length %d octets\n" RESET, current_managed_parameters_struct.aos_iz_len);
#endif
        *byte_idx += current_managed_parameters_struct.aos_iz_len;
    }

end_of_function:
    return status;
}


int32_t Crypto_AOSP_Get_SPI(uint8_t *p_ingest, uint16_t *byte_idx, uint16_t *spi)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    *spi = (uint8_t)p_ingest[*byte_idx] << 8 | (uint8_t)p_ingest[*byte_idx + 1];
    // Move index to past the SPI
    *byte_idx += 2;

    return status;
}