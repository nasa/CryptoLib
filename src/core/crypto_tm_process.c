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
 * - CCSDS 132.0-B-3 (TM Space Data Link Protocol)
 * - CCSDS 355.0-B-2 (Space Data Link Security Protocol)
 */

/**
 * @brief Function: Crypto_TM_ProcessSecurity
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @return int32: Success/Failure
 **/
int32_t Crypto_TM_ProcessSecurity(uint8_t *p_ingest, uint16_t len_ingest, uint8_t **pp_processed_frame,
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
    uint8_t                secondary_hdr_len = 0;
    uint8_t                spi               = -1;
    crypto_key_t          *ekp               = NULL;
    crypto_key_t          *akp               = NULL;

    // Bit math to give concise access to values in the ingest
    tm_frame_pri_hdr.tfvn = ((uint8_t)p_ingest[0] & 0xC0) >> 6;
    tm_frame_pri_hdr.scid = (((uint16_t)p_ingest[0] & 0x3F) << 4) | (((uint16_t)p_ingest[1] & 0xF0) >> 4);
    tm_frame_pri_hdr.vcid = ((uint8_t)p_ingest[1] & 0x0E) >> 1;

    status = Crypto_TM_Process_Setup(len_ingest, &byte_idx, p_ingest, &secondary_hdr_len);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    /**
     * Begin Security Header Fields
     * Reference CCSDS SDLP 3550b1 4.1.1.1.3
     **/
    // Get SPI
    spi = Crypto_TMP_Get_SPI(p_ingest, &byte_idx);

    status = sa_if->sa_get_from_spi(spi, &sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    if (sa_ptr->sa_state != SA_OPERATIONAL)
    {
        status = CRYPTO_LIB_ERR_SA_NOT_OPERATIONAL;
        goto end_of_function;
    }

#ifdef SA_DEBUG
    printf(KYEL "DEBUG - Printing SA Entry for current frame.\n" RESET);
    Crypto_saPrint(sa_ptr);
#endif
    // Determine SA Service Type
    status = Crypto_TM_Determine_SA_Service_Type(&sa_service_type, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Determine Algorithm cipher & mode
    status = Crypto_TMP_Determine_Cipher_Mode(sa_service_type, sa_ptr, &encryption_cipher, &ecs_is_aead_algorithm);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

#ifdef TM_DEBUG
    Crypto_TM_SA_Service_Type_Debug_Print(sa_service_type);
#endif
    status = Crypto_TMP_Verify_Frame_Size(byte_idx, len_ingest, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Parse & Check FECF, if present, and update fecf length
    status = Crypto_TMP_FECF_Validate(p_ingest, len_ingest, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
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

    // Copy over TM Primary Header (6 bytes),Secondary (if present)
    // If present, the TF Secondary Header will follow the TF PriHdr
    memcpy(p_new_dec_frame, &p_ingest[0], 6 + secondary_hdr_len);

    // Byte_idx is still set to just past the SPI
    // If IV is present, note location
    if (sa_ptr->iv_len > 0)
    {
        iv_loc = byte_idx;
    }

    // Increment byte_idx past Security Header Fields based on SA values
    byte_idx += sa_ptr->shivf_len;
    byte_idx += sa_ptr->shsnf_len;
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
    Crypto_TMP_Calc_PDU_MAC(&pdu_len, byte_idx, sa_ptr, &mac_loc);

    if (current_managed_parameters_struct.max_frame_size < pdu_len)
    {
        status = CRYPTO_LIB_ERR_TM_FRAME_LENGTH_UNDERFLOW;
        goto end_of_function;
    }

    Crypto_TM_Process_Debug_Print(byte_idx, pdu_len, sa_ptr);
    Crypto_Set_FSR(p_ingest, byte_idx, pdu_len, sa_ptr);

    // Get Key
    status = Crypto_TM_Get_Keys(&ekp, &akp, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    /**
     * Begin Authentication / Encryption
     **/
    // Parse MAC, prepare AAD
    status = Crypto_TMP_Parse_Mac_Prep_AAD(sa_service_type, p_ingest, mac_loc, sa_ptr, &aad_len, byte_idx, aad);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    status =
        Crypto_TM_Do_Decrypt(sa_service_type, sa_ptr, ecs_is_aead_algorithm, byte_idx, p_new_dec_frame, pdu_len,
                             p_ingest, ekp, akp, iv_loc, mac_loc, aad_len, aad, pp_processed_frame, p_decrypted_length);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

end_of_function:
    if (status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_TC_Safe_Free_Ptr(p_new_dec_frame);
    }
    if (mc_if != NULL)
    {
        mc_if->mc_log(status);
    }
    return status;
}

/**
 * @brief Function: Crypto_TM_Process_Setup
 * Sets up TM Process Security.  Verifies ingest length, verifies pointers are not null,
 * Retreives managed parameters,  validates GVCID, and verifies the presence of Secondary Header
 * @param len_ingest: uint16_t
 * @param byte_idx: uint16_t*
 * @param p_ingest: uint8_t*
 * @param secondary_hdr_len: uint8_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TM_Process_Setup(uint16_t len_ingest, uint16_t *byte_idx, uint8_t *p_ingest, uint8_t *secondary_hdr_len)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
#ifdef DEBUG
    printf(KYEL "\n----- Crypto_TM_ProcessSecurity START -----\n" RESET);
#endif

    if (len_ingest < 6) // Frame length doesn't even have enough bytes for header -- error out.
    {
        status = CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TM_STANDARD;
        goto end_of_function;
    }

    if (((crypto_config.init_status == UNITIALIZED) || (mc_if == NULL) || (sa_if == NULL)))
    {
#ifdef TM_DEBUG
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
#endif
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        goto end_of_function;
    }

    // Query SA DB for active SA / SDLS parameters
    if ((sa_if == NULL)) // This should not happen, but tested here for safety
    {
        printf(KRED "ERROR: SA DB Not initalized! -- CRYPTO_LIB_ERR_NO_INIT, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_INIT;
        goto end_of_function;
    }

#ifdef TM_DEBUG
    printf(KGRN "TM Process Using following parameters:\n\t" RESET);
    printf(KGRN "tvfn: %d\t scid: %d\t vcid: %d\n" RESET, tm_frame_pri_hdr.tfvn, tm_frame_pri_hdr.scid,
           tm_frame_pri_hdr.vcid);
#endif

    // Lookup-retrieve managed parameters for frame via gvcid:
    status =
        Crypto_Get_Managed_Parameters_For_Gvcid(tm_frame_pri_hdr.tfvn, tm_frame_pri_hdr.scid, tm_frame_pri_hdr.vcid,
                                                gvcid_managed_parameters_array, &current_managed_parameters_struct);
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef TM_DEBUG
        printf(KRED "**NO LUCK WITH GVCID!\n" RESET);
#endif
        goto end_of_function;
    } // Unable to get necessary Managed Parameters for TM TF -- return with error.

    // Check if secondary header is present within frame
    // Note: Secondary headers are static only for a mission phase, not guaranteed static
    // over the life of a mission Per CCSDS 132.0-B.3 Section 4.1.2.7.2.3

    // Secondary Header flag is 1st bit of 5th byte (index 4)
    *byte_idx = 4;
    if ((p_ingest[*byte_idx] & 0x80) == 0x80)
    {
#ifdef TM_DEBUG
        printf(KYEL "A TM Secondary Header flag is set!\n");
#endif
        // Secondary header is present
        *byte_idx = 6;
        // Determine Secondary Header Version Number, should always be 0b00
        uint8_t shvn = (p_ingest[*byte_idx] & 0xC0) >> 6;
#ifdef TM_DEBUG
        printf("Secondary Header Version Number: %d\n", shvn);
#endif
        if (shvn > 0)
        {
            status = CRYPTO_LIB_ERR_TM_SECONDARY_HDR_VN;
            goto end_of_function;
        }
        // Determine length of secondary header
        // Length coded as total length of secondary header - 1
        // Reference CCSDS 132.0-B-3 4.1.3.2.3
        *secondary_hdr_len = (p_ingest[*byte_idx] & 0x3F) + 1;
#ifdef TM_DEBUG
        printf(KYEL "Secondary Header Length is decoded as: %d\n", *secondary_hdr_len - 1);
        printf("len_ingest: %d \n", len_ingest);
        printf("byte_idx: %d\n", *byte_idx);
        printf("Actual secondary header length: %d\n", *secondary_hdr_len);
#endif
        // We have a secondary header length now, is it sane?
        // Does it violate spec maximum?
        // Reference CCSDS 1320b3 4.1.3.1.3
        if (*secondary_hdr_len > TM_SECONDARY_HDR_MAX_VALUE + 1)
        {
            status = CRYPTO_LIB_ERR_TM_SECONDARY_HDR_SIZE;
            goto end_of_function;
        }

        // Does it 'fit' in the overall frame correctly?
        // We can't validate it down to the byte yet,
        // we don't know the variable lengths from the SA yet
        // Protects from overruns on very short max frame sizes
        // Smallest frame here is Header | Secondary Header | 1 byte data
        if (len_ingest < (TM_FRAME_PRIMARYHEADER_SIZE + *secondary_hdr_len + 1))
        {
            status = CRYPTO_LIB_ERR_TM_SECONDARY_HDR_SIZE;
            goto end_of_function;
        }
        // Increment from current byte (1st byte of secondary header),
        // to where the SPI would start
        *byte_idx += *secondary_hdr_len;
    }
    else
    {
        // No Secondary header, carry on as usual and increment to SPI start
        *byte_idx = 6;
    }

end_of_function:
    return status;
}

uint8_t Crypto_TMP_Get_SPI(uint8_t *p_ingest, uint16_t *byte_idx)
{
    uint16_t spi = (uint8_t)p_ingest[*byte_idx] << 8 | (uint8_t)p_ingest[*byte_idx + 1];
    // Move index to past the SPI
    *byte_idx += 2;
    return spi;
}

/**
 * @brief Function: Crypto_TM_Do_Decrypt
 * Parent TM Decryption Functionality
 * @param sa_service_type: uint8_t
 * @param sa_ptr: SecurityAssociation_t*
 * @param ecs_is_aead_algorithm: uint8_t
 * @param byte_idx: uint16_t
 * @param p_new_dec_frame: uint8_t*
 * @param pdu_len: uint16_t
 * @param p_ingest: uint8_t*
 * @param ekp: crypto_key_t*
 * @param akp: crypto_key_t*
 * @param iv_loc: uint8_t
 * @param mac_loc: int
 * @param aad_len: uint16_t
 * @param aad: uint8_t*
 * @param pp_processed_frame: uint8_t**
 * @param p_decrypted_length: uint16_t*
 * @return int32_t: Success/Failure
 */
int32_t Crypto_TM_Do_Decrypt(uint8_t sa_service_type, SecurityAssociation_t *sa_ptr, uint8_t ecs_is_aead_algorithm,
                             uint16_t byte_idx, uint8_t *p_new_dec_frame, uint16_t pdu_len, uint8_t *p_ingest,
                             crypto_key_t *ekp, crypto_key_t *akp, uint8_t iv_loc, int mac_loc, uint16_t aad_len,
                             uint8_t *aad, uint8_t **pp_processed_frame, uint16_t *p_decrypted_length)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (sa_service_type != SA_PLAINTEXT && ecs_is_aead_algorithm == CRYPTO_TRUE)
    {
        status = Crypto_TM_Do_Decrypt_AEAD(sa_service_type, p_ingest, p_new_dec_frame, byte_idx, pdu_len, ekp, sa_ptr,
                                           iv_loc, mac_loc, aad_len, aad);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            goto end_of_function;
        }
    }

    else if (sa_service_type != SA_PLAINTEXT && ecs_is_aead_algorithm == CRYPTO_FALSE)
    {
        status = Crypto_TM_Do_Decrypt_NONAEAD(sa_service_type, pdu_len, p_new_dec_frame, byte_idx, p_ingest, akp, ekp,
                                              sa_ptr, iv_loc, mac_loc, aad_len, aad);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            goto end_of_function;
        }
        // TODO - implement non-AEAD algorithm logic
    }

    // If plaintext, copy byte by byte
    else if (sa_service_type == SA_PLAINTEXT)
    {
        memcpy(p_new_dec_frame + byte_idx, &(p_ingest[byte_idx]), pdu_len);
    }

#ifdef TM_DEBUG
    printf(KYEL "Printing received frame:\n\t" RESET);
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
    printf(KYEL "----- Crypto_TM_ProcessSecurity END -----\n" RESET);
#endif

end_of_function:
    return status;
}

/**
 * @brief Function: Crypto_TM_Do_Decrypt_AEAD
 * Performs decryption on AEAD Authentication, Encryption, and Authenticated Encryption
 * @param sa_service_type: uint8_t
 * @param p_ingest: uint8_t*
 * @param p_new_dec_frame: uint8_t*
 * @param byte_idx: uint16_t
 * @param pdu_len: uint16_t
 * @param ekp: crypto_key_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @param iv_loc: uint8_t
 * @param mac_loc: int
 * @param aad_len: uint16_t
 * @param aad:  uint8_t*
 * @return int32_t: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.3.4 (TM Decryption Processing)
 */
int32_t Crypto_TM_Do_Decrypt_AEAD(uint8_t sa_service_type, uint8_t *p_ingest, uint8_t *p_new_dec_frame,
                                  uint16_t byte_idx, uint16_t pdu_len, crypto_key_t *ekp, SecurityAssociation_t *sa_ptr,
                                  uint8_t iv_loc, int mac_loc, uint16_t aad_len, uint8_t *aad)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
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
                                                            p_ingest + iv_loc,  // IV
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
    return status;
}

/**
 * @brief Function: Crypto_TM_Do_Decrypt_NONAEAD
 * Performs decryption on NON AEAD Encryption and Authenticated Encryption
 * @param sa_service_type: uint8_t
 * @param pdu_len: uint16_t
 * @param p_new_dec_frame: uint8_t*
 * @param byte_idx: uint16_t
 * @param p_ingest: uint8_t*
 * @param akp: crypto_key_t*
 * @param ekp: crypto_key_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @param iv_loc: uint8_t
 * @param mac_loc: int
 * @param aad_len: uint16_t
 * @param aad: uint8_t
 * @return int32_t: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.3.4 (TM Decryption Processing)
 */
int32_t Crypto_TM_Do_Decrypt_NONAEAD(uint8_t sa_service_type, uint16_t pdu_len, uint8_t *p_new_dec_frame,
                                     uint16_t byte_idx, uint8_t *p_ingest, crypto_key_t *akp, crypto_key_t *ekp,
                                     SecurityAssociation_t *sa_ptr, uint8_t iv_loc, int mac_loc, uint16_t aad_len,
                                     uint8_t *aad)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (sa_service_type == SA_AUTHENTICATION || sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
    {
        status = cryptography_if->cryptography_validate_authentication(p_new_dec_frame + byte_idx, // plaintext output
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
        if (status != CRYPTO_LIB_SUCCESS)
        {
            goto end_of_function;
        }
    }
    if (sa_service_type == SA_ENCRYPTION || sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
    {
        if (crypto_config.key_type != KEY_TYPE_KMC)
        {
            // Check that key length to be used meets the algorithm requirement
            if ((int32_t)ekp->key_len != Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs))
            {
                status = CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
                goto end_of_function;
            }
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
        if (status != CRYPTO_LIB_SUCCESS)
        {
            goto end_of_function;
        }
    }

end_of_function:
    return status;
}

void Crypto_TM_SA_Service_Type_Debug_Print(uint8_t sa_service_type)
{
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
}

/**
 * @brief Function: Crypto_TMP_Determine_Cipher_Mode
 * Determines Cipher mode and Algorithm type
 * @param sa_service_type: uint8_t
 * @param sa_ptr: SecurityAssociation_t*
 * @param encryption_cipher: uint32_t*
 * @param ecs_is_aead_algorithm: uint8_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TMP_Determine_Cipher_Mode(uint8_t sa_service_type, SecurityAssociation_t *sa_ptr,
                                         uint32_t *encryption_cipher, uint8_t *ecs_is_aead_algorithm)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (sa_service_type != SA_PLAINTEXT)
    {
        if (sa_ptr->ecs != CRYPTO_CIPHER_NONE)
        {
            *encryption_cipher = sa_ptr->ecs;
#ifdef TC_DEBUG
            printf(KYEL "SA Encryption Cipher: %d\n", *encryption_cipher);
#endif
        }
        // If no pointer, must not be using ECS at all
        else
        {
            *encryption_cipher = CRYPTO_CIPHER_NONE;
        }
        *ecs_is_aead_algorithm = Crypto_Is_AEAD_Algorithm(*encryption_cipher);
    }

    if (*encryption_cipher == CRYPTO_CIPHER_NONE && sa_ptr->est == 1)
    {
        status = CRYPTO_LIB_ERR_NO_ECS_SET_FOR_ENCRYPTION_MODE;
    }

    return status;
}

int32_t Crypto_TMP_Verify_Frame_Size(uint16_t byte_idx, uint16_t len_ingest, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (current_managed_parameters_struct.max_frame_size <= byte_idx - sa_ptr->stmacf_len)
    {
        status = CRYPTO_LIB_ERR_TM_FRAME_LENGTH_UNDERFLOW;
        goto end_of_function;
    }

    // Received the wrong amount of bytes from mandated frame size
    if (len_ingest < current_managed_parameters_struct.max_frame_size)
    {
        status = CRYPTO_LIB_ERR_TM_FRAME_LENGTH_UNDERFLOW;
        goto end_of_function;
    }

end_of_function:
    return status;
}

/**
 * @brief Function: Crypto_TMP_Calc_PDU_MAC
 * Calculates the PDU MAC
 * @param pdu_len: uint16_t*
 * @param byte_idx: uint16_t
 * @param sa_ptr: SecurityAssociation_t*
 * @param mac_loc: int*
 * @return int32_t: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.3.2 (TM Security Trailer)
 */
void Crypto_TMP_Calc_PDU_MAC(uint16_t *pdu_len, uint16_t byte_idx, SecurityAssociation_t *sa_ptr, int *mac_loc)
{
    *pdu_len = current_managed_parameters_struct.max_frame_size - (byte_idx)-sa_ptr->stmacf_len;
    if (current_managed_parameters_struct.has_ocf == TM_HAS_OCF)
    {
        *pdu_len -= 4;
    }
    if (current_managed_parameters_struct.has_fecf == TM_HAS_FECF)
    {
        *pdu_len -= 2;
    }

    // If MAC exists, comes immediately after pdu
    if (sa_ptr->stmacf_len > 0)
    {
        *mac_loc = byte_idx + *pdu_len;
    }
}

/**
 * @brief Function: Crypto_TMP_Parse_Mac_Prep_AAD
 * Parses TM MAC, and calls AAD Prep functionality
 * @param sa_service_type: uint8_t
 * @param p_ingest: uint8_t*
 * @param mac_loc: int
 * @param sa_ptr: SecurityAssociation_t*
 * @param aad_len: uint16_t*
 * @param byte_idx: uint16_t
 * @param aad: uint8_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TMP_Parse_Mac_Prep_AAD(uint8_t sa_service_type, uint8_t *p_ingest, int mac_loc,
                                      SecurityAssociation_t *sa_ptr, uint16_t *aad_len, uint16_t byte_idx, uint8_t *aad)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if ((sa_service_type == SA_AUTHENTICATION) || (sa_service_type == SA_AUTHENTICATED_ENCRYPTION))
    {
#ifdef MAC_DEBUG
        printf("MAC Parsed from Frame:\n");
        Crypto_hexprint(p_ingest + mac_loc, sa_ptr->stmacf_len);
#endif
        if (sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
        {
            *aad_len = byte_idx;
        }
        else
        {
            *aad_len = mac_loc;
        }
        if (sa_ptr->abm_len < *aad_len)
        {
            status = CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
            goto end_of_function;
        }
        // Use ingest and abm to create aad
        status = Crypto_Prepare_TM_AAD(p_ingest, *aad_len, sa_ptr->abm, aad);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            goto end_of_function;
        }

#ifdef MAC_DEBUG
        printf("AAD Debug:\n\tAAD Length is %d\n\t AAD is: ", *aad_len);
        for (int i = 0; i < *aad_len; i++)
        {
            printf("%02X", aad[i]);
        }
        printf("\n");
#endif
    }

end_of_function:
    return status;
}

/**
 * @brief Function: Crypto_TMP_FECF_Validate
 * Validates FECF in frame per CCSDS requirements
 * @param p_ingest: uint8_t* - Input frame
 * @param len_ingest: uint16_t - Frame length
 * @param sa_ptr: SecurityAssociation_t* - Security association
 * @return int32_t: Success/Failure
 *
 * CCSDS Compliance: CCSDS 132.0-B-3 Section 4.1.4 (Frame Error Control Field)
 **/
int32_t Crypto_TMP_FECF_Validate(uint8_t *p_ingest, uint16_t len_ingest, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (current_managed_parameters_struct.has_fecf == TM_HAS_FECF)
    {
        uint16_t received_fecf = (((p_ingest[current_managed_parameters_struct.max_frame_size - 2] << 8) & 0xFF00) |
                                  (p_ingest[current_managed_parameters_struct.max_frame_size - 1] & 0x00FF));

        if (crypto_config.crypto_check_fecf == TM_CHECK_FECF_TRUE)
        {
            // Calculate FECF over appropriate data
            uint8_t  is_encrypted    = (sa_ptr->est == 1);
            uint16_t calculated_fecf = Crypto_TMP_FECF_Calculate(p_ingest, len_ingest - 2, is_encrypted);

            // Compare FECFs
            if (received_fecf != calculated_fecf)
            {
#ifdef FECF_DEBUG
                printf("Received FECF is 0x%04X\n", received_fecf);
                printf("Calculated FECF is 0x%04X\n", calculated_fecf);
                printf("FECF was Calced over %d bytes\n", len_ingest - 2);
#endif
                status = CRYPTO_LIB_ERR_INVALID_FECF;
                mc_if->mc_log(status);
            }
        }
    }
    else if (current_managed_parameters_struct.has_fecf != TM_NO_FECF)
    {
#ifdef TM_DEBUG
        printf(KRED "TM_Process Error...tfvn: %d scid: 0x%04X vcid: 0x%02X fecf_enum: %d\n" RESET,
               current_managed_parameters_struct.tfvn, current_managed_parameters_struct.scid,
               current_managed_parameters_struct.vcid, current_managed_parameters_struct.has_fecf);
#endif
        status = CRYPTO_LIB_ERR_TC_ENUM_USED_FOR_TM_CONFIG;
        mc_if->mc_log(status);
    }
    return status;
}

/**
 * @brief Function: Crypto_TMP_FECF_Calculate
 * Calculates FECF over frame data per CCSDS 132.0-B-3
 * @param data: const uint8_t*
 * @param length: uint16_t
 * @param is_encrypted: uint8_t
 * @return uint16_t: Calculated FECF
 *
 * CCSDS Compliance: CCSDS 132.0-B-3 Section 4.1.4 (Frame Error Control Field)
 **/
uint16_t Crypto_TMP_FECF_Calculate(const uint8_t *data, uint16_t length, uint8_t is_encrypted)
{
    uint16_t crc = 0xFFFF;
    uint16_t i;
    uint8_t  byte;

    // For encrypted data, FECF is calculated over the ciphertext
    // This parameter allows for future encryption-specific FECF calculation if needed
    (void)is_encrypted; // Silence unused parameter warning while maintaining API

    for (i = 0; i < length; i++)
    {
        byte = data[i];
        crc ^= (byte << 8);
        for (uint8_t j = 0; j < 8; j++)
        {
            if (crc & 0x8000)
            {
                crc = (crc << 1) ^ 0x1021; // CRC-16-CCITT polynomial
            }
            else
            {
                crc <<= 1;
            }
        }
    }
    return crc;
}

/**
 * @brief Function: Crypto_TM_Process_Debug_Print
 * TM Process Helper Debug Print
 * Displays Index/data location start, Data Size, OCF Location, FECF Location
 * @param byte_idx: uint16_t
 * @param pdu_len: uint16_t
 * @param sa_ptr: SecurityAssociation_t*
 */
void Crypto_TM_Process_Debug_Print(uint16_t byte_idx, uint16_t pdu_len, SecurityAssociation_t *sa_ptr)
{
    // Fix for variable warnings
    byte_idx = byte_idx;
    pdu_len  = pdu_len;
    sa_ptr   = sa_ptr;
#ifdef TM_DEBUG
    printf(KYEL "Index / data location starts at: %d\n" RESET, byte_idx);
    printf(KYEL "Data size is: %d\n" RESET, pdu_len);
    if (current_managed_parameters_struct.has_ocf == TM_HAS_OCF)
    {
        // If OCF exists, comes immediately after MAC
        printf(KYEL "OCF Location is: %d\n" RESET, byte_idx + pdu_len + sa_ptr->stmacf_len);
    }
    if (current_managed_parameters_struct.has_fecf == TM_HAS_FECF)
    {
        // If FECF exists, comes just before end of the frame
        printf(KYEL "FECF Location is: %d\n" RESET, current_managed_parameters_struct.max_frame_size - 2);
    }
#endif
}