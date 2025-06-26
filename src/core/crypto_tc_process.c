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

#include <string.h> // memcpy

/**
 * @brief Function: Crypto_TC_ProcessSecurity
 * Processes TC frame security
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @param tc_sdls_processed_frame: TC_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2 (TC Security)
 **/
int32_t Crypto_TC_ProcessSecurity(uint8_t *ingest, int *len_ingest, TC_t *tc_sdls_processed_frame)
{
    // Pass-through to maintain original function signature when CAM isn't used.
    return Crypto_TC_ProcessSecurity_Cam(ingest, len_ingest, tc_sdls_processed_frame, NULL);
}

/**
 * @brief Function: Crypto_TC_ProcessSecurity_Cam
 * Processes TC frame security with CAM support
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @param tc_sdls_processed_frame: TC_t*
 * @param cam_cookies: char*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.3 (TC Security Processing)
 **/
int32_t Crypto_TC_ProcessSecurity_Cam(uint8_t *ingest, int *len_ingest, TC_t *tc_sdls_processed_frame,
                                      char *cam_cookies)
{
    // Local Variables
    cam_cookies                                       = cam_cookies;
    int32_t                status                     = CRYPTO_LIB_SUCCESS;
    SecurityAssociation_t *sa_ptr                     = NULL;
    uint8_t                sa_service_type            = -1;
    uint8_t               *aad                        = NULL;
    uint8_t                ecs_is_aead_algorithm      = -1;
    crypto_key_t          *ekp                        = NULL;
    crypto_key_t          *akp                        = NULL;
    int                    byte_idx                   = 0;
    uint8_t                fecf_len                   = FECF_SIZE;
    uint8_t                ocf_len                    = TELEMETRY_FRAME_OCF_CLCW_SIZE;
    uint8_t                segment_hdr_len            = TC_SEGMENT_HDR_SIZE;
    uint16_t               tc_enc_payload_start_index = 0;
    uint16_t               aad_len;
    uint32_t               encryption_cipher;

    status = Crypto_TCP_Sanity_Check(len_ingest);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Primary Header
    Crypto_TC_Set_Primary_Header(&ingest[byte_idx], &tc_sdls_processed_frame->tc_header);
    byte_idx += TC_FRAME_HEADER_SIZE;

    if (tc_sdls_processed_frame->tc_header.fl + 1 != *len_ingest) // Specified frame length larger than provided frame!
    {
        status = CRYPTO_LIB_ERR_TC_FRAME_LENGTH_MISMATCH;
        goto end_of_function;
    }

    // Lookup-retrieve managed parameters for frame via gvcid:
    status = Crypto_Get_Managed_Parameters_For_Gvcid(
        tc_sdls_processed_frame->tc_header.tfvn, tc_sdls_processed_frame->tc_header.scid,
        tc_sdls_processed_frame->tc_header.vcid, gvcid_managed_parameters_array, &current_managed_parameters_struct);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    } // Unable to get necessary Managed Parameters for TC TF -- return with error.

    // Segment Header
    Crypto_TCA_Set_Segment_Header(tc_sdls_processed_frame, ingest, &byte_idx);

    // Security Header
    Crypto_TCP_Set_SPI(ingest, &byte_idx, &tc_sdls_processed_frame->tc_sec_header);

#ifdef TC_DEBUG
    printf("vcid = %d \n", tc_sdls_processed_frame->tc_header.vcid);
    printf("spi  = %d \n", tc_sdls_processed_frame->tc_sec_header.spi);
#endif

    status = Crypto_TCP_Sanity_Validations(tc_sdls_processed_frame, &sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Allocate the necessary byte arrays within the security header + trailer given the SA
    Crypto_TCP_Set_Security_Header(&tc_sdls_processed_frame->tc_sec_header, sa_ptr);
    Crypto_TCP_Set_Security_Trailer(&tc_sdls_processed_frame->tc_sec_trailer, sa_ptr);

    // Determine SA Service Type
    Crypto_TC_Get_SA_Service_Type(&sa_service_type, sa_ptr);

    // Determine Algorithm cipher & mode. // TODO - Parse authentication_cipher, and handle AEAD cases properly
    Crypto_TCP_Get_Cipher_Mode(sa_service_type, &encryption_cipher, &ecs_is_aead_algorithm, sa_ptr);

#ifdef TC_DEBUG
    Crypto_TC_SA_Service_Type_Debug_Print(sa_service_type);
#endif

    Crypto_TC_Calc_Lengths(&fecf_len, &segment_hdr_len, &ocf_len);

    // Parse & Check FECF
    status = Crypto_TC_Parse_Check_FECF(ingest, len_ingest, tc_sdls_processed_frame);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Parse transmitted portion of IV from received frame (Will be Whole IV if iv_len==shivf_len)
    Crypto_TCP_Copy_IV(&tc_sdls_processed_frame->tc_sec_header, ingest, segment_hdr_len, sa_ptr);

    // Handle non-transmitted IV increment case (transmitted-portion roll-over)
    status = Crypto_TCP_Nontransmitted_IV_Increment(sa_ptr, tc_sdls_processed_frame);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

#ifdef DEBUG
    printf("Full IV Value from Frame and SADB (if applicable):\n");
    Crypto_hexprint(tc_sdls_processed_frame->tc_sec_header.iv, sa_ptr->iv_len);
#endif

    // Parse transmitted portion of ARSN
    Crypto_TCP_Copy_ARSN(&tc_sdls_processed_frame->tc_sec_header, ingest, segment_hdr_len, sa_ptr);

    // Handle non-transmitted SN increment case (transmitted-portion roll-over)
    status = Crypto_TCP_Nontransmitted_SN_Increment(sa_ptr, tc_sdls_processed_frame);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

#ifdef DEBUG
    printf("Full ARSN Value from Frame and SADB (if applicable):\n");
    Crypto_hexprint(tc_sdls_processed_frame->tc_sec_header.sn, sa_ptr->arsn_len);
#endif

    // Parse pad length
    Crypto_TCP_Copy_Pad(&tc_sdls_processed_frame->tc_sec_header, ingest, segment_hdr_len, sa_ptr);

    // Parse MAC, prepare AAD
    status = Crypto_TCP_Prep_AAD(tc_sdls_processed_frame, fecf_len, sa_service_type, ecs_is_aead_algorithm, &aad_len,
                                 sa_ptr, segment_hdr_len, ingest, &aad);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    Crypto_TCP_Calc_Payload_Start_Idx(&tc_enc_payload_start_index, segment_hdr_len, sa_ptr);

    // Todo -- if encrypt only, ignore stmacf_len entirely to avoid erroring on SA misconfiguration... Or just throw a
    // warning/error indicating SA misconfiguration?
    Crypto_TCP_Copy_PDU_Len(tc_sdls_processed_frame, tc_enc_payload_start_index, sa_ptr, fecf_len);

    status = Crypto_TCP_Validate_PDU_Len(tc_sdls_processed_frame);
    if (status != CRYPTO_LIB_SUCCESS) // invalid header parsed, sizes overflowed & make no sense!
    {
        goto end_of_function;
    }

#ifdef DEBUG
    printf(KYEL "TC PDU Calculated Length: %d \n" RESET, tc_sdls_processed_frame->tc_pdu_len);
#endif

    /* Get Key */
    status = Crypto_TCP_Get_Keys(&ekp, &akp, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }
    status = Crypto_TCP_Do_Decrypt(sa_service_type, ecs_is_aead_algorithm, ekp, sa_ptr, aad, tc_sdls_processed_frame,
                                   ingest, tc_enc_payload_start_index, aad_len, cam_cookies, akp, segment_hdr_len);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }
    // Now that MAC has been verified, check IV & ARSN if applicable
    status = Crypto_TCP_Check_IV_ARSN(sa_ptr, tc_sdls_processed_frame);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }
    // Extended PDU processing, if applicable
    if (crypto_config.process_sdls_pdus == TC_PROCESS_SDLS_PDUS_TRUE)
    {
        status = Crypto_Process_Extended_Procedure_Pdu(tc_sdls_processed_frame, ingest, *len_ingest);
    }

end_of_function:
    Crypto_TC_Safe_Free_Ptr(aad);
    if (mc_if != NULL)
    {
        mc_if->mc_log(status);
    }
    return status;
}

/**
 * @brief Function: Crypto_TCP_Sanity_Check
 * Performs sanity checks on TC frame
 * @param len_ingest: int*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1 (Frame Format)
 **/
int32_t Crypto_TCP_Sanity_Check(int *len_ingest)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_TC_ProcessSecurity START -----\n" RESET);
#endif

    if ((mc_if == NULL) || (crypto_config.init_status == UNITIALIZED))
    {
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        goto end_of_function;
    }
    if (*len_ingest < 5) // Frame length doesn't even have enough bytes for header -- error out.
    {
        status = CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TC_STANDARD;
        goto end_of_function;
    }

end_of_function:
    return status;
}

/**
 * @brief Function: Crypto_TCA_Set_Segment_Header
 * Sets segment header for TC frame
 * @param tc_sdls_processed_frame: TC_t*
 * @param ingest: uint8_t*
 * @param byte_idx: int*
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1.3 (Segment Header)
 **/
void Crypto_TCA_Set_Segment_Header(TC_t *tc_sdls_processed_frame, uint8_t *ingest, int *byte_idx)
{
    int byte_idx_tmp = *byte_idx;
    if (current_managed_parameters_struct.has_segmentation_hdr == TC_HAS_SEGMENT_HDRS)
    {
        tc_sdls_processed_frame->tc_sec_header.sh = (uint8_t)ingest[*byte_idx];
        byte_idx_tmp++;
    }
    *byte_idx = byte_idx_tmp;
}

/**
 * @brief Function: Crypto_TCP_Get_Cipher_Mode
 * Gets cipher mode for TC processing
 * @param sa_service_type: uint8_t
 * @param encryption_cipher: uint32_t*
 * @param ecs_is_aead_algorithm: uint8_t*
 * @param sa_ptr: SecurityAssociation_t*
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.2 (Cryptographic Algorithms)
 **/
void Crypto_TCP_Get_Cipher_Mode(uint8_t sa_service_type, uint32_t *encryption_cipher, uint8_t *ecs_is_aead_algorithm,
                                SecurityAssociation_t *sa_ptr)
{
    if (sa_service_type != SA_PLAINTEXT)
    {
        *encryption_cipher     = sa_ptr->ecs;
        *ecs_is_aead_algorithm = Crypto_Is_AEAD_Algorithm(*encryption_cipher);
    }
}

/**
 * @brief Function: Crypto_TC_Parse_Check_FECF
 * Validates Frame Error Control Field
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @param tc_sdls_processed_frame: TC_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1.4 (Frame Error Control Field)
 **/
int32_t Crypto_TC_Parse_Check_FECF(uint8_t *ingest, int *len_ingest, TC_t *tc_sdls_processed_frame)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (current_managed_parameters_struct.has_fecf == TC_HAS_FECF)
    {
        tc_sdls_processed_frame->tc_sec_trailer.fecf =
            (((ingest[tc_sdls_processed_frame->tc_header.fl - 1] << 8) & 0xFF00) |
             (ingest[tc_sdls_processed_frame->tc_header.fl] & 0x00FF));

        if (crypto_config.crypto_check_fecf == TC_CHECK_FECF_TRUE)
        {
            uint16_t received_fecf = tc_sdls_processed_frame->tc_sec_trailer.fecf;
            // Calculate our own
            uint16_t calculated_fecf = Crypto_Calc_FECF(ingest, *len_ingest - 2);
            // Compare
#ifdef DEBUG
            printf("Received FECF is 0x%04X\n", received_fecf);
            printf("Calculated FECF is 0x%04X\n", calculated_fecf);
            printf("FECF was Calced over %d bytes\n", *len_ingest - 2);
#endif
            if (received_fecf != calculated_fecf)
            {
                status = CRYPTO_LIB_ERR_INVALID_FECF;
                mc_if->mc_log(status);
            }
        }
    }
    return status;
}

void Crypto_TCP_Set_SPI(uint8_t *ingest, int *index, TC_FrameSecurityHeader_t *header)
{
    header->spi = ((uint16_t)ingest[*index] << 8) | (uint16_t)ingest[*index + 1];
    *index += 2;
}

void Crypto_TCP_Set_Security_Header(TC_FrameSecurityHeader_t *tc_sec_header, SecurityAssociation_t *sa_ptr)
{
    tc_sec_header->iv_field_len  = sa_ptr->iv_len;
    tc_sec_header->sn_field_len  = sa_ptr->arsn_len;
    tc_sec_header->pad_field_len = sa_ptr->shplf_len;
}

void Crypto_TCP_Set_Security_Trailer(TC_FrameSecurityTrailer_t *tc_sec_trailer, SecurityAssociation_t *sa_ptr)
{
    tc_sec_trailer->mac_field_len = sa_ptr->stmacf_len;
}

void Crypto_TCP_Copy_IV(TC_FrameSecurityHeader_t *tc_sec_header, uint8_t *ingest, uint8_t segment_hdr_len,
                        SecurityAssociation_t *sa_ptr)
{
    memcpy(tc_sec_header->iv + (sa_ptr->iv_len - sa_ptr->shivf_len),
           &(ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN]), sa_ptr->shivf_len);
}

void Crypto_TCP_Copy_ARSN(TC_FrameSecurityHeader_t *tc_sec_header, uint8_t *ingest, uint8_t segment_hdr_len,
                          SecurityAssociation_t *sa_ptr)
{
    memcpy(tc_sec_header->sn + (sa_ptr->arsn_len - sa_ptr->shsnf_len),
           &(ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len]), sa_ptr->shsnf_len);
}

void Crypto_TCP_Copy_Pad(TC_FrameSecurityHeader_t *tc_sec_header, uint8_t *ingest, uint8_t segment_hdr_len,
                         SecurityAssociation_t *sa_ptr)
{
    memcpy((tc_sec_header->pad),
           &(ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len]),
           sa_ptr->shplf_len);
}

void Crypto_TCP_Calc_Payload_Start_Idx(uint16_t *tc_enc_payload_start_index, uint8_t segment_hdr_len,
                                       SecurityAssociation_t *sa_ptr)
{
    *tc_enc_payload_start_index =
        TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len + sa_ptr->shplf_len;
}

void Crypto_TCP_Copy_PDU_Len(TC_t *tc_sdls_processed_frame, uint16_t tc_enc_payload_start_index,
                             SecurityAssociation_t *sa_ptr, uint8_t fecf_len)
{
    tc_sdls_processed_frame->tc_pdu_len = tc_sdls_processed_frame->tc_header.fl + 1 - tc_enc_payload_start_index -
                                          sa_ptr->stmacf_len - fecf_len; // TODO: subtract FSR/OCF?
}

int32_t Crypto_TCP_Validate_PDU_Len(TC_t *tc_sdls_processed_frame)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (tc_sdls_processed_frame->tc_pdu_len >
        tc_sdls_processed_frame->tc_header.fl) // invalid header parsed, sizes overflowed & make no sense!
    {
        status = CRYPTO_LIB_ERR_INVALID_HEADER;
    }
    return status;
}

/**
 * @brief Function: Crypto_TCP_Do_Decrypt
 * Performs TC frame decryption
 * @param sa_service_type: uint8_t
 * @param ecs_is_aead_algorithm: uint8_t
 * @param ekp: crypto_key_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @param aad: uint8_t*
 * @param tc_sdls_processed_frame: TC_t*
 * @param ingest: uint8_t*
 * @param tc_enc_payload_start_index: uint16_t
 * @param aad_len: uint16_t
 * @param cam_cookies: char*
 * @param akp: crypto_key_t*
 * @param segment_hdr_len: uint8_t
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.3 (TC Security Processing)
 **/
int32_t Crypto_TCP_Do_Decrypt(uint8_t sa_service_type, uint8_t ecs_is_aead_algorithm, crypto_key_t *ekp,
                              SecurityAssociation_t *sa_ptr, uint8_t *aad, TC_t *tc_sdls_processed_frame,
                              uint8_t *ingest, uint16_t tc_enc_payload_start_index, uint16_t aad_len, char *cam_cookies,
                              crypto_key_t *akp, uint8_t segment_hdr_len)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (sa_service_type != SA_PLAINTEXT && ecs_is_aead_algorithm == CRYPTO_TRUE)
    {
        // Check that key length to be used meets the algorithm requirement
        if (crypto_config.key_type != KEY_TYPE_KMC)
        {
            status = Crypto_TCP_Check_ECS_Keylen(ekp, sa_ptr);
            if (status != CRYPTO_LIB_SUCCESS)
            {
                goto end_of_function;
            }
        }

        status = cryptography_if->cryptography_aead_decrypt(
            tc_sdls_processed_frame->tc_pdu,               // plaintext output
            (size_t)(tc_sdls_processed_frame->tc_pdu_len), // length of data
            &(ingest[tc_enc_payload_start_index]),         // ciphertext input
            (size_t)(tc_sdls_processed_frame->tc_pdu_len), // in data length
            &(ekp->value[0]),                              // Key
            Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs),       //
            sa_ptr,                                        // SA for key reference
            tc_sdls_processed_frame->tc_sec_header.iv,     // IV
            sa_ptr->iv_len,                                // IV Length
            tc_sdls_processed_frame->tc_sec_trailer.mac,   // Frame Expected Tag
            sa_ptr->stmacf_len,                            // tag size
            aad,                                           // additional authenticated data
            aad_len,                                       // length of AAD
            (sa_ptr->est),                                 // Decryption Bool
            (sa_ptr->ast),                                 // Authentication Bool
            (sa_ptr->ast),                                 // AAD Bool
            &sa_ptr->ecs,                                  // encryption cipher
            &sa_ptr->acs,                                  // authentication cipher
            cam_cookies                                    //
        );
    }
    else if (sa_service_type != SA_PLAINTEXT && ecs_is_aead_algorithm == CRYPTO_FALSE) // Non aead algorithm
    {
        // TODO - implement non-AEAD algorithm logic
        if (sa_service_type == SA_AUTHENTICATION || sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
        {
            if (crypto_config.key_type != KEY_TYPE_KMC)
            {
                // Check that key length to be used ets the algorithm requirement
                status = Crypto_TCP_Check_ACS_Keylen(akp, sa_ptr);
                if (status != CRYPTO_LIB_SUCCESS)
                {
                    goto end_of_function;
                }
            }

            status = cryptography_if->cryptography_validate_authentication(
                tc_sdls_processed_frame->tc_pdu,               // plaintext output
                (size_t)(tc_sdls_processed_frame->tc_pdu_len), // length of data
                &(ingest[tc_enc_payload_start_index]),         // ciphertext input
                (size_t)(tc_sdls_processed_frame->tc_pdu_len), // in data length
                &(akp->value[0]),                              // Key
                Crypto_Get_ACS_Algo_Keylen(sa_ptr->acs),       //
                sa_ptr,                                        // SA for key reference
                tc_sdls_processed_frame->tc_sec_header.iv,     // IV
                sa_ptr->iv_len,                                // IV Length
                tc_sdls_processed_frame->tc_sec_trailer.mac,   // Frame Expected Tag
                sa_ptr->stmacf_len,                            // tag size
                aad,                                           // additional authenticated data
                aad_len,                                       // length of AAD
                CRYPTO_CIPHER_NONE,                            // encryption cipher
                sa_ptr->acs,                                   // authentication cipher
                cam_cookies                                    //
            );
        }
        if (sa_service_type == SA_ENCRYPTION || sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
        {
            if (crypto_config.key_type != KEY_TYPE_KMC)
            {
                // Check that key length to be used emets the algorithm requirement
                if ((int32_t)ekp->key_len != Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs))
                {
                    status = CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
                    goto end_of_function;
                }
            }

            status =
                cryptography_if->cryptography_decrypt(tc_sdls_processed_frame->tc_pdu,               // plaintext output
                                                      (size_t)(tc_sdls_processed_frame->tc_pdu_len), // length of data
                                                      &(ingest[tc_enc_payload_start_index]),         // ciphertext input
                                                      (size_t)(tc_sdls_processed_frame->tc_pdu_len), // in data length
                                                      &(ekp->value[0]),                              // Key
                                                      Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs),       //
                                                      sa_ptr,                                    // SA for key reference
                                                      tc_sdls_processed_frame->tc_sec_header.iv, // IV
                                                      sa_ptr->iv_len,                            // IV Length
                                                      &sa_ptr->ecs,                              // encryption cipher
                                                      &sa_ptr->acs, // authentication cipher
                                                      cam_cookies   //
                );

            // Handle Padding Removal
            if (sa_ptr->shplf_len != 0)
            {
                int padding_location =
                    TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len;
                uint16_t padding_amount = 0;
                // Get Padding Amount from ingest frame
                padding_amount = (int)ingest[padding_location];
                // Remove Padding from final decrypted portion
                tc_sdls_processed_frame->tc_pdu_len -= padding_amount;
            }
        }
    }
    else if (sa_service_type == SA_PLAINTEXT)
    {
        memcpy(tc_sdls_processed_frame->tc_pdu, &(ingest[tc_enc_payload_start_index]),
               tc_sdls_processed_frame->tc_pdu_len);
    }

end_of_function:
    return status;
}

/**
 * @brief Function: Crypto_TCP_Nontransmitted_IV_Increment
 * Increments non-transmitted part of IV
 * @param sa_ptr: SecurityAssociation_t*
 * @param tc_sdls_processed_frame: TC_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
int32_t Crypto_TCP_Nontransmitted_IV_Increment(SecurityAssociation_t *sa_ptr, TC_t *tc_sdls_processed_frame)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (sa_ptr->shivf_len < sa_ptr->iv_len && crypto_config.ignore_anti_replay == TC_IGNORE_ANTI_REPLAY_FALSE &&
        crypto_config.crypto_increment_nontransmitted_iv == SA_INCREMENT_NONTRANSMITTED_IV_TRUE)
    {
        status = Crypto_TCP_Handle_Incrementing_Nontransmitted_Counter(
            tc_sdls_processed_frame->tc_sec_header.iv, sa_ptr->iv, sa_ptr->iv_len, sa_ptr->shivf_len, sa_ptr->arsnw);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            mc_if->mc_log(status);
            return status;
        }
    }
    else // Not checking IV ARSNW or only non-transmitted portion is static; Note, non-transmitted IV in SA must match
         // frame or will fail MAC check.
    {
        // Retrieve non-transmitted portion of IV from SA (if applicable)
        memcpy(tc_sdls_processed_frame->tc_sec_header.iv, sa_ptr->iv, sa_ptr->iv_len - sa_ptr->shivf_len);
    }
    return status;
}

/**
 * @brief Function: Crypto_TCP_Prep_AAD
 * Prepares Additional Authenticated Data for TC frame
 * @param tc_sdls_processed_frame: TC_t*
 * @param fecf_len: uint8_t
 * @param sa_service_type: uint8_t
 * @param ecs_is_aead_algorithm: uint8_t
 * @param aad_len: uint16_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @param segment_hdr_len: uint8_t
 * @param ingest: uint8_t*
 * @param aad: uint8_t**
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.3.3 (TC Authentication Processing)
 **/
int32_t Crypto_TCP_Prep_AAD(TC_t *tc_sdls_processed_frame, uint8_t fecf_len, uint8_t sa_service_type,
                            uint8_t ecs_is_aead_algorithm, uint16_t *aad_len, SecurityAssociation_t *sa_ptr,
                            uint8_t segment_hdr_len, uint8_t *ingest, uint8_t **aad)
{
    int32_t  status       = CRYPTO_LIB_SUCCESS;
    uint16_t aad_len_temp = *aad_len;

    if ((sa_service_type == SA_AUTHENTICATION) || (sa_service_type == SA_AUTHENTICATED_ENCRYPTION))
    {
        uint16_t tc_mac_start_index = tc_sdls_processed_frame->tc_header.fl + 1 - fecf_len - sa_ptr->stmacf_len;
        if (current_managed_parameters_struct.max_frame_size < tc_mac_start_index)
        {
            status = CRYPTO_LIB_ERR_TC_FRAME_LENGTH_UNDERFLOW;
            mc_if->mc_log(status);
            return status;
        }
        // Parse the received MAC
        memcpy((tc_sdls_processed_frame->tc_sec_trailer.mac), &(ingest[tc_mac_start_index]), sa_ptr->stmacf_len);
#ifdef DEBUG
        printf("MAC Parsed from Frame:\n");
        Crypto_hexprint(tc_sdls_processed_frame->tc_sec_trailer.mac, sa_ptr->stmacf_len);
#endif
        aad_len_temp = tc_mac_start_index;

        if ((sa_service_type == SA_AUTHENTICATED_ENCRYPTION) && (ecs_is_aead_algorithm == CRYPTO_TRUE))
        {
            aad_len_temp = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len +
                           sa_ptr->shplf_len;
        }
        if (sa_ptr->abm_len < aad_len_temp)
        {
            status = CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
            mc_if->mc_log(status);
            return status;
        }
        *aad = Crypto_Prepare_TC_AAD(ingest, aad_len_temp, sa_ptr->abm);
        if (*aad == NULL)
        {
            status = CRYPTO_LIB_ERROR;
            mc_if->mc_log(status);
            return status;
        }
        *aad_len = aad_len_temp;
        aad      = aad;
    }
    return status;
}

/**
 * @brief Function: Crypto_TCP_Sanity_Validations
 * Performs sanity validations on TC frame
 * @param tc_sdls_processed_frame: TC_t*
 * @param sa_ptr: SecurityAssociation_t**
 * @return uint32: Status code
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1 (Frame Format)
 **/
uint32_t Crypto_TCP_Sanity_Validations(TC_t *tc_sdls_processed_frame, SecurityAssociation_t **sa_ptr)
{
    uint32_t status = CRYPTO_LIB_SUCCESS;

    status = sa_if->sa_get_from_spi(tc_sdls_processed_frame->tc_sec_header.spi, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Try to assure SA is sane
    status = Crypto_TC_Validate_SA(*sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

end_of_function:
    return status;
}

/**
 * @brief Function: Crypto_TCP_Check_IV_ARSN
 * Checks IV/ARSN values for anti-replay
 * @param sa_ptr: SecurityAssociation_t*
 * @param tc_sdls_processed_frame: TC_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
int32_t Crypto_TCP_Check_IV_ARSN(SecurityAssociation_t *sa_ptr, TC_t *tc_sdls_processed_frame)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (crypto_config.ignore_anti_replay == TC_IGNORE_ANTI_REPLAY_FALSE)
    {
        status = Crypto_Check_Anti_Replay(sa_ptr, tc_sdls_processed_frame->tc_sec_header.sn,
                                          tc_sdls_processed_frame->tc_sec_header.iv);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            goto end_of_function;
        }

        // Only save the SA (IV/ARSN) if checking the anti-replay counter; Otherwise we don't update.
        status = sa_if->sa_save_sa(sa_ptr);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            goto end_of_function;
        }
    }
    else
    {
        if (crypto_config.sa_type == SA_TYPE_MARIADB)
        {
            if (sa_ptr->ek_ref[0] != '\0')
                clean_ekref(sa_ptr);
            if (sa_ptr->ak_ref[0] != '\0')
                clean_akref(sa_ptr);
            free(sa_ptr);
        }
    }

end_of_function:
    return status;
}

/**
 * @brief Function: Crypto_TCP_Get_Keys
 * Retrieves keys for TC processing
 * @param ekp: crypto_key_t**
 * @param akp: crypto_key_t**
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.2 (Key Management)
 **/
int32_t Crypto_TCP_Get_Keys(crypto_key_t **ekp, crypto_key_t **akp, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (crypto_config.key_type != KEY_TYPE_KMC)
    {
        *ekp = key_if->get_key(sa_ptr->ekid);
        *akp = key_if->get_key(sa_ptr->akid);
    }

    if (sa_ptr->est == 1)
    {
        if (*ekp == NULL)
        {
            status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
            goto end_of_function;
        }
        if ((*ekp)->key_state != KEY_ACTIVE)
        {
            status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
            goto end_of_function;
        }
    }
    if (sa_ptr->ast == 1)
    {
        if (*akp == NULL)
        {
            status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
            goto end_of_function;
        }
        if ((*akp)->key_state != KEY_ACTIVE)
        {
            status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
            goto end_of_function;
        }
    }

end_of_function:
    return status;
}

/**
 * @brief Function: Crypto_TCP_Nontransmitted_SN_Increment
 * Increments non-transmitted part of sequence number
 * @param sa_ptr: SecurityAssociation_t*
 * @param tc_sdls_processed_frame: TC_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
int32_t Crypto_TCP_Nontransmitted_SN_Increment(SecurityAssociation_t *sa_ptr, TC_t *tc_sdls_processed_frame)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (sa_ptr->shsnf_len < sa_ptr->arsn_len && crypto_config.ignore_anti_replay == TC_IGNORE_ANTI_REPLAY_FALSE)
    {
        status = Crypto_TCP_Handle_Incrementing_Nontransmitted_Counter(tc_sdls_processed_frame->tc_sec_header.sn,
                                                                       sa_ptr->arsn, sa_ptr->arsn_len,
                                                                       sa_ptr->shsnf_len, sa_ptr->arsnw);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            mc_if->mc_log(status);
        }
    }
    else // Not checking ARSN in ARSNW
    {
        // Parse non-transmitted portion of ARSN from SA
        memcpy(tc_sdls_processed_frame->tc_sec_header.sn, sa_ptr->arsn, sa_ptr->arsn_len - sa_ptr->shsnf_len);
    }
    return status;
}

/**
 * @brief Function: Crypto_TCP_Check_ACS_Keylen
 * Validates authentication key length
 * @param akp: crypto_key_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.2 (Cryptographic Algorithms)
 **/
int32_t Crypto_TCP_Check_ACS_Keylen(crypto_key_t *akp, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if ((int32_t)akp->key_len != Crypto_Get_ACS_Algo_Keylen(sa_ptr->acs))
    {
        status = CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
        mc_if->mc_log(status);
    }
    return status;
}

/**
 * @brief Function: Crypto_TCP_Check_ECS_Keylen
 * Validates encryption key length
 * @param ekp: crypto_key_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.2 (Cryptographic Algorithms)
 **/
int32_t Crypto_TCP_Check_ECS_Keylen(crypto_key_t *ekp, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if ((int32_t)ekp->key_len != Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs))
    {
        status = CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
        mc_if->mc_log(status);
    }
    return status;
}

/**
 * @brief Function: Crypto_TCP_Handle_Incrementing_Nontransmitted_Counter
 * Handles incrementing non-transmitted counters
 * @param dest: uint8_t*
 * @param src: uint8_t*
 * @param src_full_len: int
 * @param transmitted_len: int
 * @param window: int
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
int32_t Crypto_TCP_Handle_Incrementing_Nontransmitted_Counter(uint8_t *dest, uint8_t *src, int src_full_len,
                                                              int transmitted_len, int window)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    /* Note: This assumes a max IV / ARSN size of 32.  If a larger value is needed, adjust in crypto_config.h*/
    if (src_full_len >
        MAX_IV_LEN) // TODO:  Does a define exist already?  Is this the best method to put a bound on IV/ARSN Size?
    {
        status = CRYPTO_LIB_ERR_IV_EXCEEDS_INCREMENT_SIZE;
        goto end_of_function;
    }

    uint8_t temp_counter[MAX_IV_LEN];
    // Copy IV to temp
    memcpy(temp_counter, src, src_full_len);

    // Increment temp_counter Until Transmitted Portion Matches Frame.
    uint8_t counter_matches = CRYPTO_TRUE;
    for (int i = 0; i < window; i++)
    {
        Crypto_increment(temp_counter, src_full_len);
        for (int x = (src_full_len - transmitted_len); x < src_full_len; x++)
        {
            // This increment doesn't match the frame!
            if (temp_counter[x] != dest[x])
            {
                counter_matches = CRYPTO_FALSE;
                break;
            }
        }
        if (counter_matches == CRYPTO_TRUE)
        {
            break;
        }
        else if (i < window - 1) // Only reset flag if there are more  windows to check.
        {
            counter_matches = CRYPTO_TRUE; // reset the flag, and continue the for loop for the next
            continue;
        }
    }

    if (counter_matches == CRYPTO_TRUE)
    {
        // Retrieve non-transmitted portion of incremented counter that matches (and may have rolled
        // over/incremented)
        memcpy(dest, temp_counter, src_full_len - transmitted_len);
#ifdef DEBUG
        printf("Incremented IV is:\n");
        Crypto_hexprint(temp_counter, src_full_len);
#endif
    }
    else
    {
        status = CRYPTO_LIB_ERR_FRAME_COUNTER_DOESNT_MATCH_SA;
        goto end_of_function;
    }

end_of_function:
    return status;
}