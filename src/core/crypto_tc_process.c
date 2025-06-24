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
    cam_cookies                            = cam_cookies;
    int32_t                status          = CRYPTO_LIB_SUCCESS;
    SecurityAssociation_t *sa_ptr          = NULL;
    uint8_t                sa_service_type = -1;
    uint8_t               *aad             = NULL;
    uint8_t                ecs_is_aead_algorithm = -1;
    crypto_key_t          *ekp                   = NULL;
    crypto_key_t          *akp                   = NULL;
    int                    byte_idx              = 0;
    uint8_t fecf_len        = FECF_SIZE;
    uint8_t ocf_len         = TELEMETRY_FRAME_OCF_CLCW_SIZE;
    uint8_t segment_hdr_len = TC_SEGMENT_HDR_SIZE;
    uint16_t tc_enc_payload_start_index = 0;
    uint16_t               aad_len;
    uint32_t               encryption_cipher;

    status = Crypto_TC_Process_Sanity_Check(len_ingest);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
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
    Crypto_TC_Set_Segment_Header(tc_sdls_processed_frame, ingest, &byte_idx);

    // Security Header
    Crypto_TCP_Set_SPI(ingest, &byte_idx, &tc_sdls_processed_frame->tc_sec_header);

#ifdef TC_DEBUG
    printf("vcid = %d \n", tc_sdls_processed_frame->tc_header.vcid);
    printf("spi  = %d \n", tc_sdls_processed_frame->tc_sec_header.spi);
#endif

    status = Crypto_TC_Sanity_Validations(tc_sdls_processed_frame, &sa_ptr);
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
    Crypto_TC_Get_Cipher_Mode_TCP(sa_service_type, &encryption_cipher, &ecs_is_aead_algorithm, sa_ptr);

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
    status = Crypto_TC_Nontransmitted_IV_Increment(sa_ptr, tc_sdls_processed_frame);
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
    status = Crypto_TC_Nontransmitted_SN_Increment(sa_ptr, tc_sdls_processed_frame);
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
    status = Crypto_TC_Prep_AAD(tc_sdls_processed_frame, fecf_len, sa_service_type, ecs_is_aead_algorithm, &aad_len,
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
    status = Crypto_TC_Get_Keys(&ekp, &akp, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }
    status = Crypto_TC_Do_Decrypt(sa_service_type, ecs_is_aead_algorithm, ekp, sa_ptr, aad, tc_sdls_processed_frame,
                                  ingest, tc_enc_payload_start_index, aad_len, cam_cookies, akp, segment_hdr_len);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }
    // Now that MAC has been verified, check IV & ARSN if applicable
    status = Crypto_TC_Check_IV_ARSN(sa_ptr, tc_sdls_processed_frame);
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
 * @brief Function: Crypto_TC_Process_Sanity_Check
 * Performs sanity checks on TC frame
 * @param len_ingest: int*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1 (Frame Format)
 **/
int32_t Crypto_TC_Process_Sanity_Check(int *len_ingest)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_TC_ProcessSecurity START -----\n" RESET);
#endif

    if ((mc_if == NULL) || (crypto_config.init_status == UNITIALIZED))
    {
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        mc_if->mc_log(status);
    }
    if ((*len_ingest < 5) &&
        (status == CRYPTO_LIB_SUCCESS)) // Frame length doesn't even have enough bytes for header -- error out.
    {
        status = CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TC_STANDARD;
        mc_if->mc_log(status);
    }
    return status;
}

/**
 * @brief Function: Crypto_TC_Set_Segment_Header
 * Sets segment header for TC frame
 * @param tc_sdls_processed_frame: TC_t*
 * @param ingest: uint8_t*
 * @param byte_idx: int*
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1.3 (Segment Header)
 **/
void Crypto_TC_Set_Segment_Header(TC_t *tc_sdls_processed_frame, uint8_t *ingest, int *byte_idx)
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
 * @brief Function: Crypto_TC_Get_Cipher_Mode_TCP
 * Gets cipher mode for TC processing
 * @param sa_service_type: uint8_t
 * @param encryption_cipher: uint32_t*
 * @param ecs_is_aead_algorithm: uint8_t*
 * @param sa_ptr: SecurityAssociation_t*
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.2 (Cryptographic Algorithms)
 **/
void Crypto_TC_Get_Cipher_Mode_TCP(uint8_t sa_service_type, uint32_t *encryption_cipher, uint8_t *ecs_is_aead_algorithm,
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

void Crypto_TCP_Copy_IV(TC_FrameSecurityHeader_t *tc_sec_header, uint8_t* ingest, uint8_t segment_hdr_len, SecurityAssociation_t *sa_ptr)
{
    memcpy(tc_sec_header->iv + (sa_ptr->iv_len - sa_ptr->shivf_len), &(ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN]), sa_ptr->shivf_len);
}

void Crypto_TCP_Copy_ARSN(TC_FrameSecurityHeader_t *tc_sec_header, uint8_t* ingest, uint8_t segment_hdr_len, SecurityAssociation_t *sa_ptr)
{
    memcpy(tc_sec_header->sn + (sa_ptr->arsn_len - sa_ptr->shsnf_len), &(ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len]), sa_ptr->shsnf_len);
}

void Crypto_TCP_Copy_Pad(TC_FrameSecurityHeader_t *tc_sec_header, uint8_t* ingest, uint8_t segment_hdr_len, SecurityAssociation_t *sa_ptr)
{
    memcpy((tc_sec_header->pad), &(ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len]), sa_ptr->shplf_len);
}

void Crypto_TCP_Calc_Payload_Start_Idx(uint16_t *tc_enc_payload_start_index, uint8_t segment_hdr_len, SecurityAssociation_t *sa_ptr)
{
    *tc_enc_payload_start_index = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len + sa_ptr->shplf_len;
}

void Crypto_TCP_Copy_PDU_Len(TC_t *tc_sdls_processed_frame, uint16_t tc_enc_payload_start_index, SecurityAssociation_t *sa_ptr, uint8_t fecf_len)
{
    tc_sdls_processed_frame->tc_pdu_len = tc_sdls_processed_frame->tc_header.fl + 1 - tc_enc_payload_start_index -
                                          sa_ptr->stmacf_len - fecf_len; // TODO: subtract FSR/OCF?
}

int32_t Crypto_TCP_Validate_PDU_Len(TC_t *tc_sdls_processed_frame)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (tc_sdls_processed_frame->tc_pdu_len > tc_sdls_processed_frame->tc_header.fl) // invalid header parsed, sizes overflowed & make no sense!
    {
        status = CRYPTO_LIB_ERR_INVALID_HEADER;
    }
    return status;
}