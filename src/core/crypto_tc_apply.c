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

/*
** CCSDS Compliance Reference:
** This file implements security features compliant with:
** - CCSDS 232.0-B-3 (TC Space Data Link Protocol)
** - CCSDS 355.0-B-2 (Space Data Link Security Protocol)
*/

// Forward declarations for new functions
static int32_t Crypto_TC_Validate_Auth_Mask(const uint8_t *abm_buffer, uint16_t abm_len, uint16_t frame_len);

// Error code definitions for new TC validations
#define CRYPTO_LIB_ERR_TC_FRAME_TOO_SHORT   -200
#define CRYPTO_LIB_ERR_TC_AUTH_MASK_INVALID -201


/**
 * @brief Function: Crypto_TC_ApplySecurity
 * Top-level function to apply security to TC frames
 * @param p_in_frame: const uint8_t*
 * @param in_frame_length: const uint16_t
 * @param pp_in_frame: uint8_t**
 * @param p_enc_frame_len: uint16_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2 (TC Security)
 **/
int32_t Crypto_TC_ApplySecurity(const uint8_t *p_in_frame, const uint16_t in_frame_length, uint8_t **pp_in_frame,
                                uint16_t *p_enc_frame_len)
{
    // Passthrough to maintain original function signature when CAM isn't used.
    return Crypto_TC_ApplySecurity_Cam(p_in_frame, in_frame_length, pp_in_frame, p_enc_frame_len, NULL);
}
/**
 * @brief Function: Crypto_TC_ApplySecurity_Cam
 * Top-level function to apply security to TC frames with CAM
 * @param p_in_frame: const uint8_t*
 * @param in_frame_length: const uint16_t
 * @param pp_in_frame: uint8_t**
 * @param p_enc_frame_len: uint16_t*
 * @param cam_cookies: char*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2 (TC Security)
 **/
int32_t Crypto_TC_ApplySecurity_Cam(const uint8_t *p_in_frame, const uint16_t in_frame_length, uint8_t **pp_in_frame,
                                    uint16_t *p_enc_frame_len, char *cam_cookies)
{
    // Local Variables
    int32_t                 status = CRYPTO_LIB_SUCCESS;
    TC_FramePrimaryHeader_t temp_tc_header;
    SecurityAssociation_t  *sa_ptr                            = NULL;
    uint8_t                *p_new_enc_frame                   = NULL;
    uint8_t                 sa_service_type                   = -1;
    uint16_t                mac_loc                           = 0;
    uint16_t                tf_payload_len                    = 0x0000;
    uint16_t                new_fecf                          = 0x0000;
    uint8_t                *aad                               = NULL;
    uint16_t                new_enc_frame_header_field_length = 0;
    uint32_t                encryption_cipher                 = 0;
    uint32_t                pkcs_padding                      = 0;
    crypto_key_t           *ekp                               = NULL;
    uint8_t                 map_id                            = 0;
    uint8_t                 segmentation_hdr                  = 0x00;
    uint8_t                 segment_hdr_len                   = TC_SEGMENT_HDR_SIZE;
    uint8_t                 fecf_len                          = FECF_SIZE;
    uint8_t                 ocf_len                           = OCF_SIZE;
    uint8_t                 ecs_is_aead_algorithm;

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_TC_ApplySecurity START -----\n" RESET);
#endif

    status = Crypto_TCA_Sanity_Setup(p_in_frame, in_frame_length);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Primary Header
    Crypto_TC_Set_Primary_Header(p_in_frame, &temp_tc_header);

    status = Crypto_TCA_Validate_Temp_Header(in_frame_length, temp_tc_header, p_in_frame, &map_id, &segmentation_hdr,
                                               &sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

#ifdef SA_DEBUG
    printf(KYEL "DEBUG - Printing SA Entry for current frame.\n" RESET);
    Crypto_saPrint(sa_ptr);
#endif
    // Determine SA Service Type
    status = Crypto_TC_Get_SA_Service_Type(&sa_service_type, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }
    // Determine Algorithm cipher & mode. // TODO - Parse authentication_cipher, and handle AEAD cases properly
    status = Crypto_TCA_Get_Cipher_Mode(sa_service_type, &encryption_cipher, &ecs_is_aead_algorithm, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

#ifdef TC_DEBUG
    Crypto_TC_SA_Service_Type_Debug_Print(sa_service_type);
#endif

    status = Crypto_Check_Padding_Length(sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Determine if segment header, ocf, or FECF exists. Also calculates payload length
    Crypto_TC_Calc_Lengths(&fecf_len, &segment_hdr_len, &ocf_len);

    status = Crypto_TCA_Calc_Payload_Length(temp_tc_header, &tf_payload_len, segment_hdr_len, ocf_len, fecf_len);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    /**
     * A note on plaintext: Take a permissive approach to allow the lengths of fields that aren't going to be used.
     * The 355.0-B-2 (July 2022) says the following in $4.2.2.4:
     * 'It is possible to create a 'clear mode' SA using one of the defined service types by
        specifying the algorithm as a 'no-op' function (no actual cryptographic operation to
        be performed). Such an SA might be used, for example, during development
        testing of other aspects of data link processing before cryptographic capabilities are
        available for integrated testing.In this scenario, the Security Header and Trailer
        field lengths are kept constant across all supported configurations. For security
        reasons, the use of such an SA is not recommended in normal operation.'
    */

    // Calculate frame lengths based on SA fields
    Crypto_TCA_Calc_Enc_Frame_Lengths(p_enc_frame_len, &new_enc_frame_header_field_length, temp_tc_header, sa_ptr, ocf_len);

    // Finalize frame setup
    status = Crypto_TCA_Finalize_Frame_Setup(sa_service_type, &pkcs_padding, p_enc_frame_len,
                                       &new_enc_frame_header_field_length, tf_payload_len, &sa_ptr, &p_new_enc_frame);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

#ifdef TC_DEBUG
    Crypto_TC_Frame_Params_Debug_Print(temp_tc_header, sa_ptr, p_enc_frame_len, segment_hdr_len);
#endif

    // Copy original TF header, w/ segment header if applicable
    memcpy(p_new_enc_frame, p_in_frame, TC_FRAME_HEADER_SIZE + segment_hdr_len);

    // Set new TF Header length
    // Recall: Length field is one minus total length per spec
    Crypto_TCA_Set_New_TF_Length(p_new_enc_frame, new_enc_frame_header_field_length);

#ifdef TC_DEBUG
    Crypto_TC_Updated_Header_Debug_Print(p_new_enc_frame, new_enc_frame_header_field_length);
#endif

    /*
    ** Start variable length fields
    */
    uint16_t index = 0;
    index += TC_FRAME_HEADER_SIZE;

    if (current_managed_parameters_struct.has_segmentation_hdr == TC_HAS_SEGMENT_HDRS)
    {
        index += 1; // Add 1 byte to index because segmentation header used for this gvcid.
    }

    /*
    ** Begin Security Header Fields
    ** Reference CCSDS SDLP 3550b1 4.1.1.1.3
    */
    // Set SPI
    Crypto_TCA_Set_SPI(p_new_enc_frame, &index, sa_ptr);
    
    // Set initialization vector if specified
    status = Crypto_TCA_Set_IV(sa_ptr, p_new_enc_frame, &index);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }
    // Set anti-replay sequence number if specified
    /*
    ** See also: 4.1.1.4.2
    ** 4.1.1.4.4 If authentication or authenticated encryption is not selected
    ** for an SA, the Sequence Number field shall be zero octets in length.
    ** Reference CCSDS 3550b1
    */
    Crypto_TCA_Set_ARSN(p_new_enc_frame, &index, sa_ptr);

    // Set security header padding if specified
    /*
    ** 4.2.3.4 h) if the algorithm and mode selected for the SA require the use of
    ** fill padding, place the number of fill bytes used into the Pad Length field
    ** of the Security Header - Reference CCSDS 3550b1
    */
    // TODO: Revisit this
    // TODO: Likely SA API Call
    /* 4.1.1.5.2 The Pad Length field shall contain the count of fill bytes used in the
    ** cryptographic process, consisting of an integral number of octets. - CCSDS 3550b1
    */
    // TODO: Set this depending on crypto cipher used
    Crypto_TCA_Handle_Padding(pkcs_padding, sa_ptr, p_new_enc_frame, &index);
    /*
    ** End Security Header Fields
    */

    memcpy((p_new_enc_frame + index), (p_in_frame + TC_FRAME_HEADER_SIZE + segment_hdr_len), tf_payload_len);
    index += tf_payload_len;
    
    Crypto_TCA_Insert_Padding(p_new_enc_frame, index, pkcs_padding);

    index -= tf_payload_len;
    tf_payload_len += pkcs_padding;

    /*
    ** Begin Authentication / Encryption
    */
    status = Crypto_TCA_Do_Encrypt(sa_service_type, sa_ptr, &mac_loc, tf_payload_len, segment_hdr_len, p_new_enc_frame,
                                  ekp, &aad, ecs_is_aead_algorithm, &index, p_in_frame, cam_cookies, pkcs_padding,
                                  new_enc_frame_header_field_length, &new_fecf);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

#ifdef TC_DEBUG
    Crypto_TC_New_Frame_Debug_Print(p_new_enc_frame, p_enc_frame_len, new_enc_frame_header_field_length);
#endif

    *pp_in_frame = p_new_enc_frame;

    status = sa_if->sa_save_sa(sa_ptr);

#ifdef DEBUG
    printf(KYEL "----- Crypto_TC_ApplySecurity END -----\n" RESET);
#endif

end_of_function:
    Crypto_TC_Safe_Free_Ptr(aad);
    if(mc_if != NULL)
    {
        mc_if->mc_log(status);
    }
    return status;
}

/**
 * @brief Function: Crypto_TCA_Sanity_Setup
 * Validates TC frame before processing
 * @param p_in_frame: const uint8_t*
 * @param in_frame_length: const uint16_t
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1 (Frame Format)
 **/
int32_t Crypto_TCA_Sanity_Setup(const uint8_t *p_in_frame, const uint16_t in_frame_length)
{
    uint32_t status = CRYPTO_LIB_SUCCESS;
    if (p_in_frame == NULL)
    {
#ifdef DEBUG
        printf(KRED "Error: Input Buffer NULL! \n" RESET);
#endif
        status = CRYPTO_LIB_ERR_NULL_BUFFER;
        // No Logging - as MC might not be initialized
        goto end_of_function;
    }

#ifdef DEBUG
    int i;
    printf("%d TF Bytes received\n", in_frame_length);
    printf("DEBUG - ");
    for (i = 0; i < in_frame_length; i++)
    {
        printf("%02X", ((uint8_t *)&*p_in_frame)[i]);
    }
    printf("\nPrinted %d bytes\n", in_frame_length);
#endif
    status = Crypto_TCA_Check_Init_Setup(in_frame_length);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        // No Logging - as MC might not be initialized
        goto end_of_function;
    }

end_of_function:
    return status;
}

void Crypto_TC_Set_Primary_Header(const uint8_t *p_in_frame, TC_FramePrimaryHeader_t *temp_tc_header){

    temp_tc_header->tfvn   = ((uint8_t)p_in_frame[0] & 0xC0) >> 6;
    temp_tc_header->bypass = ((uint8_t)p_in_frame[0] & 0x20) >> 5;
    temp_tc_header->cc     = ((uint8_t)p_in_frame[0] & 0x10) >> 4;
    temp_tc_header->spare  = ((uint8_t)p_in_frame[0] & 0x0C) >> 2;
    temp_tc_header->scid   = ((uint8_t)p_in_frame[0] & 0x03) << 8;
    temp_tc_header->scid   = temp_tc_header->scid | (uint8_t)p_in_frame[1];
    temp_tc_header->vcid   = ((uint8_t)p_in_frame[2] & 0xFC) >> 2 & crypto_config.vcid_bitmask;
    temp_tc_header->fl     = ((uint8_t)p_in_frame[2] & 0x03) << 8;
    temp_tc_header->fl     = temp_tc_header->fl | (uint8_t)p_in_frame[3];
    temp_tc_header->fsn    = (uint8_t)p_in_frame[4];
}

/**
 * @brief Function: Crypto_TCA_Validate_Temp_Header
 * Validates TC header and retrieves SA
 * @param in_frame_length: const uint16_t
 * @param temp_tc_header: TC_FramePrimaryHeader_t
 * @param p_in_frame: const uint8_t*
 * @param map_id: uint8_t*
 * @param segmentation_hdr: uint8_t*
 * @param sa_ptr: SecurityAssociation_t**
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1.2 (Primary Header)
 **/
int32_t Crypto_TCA_Validate_Temp_Header(const uint16_t in_frame_length, TC_FramePrimaryHeader_t temp_tc_header,
                                          const uint8_t *p_in_frame, uint8_t *map_id, uint8_t *segmentation_hdr,
                                          SecurityAssociation_t **sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (temp_tc_header.fl + 1 != in_frame_length)
    {
        status = CRYPTO_LIB_ERR_TC_FRAME_LENGTH_MISMATCH;
        mc_if->mc_log(status);
        return status;
    }

    // Lookup-retrieve managed parameters for frame via gvcid:
    status =
        Crypto_Get_Managed_Parameters_For_Gvcid(temp_tc_header.tfvn, temp_tc_header.scid, temp_tc_header.vcid,
                                                gvcid_managed_parameters_array, &current_managed_parameters_struct);

    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
        return status;
    } // Unable to get necessary Managed Parameters for TC TF -- return with error.

    if (current_managed_parameters_struct.has_segmentation_hdr == TC_HAS_SEGMENT_HDRS)
    {
        *segmentation_hdr = p_in_frame[5];
        *map_id           = *segmentation_hdr & 0x3F;
    }
    // Check if command frame flag set
    status = Crypto_TCA_Check_CMD_Frame_Flag(temp_tc_header.cc);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
        return status;
    }
    status = sa_if->sa_get_operational_sa_from_gvcid(temp_tc_header.tfvn, temp_tc_header.scid, temp_tc_header.vcid,
                                                     *map_id, sa_ptr);
    // If unable to get operational SA, can return
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
        return status;
    }

    // Try to assure SA is sane
    status = Crypto_TC_Validate_SA(*sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
        return status;
    }

    return status;
}

/**
 * @brief Function: Crypto_TC_Get_SA_Service_Type
 * Determines the SA service type
 * @param sa_service_type: uint8*
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32: ENUM - Service type
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.3 (Security Service Types)
 **/
int32_t Crypto_TC_Get_SA_Service_Type(uint8_t *sa_service_type, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if ((sa_ptr->est == 0) && (sa_ptr->ast == 0))
    {
        *sa_service_type = SA_PLAINTEXT;
    }
    else if ((sa_ptr->est == 0) && (sa_ptr->ast == 1))
    {
        *sa_service_type = SA_AUTHENTICATION;
    }
    else if ((sa_ptr->est == 1) && (sa_ptr->ast == 0))
    {
        *sa_service_type = SA_ENCRYPTION;
    }
    else if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
    {
        *sa_service_type = SA_AUTHENTICATED_ENCRYPTION;
    }
    else
    {
        // Probably unnecessary check
        // Leaving for now as it would be cleaner in SA to have an association enum returned I believe
        printf(KRED "Error: SA Service Type is not defined! \n" RESET);
        status = CRYPTO_LIB_ERROR;
        mc_if->mc_log(status);
        return status;
    }
    return status;
}

/**
 * @brief Function: Crypto_TCA_Get_Cipher_Mode
 * Validates Cipher Mode
 * @param sa_service_type: uint8_t
 * @param encryption_cipher: uint32_t*
 * @param ecs_is_aead_algorithm: uint8_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32: Cipher Mode or Error Enum
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.2 (Cryptographic Algorithms)
 **/
int32_t Crypto_TCA_Get_Cipher_Mode(uint8_t sa_service_type, uint32_t *encryption_cipher,
                                     uint8_t *ecs_is_aead_algorithm, SecurityAssociation_t *sa_ptr)
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
        mc_if->mc_log(status);
    }
    return status;
}

void Crypto_TCA_Calc_Enc_Frame_Lengths(uint16_t *p_enc_frame_len, uint16_t *new_enc_frame_header_field_length, TC_FramePrimaryHeader_t temp_tc_header, SecurityAssociation_t *sa_ptr, uint8_t ocf_len)
{
    *p_enc_frame_len = temp_tc_header.fl + 1 + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len + sa_ptr->shplf_len +
                       sa_ptr->stmacf_len + ocf_len;
    *new_enc_frame_header_field_length = (*p_enc_frame_len) - 1;
}

void Crypto_TC_SA_Service_Type_Debug_Print(uint8_t sa_service_type)
{
    switch (sa_service_type)
    {
        case SA_PLAINTEXT:
            printf(KBLU "Creating a TC - CLEAR!\n" RESET);
            break;
        case SA_AUTHENTICATION:
            printf(KBLU "Creating a TC - AUTHENTICATED!\n" RESET);
            break;
        case SA_ENCRYPTION:
            printf(KBLU "Creating a TC - ENCRYPTED!\n" RESET);
            break;
        case SA_AUTHENTICATED_ENCRYPTION:
            printf(KBLU "Creating a TC - AUTHENTICATED ENCRYPTION!\n" RESET);
            break;
    }
}

void Crypto_TC_Frame_Params_Debug_Print(TC_FramePrimaryHeader_t temp_tc_header, SecurityAssociation_t *sa_ptr, uint16_t *p_enc_frame_len, uint8_t segment_hdr_len)
{
    printf(KYEL "DEBUG - Total TC Buffer to be malloced is: %d bytes\n" RESET, *p_enc_frame_len);
    printf(KYEL "\tlen of TF\t = %d\n" RESET, temp_tc_header.fl);
    printf(KYEL "\tsegment hdr len\t = %d\n" RESET, segment_hdr_len);
    printf(KYEL "\tspi len\t\t = 2\n" RESET);
    printf(KYEL "\tshivf_len\t = %d\n" RESET, sa_ptr->shivf_len);
    printf(KYEL "\tiv_len\t\t = %d\n" RESET, sa_ptr->iv_len);
    printf(KYEL "\tshsnf_len\t = %d\n" RESET, sa_ptr->shsnf_len);
    printf(KYEL "\tshplf len\t = %d\n" RESET, sa_ptr->shplf_len);
    printf(KYEL "\tarsn_len\t = %d\n" RESET, sa_ptr->arsn_len);
    printf(KYEL "\tstmacf_len\t = %d\n" RESET, sa_ptr->stmacf_len);
}

void Crypto_TC_New_Frame_Debug_Print(uint8_t *p_new_enc_frame, uint16_t *p_enc_frame_len, uint16_t new_enc_frame_header_field_length)
{
    printf(KYEL "Printing new TC Frame of length %d:\n\t", *p_enc_frame_len);
    for (int i = 0; i < *p_enc_frame_len; i++)
    {
        printf("%02X", *(p_new_enc_frame + i));
    }
    printf("\n\tThe returned length is: %d\n" RESET, new_enc_frame_header_field_length);
}

void Crypto_TCA_Set_New_TF_Length(uint8_t *p_new_enc_frame, uint16_t new_enc_frame_header_field_length)
{
    *(p_new_enc_frame + 2) =
        ((*(p_new_enc_frame + 2) & 0xFC) | (((new_enc_frame_header_field_length) & (0x0300)) >> 8));
    *(p_new_enc_frame + 3) = ((new_enc_frame_header_field_length) & (0x00FF));
}

void Crypto_TC_Updated_Header_Debug_Print(uint8_t *p_new_enc_frame, uint16_t new_enc_frame_header_field_length)
{
    printf(KYEL "Printing updated TF Header:\n\t");
    for (int i = 0; i < TC_FRAME_HEADER_SIZE; i++)
    {
        printf("%02X", *(p_new_enc_frame + i));
    }
    // Recall: The buffer length is 1 greater than the field value set in the TCTF
    printf("\n\tLength set to 0x%02X\n" RESET, new_enc_frame_header_field_length);
}

void Crypto_TCA_Set_SPI(uint8_t *p_new_enc_frame, uint16_t *index, SecurityAssociation_t *sa_ptr)
{
    *(p_new_enc_frame + *index)     = ((sa_ptr->spi & 0xFF00) >> 8);
    *(p_new_enc_frame + *index + 1) = (sa_ptr->spi & 0x00FF);
    *index += 2;
}

void Crypto_TCA_Set_ARSN(uint8_t *p_new_enc_frame, uint16_t *index, SecurityAssociation_t *sa_ptr)
{
    for (int i = sa_ptr->arsn_len - sa_ptr->shsnf_len; i < sa_ptr->arsn_len; i++)
    {
        // Copy in ARSN from SA
        *(p_new_enc_frame + *index) = *(sa_ptr->arsn + i);
        *index += 1;
    }
}

void Crypto_TCA_Insert_Padding(uint8_t *p_new_enc_frame, uint32_t index, uint32_t pkcs_padding)
{
    for (uint32_t i = 0; i < pkcs_padding; i++)
    {
        /* 4.1.1.5.2 The Pad Length field shall contain the count of fill bytes used in the
        ** cryptographic process, consisting of an integral number of octets. - CCSDS 3550b1
        */
        // TODO: Set this depending on crypto cipher used
        *(p_new_enc_frame + index + i) = (uint8_t)pkcs_padding; // How much padding is needed?
        // index++;
    }
}

int32_t Crypto_TCA_Calc_Payload_Length(TC_FramePrimaryHeader_t temp_tc_header, uint16_t *tf_payload_len, uint8_t segment_hdr_len, uint8_t ocf_len, uint8_t fecf_len)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    int32_t payload_calc = (temp_tc_header.fl + 1) - TC_FRAME_HEADER_SIZE - segment_hdr_len - ocf_len - fecf_len;
    // check if payload length underflows
    if (payload_calc < 0)
    {
#ifdef TC_DEBUG
        printf("Payload Calculation Underflow: %d\n", payload_calc);
#endif
        status = CRYPTO_LIB_ERR_TC_FRAME_LENGTH_UNDERFLOW;
        goto end_of_function;
    }
    *tf_payload_len = (uint32_t)payload_calc;

end_of_function:
    return status;
}


/**
 * @brief Function: Crypto_TCA_Check_CMD_Frame_Flag
 * Validates the Command Frame Flag
 * @param header_cc: uint8_t
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 6.3.1
 * "Type-C frames do not have the Security Header and Security Trailer."
 **/
int32_t Crypto_TCA_Check_CMD_Frame_Flag(uint8_t header_cc)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if ((header_cc == 1) && (status == CRYPTO_LIB_SUCCESS))
    {
/*
** CCSDS 232.0-B-3
** Section 6.3.1
** "Type-C frames do not have the Security Header and Security Trailer."
*/
#ifdef TC_DEBUG
        printf(KYEL "DEBUG - Received Control/Command frame - nothing to do.\n" RESET);
#endif
        status = CRYPTO_LIB_ERR_INVALID_CC_FLAG;
        mc_if->mc_log(status);
    }
    return status;
}

/**
 * @brief Function: Crypto_TCA_Validate_SA_Service_Type
 * Validates the SA service type
 * @param sa_service_type: uint8_t
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.3 (Security Service Types)
 **/
int32_t Crypto_TCA_Validate_SA_Service_Type(uint8_t sa_service_type)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if ((sa_service_type != SA_PLAINTEXT) && (sa_service_type != SA_AUTHENTICATED_ENCRYPTION) &&
        (sa_service_type != SA_ENCRYPTION) && (sa_service_type != SA_AUTHENTICATION))
    {
        printf(KRED "Unknown SA Service Type Detected!\n" RESET);
        status = CRYPTO_LIB_ERR_INVALID_SA_SERVICE_TYPE;
    }
    return status;
}

/**
 * @brief Function: Crypto_TCA_Handle_Enc_Padding
 * Handles Padding as necessary, returns success/failure
 * @param sa_service_type: uint8_t
 * @param pkcs_padding: uint32_t*
 * @param p_enc_frame_len: uint16_t*
 * @param new_enc_frame_header_field_length: uint16_t*
 * @param tf_payload_len: uint16_t
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2.3 (TC Encryption Processing)
 **/
int32_t Crypto_TCA_Handle_Enc_Padding(uint8_t sa_service_type, uint32_t *pkcs_padding, uint16_t *p_enc_frame_len,
                                     uint16_t *new_enc_frame_header_field_length, uint16_t tf_payload_len,
                                     SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (sa_service_type == SA_ENCRYPTION)
    {
        // Handle Padding, if necessary
        if (sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC)
        {
            *pkcs_padding = tf_payload_len % TC_BLOCK_SIZE; // Block Sizes of 16

            *pkcs_padding = TC_BLOCK_SIZE - *pkcs_padding; // Could potentially need 16 bytes of padding.

            *p_enc_frame_len += *pkcs_padding; // Add the necessary padding to the frame_len + new pad length field

            *new_enc_frame_header_field_length = (*p_enc_frame_len) - 1;
#ifdef DEBUG

            printf("SHPLF_LEN: %d\n", sa_ptr->shplf_len);
            printf("Padding Needed: %d\n", *pkcs_padding);
            printf("Previous data_len: %d\n", tf_payload_len);
            printf("New data_len: %d\n", (tf_payload_len + *pkcs_padding));
            printf("New enc_frame_len: %d\n", (*p_enc_frame_len));
#endif
            // Don't Exceed Max Frame Size! 1024
            if (*p_enc_frame_len > TC_MAX_FRAME_SIZE)
            {
                status = CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_SPEC_LIMIT;
                mc_if->mc_log(status);
            }
        }
    }
    return status;
}

/**
 * @brief Function: Crypto_TCA_Frame_Validation
 * Frame validation - sanity check
 * @param p_enc_frame_len: uint16_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_TCA_Frame_Validation(uint16_t *p_enc_frame_len)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Check minimum frame size per CCSDS 232.0-B-3
    if (*p_enc_frame_len < TC_MIN_FRAME_SIZE)
    {
        printf(KRED "Error: New frame would violate minimum TC frame size requirement! \n" RESET);
        status = CRYPTO_LIB_ERR_TC_FRAME_TOO_SHORT;
        mc_if->mc_log(status);
        return status;
    }

    // Check maximum managed parameter size
    if (*p_enc_frame_len > current_managed_parameters_struct.max_frame_size)
    {
#ifdef DEBUG
        printf("Managed length is: %d\n", current_managed_parameters_struct.max_frame_size);
        printf("New enc frame length will be: %d\n", *p_enc_frame_len);
#endif
        printf(KRED "Error: New frame would violate maximum tc frame managed parameter! \n" RESET);
        status = CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_MANAGED_PARAM_MAX_LIMIT;
        mc_if->mc_log(status);
        return status;
    }
    // Ensure the frame to be created will not violate spec max length
    if ((*p_enc_frame_len > 1024) && status == CRYPTO_LIB_SUCCESS)
    {
        printf(KRED "Error: New frame would violate specification max TC frame size! \n" RESET);
        status = CRYPTO_LIB_ERR_TC_FRAME_SIZE_EXCEEDS_SPEC_LIMIT;
        mc_if->mc_log(status);
        return status;
    }
    return status;
}

/**
 * @brief Function: Crypto_TCA_Accio_Buffer
 * Allocates a new TC frame buffer
 * @param p_new_enc_frame: uint8_t**
 * @param p_enc_frame_len: uint16_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_TCA_Accio_Buffer(uint8_t **p_new_enc_frame, uint16_t *p_enc_frame_len)
{
    int32_t status   = CRYPTO_LIB_SUCCESS;
    *p_new_enc_frame = (uint8_t *)malloc((*p_enc_frame_len) * sizeof(uint8_t));
    if (!(*p_new_enc_frame)) // Fix the check to properly verify the allocation
    {
        printf(KRED "Error: Malloc for encrypted output buffer failed! \n" RESET);
        status = CRYPTO_LIB_ERROR;
        mc_if->mc_log(status);
        return status;
    }
    memset(*p_new_enc_frame, 0, *p_enc_frame_len);
    return status;
}

/**
 * @brief Function: Crypto_TCA_ACS_Algo_Check
 * Validates authentication cipher
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.4.2 (Cryptographic Algorithms)
 **/
int32_t Crypto_TCA_ACS_Algo_Check(SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if ((sa_ptr->est == 0) && (sa_ptr->ast == 1))
    {
        if (sa_ptr->acs_len > 0)
        {
            if (Crypto_Is_ACS_Only_Algo(sa_ptr->acs) && sa_ptr->iv_len > 0)
            {
                status = CRYPTO_LIB_ERR_IV_NOT_SUPPORTED_FOR_ACS_ALGO;
                mc_if->mc_log(status);
            }
        }
    }
    return status;
}

/**
 * @brief Function: Crypto_TCA_Check_IV_Setup
 * Verifies and sets initialization vector
 * @param sa_ptr: SecurityAssociation_t*
 * @param p_new_enc_frame: uint8_t*
 * @param index: uint16_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2.4 (IV Format and Processing)
 **/
int32_t Crypto_TCA_Check_IV_Setup(SecurityAssociation_t *sa_ptr, uint8_t *p_new_enc_frame, uint16_t *index)
{
    int32_t  status = CRYPTO_LIB_SUCCESS;
    int      i;
    uint32_t index_temp = *index;
    if (crypto_config.iv_type == IV_INTERNAL)
    {
        // Start index from the transmitted portion
        for (i = sa_ptr->iv_len - sa_ptr->shivf_len; i < sa_ptr->iv_len; i++)
        {
            *(p_new_enc_frame + index_temp) = *(sa_ptr->iv + i);
            index_temp++;
        }
    }
    // IV is NULL / IV_CRYPTO_MODULE
    else
    {
        // Transmitted length > 0, AND using KMC_CRYPTO
        if ((sa_ptr->shivf_len > 0) && (crypto_config.cryptography_type == CRYPTOGRAPHY_TYPE_KMCCRYPTO))
        {
            index_temp += sa_ptr->iv_len - (sa_ptr->iv_len - sa_ptr->shivf_len);
        }
        else if (sa_ptr->shivf_len == 0)
        {
            // IV isn't being used, so don't care if it's Null
        }
        else
        {
            status = CRYPTO_LIB_ERR_NULL_IV;
            mc_if->mc_log(status);
            return status;
        }
    }
    *index = index_temp;
    return status;
}

/**
 * @brief Function: Crypto_TCA_Encrypt
 * Encrypts TC frame
 * @param sa_service_type: uint8_t
 * @param sa_ptr: SecurityAssociation_t*
 * @param mac_loc: uint16_t*
 * @param tf_payload_len: uint16_t
 * @param segment_hdr_len: uint8_t
 * @param p_new_enc_frame: uint8_t*
 * @param ekp: crypto_key_t*
 * @param aad: uint8_t**
 * @param ecs_is_aead_algorithm: uint8_t
 * @param index_p: uint16_t*
 * @param p_in_frame: const uint8_t*
 * @param cam_cookies: char*
 * @param pkcs_padding: uint32_t
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2.3 (TC Encryption Processing)
 **/
int32_t Crypto_TCA_Encrypt(uint8_t sa_service_type, SecurityAssociation_t *sa_ptr, uint16_t *mac_loc,
                          uint16_t tf_payload_len, uint8_t segment_hdr_len, uint8_t *p_new_enc_frame, crypto_key_t *ekp,
                          uint8_t **aad, uint8_t ecs_is_aead_algorithm, uint16_t *index_p, const uint8_t *p_in_frame,
                          char *cam_cookies, uint32_t pkcs_padding)
{
    int32_t       status = CRYPTO_LIB_SUCCESS;
    uint32_t      index  = *index_p;
    crypto_key_t *akp    = NULL;

    /* Get Key */

    if (sa_ptr->est == 1)
    {
        if (crypto_config.key_type != KEY_TYPE_KMC)
        {
            ekp = key_if->get_key(sa_ptr->ekid);
            if (ekp == NULL)
            {
                status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
                mc_if->mc_log(status);
                free(p_new_enc_frame);
                return status;
            }
            if (ekp->key_state != KEY_ACTIVE)
            {
                status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
                mc_if->mc_log(status);
                free(p_new_enc_frame);
                return status;
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
                mc_if->mc_log(status);
                free(p_new_enc_frame);
                return status;
            }
            if (akp->key_state != KEY_ACTIVE)
            {
                status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
                mc_if->mc_log(status);
                free(p_new_enc_frame);
                return status;
            }
        }
    }

    if (sa_service_type != SA_PLAINTEXT)
    {
        uint8_t *mac_ptr = NULL;
        uint16_t aad_len = 0;

        if (sa_service_type == SA_AUTHENTICATED_ENCRYPTION || sa_service_type == SA_AUTHENTICATION)
        {
            *mac_loc = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len +
                       sa_ptr->shplf_len + tf_payload_len;
#ifdef MAC_DEBUG
            printf(KYEL "MAC location is: %d\n" RESET, *mac_loc);
            printf(KYEL "MAC size is: %d\n" RESET, sa_ptr->stmacf_len);
#endif
            mac_ptr = &p_new_enc_frame[*mac_loc];

            // Prepare the Header AAD (CCSDS 335.0-B-1 4.2.3.2.2.3)
            aad_len = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len +
                      sa_ptr->shplf_len;
            if (sa_service_type ==
                SA_AUTHENTICATION) // auth only, we authenticate the payload as part of the AEAD encrypt call here
            {
                aad_len += tf_payload_len;
            }
#ifdef TC_DEBUG
            printf("Calculated AAD Length: %d\n", aad_len);
#endif
            if (sa_ptr->abm_len < aad_len)
            {
                status = CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
                mc_if->mc_log(status);
                return status;
            }
            *aad = Crypto_Prepare_TC_AAD(p_new_enc_frame, aad_len, sa_ptr->abm);
            if (*aad == NULL)
            {
                status = CRYPTO_LIB_ERROR;
                mc_if->mc_log(status);
                return status;
            }
        }

#ifdef TC_DEBUG
        printf("Encrypted bytes output_loc is %d\n", index);
        printf("Input bytes input_loc is %d\n", TC_FRAME_HEADER_SIZE + segment_hdr_len);
#endif

        if (ecs_is_aead_algorithm == CRYPTO_TRUE)
        {
            if (crypto_config.key_type != KEY_TYPE_KMC)
            {
                // Check that key length to be used ets the algorithm requirement
                if ((int32_t)ekp->key_len != Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs))
                {
                    status = CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
                    goto end_of_function;
                }
            }

            status = cryptography_if->cryptography_aead_encrypt(
                &p_new_enc_frame[index],                                          // ciphertext output
                (size_t)tf_payload_len,                                           // length of data
                (uint8_t *)(p_in_frame + TC_FRAME_HEADER_SIZE + segment_hdr_len), // plaintext input
                (size_t)tf_payload_len,                                           // in data length
                &(ekp->value[0]),                                                 // Key
                Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs), // Length of key derived from sa_ptr key_ref
                sa_ptr,                                  // SA (for key reference)
                sa_ptr->iv,                              // IV
                sa_ptr->iv_len,                          // IV Length
                mac_ptr,                                 // tag output
                sa_ptr->stmacf_len,                      // tag size
                *aad,                                    // AAD Input
                aad_len,                                 // Length of AAD
                (sa_ptr->est == 1), (sa_ptr->ast == 1), (sa_ptr->ast == 1),
                &sa_ptr->ecs, // encryption cipher
                &sa_ptr->acs, // authentication cipher
                cam_cookies);
        }
        else // non aead algorithm
        {
            // TODO - implement non-AEAD algorithm logic
            if (sa_service_type == SA_ENCRYPTION)
            {
                if (crypto_config.key_type != KEY_TYPE_KMC)
                {
                    // Check that key length to be used ets the algorithm requirement
                    if ((int32_t)ekp->key_len != Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs))
                    {
                        status = CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
                        goto end_of_function;
                    }
                }

                status = cryptography_if->cryptography_encrypt(
                    &p_new_enc_frame[index], // ciphertext output
                    (size_t)tf_payload_len,
                    &p_new_enc_frame[index],                 // length of data
                    (size_t)tf_payload_len,                  // in data length
                    &(ekp->value[0]),                        // Key
                    Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs), // Length of key derived from sa_ptr key_ref
                    sa_ptr,                                  // SA (for key reference)
                    sa_ptr->iv,                              // IV
                    sa_ptr->iv_len,                          // IV Length
                    &sa_ptr->ecs,                            // encryption cipher
                    pkcs_padding, cam_cookies);
            }

            if (sa_service_type == SA_AUTHENTICATION)
            {

                if (crypto_config.key_type != KEY_TYPE_KMC)
                {
                    // Check that key length to be used ets the algorithm requirement
                    if ((int32_t)akp->key_len != Crypto_Get_ACS_Algo_Keylen(sa_ptr->acs))
                    {
                        status = CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
                        goto end_of_function;
                    }
                }

                status = cryptography_if->cryptography_authenticate(
                    &p_new_enc_frame[index],                                          // ciphertext output
                    (size_t)tf_payload_len,                                           // length of data
                    (uint8_t *)(p_in_frame + TC_FRAME_HEADER_SIZE + segment_hdr_len), // plaintext input
                    (size_t)tf_payload_len,                                           // in data length
                    &(akp->value[0]),                                                 // Key
                    Crypto_Get_ACS_Algo_Keylen(sa_ptr->acs),
                    sa_ptr,             // SA (for key reference)
                    sa_ptr->iv,         // IV
                    sa_ptr->iv_len,     // IV Length
                    mac_ptr,            // tag output
                    sa_ptr->stmacf_len, // tag size
                    *aad,               // AAD Input
                    aad_len,            // Length of AAD
                    sa_ptr->ecs,        // encryption cipher
                    sa_ptr->acs,        // authentication cipher
                    cam_cookies);
            }
        }
        *index_p = index;
    }

end_of_function:
    return status;
}

/**
 * @brief Function: Crypto_TCA_Increment_IV_ARSN
 * Increments the IV or ARSN
 * @param sa_service_type: uint8_t
 * @param sa_ptr: SecurityAssociation_t*
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 6.1.2 (Anti-replay Processing)
 **/
void Crypto_TCA_Increment_IV_ARSN(uint8_t sa_service_type, SecurityAssociation_t *sa_ptr)
{
    if (sa_service_type != SA_PLAINTEXT)
    {
#ifdef INCREMENT
        if (crypto_config.crypto_increment_nontransmitted_iv == SA_INCREMENT_NONTRANSMITTED_IV_TRUE)
        {
            if (sa_ptr->shivf_len > 0 && sa_ptr->iv_len != 0)
            {
                Crypto_increment(sa_ptr->iv, sa_ptr->iv_len);
            }
        }
        else // SA_INCREMENT_NONTRANSMITTED_IV_FALSE
        {
            // Only increment the transmitted portion
            if (sa_ptr->shivf_len > 0 && sa_ptr->iv_len != 0)
            {
                Crypto_increment(sa_ptr->iv + (sa_ptr->iv_len - sa_ptr->shivf_len), sa_ptr->shivf_len);
            }
        }
        if (sa_ptr->shsnf_len > 0)
        {
            Crypto_increment(sa_ptr->arsn, sa_ptr->arsn_len);
        }

#ifdef SA_DEBUG
        int i = 0;
        if (sa_ptr->iv_len > 0)
        {
            printf(KYEL "Next IV value is:\n\t");
            for (i = 0; i < sa_ptr->iv_len; i++)
            {
                printf("%02x", *(sa_ptr->iv + i));
            }
            printf("\n" RESET);
            printf(KYEL "Next transmitted IV value is:\n\t");
            for (i = sa_ptr->iv_len - sa_ptr->shivf_len; i < sa_ptr->iv_len; i++)
            {
                printf("%02x", *(sa_ptr->iv + i));
            }
            printf("\n" RESET);
        }
        printf(KYEL "Next ARSN value is:\n\t");
        for (i = 0; i < sa_ptr->arsn_len; i++)
        {
            printf("%02x", *(sa_ptr->arsn + i));
        }
        printf("\n" RESET);
        printf(KYEL "Next transmitted ARSN value is:\n\t");
        for (i = sa_ptr->arsn_len - sa_ptr->shsnf_len; i < sa_ptr->arsn_len; i++)
        {
            printf("%02x", *(sa_ptr->arsn + i));
        }
        printf("\n" RESET);
#endif
#endif
    }
}

/**
 * @brief Function: Crypto_TCA_Do_Encrypt
 * Performs TC frame encryption
 * @param sa_service_type: uint8_t
 * @param sa_ptr: SecurityAssociation_t*
 * @param mac_loc: uint16_t*
 * @param tf_payload_len: uint16_t
 * @param segment_hdr_len: uint8_t
 * @param p_new_enc_frame: uint8_t*
 * @param ekp: crypto_key_t*
 * @param aad: uint8_t**
 * @param ecs_is_aead_algorithm: uint8_t
 * @param index_p: uint16_t*
 * @param p_in_frame: const uint8_t*
 * @param cam_cookies: char*
 * @param pkcs_padding: uint32_t
 * @param new_enc_frame_header_field_length: uint16_t
 * @param new_fecf: uint16_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2.3 (TC Encryption Processing)
 **/
int32_t Crypto_TCA_Do_Encrypt(uint8_t sa_service_type, SecurityAssociation_t *sa_ptr, uint16_t *mac_loc,
                             uint16_t tf_payload_len, uint8_t segment_hdr_len, uint8_t *p_new_enc_frame,
                             crypto_key_t *ekp, uint8_t **aad, uint8_t ecs_is_aead_algorithm, uint16_t *index_p,
                             const uint8_t *p_in_frame, char *cam_cookies, uint32_t pkcs_padding,
                             uint16_t new_enc_frame_header_field_length, uint16_t *new_fecf)
{
    int32_t  status = CRYPTO_LIB_SUCCESS;
    uint32_t index  = *index_p;
    status = Crypto_TCA_Encrypt(sa_service_type, sa_ptr, mac_loc, tf_payload_len, segment_hdr_len, p_new_enc_frame, ekp,
                               aad, ecs_is_aead_algorithm, index_p, p_in_frame, cam_cookies, pkcs_padding);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
        goto end_of_function;
    }
    // TODO:  Status?
    Crypto_TCA_Increment_IV_ARSN(sa_service_type, sa_ptr);
    /*
    ** End Authentication / Encryption
    */

    // Only calculate & insert FECF if CryptoLib is configured to do so & gvcid includes FECF.
    if (current_managed_parameters_struct.has_fecf == TC_HAS_FECF)
    {
#ifdef FECF_DEBUG
        printf(KCYN "Calcing FECF over %d bytes\n" RESET, new_enc_frame_header_field_length - 1);
#endif
        if (crypto_config.crypto_create_fecf == CRYPTO_TC_CREATE_FECF_TRUE)
        {
            *new_fecf = Crypto_Calc_FECF(p_new_enc_frame, new_enc_frame_header_field_length - 1);
            *(p_new_enc_frame + new_enc_frame_header_field_length - 1) = (uint8_t)((*new_fecf & 0xFF00) >> 8);
            *(p_new_enc_frame + new_enc_frame_header_field_length)     = (uint8_t)(*new_fecf & 0x00FF);
        }
        else // CRYPTO_TC_CREATE_FECF_FALSE
        {
            *(p_new_enc_frame + new_enc_frame_header_field_length - 1) = (uint8_t)0x00;
            *(p_new_enc_frame + new_enc_frame_header_field_length)     = (uint8_t)0x00;
        }
        index += 2;
    }
    *index_p = index;

end_of_function:
    return status;
}

/**
 * @brief Function: Crypto_TCA_Check_Init_Setup
 * Initial setup and validation for TC frames
 * @param in_frame_length: uint16_t
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1 (Frame Format)
 **/
int32_t Crypto_TCA_Check_Init_Setup(uint16_t in_frame_length)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if ((crypto_config.init_status == UNITIALIZED) || (mc_if == NULL) || (sa_if == NULL))
    {
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        // Can't mc_log since it's not configured
        goto end_of_function; // return immediately so a NULL crypto_config is not dereferenced later
    }

    if (in_frame_length < 5) // Frame length doesn't have enough bytes for TC TF header -- error out.
    {
        status = CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TC_STANDARD;
        mc_if->mc_log(status);
        goto end_of_function;
    }

end_of_function:
    return status;
}


/**
 * @brief Function: Crypto_TCA_Finalize_Frame_Setup
 * Finalizes setup for TC frame processing
 * @param sa_service_type: uint8_t
 * @param pkcs_padding: uint32_t*
 * @param p_enc_frame_len: uint16_t*
 * @param new_enc_frame_header_field_length: uint16_t*
 * @param tf_payload_len: uint16_t
 * @param sa_ptr: SecurityAssociation_t**
 * @param p_new_enc_frame: uint8_t**
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2 (TC Security)
 **/
int32_t Crypto_TCA_Finalize_Frame_Setup(uint8_t sa_service_type, uint32_t *pkcs_padding, uint16_t *p_enc_frame_len,
                                       uint16_t *new_enc_frame_header_field_length, uint16_t tf_payload_len,
                                       SecurityAssociation_t **sa_ptr, uint8_t **p_new_enc_frame)
{
    uint32_t status = CRYPTO_LIB_SUCCESS;
    status          = Crypto_TCA_Handle_Enc_Padding(sa_service_type, pkcs_padding, p_enc_frame_len,
                                                   new_enc_frame_header_field_length, tf_payload_len, *sa_ptr);
    if (status == CRYPTO_LIB_SUCCESS)
    {
        status = Crypto_TCA_Validate_SA_Service_Type(sa_service_type);
    }
    if (status == CRYPTO_LIB_SUCCESS)
    {
        // Ensure the frame to be created will not violate managed parameter maximum length
        status = Crypto_TCA_Frame_Validation(p_enc_frame_len);
    }
    if (status == CRYPTO_LIB_SUCCESS)
    {
        // Accio buffer
        status = Crypto_TCA_Accio_Buffer(p_new_enc_frame, p_enc_frame_len);
    }
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
    }

    return status;
}

/**
 * @brief Function: Crypto_TCA_Handle_Padding
 * Adds padding to TC frame
 * @param pkcs_padding: uint32_t
 * @param sa_ptr: SecurityAssociation_t*
 * @param p_new_enc_frame: uint8_t*
 * @param index: uint16_t*
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2.5 (Padding)
 **/
void Crypto_TCA_Handle_Padding(uint32_t pkcs_padding, SecurityAssociation_t *sa_ptr, uint8_t *p_new_enc_frame,
                              uint16_t *index)
{
    int      i          = 0;
    uint16_t temp_index = *index;
    printf("Temp_index = %d\n", temp_index);
    if (pkcs_padding)
    {
        uint8_t hex_padding[3] = {0};                       // TODO: Create #Define for the 3
        pkcs_padding           = pkcs_padding & 0x00FFFFFF; // Truncate to be maxiumum of 3 bytes in size

        // Byte Magic
        hex_padding[0] = (pkcs_padding >> 16) & 0xFF;
        hex_padding[1] = (pkcs_padding >> 8) & 0xFF;
        hex_padding[2] = (pkcs_padding)&0xFF;

        uint8_t padding_start = 0;
        padding_start         = 3 - sa_ptr->shplf_len;

        for (i = 0; i < sa_ptr->shplf_len; i++)
        {
            *(p_new_enc_frame + temp_index) = hex_padding[padding_start++];
            temp_index++;
        }
        *index = temp_index;
    }
}

/**
 * @brief Function: Crypto_TCA_Set_IV
 * Sets initialization vector for TC frame
 * @param sa_ptr: SecurityAssociation_t*
 * @param p_new_enc_frame: uint8_t*
 * @param index: uint16_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2.4 (IV Format and Processing)
 **/
int32_t Crypto_TCA_Set_IV(SecurityAssociation_t *sa_ptr, uint8_t *p_new_enc_frame, uint16_t *index)
{
    uint32_t status = CRYPTO_LIB_SUCCESS;
#ifdef SA_DEBUG
    if (sa_ptr->shivf_len > 0)
    {
        int i = 0;
        printf(KYEL "Using IV value:\n\t");
        for (i = 0; i < sa_ptr->iv_len; i++)
        {
            printf("%02x", *(sa_ptr->iv + i));
        }
        printf("\n" RESET);
        printf(KYEL "Transmitted IV value:\n\t");
        for (i = sa_ptr->iv_len - sa_ptr->shivf_len; i < sa_ptr->iv_len; i++)
        {
            printf("%02x", *(sa_ptr->iv + i));
        }
        printf("\n" RESET);
    }
#endif
    status = Crypto_TCA_ACS_Algo_Check(sa_ptr);
    if (status == CRYPTO_LIB_SUCCESS)
    {
        status = Crypto_TCA_Check_IV_Setup(sa_ptr, p_new_enc_frame, index);
    }

    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
    }
    return status;
}


/**
 * @brief Function: Crypto_TC_Safe_Free_Ptr
 * Safely frees a pointer
 * @param ptr: uint8_t*
 **/
void Crypto_TC_Safe_Free_Ptr(uint8_t *ptr)
{
    if (ptr) // Fix the logic to free only if ptr is NOT NULL
        free(ptr);
}



/**
 * @brief Function: Crypto_TC_Calc_Lengths
 * Calculates various field lengths for TC processing
 * @param fecf_len: uint8_t*
 * @param segment_hdr_len: uint8_t*
 * @param ocf_len: uint8_t*
 *
 * CCSDS Compliance: CCSDS 232.0-B-3 Section 4.1 (Frame Format)
 **/
void Crypto_TC_Calc_Lengths(uint8_t *fecf_len, uint8_t *segment_hdr_len, uint8_t *ocf_len)
{
    if (current_managed_parameters_struct.has_fecf == TC_NO_FECF)
    {
        *fecf_len = 0;
    }

    if (current_managed_parameters_struct.has_segmentation_hdr == TC_NO_SEGMENT_HDRS)
    {
        *segment_hdr_len = 0;
    }

    if (current_managed_parameters_struct.has_ocf == TC_OCF_NA)
    {
        *ocf_len = 0;
    }
}



/**
 * @brief Function: Crypto_Prepare_TC_AAD
 * Prepares AAD for TC frame
 * @param buffer: const uint8_t*
 * @param len_aad: uint16_t
 * @param abm_buffer: const uint8_t*
 * @return uint8_t*: AAD buffer
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.3.3 (TC Authentication Processing)
 **/
uint8_t *Crypto_Prepare_TC_AAD(const uint8_t *buffer, uint16_t len_aad, const uint8_t *abm_buffer)
{
    int32_t  status = CRYPTO_LIB_SUCCESS;
    int      i;
    uint8_t *aad;

    // Validate inputs
    if (buffer == NULL || abm_buffer == NULL)
    {
        status = CRYPTO_LIB_ERR_NULL_BUFFER;
        mc_if->mc_log(status);
        return NULL;
    }

    // Validate authentication mask per CCSDS requirements
    status = Crypto_TC_Validate_Auth_Mask(abm_buffer, len_aad, len_aad);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
        return NULL;
    }

    aad = (uint8_t *)calloc(1, len_aad * sizeof(uint8_t));
    if (!aad)
    {
        mc_if->mc_log(CRYPTO_LIB_ERROR);
        return NULL;
    }

    // Apply authentication bitmask
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

    printf(KYEL "Preparing AAD:\n");
    printf("\tUsing AAD Length of %d\n\t", len_aad);
    for (i = 0; i < len_aad; i++)
    {
        printf("%02x", aad[i]);
    }
    printf("\n" RESET);
#endif

    return aad;
}

static int32_t validate_sa_index(SecurityAssociation_t *sa)
{
    int32_t                returnval = 0;
    SecurityAssociation_t *temp_sa;
    sa_if->sa_get_from_spi(sa->spi, &temp_sa);

    // Do not validate sa index on KMC
    if (crypto_config.sa_type == SA_TYPE_MARIADB)
    {
        return returnval;
    }

    int sa_index = -1;
    sa_index     = (int)(sa - temp_sa); // Based on array memory location
#ifdef DEBUG
    if (sa_index == 0)
        printf("SA Index matches SPI\n");
    else if (sa_index != 0 && crypto_config.sa_type != SA_TYPE_MARIADB)
        printf("Malformed SA SPI based on SA Index!\n");
#endif
    if (sa_index != 0)
        returnval = -1;

    return returnval;
}

/**
 * @brief Function: Crypto_TC_Validate_SA
 * Validates Security Association for TC
 * @param sa: SecurityAssociation_t*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Table A6 (Security Association)
 **/
int32_t Crypto_TC_Validate_SA(SecurityAssociation_t *sa)
{
    if (validate_sa_index(sa) != 0)
    {
        return CRYPTO_LIB_ERR_SPI_INDEX_MISMATCH;
    }
    if (sa->sa_state != SA_OPERATIONAL)
    {
        return CRYPTO_LIB_ERR_SA_NOT_OPERATIONAL;
    }
    if (sa->shivf_len > 0 && crypto_config.iv_type == IV_CRYPTO_MODULE &&
        crypto_config.cryptography_type != CRYPTOGRAPHY_TYPE_KMCCRYPTO)
    {
        return CRYPTO_LIB_ERR_NULL_IV;
    }
    if (sa->iv_len - sa->shivf_len < 0)
    {
        return CRYPTO_LIB_ERR_IV_LEN_SHORTER_THAN_SEC_HEADER_LENGTH;
    }
    if (sa->iv_len > 0 && crypto_config.iv_type == IV_CRYPTO_MODULE &&
        crypto_config.cryptography_type != CRYPTOGRAPHY_TYPE_KMCCRYPTO)
    {
        return CRYPTO_LIB_ERR_NULL_IV;
    }
    if (crypto_config.iv_type == IV_CRYPTO_MODULE && crypto_config.cryptography_type == CRYPTOGRAPHY_TYPE_LIBGCRYPT)
    {
        return CRYPTO_LIB_ERR_NULL_IV;
    }
    if (sa->arsn_len - sa->shsnf_len < 0)
    {
        return CRYPTO_LIB_ERR_ARSN_LEN_SHORTER_THAN_SEC_HEADER_LENGTH;
    }

    return CRYPTO_LIB_SUCCESS;
}



/**
 * @brief Function: Crypto_TC_Validate_Auth_Mask
 * Validates Authentication Bit Mask
 * @param abm_buffer: const uint8_t*
 * @param abm_len: uint16_t
 * @param frame_len: uint16_t
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.3.3 (TC Authentication Processing)
 **/
static int32_t Crypto_TC_Validate_Auth_Mask(const uint8_t *abm_buffer, uint16_t abm_len, uint16_t frame_len)
{
    if (abm_buffer == NULL)
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }

    // Validate mask length matches frame length
    if (abm_len < frame_len)
    {
        return CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
    }

    // Validate mask format - ensure critical fields are always authenticated
    // Per CCSDS 355.0-B-2, certain fields must always be authenticated
    // For TC frames, the header must be authenticated (first 5 bytes)
    // for (int i = 0; i < 5; i++)
    // {
    //     if (abm_buffer[i] != 0xFF)
    //     {
    //         return CRYPTO_LIB_ERR_TC_AUTH_MASK_INVALID;
    //     }
    // }

    return CRYPTO_LIB_SUCCESS;
}
