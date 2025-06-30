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
 * @brief Function: Crypto_AOS_ApplySecurity
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @return int32: Success/Failure
 *
 * The AOS ApplySecurity Payload shall consist of the portion of the AOS Transfer Frame (see
 * reference [1]) from the first octet of the Transfer Frame Primary Header to the last octet of
 * the Transfer Frame Data Field.
 * NOTES
 * 1 The AOS Transfer Frame is the fixed-length protocol data unit of the AOS Space Data
 * Link Protocol. The length of any Transfer Frame transferred on a physical channel is
 * constant, and is established by management.
 * 2 The portion of the AOS Transfer Frame contained in the AOS ApplySecurity Payload
 * parameter includes the Security Header field. When the ApplySecurity Function is
 * called, the Security Header field is empty; i.e., the caller has not set any values in the
 * Security Header
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 5 (AOS Protocol), CCSDS 732.0-B-4
 **/
int32_t Crypto_AOS_ApplySecurity(uint8_t *pTfBuffer, uint16_t len_ingest)
{
    int32_t                status          = CRYPTO_LIB_SUCCESS;
    int                    mac_loc         = 0;
    uint16_t               aad_len         = 0;
    uint16_t               idx             = 0;
    uint8_t                sa_service_type = -1;
    uint16_t               pdu_len         = -1;
    uint32_t               pkcs_padding    = 0;
    SecurityAssociation_t *sa_ptr          = NULL;
    uint8_t                tfvn            = 0;
    uint16_t               scid            = 0;
    uint16_t               vcid            = 0;
    uint16_t               cbc_padding     = 0;
    crypto_key_t          *ekp             = NULL;
    crypto_key_t          *akp             = NULL;
    uint8_t                aad[1786];
    uint16_t               data_loc;
    uint8_t                ecs_is_aead_algorithm;

    // Prevent set but unused error
    cbc_padding = cbc_padding;

    status = Crypto_AOSA_Initial_Error_Checks(&pTfBuffer[0]);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    Crypto_AOSA_Parse_Header(&pTfBuffer[0], &tfvn, &scid, &vcid);

    status = sa_if->sa_get_operational_sa_from_gvcid(tfvn, scid, vcid, 0, &sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef AOS_DEBUG
        printf(KRED "Error: Could not retrieve an SA!\n" RESET);
#endif
        goto end_of_function;
    }

    status = Crypto_Get_Managed_Parameters_For_Gvcid(tfvn, scid, vcid, gvcid_managed_parameters_array,
                                                     &current_managed_parameters_struct);

    // No managed parameters found
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef AOS_DEBUG
        printf(KRED "Error: No managed parameters found!\n" RESET);
#endif
        goto end_of_function;
    }

    status = Crypto_AOSA_Check_Frame_Lengths(len_ingest, sa_ptr, &cbc_padding);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

#ifdef AOS_DEBUG
    printf(KYEL "AOS BEFORE Apply Sec:\n\t" RESET);
    for (int16_t i = 0; i < current_managed_parameters_struct.max_frame_size - cbc_padding; i++)
    {
        printf("%02X", pTfBuffer[i]);
    }
    printf("\n");
#endif

#ifdef SA_DEBUG
    printf(KYEL "DEBUG - Printing SA Entry for current frame.\n" RESET);
    Crypto_saPrint(sa_ptr);
#endif

    /*
    ** CCSDS 355.0-B-2 Compliance:
    ** Section 3.3 - Security Service Types
    */
    // Determine SA Service Type
    status = Crypto_AOS_Get_SA_Service_Type(&sa_service_type, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Determine Algorithm cipher & mode. // TODO - Parse authentication_cipher, and handle AEAD cases properly
    if (sa_service_type != SA_PLAINTEXT)
    {
        ecs_is_aead_algorithm = Crypto_Is_AEAD_Algorithm(sa_ptr->ecs);
    }

#ifdef AOS_DEBUG
    Crypto_AOS_SA_Service_Type_Debug_Print(sa_service_type);
#endif

    // Increment to end of mandatory 6 byte AOS Pri Hdr
    idx = 6;

    // Detect if optional 2 byte FHEC is present
    Crypto_AOSA_Handle_FHEC(pTfBuffer, &idx);

    // Detect if optional variable length Insert Zone is present
    // Per CCSDS 732.0-B-4 Section 4.1.3, Insert Zone is optional but fixed length for a physical channel
    status = Crypto_AOSA_Handle_IZ(&idx);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Idx is now at SPI location
    /**
     * Begin Security Header Fields
     * Reference CCSDS SDLP 3550b1 4.1.1.1.3
     **/
    Crypto_AOSA_Handle_Security_Header(&pTfBuffer[0], &idx, sa_ptr, sa_service_type, &pkcs_padding, cbc_padding);

    /**
     * End Security Header Fields
     **/

    /**
     * ~~~Index currently at start of data field, AKA end of security header~~~
     **/
    data_loc = idx;

    if (current_managed_parameters_struct.max_frame_size < idx - sa_ptr->stmacf_len)
    {
        status = CRYPTO_LIB_ERR_AOS_FRAME_LENGTH_UNDERFLOW;
        goto end_of_function;
    }

    // Calculate size of data to be encrypted
    status = Crypto_AOSA_Calc_PDU_Length(&pdu_len, idx, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

#ifdef AOS_DEBUG
    printf(KYEL "Data location starts at: %d\n" RESET, idx);
    printf(KYEL "Data size is: %d\n" RESET, pdu_len);
    printf(KYEL "Index at end of SPI is: %d\n", idx);
    if (current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        // If OCF exists, comes immediately after MAC
        printf(KYEL "OCF Location is: %d" RESET, idx + pdu_len + sa_ptr->stmacf_len);
    }
    if (current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        // If FECF exists, comes just before end of the frame
        printf(KYEL "FECF Location is: %d\n" RESET, current_managed_parameters_struct.max_frame_size - 2);
    }
#endif

    Crypto_AOSA_Apply_Padding(pTfBuffer, pdu_len, sa_ptr, idx, pkcs_padding);

    // Get Key
    status = Crypto_AOS_Get_Keys(sa_ptr, &ekp, &akp);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    /**
     * Begin Authentication / Encryption
     **/
    status =
        Crypto_AOSA_Handle_MAC_AAD(sa_service_type, &mac_loc, &aad[0], &aad_len, sa_ptr, idx, pdu_len, &pTfBuffer[0]);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    status = Crypto_AOS_Encrypt(sa_service_type, ecs_is_aead_algorithm, &pTfBuffer[0], data_loc, pdu_len, ekp, akp,
                                sa_ptr, pkcs_padding, &aad[0], aad_len, mac_loc);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Move idx to mac location
    idx += pdu_len;
    Crypto_AOSA_Handle_Security_Trailer(&pTfBuffer[0], sa_ptr, &idx, pdu_len);

#ifdef AOS_DEBUG
    printf(KYEL "Printing new AOS frame:\n\t");
    for (int i = 0; i < current_managed_parameters_struct.max_frame_size; i++)
    {
        printf("%02X", pTfBuffer[i]);
    }
    printf("\n");
#endif

    status = sa_if->sa_save_sa(sa_ptr);

#ifdef DEBUG
    printf(KYEL "----- Crypto_AOS_ApplySecurity END -----\n" RESET);
#endif

end_of_function:
    if (mc_if != NULL)
    {
        mc_if->mc_log(status);
    }
    return status;
}

int32_t Crypto_AOSA_Check_Frame_Lengths(uint16_t len_ingest, SecurityAssociation_t *sa_ptr, uint16_t *cbc_padding)
{
    /*
    ** CCSDS 732.0-B-4 Compliance:
    ** Section 4.1.1 - AOS frames must have a fixed length for a given physical channel
    ** Special case for CBC mode ciphers that require padding
    */
    int32_t status = CRYPTO_LIB_SUCCESS;

    if ((sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC || sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC_MAC) &&
        (current_managed_parameters_struct.max_frame_size - len_ingest) <= 16)
    {
        // For CBC mode, allow frames that are slightly shorter to account for padding
        *cbc_padding = current_managed_parameters_struct.max_frame_size - len_ingest;
    }
    else if ((current_managed_parameters_struct.max_frame_size - len_ingest) != 0)
    {
        status = CRYPTO_LIB_ERR_AOS_FL_LT_MAX_FRAME_SIZE;
    }

    return status;
}

/**
 * @brief Function: Crypto_AOS_Get_SA_Service_Type
 * Determines the SA service type
 * @param sa_service_type: uint8*
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32: ENUM - Service type
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 3.3 (Security Service Types)
 **/
int32_t Crypto_AOS_Get_SA_Service_Type(uint8_t *sa_service_type, SecurityAssociation_t *sa_ptr)
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
        return status;
    }
    return status;
}

void Crypto_AOS_SA_Service_Type_Debug_Print(uint8_t sa_service_type)
{
    switch (sa_service_type)
    {
        case SA_PLAINTEXT:
            printf(KBLU "Creating a SDLS AOS - CLEAR!\n" RESET);
            break;
        case SA_AUTHENTICATION:
            printf(KBLU "Creating a SDLS AOS - AUTHENTICATED!\n" RESET);
            break;
        case SA_ENCRYPTION:
            printf(KBLU "Creating a SDLS AOS - ENCRYPTED!\n" RESET);
            break;
        case SA_AUTHENTICATED_ENCRYPTION:
            printf(KBLU "Creating a SDLS AOS - AUTHENTICATED ENCRYPTION!\n" RESET);
            break;
    }
}

void Crypto_AOSA_Handle_FHEC(uint8_t *pTfBuffer, uint16_t *idx)
{
    if (current_managed_parameters_struct.aos_has_fhec == AOS_HAS_FHEC)
    {
#ifdef AOS_DEBUG
        printf(KYEL "Calculating FHECF...\n" RESET);
#endif
        uint16_t calculated_fhecf = Crypto_Calc_FHECF(pTfBuffer);
        pTfBuffer[*idx]           = (calculated_fhecf >> 8) & 0x00FF;
        pTfBuffer[(*idx) + 1]     = (calculated_fhecf)&0x00FF;
        *idx                      = 8;
    }
}

int32_t Crypto_AOSA_Handle_IZ(uint16_t *idx)
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

        *idx += current_managed_parameters_struct.aos_iz_len;
    }

end_of_function:
    return status;
}

void Crypto_AOSA_Set_SPI(uint8_t *pTfBuffer, uint16_t *idx, SecurityAssociation_t *sa_ptr)
{
    pTfBuffer[*idx] = (uint8_t)(sa_ptr->spi >> 8);
    (*idx)++;
    pTfBuffer[*idx] = (sa_ptr->spi & 0xFF);
    (*idx)++;
}

void Crypto_AOS_IV_Debug_Print(SecurityAssociation_t *sa_ptr)
{
    int i = 0;

    if (sa_ptr->shivf_len > 0)
    {
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
}

void Crypto_AOSA_Set_IV(uint8_t *pTfBuffer, SecurityAssociation_t *sa_ptr, uint16_t *idx)
{
    for (int i = sa_ptr->iv_len - sa_ptr->shivf_len; i < sa_ptr->iv_len; i++)
    {
        // Copy in IV from SA
        pTfBuffer[*idx] = *(sa_ptr->iv + i);
        (*idx)++;
    }
}

void Crypto_AOSA_Set_ARSN(uint8_t *pTfBuffer, SecurityAssociation_t *sa_ptr, uint16_t *idx)
{
    for (int i = sa_ptr->arsn_len - sa_ptr->shsnf_len; i < sa_ptr->arsn_len; i++)
    {
        // Copy in ARSN from SA
        pTfBuffer[*idx] = *(sa_ptr->arsn + i);
        (*idx)++;
    }
}

int32_t Crypto_AOSA_Check_Padding_Lengths(uint8_t *pTfBuffer, uint16_t *idx, SecurityAssociation_t *sa_ptr,
                                          uint32_t *pkcs_padding, uint16_t cbc_padding)
{
    uint16_t padding_length = 0;
    uint8_t  i              = 0;
    int32_t  status         = CRYPTO_LIB_SUCCESS;

    if (sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC || sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC_MAC)
    {
        for (i = 0; i < sa_ptr->shplf_len; i++)
        {
            padding_length = (padding_length << 8) | (uint8_t)pTfBuffer[*idx];
            (*idx)++;
        }
        *pkcs_padding = padding_length;
    }

    if (*pkcs_padding < cbc_padding)
    {
        status = CRYPTO_LIB_ERROR;
#ifdef AOS_DEBUG
        printf(KRED "Error: pkcs_padding length  of %d is less than required length of %d\n" RESET, *pkcs_padding,
               cbc_padding);
#endif
    }

    return status;
}

int32_t Crypto_AOSA_Calc_PDU_Length(uint16_t *pdu_len, uint16_t idx, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    *pdu_len = current_managed_parameters_struct.max_frame_size - idx - sa_ptr->stmacf_len;
    // Check other managed parameter flags, subtract their lengths from data field if present
    if (current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        *pdu_len -= 4;
    }
    if (current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        *pdu_len -= 2;
    }

    if (current_managed_parameters_struct.max_frame_size < *pdu_len)
    {
        status = CRYPTO_LIB_ERR_AOS_FRAME_LENGTH_UNDERFLOW;
    }

    return status;
}

void Crypto_AOSA_Apply_Padding(uint8_t *pTfBuffer, uint16_t pdu_len, SecurityAssociation_t *sa_ptr, uint16_t idx,
                               uint32_t pkcs_padding)
{
    uint8_t i                = 0;
    int     padding_location = idx + pdu_len;

    // done with data field, now add padding
    if (pkcs_padding)
    {
        uint8_t hex_padding[3] = {0};                       // TODO: Create #Define for the 3
        hex_padding[0]         = 0x00;                      // Prevent set but not used warning
        hex_padding[1]         = 0x00;                      // Prevent set but not used warning
        hex_padding[2]         = 0x00;                      // Prevent set but not used warning
        pkcs_padding           = pkcs_padding & 0x00FFFFFF; // Truncate to be maxiumum of 3 bytes in size

        for (i = 0; i < sa_ptr->shplf_len; i++)
        {
            hex_padding[i] = (pkcs_padding >> (8 * (sa_ptr->shplf_len - i - 1))) & 0xFF;
        }

#ifdef AOS_DEBUG
        printf("pkcs_padding: %d\n", (int)pkcs_padding);
#endif
        for (i = 0; i < (int)pkcs_padding; i++)
        {
            for (int j = 0; j < sa_ptr->shplf_len; j++)
            {
                pTfBuffer[padding_location] = hex_padding[j];
                padding_location++;
                if (j != sa_ptr->shplf_len - 1)
                {
                    i++;
                }
            }
        }
    }
}

int32_t Crypto_AOS_Get_Keys(SecurityAssociation_t *sa_ptr, crypto_key_t **ekp, crypto_key_t **akp)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (crypto_config.key_type != KEY_TYPE_KMC)
    {
        *ekp = key_if->get_key(sa_ptr->ekid);
        *akp = key_if->get_key(sa_ptr->akid);

        if (*ekp == NULL || *akp == NULL)
        {
            status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
            goto end_of_function;
        }
        if (sa_ptr->est == 1)
        {
            if ((*ekp)->key_state != KEY_ACTIVE)
            {
                status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
                goto end_of_function;
            }
        }
        if (sa_ptr->ast == 1)
        {
            if ((*akp)->key_state != KEY_ACTIVE)
            {
                status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
                goto end_of_function;
            }
        }
    }

end_of_function:
    return status;
}

int32_t Crypto_AOSA_Handle_MAC_AAD(uint8_t sa_service_type, int *mac_loc, uint8_t *aad, uint16_t *aad_len,
                                   SecurityAssociation_t *sa_ptr, uint16_t idx, uint16_t pdu_len, uint8_t *pTfBuffer)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (sa_service_type != SA_PLAINTEXT)
    {
        *aad_len = 0;

        if (sa_service_type == SA_AUTHENTICATED_ENCRYPTION || sa_service_type == SA_AUTHENTICATION)
        {
            *mac_loc = idx + pdu_len;
#ifdef MAC_DEBUG
            printf(KYEL "MAC location is: %d\n" RESET, *mac_loc);
            printf(KYEL "MAC size is: %d\n" RESET, sa_ptr->stmacf_len);
#endif

            // Prepare the Header AAD (CCSDS 335.0-B-2 4.2.3.4)
            *aad_len = idx; // At the very least AAD includes the header
            if (sa_service_type ==
                SA_AUTHENTICATION) // auth only, we authenticate the payload as part of the AEAD encrypt call here
            {
                *aad_len += pdu_len;
            }
#ifdef AOS_DEBUG
            printf("Calculated AAD Length: %d\n", *aad_len);
#endif
            if (sa_ptr->abm_len < *aad_len)
            {
                status = CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
#ifdef AOS_DEBUG
                printf(KRED "Error: abm_len of %d < aad_len of %d\n" RESET, sa_ptr->abm_len, *aad_len);
#endif
                goto end_of_function;
            }

            status = Crypto_Prepare_AOS_AAD(&pTfBuffer[0], *aad_len, sa_ptr->abm, &aad[0]);
            if (status != CRYPTO_LIB_SUCCESS)
            {
                goto end_of_function;
            }
        }
    }

end_of_function:
    return status;
}

void Crypto_AOSA_Handle_FECF(uint8_t *pTfBuffer, uint16_t *idx)
{
    if (current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
#ifdef FECF_DEBUG
        printf(KCYN "Calcing FECF over %d bytes\n" RESET, current_managed_parameters_struct.max_frame_size - 2);
#endif
        uint16_t new_fecf = 0x0000;

        if (crypto_config.crypto_create_fecf == CRYPTO_AOS_CREATE_FECF_TRUE)
        {
            new_fecf = Crypto_Calc_FECF((uint8_t *)pTfBuffer, current_managed_parameters_struct.max_frame_size - 2);
            pTfBuffer[current_managed_parameters_struct.max_frame_size - 2] = (uint8_t)((new_fecf & 0xFF00) >> 8);
            pTfBuffer[current_managed_parameters_struct.max_frame_size - 1] = (uint8_t)(new_fecf & 0x00FF);
        }
        else // CRYPTO_TC_CREATE_FECF_FALSE
        {
            pTfBuffer[current_managed_parameters_struct.max_frame_size - 2] = (uint8_t)0x00;
            pTfBuffer[current_managed_parameters_struct.max_frame_size - 1] = (uint8_t)0x00;
        }

        *idx += 2;
    }
}

void Crypto_AOSA_IV_ARSN_Debug_Print(SecurityAssociation_t *sa_ptr)
{
#ifdef DEBUG
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
}

void Crypto_AOSA_MAC_Debug_Print(SecurityAssociation_t *sa_ptr, uint16_t pdu_len, uint16_t idx)
{
#ifdef DEBUG
    if (sa_ptr->stmacf_len > 0)
    {
        printf(KYEL "Data length is %d\n" RESET, pdu_len);
        printf(KYEL "MAC location starts at: %d\n" RESET, idx);
        printf(KYEL "MAC length of %d\n" RESET, sa_ptr->stmacf_len);
    }
    else
    {
        printf(KYEL "MAC NOT SET TO BE USED IN SA - LENGTH IS 0\n");
    }
#endif
}

void Crypto_AOSA_Handle_OCF(uint8_t *pTfBuffer, SecurityAssociation_t *sa_ptr, uint16_t *idx, uint16_t pdu_len)
{
    if (current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        // Section 4.1.4.2 - OCF is always 4 octets
        uint16_t ocf_location = *idx + pdu_len + sa_ptr->stmacf_len;

#ifdef AOS_DEBUG
        printf(KYEL "OCF present at location %d\n" RESET, ocf_location);
#endif

        // If Idle data is being transmitted (no real data), set CLCW flag accordingly
        // Per Section 6.4.1 - we're handling Type-1 Report which corresponds to CLCW
        if (pdu_len == 0)
        {
            // Set Control Word Type Flag to 0 for CLCW
            pTfBuffer[ocf_location] &= 0x7F;

#ifdef AOS_DEBUG
            printf(KYEL "Setting OCF CLCW flag for idle data\n" RESET);
#endif
        }

        // Note: We don't modify other OCF fields as they should be handled by upper layers
        // This just ensures the OCF is properly accounted for in the frame structure
        *idx += OCF_SIZE;
    }
}

void Crypto_AOSA_Increment_ARSN(SecurityAssociation_t *sa_ptr)
{
    // Implement proper anti-replay sequence number handling per CCSDS 355.0-B-2
    if (sa_ptr->shsnf_len > 0)
    {
        // Section 4.2.5 of CCSDS 355.0-B-2: Sequence numbers shall be incremented by one for each frame
        Crypto_increment(sa_ptr->arsn, sa_ptr->arsn_len);

        // Check for sequence number rollover
        int is_all_zeros = CRYPTO_TRUE;
        for (int i = 0; i < sa_ptr->arsn_len; i++)
        {
            if (*(sa_ptr->arsn + i) != 0)
            {
                is_all_zeros = CRYPTO_FALSE;
                break;
            }
        }

        // Section 4.2.5.3: If a rollover is detected, SA must be re-established
        if (is_all_zeros)
        {
#ifdef SA_DEBUG
            printf(KRED "ARSN has rolled over! SA should be re-established.\n" RESET);
#endif
            // Mark the SA for rekeying
            sa_ptr->sa_state = SA_NONE;
        }
    }
}

int32_t Crypto_AOSA_Service_Type_Verify_Lengths(uint8_t sa_service_type, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (sa_service_type != SA_PLAINTEXT && sa_ptr->ecs_len == 0 && sa_ptr->acs_len == 0)
    {
        status = CRYPTO_LIB_ERR_NULL_CIPHERS;
#ifdef AOS_DEBUG
        printf(KRED "CRYPTO_LIB_ERR_NULL_CIPHERS, Invalid cipher lengths, %d\n" RESET, CRYPTO_LIB_ERR_NULL_CIPHERS);
        printf(KRED "\tservice type is: %d\n", sa_service_type);
        printf(KRED "\tsa_ptr->ecs_len is: %d\n", sa_ptr->ecs_len);
        printf(KRED "\tsa_ptr->acs_len is: %d\n", sa_ptr->acs_len);
#endif
        goto end_of_function;
    }

    if (sa_ptr->est == 0 && sa_ptr->ast == 1)
    {
        if (sa_ptr->acs_len > 0)
        {
            if (Crypto_Is_ACS_Only_Algo(sa_ptr->acs) && sa_ptr->iv_len > 0)
            {
                status = CRYPTO_LIB_ERR_IV_NOT_SUPPORTED_FOR_ACS_ALGO;
                goto end_of_function;
            }
        }
    }

end_of_function:
    return status;
}

int32_t Crypto_AOSA_Initial_Error_Checks(uint8_t *pTfBuffer)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Passed a null, return an error
    if (!pTfBuffer)
    {
        status = CRYPTO_LIB_ERR_NULL_BUFFER;
        goto end_of_function;
    }

    if ((crypto_config.init_status == UNITIALIZED) || (mc_if == NULL) || (sa_if == NULL))
    {
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        goto end_of_function;
    }

end_of_function:
    return status;
}

void Crypto_AOSA_Parse_Header(uint8_t *pTfBuffer, uint8_t *tfvn, uint16_t *scid, uint16_t *vcid)
{
    *tfvn = (pTfBuffer[0] & 0xC0) >> 6;
    *scid = ((pTfBuffer[0] & 0x3F) << 2) | ((pTfBuffer[1] & 0xC0) >> 6);
    *vcid = (pTfBuffer[1] & 0x3F);

#ifdef AOS_DEBUG
    printf(KYEL "\n----- Crypto_AOS_ApplySecurity START -----\n" RESET);
    printf("The following GVCID parameters will be used:\n");
    printf("\tTVFN: 0x%04X\t", *tfvn);
    printf("\tSCID: 0x%04X", *scid);
    printf("\tVCID: 0x%04X", *vcid);
    printf("\tMAP: %d\n", 0);
    printf("\tPriHdr as follows:\n\t\t");
    for (int i = 0; i < 6; i++)
    {
        printf("%02X", pTfBuffer[i]);
    }
    printf("\n");
#endif
}

int32_t Crypto_AOS_Encrypt(uint8_t sa_service_type, uint8_t ecs_is_aead_algorithm, uint8_t *pTfBuffer,
                           uint16_t data_loc, uint16_t pdu_len, crypto_key_t *ekp, crypto_key_t *akp,
                           SecurityAssociation_t *sa_ptr, uint32_t pkcs_padding, uint8_t *aad, uint16_t aad_len,
                           int mac_loc)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // AEAD Algorithm Logic
    if (sa_service_type != SA_PLAINTEXT && ecs_is_aead_algorithm == CRYPTO_TRUE)
    {
        if (sa_service_type == SA_ENCRYPTION)
        {
            status =
                cryptography_if
                    ->cryptography_encrypt( // Stub out data in/out as this is done in place and want to save cycles
                        (uint8_t *)(&pTfBuffer[data_loc]), // ciphertext output
                        (size_t)pdu_len,                   // length of data
                        (uint8_t *)(&pTfBuffer[data_loc]), // plaintext input
                        (size_t)pdu_len,                   // in data length - from start of frame to end of data
                        &(ekp->value[0]),                  // Key
                        Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs),
                        sa_ptr,         // SA (for key reference)
                        sa_ptr->iv,     // IV
                        sa_ptr->iv_len, // IV Length
                        &sa_ptr->ecs,   // encryption cipher
                        pkcs_padding,   // authentication cipher
                        NULL);
            if (status != CRYPTO_LIB_SUCCESS)
            {
                goto end_of_function;
            }
        }
        if (sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
        {
            status = cryptography_if->cryptography_aead_encrypt(
                (uint8_t *)(&pTfBuffer[data_loc]),       // ciphertext output
                (size_t)pdu_len,                         // length of data
                (uint8_t *)(&pTfBuffer[data_loc]),       // plaintext input
                (size_t)pdu_len,                         // in data length
                &(ekp->value[0]),                        // Key
                Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs), // Length of key derived from sa_ptr key_ref
                sa_ptr,                                  // SA (for key reference)
                sa_ptr->iv,                              // IV
                sa_ptr->iv_len,                          // IV Length
                &pTfBuffer[mac_loc],                     // tag output
                sa_ptr->stmacf_len,                      // tag size
                aad,                                     // AAD Input
                aad_len,                                 // Length of AAD
                (sa_ptr->est == 1), (sa_ptr->ast == 1), (sa_ptr->ast == 1),
                &sa_ptr->ecs, // encryption cipher
                &sa_ptr->acs, // authentication cipher
                NULL);
            if (status != CRYPTO_LIB_SUCCESS)
            {
                goto end_of_function;
            }
        }
    }

    else if (sa_service_type != SA_PLAINTEXT && ecs_is_aead_algorithm == CRYPTO_FALSE) // Non aead algorithm
    {
        // TODO - implement non-AEAD algorithm logic
        if (sa_service_type == SA_AUTHENTICATION)
        {
            status = cryptography_if->cryptography_authenticate( // Stub out data in/out as this is done in place and
                                                                 // want to save cycles
                (uint8_t *)(&pTfBuffer[0]),                      // ciphertext output
                (size_t)0,                                       // length of data
                (uint8_t *)(&pTfBuffer[0]),                      // plaintext input
                (size_t)0,                                       // in data length - from start of frame to end of data
                &(akp->value[0]),                                // Key
                Crypto_Get_ACS_Algo_Keylen(sa_ptr->acs),
                sa_ptr,              // SA (for key reference)
                sa_ptr->iv,          // IV
                sa_ptr->iv_len,      // IV Length
                &pTfBuffer[mac_loc], // tag output
                sa_ptr->stmacf_len,  // tag size
                aad,                 // AAD Input
                aad_len,             // Length of AAD
                sa_ptr->ecs,         // encryption cipher
                sa_ptr->acs,         // authentication cipher
                NULL);
            if (status != CRYPTO_LIB_SUCCESS)
            {
                goto end_of_function;
            }
        }
        else if (sa_service_type == SA_ENCRYPTION || sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
        {
            if (sa_service_type == SA_ENCRYPTION)
            {
                status =
                    cryptography_if
                        ->cryptography_encrypt( // Stub out data in/out as this is done in place and want to save cycles
                            (uint8_t *)(&pTfBuffer[data_loc]), // ciphertext output
                            (size_t)pdu_len,                   // length of data
                            (uint8_t *)(&pTfBuffer[data_loc]), // plaintext input
                            (size_t)pdu_len,                   // in data length - from start of frame to end of data
                            &(ekp->value[0]),                  // Key
                            Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs),
                            sa_ptr,         // SA (for key reference)
                            sa_ptr->iv,     // IV
                            sa_ptr->iv_len, // IV Length
                            &sa_ptr->ecs,   // encryption cipher
                            pkcs_padding,   // padding length
                            NULL);
                if (status != CRYPTO_LIB_SUCCESS)
                {
                    goto end_of_function;
                }
            }
        }
        else if (sa_service_type == SA_PLAINTEXT)
        {
            // Do nothing, SDLS fields were already copied into static frame in memory
        }
        else
        {
#ifdef AOS_DEBUG
            printf(KRED "Service type reported as: %d\n" RESET, sa_service_type);
            printf(KRED "ECS IS AEAD Value: %d\n" RESET, ecs_is_aead_algorithm);
#endif
            status = CRYPTO_LIB_ERR_UNSUPPORTED_MODE;
            goto end_of_function;
        }
    }

    if (sa_service_type != SA_PLAINTEXT)
    {
        Crypto_AOSA_Increment_ARSN(sa_ptr);

#ifdef SA_DEBUG
        Crypto_AOSA_IV_ARSN_Debug_Print(sa_ptr);
#endif
    }

end_of_function:
    return status;
}


int32_t Crypto_AOSA_Handle_Security_Header(uint8_t *pTfBuffer, uint16_t *idx, SecurityAssociation_t *sa_ptr, uint8_t sa_service_type, uint32_t *pkcs_padding, uint16_t cbc_padding)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    // Set SPI
    Crypto_AOSA_Set_SPI(pTfBuffer, idx, sa_ptr);

    // Set initialization vector if specified
#ifdef SA_DEBUG
    Crypto_AOS_IV_Debug_Print(sa_ptr);
#endif

    status = Crypto_AOSA_Service_Type_Verify_Lengths(sa_service_type, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

    // Start index from the transmitted portion
    Crypto_AOSA_Set_IV(pTfBuffer, sa_ptr, idx);

    // Set anti-replay sequence number if specified
    /**
     * See also: 4.1.1.4.2
     * 4.1.1.4.4 If authentication or authenticated encryption is not selected
     * for an SA, the Sequence Number field shall be zero octets in length.
     * Reference CCSDS 3550b1
     **/
    Crypto_AOSA_Set_ARSN(pTfBuffer, sa_ptr, idx);

    // Set security header padding if specified
    /**
     * 4.2.3.4 h) if the algorithm and mode selected for the SA require the use of
     * fill padding, place the number of fill bytes used into the Pad Length field
     * of the Security Header - Reference CCSDS 3550b1
     **/
    // TODO: Revisit this
    // TODO: Likely SA API Call
    /** 4.1.1.5.2 The Pad Length field shall contain the count of fill bytes used in the
     * cryptographic process, consisting of an integral number of octets. - CCSDS 3550b1
     **/
    // TODO: Set this depending on crypto cipher used

    status = Crypto_AOSA_Check_Padding_Lengths(pTfBuffer, idx, sa_ptr, pkcs_padding, cbc_padding);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        goto end_of_function;
    }

end_of_function:
    return status;
}


void Crypto_AOSA_Handle_Security_Trailer(uint8_t *pTfBuffer, SecurityAssociation_t *sa_ptr, uint16_t *idx, uint16_t pdu_len)
{
#ifdef AOS_DEBUG
    Crypto_AOSA_MAC_Debug_Print(sa_ptr, pdu_len, *idx);
#endif

    // Handle OCF (Operational Control Field) per CCSDS 732.0-B-4 Section 4.1.4
    Crypto_AOSA_Handle_OCF(&pTfBuffer[0], sa_ptr, idx, pdu_len);

    /**
     * End Authentication / Encryption
     **/

    // Only calculate & insert FECF if CryptoLib is configured to do so & gvcid includes FECF.
    Crypto_AOSA_Handle_FECF(&pTfBuffer[0], idx);
}