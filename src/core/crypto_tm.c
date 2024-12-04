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

#include <string.h> // memcpy/memset

/**
 * @brief Function: Crypto_TM_Sanity_Check
 * Verify that needed buffers and settings are not null
 * @param pTfBuffer: uint8_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_TM_Sanity_Check(uint8_t *pTfBuffer)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    // Passed a null, return an error
    if (!pTfBuffer)
    {
        status = CRYPTO_LIB_ERR_NULL_BUFFER;
    }

    if ((status == CRYPTO_LIB_SUCCESS) &&
        ((crypto_config.init_status == UNITIALIZED) || (mc_if == NULL) || (sa_if == NULL)))
    {
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        // Can't mc_log since it's not configured
    }
    return status;
}

/**
 * @brief Function: Crypto_TM_Determine_SA_Service_Type
 * Determines the service type for Security Association
 * @param sa_service_type: uint8_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TM_Determine_SA_Service_Type(uint8_t *sa_service_type, SecurityAssociation_t *sa_ptr)
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
    }
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
    }
    return status;
}

/**
 * @brief Function: Crypto_TM_Check_For_Secondary_Header
 * Determines if a secondary header exists
 * @param pTfBuffer: uint8_t*
 * @param idx: uint16_t*
 **/
void Crypto_TM_Check_For_Secondary_Header(uint8_t *pTfBuffer, uint16_t *idx)
{
    *idx = 4;
    if ((pTfBuffer[*idx] & 0x80) == 0x80)
    {
#ifdef TM_DEBUG
        printf(KYEL "A TM Secondary Header flag is set!\n");
#endif
        // Secondary header is present
        *idx = 6;
        // Determine length of secondary header
        // Length coded as total length of secondary header - 1
        // Reference CCSDS 132.0-B-2 4.1.3.2.3
        uint8_t secondary_hdr_len = (pTfBuffer[*idx] & 0x3F);
#ifdef TM_DEBUG
        printf(KYEL "Secondary Header Length is decoded as: %d\n", secondary_hdr_len);
#endif
        // Increment from current byte (1st byte of secondary header),
        // to where the SPI would start
        *idx += secondary_hdr_len + 1;
    }
    else
    {
        // No Secondary header, carry on as usual and increment to SPI start
        *idx = 6;
    }
}

/**
 * @brief Function: Crypto_TM_IV_Sanity_Check
 * Verifies sanity of IV.  Validates IV Values, Ciphers, and Algorithms
 * @param sa_service_type: uint8_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TM_IV_Sanity_Check(uint8_t *sa_service_type, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
#ifdef SA_DEBUG
    if (sa_ptr->shivf_len > 0)
    {
        printf(KYEL "Using IV value:\n\t");
        for (int i = 0; i < sa_ptr->iv_len; i++)
        {
            printf("%02x", *(sa_ptr->iv + i));
        }
        printf("\n" RESET);
        printf(KYEL "Transmitted IV value:\n\t");
        for (int i = sa_ptr->iv_len - sa_ptr->shivf_len; i < sa_ptr->iv_len; i++)
        {
            printf("%02x", *(sa_ptr->iv + i));
        }
        printf("\n" RESET);
    }
#endif
    if (*sa_service_type != SA_PLAINTEXT && sa_ptr->ecs_len == 0 && sa_ptr->acs_len == 0)
    {
        status = CRYPTO_LIB_ERR_NULL_CIPHERS;
#ifdef TM_DEBUG
        printf(KRED "CRYPTO_LIB_ERR_NULL_CIPHERS, Invalid cipher lengths, %d\n" RESET, CRYPTO_LIB_ERR_NULL_CIPHERS);
#endif
        mc_if->mc_log(status);
        return status;
    }

    if (sa_ptr->est == 0 && sa_ptr->ast == 1)
    {
        if (sa_ptr->acs_len != 0)
        {
            if ((sa_ptr->acs == CRYPTO_MAC_CMAC_AES256 || sa_ptr->acs == CRYPTO_MAC_HMAC_SHA256 ||
                 sa_ptr->acs == CRYPTO_MAC_HMAC_SHA512) &&
                sa_ptr->iv_len > 0)
            {
                status = CRYPTO_LIB_ERR_IV_NOT_SUPPORTED_FOR_ACS_ALGO;
                mc_if->mc_log(status);
                return status;
            }
        }
    }
    return status;
}

/**
 * @brief Function: Crypto_TM_PKCS_Padding
 * Handles pkcs padding as necessary
 * @param pkcs_padding: uint32_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @param pTfBuffer: uint8_t*
 * @param idx_p: uint16_t*
 **/
void Crypto_TM_PKCS_Padding(uint32_t *pkcs_padding, SecurityAssociation_t *sa_ptr, uint8_t *pTfBuffer, uint16_t *idx_p)
{
    uint16_t idx = *idx_p;
    if (*pkcs_padding)
    {
        uint8_t hex_padding[3] = {0};                        // TODO: Create #Define for the 3
        *pkcs_padding          = *pkcs_padding & 0x00FFFFFF; // Truncate to be maxiumum of 3 bytes in size

        // Byte Magic
        hex_padding[0] = (*pkcs_padding >> 16) & 0xFF;
        hex_padding[1] = (*pkcs_padding >> 8) & 0xFF;
        hex_padding[2] = (*pkcs_padding) & 0xFF;

        uint8_t padding_start = 0;
        padding_start         = 3 - sa_ptr->shplf_len;

        for (int i = 0; i < sa_ptr->shplf_len; i++)
        {
            pTfBuffer[idx] = hex_padding[padding_start++];
            idx++;
        }
    }
    *idx_p = idx;
}

/**
 * @brief Function: Crypto_TM_Handle_Managed_Parameter_Flags
 * Handles pdu length while dealing with ocf/fecf
 * @param pdu_len: uint16_t*
 **/
void Crypto_TM_Handle_Managed_Parameter_Flags(uint16_t *pdu_len)
{
    if (current_managed_parameters_struct.has_ocf == TM_HAS_OCF)
    {
        *pdu_len -= 4;
    }
    if (current_managed_parameters_struct.has_fecf == TM_HAS_FECF)
    {
        *pdu_len -= 2;
    }
}

/**
 * @brief Function: Crypto_TM_Get_Keys
 * Retrieves keys from SA based on ekid/akid.
 * @param ekp: crypto_key_t**
 * @param akp: crypto_key_t**
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TM_Get_Keys(crypto_key_t **ekp, crypto_key_t **akp, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (sa_ptr->est == 1)
    {
        *ekp = key_if->get_key(sa_ptr->ekid);
        if (*ekp == NULL)
        {
            status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
            mc_if->mc_log(status);
            return status;
        }
        if ((*ekp)->key_state != KEY_ACTIVE)
        {
            status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
            mc_if->mc_log(status);
            return status;
        }
    }
    if (sa_ptr->ast == 1)
    {
        *akp = key_if->get_key(sa_ptr->akid);
        if (*akp == NULL)
        {
            status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
            mc_if->mc_log(status);
            return status;
        }
        if ((*akp)->key_state != KEY_ACTIVE)
        {
            status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
            mc_if->mc_log(status);
            return status;
        }
    }
    return status;
}

/**
 * @brief Function: Crypto_TM_Do_Encrypt_NONPLAINTEXT
 * Preps Encryption for Non-plain-text Authentication and Authenticated Encryption
 * @param sa_service_type: uint8_t
 * @param aad_len: uint16_t*
 * @param mac_loc: int*
 * @param idx_p: uint16_t*
 * @param pdu_len: uint16_t
 * @param pTfBuffer: uint8_t*
 * @param aad: uint8_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TM_Do_Encrypt_NONPLAINTEXT(uint8_t sa_service_type, uint16_t *aad_len, int *mac_loc, uint16_t *idx_p,
                                          uint16_t pdu_len, uint8_t *pTfBuffer, uint8_t *aad,
                                          SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    int16_t idx    = *idx_p;

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
#ifdef TM_DEBUG
            printf("Calculated AAD Length: %d\n", *aad_len);
#endif
            if (sa_ptr->abm_len < *aad_len)
            {
                status = CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
                printf(KRED "Error: abm_len of %d < *aad_len of %d\n" RESET, sa_ptr->abm_len, *aad_len);
                mc_if->mc_log(status);
            }
            if (status == CRYPTO_LIB_SUCCESS)
            {
                status = Crypto_Prepare_TM_AAD(pTfBuffer, *aad_len, sa_ptr->abm, aad);
            }
        }
    }

    *idx_p = idx;
    return status;
}

/**
 * @brief Function: Crypto_TM_Do_Encrypt_NONPLAINTEXT_AEAD_Logic
 * Preps Encryption for Non-plain-text Encryption and Authenticated Encryption for AEAD Algorithms
 * @param sa_service_type: uint8_t
 * @param ecs_is_aead_algorithm: uint8_t
 * @param pTfBuffer: uint8_t*
 * @param pdu_len: uint16_t
 * @param data_loc: uint16_t
 * @param ekp: crypto_key_t*
 * @param akp: crypto_key_t*
 * @param pkcs_padding: uint32_t
 * @param mac_loc: int*
 * @param aad_len: uint16_t*
 * @param aad: uint8_t*
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TM_Do_Encrypt_NONPLAINTEXT_AEAD_Logic(uint8_t sa_service_type, uint8_t ecs_is_aead_algorithm,
                                                     uint8_t *pTfBuffer, uint16_t pdu_len, uint16_t data_loc,
                                                     crypto_key_t *ekp, crypto_key_t *akp, uint32_t pkcs_padding,
                                                     int *mac_loc, uint16_t *aad_len, uint8_t *aad,
                                                     SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

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
                &pTfBuffer[*mac_loc],                    // tag output
                sa_ptr->stmacf_len,                      // tag size
                aad,                                     // AAD Input
                *aad_len,                                // Length of AAD
                (sa_ptr->est == 1), (sa_ptr->ast == 1), (sa_ptr->ast == 1),
                &sa_ptr->ecs, // encryption cipher
                &sa_ptr->acs, // authentication cipher
                NULL);
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
                sa_ptr,               // SA (for key reference)
                sa_ptr->iv,           // IV
                sa_ptr->iv_len,       // IV Length
                &pTfBuffer[*mac_loc], // tag output
                sa_ptr->stmacf_len,   // tag size
                aad,                  // AAD Input
                *aad_len,             // Length of AAD
                sa_ptr->ecs,          // encryption cipher
                sa_ptr->acs,          // authentication cipher
                NULL);
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
                            pkcs_padding,   // authentication cipher
                            NULL);
            }
        }
        else if (sa_service_type == SA_PLAINTEXT)
        {
            // Do nothing, SDLS fields were already copied into static frame in memory
        }
        else
        {
#ifdef TM_DEBUG
            printf(KRED "Service type reported as: %d\n" RESET, sa_service_type);
            printf(KRED "ECS IS AEAD Value: %d\n" RESET, ecs_is_aead_algorithm);
#endif
            status = CRYPTO_LIB_ERR_UNSUPPORTED_MODE;
        }
    }
    return status;
}

/**
 * @brief Function: Crypto_TM_Do_Encrypt_Handle_Increment
 * Handles the incrementing of IV and ARSN as necessary
 * @param sa_service_type: uint8_t
 * @param sa_ptr: SecurityAssociation_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TM_Do_Encrypt_Handle_Increment(uint8_t sa_service_type, SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (sa_service_type != SA_PLAINTEXT)
    {
#ifdef INCREMENT
        if (crypto_config.crypto_increment_nontransmitted_iv == SA_INCREMENT_NONTRANSMITTED_IV_TRUE)
        {
            if (sa_ptr->shivf_len > 0 && sa_ptr->iv_len != 0)
            {
                status = Crypto_increment(sa_ptr->iv, sa_ptr->iv_len);
            }
        }
        else // SA_INCREMENT_NONTRANSMITTED_IV_FALSE
        {
            // Only increment the transmitted portion
            if (sa_ptr->shivf_len > 0 && sa_ptr->iv_len != 0)
            {
                status = Crypto_increment(sa_ptr->iv + (sa_ptr->iv_len - sa_ptr->shivf_len), sa_ptr->shivf_len);
            }
        }
        if (sa_ptr->shsnf_len > 0 && status == CRYPTO_LIB_SUCCESS)
        {
            status = Crypto_increment(sa_ptr->arsn, sa_ptr->arsn_len);
        }

#ifdef SA_DEBUG
        if (sa_ptr->iv_len > 0)
        {
            printf(KYEL "Next IV value is:\n\t");
            for (int i = 0; i < sa_ptr->iv_len; i++)
            {
                printf("%02x", *(sa_ptr->iv + i));
            }
            printf("\n" RESET);
            printf(KYEL "Next transmitted IV value is:\n\t");
            for (int i = sa_ptr->iv_len - sa_ptr->shivf_len; i < sa_ptr->iv_len; i++)
            {
                printf("%02x", *(sa_ptr->iv + i));
            }
            printf("\n" RESET);
        }
        printf(KYEL "Next ARSN value is:\n\t");
        for (int i = 0; i < sa_ptr->arsn_len; i++)
        {
            printf("%02x", *(sa_ptr->arsn + i));
        }
        printf("\n" RESET);
        printf(KYEL "Next transmitted ARSN value is:\n\t");
        for (int i = sa_ptr->arsn_len - sa_ptr->shsnf_len; i < sa_ptr->arsn_len; i++)
        {
            printf("%02x", *(sa_ptr->arsn + i));
        }
        printf("\n" RESET);
#endif
#endif
    }
    return status;
}

/**
 * @brief Function: Crypto_TM_Do_Encrypt
 * Parent function for performing TM Encryption
 * @param sa_service_type: uint8_t
 * @param sa_ptr: SecurityAssociation_t*
 * @param aad_len: uint16_t*
 * @param mac_loc: int*
 * @param idx_p: uint16_t*
 * @param pdu_len: uint16_t
 * @param pTfBuffer: uint8_t*
 * @param aad: uint8_t*
 * @param ecs_is_aead_algorithm: uint8_t
 * @param data_loc: uint16_t
 * @param ekp: crypto_key_t*
 * @param akp: crypto_key_t*
 * @param pkcs_padding: uint32_t
 * @param new_fecf: uint16_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TM_Do_Encrypt(uint8_t sa_service_type, SecurityAssociation_t *sa_ptr, uint16_t *aad_len, int *mac_loc,
                             uint16_t *idx_p, uint16_t pdu_len, uint8_t *pTfBuffer, uint8_t *aad,
                             uint8_t ecs_is_aead_algorithm, uint16_t data_loc, crypto_key_t *ekp, crypto_key_t *akp,
                             uint32_t pkcs_padding, uint16_t *new_fecf)
{
    /**
     * Begin Authentication / Encryption
     **/
    uint16_t idx    = *idx_p;
    int32_t  status = CRYPTO_LIB_SUCCESS;
    status =
        Crypto_TM_Do_Encrypt_NONPLAINTEXT(sa_service_type, aad_len, mac_loc, idx_p, pdu_len, pTfBuffer, aad, sa_ptr);

    // AEAD Algorithm Logic
    if (status == CRYPTO_LIB_SUCCESS)
    {
        status = Crypto_TM_Do_Encrypt_NONPLAINTEXT_AEAD_Logic(sa_service_type, ecs_is_aead_algorithm, pTfBuffer,
                                                              pdu_len, data_loc, ekp, akp, pkcs_padding, mac_loc,
                                                              aad_len, aad, sa_ptr);
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
        status = Crypto_TM_Do_Encrypt_Handle_Increment(sa_service_type, sa_ptr);
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
        // Move idx to mac location
        idx += pdu_len;
#ifdef TM_DEBUG
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

        // TODO OCF - ? Here, elsewhere?

        /**
         * End Authentication / Encryption
         **/

        // Only calculate & insert FECF if CryptoLib is configured to do so & gvcid includes FECF.
        if (current_managed_parameters_struct.has_fecf == TM_HAS_FECF)
        {
#ifdef FECF_DEBUG
            printf(KCYN "Calcing FECF over %d bytes\n" RESET, current_managed_parameters_struct.max_frame_size - 2);
#endif
            if (crypto_config.crypto_create_fecf == CRYPTO_TM_CREATE_FECF_TRUE)
            {
                *new_fecf =
                    Crypto_Calc_FECF((uint8_t *)pTfBuffer, current_managed_parameters_struct.max_frame_size - 2);
                pTfBuffer[current_managed_parameters_struct.max_frame_size - 2] = (uint8_t)((*new_fecf & 0xFF00) >> 8);
                pTfBuffer[current_managed_parameters_struct.max_frame_size - 1] = (uint8_t)(*new_fecf & 0x00FF);
            }
            else // CRYPTO_TC_CREATE_FECF_FALSE
            {
                pTfBuffer[current_managed_parameters_struct.max_frame_size - 2] = (uint8_t)0x00;
                pTfBuffer[current_managed_parameters_struct.max_frame_size - 1] = (uint8_t)0x00;
            }
            idx += 2;
        }

#ifdef TM_DEBUG
        printf(KYEL "Printing new TM frame:\n\t");
        for (int i = 0; i < current_managed_parameters_struct.max_frame_size; i++)
        {
            printf("%02X", pTfBuffer[i]);
        }
        printf("\n");
#endif
    }
    if (status == CRYPTO_LIB_SUCCESS)
    {
        status = sa_if->sa_save_sa(sa_ptr);

#ifdef DEBUG
        printf(KYEL "----- Crypto_TM_ApplySecurity END -----\n" RESET);
#endif

        *idx_p = idx;
    }
    return status;
}

/**
 * @brief Function: Crypto_TM_ApplySecurity_Debug_Print
 * Simple Debug Print function for TM.  Displays
 * Data Location, size, and index at end of SPI.  OCF Location, FECF Location
 * @param idx: uint16_t
 * @param pdu_len: uint16_t
 * @param sa_ptr: SecurityAssociation_t*
 **/
void Crypto_TM_ApplySecurity_Debug_Print(uint16_t idx, uint16_t pdu_len, SecurityAssociation_t *sa_ptr)
{
    // Fix to ignore warnings
    idx     = idx;
    pdu_len = pdu_len;
    sa_ptr  = sa_ptr;

#ifdef TM_DEBUG
    printf(KYEL "Data location starts at: %d\n" RESET, idx);
    printf(KYEL "Data size is: %d\n" RESET, pdu_len);
    printf(KYEL "Index at end of SPI is: %d\n", idx);
    if (current_managed_parameters_struct.has_ocf == TM_HAS_OCF)
    {
        // If OCF exists, comes immediately after MAC
        printf(KYEL "OCF Location is: %d\n" RESET, idx + pdu_len + sa_ptr->stmacf_len);
    }
    if (current_managed_parameters_struct.has_fecf == TM_HAS_FECF)
    {
        // If FECF exists, comes just before end of the frame
        printf(KYEL "FECF Location is: %d\n" RESET, current_managed_parameters_struct.max_frame_size - 2);
    }
#endif
}

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
int32_t Crypto_TM_ApplySecurity(uint8_t *pTfBuffer)
{
    int32_t                status  = CRYPTO_LIB_SUCCESS;
    int                    mac_loc = 0;
    uint8_t                aad[1786];
    uint16_t               aad_len = 0;
    int                    i       = 0;
    uint16_t               data_loc;
    uint16_t               idx             = 0;
    uint8_t                sa_service_type = -1;
    uint16_t               pdu_len         = -1;
    uint32_t               pkcs_padding    = 0;
    uint16_t               new_fecf        = 0x0000;
    uint8_t                ecs_is_aead_algorithm;
    SecurityAssociation_t *sa_ptr = NULL;
    uint8_t                tfvn   = 0;
    uint16_t               scid   = 0;
    uint16_t               vcid   = 0;

    status = Crypto_TM_Sanity_Check(pTfBuffer);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    tfvn = ((uint8_t)pTfBuffer[0] & 0xC0) >> 6;
    scid = (((uint16_t)pTfBuffer[0] & 0x3F) << 4) | (((uint16_t)pTfBuffer[1] & 0xF0) >> 4);
    vcid = ((uint8_t)pTfBuffer[1] & 0x0E) >> 1;

#ifdef TM_DEBUG
    printf(KYEL "\n----- Crypto_TM_ApplySecurity START -----\n" RESET);
    printf("The following GVCID parameters will be used:\n");
    printf("\tTVFN: 0x%04X\t", tfvn);
    printf("\tSCID: 0x%04X", scid);
    printf("\tVCID: 0x%04X", vcid);
    printf("\tMAP: %d\n", 0);
    printf("\tPriHdr as follows:\n\t\t");
    for (int i = 0; i < 6; i++)
    {
        printf("%02X", (uint8_t)pTfBuffer[i]);
    }
    printf("\n");
#endif

    status = sa_if->sa_get_operational_sa_from_gvcid(tfvn, scid, vcid, 0, &sa_ptr);

    // No operational/valid SA found
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef TM_DEBUG
        printf(KRED "Error: Could not retrieve an SA!\n" RESET);
#endif
        mc_if->mc_log(status);
        return status;
    }

    status = Crypto_Get_Managed_Parameters_For_Gvcid(tfvn, scid, vcid, gvcid_managed_parameters_array,
                                                     &current_managed_parameters_struct);

    // No managed parameters found
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef TM_DEBUG
        printf(KRED "Error: No managed parameters found!\n" RESET);
#endif
        mc_if->mc_log(status);
        return status;
    }

#ifdef TM_DEBUG
    printf(KYEL "TM BEFORE Apply Sec:\n\t" RESET);
    for (int16_t i = 0; i < current_managed_parameters_struct.max_frame_size; i++)
    {
        printf("%02X", pTfBuffer[i]);
    }
    printf("\n");
#endif

#ifdef SA_DEBUG
    printf(KYEL "DEBUG - Printing SA Entry for current frame.\n" RESET);
    Crypto_saPrint(sa_ptr);
#endif

    // Determine SA Service Type
    status = Crypto_TM_Determine_SA_Service_Type(&sa_service_type, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
        return status;

    // Determine Algorithm cipher & mode. // TODO - Parse authentication_cipher, and handle AEAD cases properly
    if (sa_service_type != SA_PLAINTEXT)
    {
        ecs_is_aead_algorithm = Crypto_Is_AEAD_Algorithm(sa_ptr->ecs);
    }

#ifdef TM_DEBUG
    switch (sa_service_type)
    {
        case SA_PLAINTEXT:
            printf(KBLU "Creating a SDLS TM - CLEAR!\n" RESET);
            break;
        case SA_AUTHENTICATION:
            printf(KBLU "Creating a SDLS TM - AUTHENTICATED!\n" RESET);
            break;
        case SA_ENCRYPTION:
            printf(KBLU "Creating a SDLS TM - ENCRYPTED!\n" RESET);
            break;
        case SA_AUTHENTICATED_ENCRYPTION:
            printf(KBLU "Creating a SDLS TM - AUTHENTICATED ENCRYPTION!\n" RESET);
            break;
    }
#endif

    // Check if secondary header is present within frame
    // Note: Secondary headers are static only for a mission phase, not guaranteed static
    // over the life of a mission Per CCSDS 132.0-B.3 Section 4.1.2.7.2.3
    // Secondary Header flag is 1st bit of 5th byte (index 4)

    Crypto_TM_Check_For_Secondary_Header(pTfBuffer, &idx);

    /**
     * Begin Security Header Fields
     * Reference CCSDS SDLP 3550b1 4.1.1.1.3
     **/

    // Set SPI
    pTfBuffer[idx]     = ((sa_ptr->spi & 0xFF00) >> 8);
    pTfBuffer[idx + 1] = (sa_ptr->spi & 0x00FF);
    idx += 2;

    // Set initialization vector if specified
    status = Crypto_TM_IV_Sanity_Check(&sa_service_type, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
        return status;

    // Start index from the transmitted portion
    for (i = sa_ptr->iv_len - sa_ptr->shivf_len; i < sa_ptr->iv_len; i++)
    {
        // Copy in IV from SA
        pTfBuffer[idx] = *(sa_ptr->iv + i);
        idx++;
    }

    // Set anti-replay sequence number if specified
    /**
     * See also: 4.1.1.4.2
     * 4.1.1.4.4 If authentication or authenticated encryption is not selected
     * for an SA, the Sequence Number field shall be zero octets in length.
     * Reference CCSDS 3550b1
     **/
    for (i = sa_ptr->arsn_len - sa_ptr->shsnf_len; i < sa_ptr->arsn_len; i++)
    {
        // Copy in ARSN from SA
        pTfBuffer[idx] = *(sa_ptr->arsn + i);
        idx++;
    }

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
    Crypto_TM_PKCS_Padding(&pkcs_padding, sa_ptr, pTfBuffer, &idx);

    /**
     * End Security Header Fields
     **/

    // TODO: Padding handled here, or TO?
    //  for (uint32_t i = 0; i < pkcs_padding; i++)
    //  {
    //      /** 4.1.1.5.2 The Pad Length field shall contain the count of fill bytes used in the
    //       * cryptographic process, consisting of an integral number of octets. - CCSDS 3550b1
    //       **/
    //      // TODO: Set this depending on crypto cipher used
    //     * (p_new_enc_frame + index + i) = (uint8_t)pkcs_padding; // How much padding is needed?
    //      // index++;
    //  }

    /**
     * ~~~Index currently at start of data field, AKA end of security header~~~
     **/
    data_loc = idx;
    // Calculate size of data to be encrypted
    pdu_len = current_managed_parameters_struct.max_frame_size - idx - sa_ptr->stmacf_len;
    // Check other managed parameter flags, subtract their lengths from data field if present
    Crypto_TM_Handle_Managed_Parameter_Flags(&pdu_len);
    Crypto_TM_ApplySecurity_Debug_Print(idx, pdu_len, sa_ptr);

    // Get Key
    crypto_key_t *ekp = NULL;
    crypto_key_t *akp = NULL;
    status            = Crypto_TM_Get_Keys(&ekp, &akp, sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    status = Crypto_TM_Do_Encrypt(sa_service_type, sa_ptr, &aad_len, &mac_loc, &idx, pdu_len, pTfBuffer, aad,
                                  ecs_is_aead_algorithm, data_loc, ekp, akp, pkcs_padding, &new_fecf);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    mc_if->mc_log(status);
    return status;
}

/** Preserving for now
    // Check for idle frame trigger
    if (((uint8_t)ingest[0] == 0x08) && ((uint8_t)ingest[1] == 0x90))
    { // Zero ingest
        for (x = 0; x <*len_ingest; x++)
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
        spp_crc = Crypto_Calc_CRC16((uint8_t*)ingest,*len_ingest);
        ingest[*len_ingest] = (spp_crc & 0xFF00) >> 8;
        ingest[*len_ingest + 1] = (spp_crc & 0x00FF);
       *len_ingest =*len_ingest + 2;
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
    Crypto_TM_updatePDU(ingest,*len_ingest);
    printf("LINE: %d\n",__LINE__);
    if (sa_if->sa_get_from_spi(spi, &sa_ptr) != CRYPTO_LIB_SUCCESS)
    {
        // TODO - Error handling
        status = CRYPTO_LIB_ERROR;
        mc_if->mc_log(status);
        return status; // Error -- unable to get SA from SPI.
    }
    printf("LINE: %d\n",__LINE__);
    // Check test flags
    if (badSPI == 1)
    {
        tm_frame.tm_sec_header.spi++;
    }
    if (badIV == 1)
    {
       * (sa_ptr->iv + sa_ptr->shivf_len - 1) =* (sa_ptr->iv + sa_ptr->shivf_len - 1) + 1;
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
    // pad_len = Crypto_Get_tmLength(*len_ingest) - TM_MIN_SIZE + IV_SIZE + TM_PAD_SIZE -*len_ingest;
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
                tempTM[count++] =* (sa_ptr->iv + x);
            }
        }
        pdu_loc = count;
        pad_len = pad_len - IV_SIZE - TM_PAD_SIZE + OCF_SIZE;
        pdu_len =*len_ingest + pad_len;
    }
    else
    {                           // Include padding length bytes - hard coded per ESA testing
        printf("LINE: %d\n",__LINE__);
        tempTM[count++] = 0x00; // pad_len >> 8;
        tempTM[count++] = 0x1A; // pad_len
        pdu_loc = count;
        pdu_len =*len_ingest + pad_len;
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
    tm_frame.tm_sec_trailer.fecf = Crypto_Calc_FECF((uint8_t*)tempTM, count);
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
            aad[y] = ingest[y] &* (sa_ptr->abm + y);
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
                                                           &(ekp->value[0]), // Key
                                                           KEY_SIZE,
                                                           sa_ptr,
                                                           sa_ptr->iv,
                                                           sa_ptr->shivf_len,
                                                           &(ingest[mac_loc]),
                                                           MAC_SIZE,
                                                           &(aad[0]), // AAD Input location
                                                           sa_ptr->abm_len, // AAD is size of ABM in this case
                                                           CRYPTO_TRUE, // Encrypt
                                                           CRYPTO_FALSE, // Authenticate // TODO -- Set to SA value,
manually setting to false here so existing tests pass. Existing data was generated with authenticate then encrypt, when
it should have been encrypt then authenticate. CRYPTO_TRUE, // Use AAD sa_ptr->ecs, // encryption cipher sa_ptr->acs, //
authentication cipher NULL // cam_cookies (not supported in TM functions yet)
                                                           );


        // Update OCF
        y = 0;
        for (x = OCF_SIZE; x > 0; x--)
        {
            ingest[fecf_loc - x] = tm_frame.tm_sec_trailer.ocf[y++];
        }

        // Update FECF
        tm_frame.tm_sec_trailer.fecf = Crypto_Calc_FECF((uint8_t*)ingest, fecf_loc - 1);
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
    mc_if->mc_log(status);
    return status;
}  **/

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
        mc_if->mc_log(status);
    }

    if ((status == CRYPTO_LIB_SUCCESS) &&
        ((crypto_config.init_status == UNITIALIZED) || (mc_if == NULL) || (sa_if == NULL)))
    {
#ifdef TM_DEBUG
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
#endif
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        // Can't mc_log if it's not configured
        if (mc_if != NULL)
        {
            mc_if->mc_log(status);
        }
    }

    // Query SA DB for active SA / SDLS parameters
    if ((sa_if == NULL) && (status == CRYPTO_LIB_SUCCESS)) // This should not happen, but tested here for safety
    {
        printf(KRED "ERROR: SA DB Not initalized! -- CRYPTO_LIB_ERR_NO_INIT, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_INIT;
    }

#ifdef TM_DEBUG
    printf(KGRN "TM Process Using following parameters:\n\t" RESET);
    printf(KGRN "tvfn: %d\t scid: %d\t vcid: %d\n" RESET, tm_frame_pri_hdr.tfvn, tm_frame_pri_hdr.scid,
           tm_frame_pri_hdr.vcid);
#endif

    // Lookup-retrieve managed parameters for frame via gvcid:
    if (status == CRYPTO_LIB_SUCCESS)
    {
        status =
            Crypto_Get_Managed_Parameters_For_Gvcid(tm_frame_pri_hdr.tfvn, tm_frame_pri_hdr.scid, tm_frame_pri_hdr.vcid,
                                                    gvcid_managed_parameters_array, &current_managed_parameters_struct);
    }

    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef TM_DEBUG
        printf(KRED "**NO LUCK WITH GVCID!\n" RESET);
#endif
        // Can't mc_log if it's not configured
        if (mc_if != NULL)
        {
            mc_if->mc_log(status);
        }
    } // Unable to get necessary Managed Parameters for TM TF -- return with error.

    // Check if secondary header is present within frame
    // Note: Secondary headers are static only for a mission phase, not guaranteed static
    // over the life of a mission Per CCSDS 132.0-B.3 Section 4.1.2.7.2.3

    if (status == CRYPTO_LIB_SUCCESS)
    {
        // Secondary Header flag is 1st bit of 5th byte (index 4)
        *byte_idx = 4;
        if ((p_ingest[*byte_idx] & 0x80) == 0x80)
        {
#ifdef TM_DEBUG
            printf(KYEL "A TM Secondary Header flag is set!\n");
#endif
            // Secondary header is present
            *byte_idx = 6;
            // Determine length of secondary header
            // Length coded as total length of secondary header - 1
            // Reference CCSDS 132.0-B-2 4.1.3.2.3
            *secondary_hdr_len = (p_ingest[*byte_idx] & 0x3F) + 1;
#ifdef TM_DEBUG
            printf(KYEL "Secondary Header Length is decoded as: %d\n", *secondary_hdr_len);
#endif
            // Increment from current byte (1st byte of secondary header),
            // to where the SPI would start
            *byte_idx += *secondary_hdr_len;
        }
        else
        {
            // No Secondary header, carry on as usual and increment to SPI start
            *byte_idx = 6;
        }
    }

    return status;
}

/**
 * @brief Function: Crypto_TM_Determine_Cipher_Mode
 * Determines Cipher mode and Algorithm type
 * @param sa_service_type: uint8_t
 * @param sa_ptr: SecurityAssociation_t*
 * @param encryption_cipher: uint32_t*
 * @param ecs_is_aead_algorithm: uint8_t*
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TM_Determine_Cipher_Mode(uint8_t sa_service_type, SecurityAssociation_t *sa_ptr,
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
        mc_if->mc_log(status);
    }

    return status;
}

/**
 * @brief Function: Crypto_TM_FECF_Setup
 * Handles FECF Calculations, Verification, and Setup
 * @param p_ingest: uint8_t*
 * @param len_ingest: uint16_t
 * @return int32_t: Success/Failure
 **/
int32_t Crypto_TM_FECF_Setup(uint8_t *p_ingest, uint16_t len_ingest)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (current_managed_parameters_struct.has_fecf == TM_HAS_FECF)
    {
        uint16_t received_fecf = (((p_ingest[current_managed_parameters_struct.max_frame_size - 2] << 8) & 0xFF00) |
                                  (p_ingest[current_managed_parameters_struct.max_frame_size - 1] & 0x00FF));

        if (crypto_config.crypto_check_fecf == TM_CHECK_FECF_TRUE)
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
                mc_if->mc_log(status);
            }
            // Valid FECF, zero out the field
            else
            {
#ifdef FECF_DEBUG
                printf(KYEL "FECF CALC MATCHES! - GOOD\n" RESET);
#endif
                ;
            }
        }
    }
    // Needs to be TM_HAS_FECF (checked above_ or TM_NO_FECF)
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
 * @brief Function: Crypto_TM_Parse_Mac_Prep_AAD
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
int32_t Crypto_TM_Parse_Mac_Prep_AAD(uint8_t sa_service_type, uint8_t *p_ingest, int mac_loc,
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
            mc_if->mc_log(status);
        }
        // Use ingest and abm to create aad
        if (status == CRYPTO_LIB_SUCCESS)
        {
            status = Crypto_Prepare_TM_AAD(p_ingest, *aad_len, sa_ptr->abm, aad);
        }

#ifdef MAC_DEBUG
        if (status == CRYPTO_LIB_SUCCESS)
        {
            printf("AAD Debug:\n\tAAD Length is %d\n\t AAD is: ", *aad_len);
            for (int i = 0; i < *aad_len; i++)
            {
                printf("%02X", aad[i]);
            }
            printf("\n");
        }
#endif
    }
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
    }
    if (sa_service_type == SA_ENCRYPTION || sa_service_type == SA_AUTHENTICATED_ENCRYPTION)
    {
        // Check that key length to be used meets the algorithm requirement
        if ((int32_t)ekp->key_len != Crypto_Get_ECS_Algo_Keylen(sa_ptr->ecs))
        {
            // free(aad); - non-heap object
            status = CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
            mc_if->mc_log(status);
            // return status;
        }

        if (status == CRYPTO_LIB_SUCCESS)
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

        // //Handle Padding Removal
        // if(sa_ptr->shplf_len != 0)
        // {
        //     int padding_location = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len +
        //                             sa_ptr->shsnf_len;
        //     uint16_t padding_amount = 0;
        //     // Get Padding Amount from ingest frame
        //     padding_amount = (int)ingest[padding_location];
        //     // Remove Padding from final decrypted portion
        //     tc_sdls_processed_frame->tc_pdu_len -= padding_amount;
        // }
    }
    return status;
}

/**
 * @brief Function: Crypto_TM_Calc_PDU_MAC
 * Calculates the PDU MAC
 * @param pdu_len: uint16_t*
 * @param byte_idx: uint16_t
 * @param sa_ptr: SecurityAssociation_t*
 * @param mac_loc: int*
 * @return int32_t: Success/Failure
 */
void Crypto_TM_Calc_PDU_MAC(uint16_t *pdu_len, uint16_t byte_idx, SecurityAssociation_t *sa_ptr, int *mac_loc)
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
    }

    else if (sa_service_type != SA_PLAINTEXT && ecs_is_aead_algorithm == CRYPTO_FALSE)
    {
        status = Crypto_TM_Do_Decrypt_NONAEAD(sa_service_type, pdu_len, p_new_dec_frame, byte_idx, p_ingest, akp, ekp,
                                              sa_ptr, iv_loc, mac_loc, aad_len, aad);
        // TODO - implement non-AEAD algorithm logic
    }

    // If plaintext, copy byte by byte
    else if (sa_service_type == SA_PLAINTEXT)
    {
        memcpy(p_new_dec_frame + byte_idx, &(p_ingest[byte_idx]), pdu_len);
        byte_idx += pdu_len;
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
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
    }

    return status;
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
    uint8_t                iv_loc;
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
    if (status == CRYPTO_LIB_SUCCESS)
    {
        /**
         * Begin Security Header Fields
         * Reference CCSDS SDLP 3550b1 4.1.1.1.3
         **/
        // Get SPI
        spi = (uint8_t)p_ingest[byte_idx] << 8 | (uint8_t)p_ingest[byte_idx + 1];
        // Move index to past the SPI
        byte_idx += 2;

        status = sa_if->sa_get_from_spi(spi, &sa_ptr);
    }

    // If no valid SPI, return
    if (status == CRYPTO_LIB_SUCCESS)
    {
#ifdef SA_DEBUG
        printf(KYEL "DEBUG - Printing SA Entry for current frame.\n" RESET);
        Crypto_saPrint(sa_ptr);
#endif
        // Determine SA Service Type
        status = Crypto_TM_Determine_SA_Service_Type(&sa_service_type, sa_ptr);
    }
    if (status == CRYPTO_LIB_SUCCESS)
    {
        // Determine Algorithm cipher & mode. // TODO - Parse authentication_cipher, and handle AEAD cases properly
        status = Crypto_TM_Determine_Cipher_Mode(sa_service_type, sa_ptr, &encryption_cipher, &ecs_is_aead_algorithm);
    }
    if (status == CRYPTO_LIB_SUCCESS)
    {
#ifdef TM_DEBUG
        switch (sa_service_type)
        {
            case SA_PLAINTEXT:
                printf(KBLU "Processing a TM - CLEAR!\n" RESET);
                break;
            case SA_AUTHENTICATION:
                printf(KBLU "Processing a TM - AUTHENTICATED!\n" RESET);
                break;
            case SA_ENCRYPTION:
                printf(KBLU "Processing a TM - ENCRYPTED!\n" RESET);
                break;
            case SA_AUTHENTICATED_ENCRYPTION:
                printf(KBLU "Processing a TM - AUTHENTICATED ENCRYPTION!\n" RESET);
                break;
        }
#endif

        // Parse & Check FECF, if present, and update fecf length
        status = Crypto_TM_FECF_Setup(p_ingest, len_ingest);
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
        // Accio buffer
        p_new_dec_frame = (uint8_t *)calloc(1, (len_ingest) * sizeof(uint8_t));
        if (!p_new_dec_frame)
        {
#ifdef DEBUG
            printf(KRED "Error: Calloc for decrypted output buffer failed! \n" RESET);
#endif
            status = CRYPTO_LIB_ERROR;
        }
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
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
        Crypto_TM_Calc_PDU_MAC(&pdu_len, byte_idx, sa_ptr, &mac_loc);

        Crypto_TM_Process_Debug_Print(byte_idx, pdu_len, sa_ptr);

        Crypto_Set_FSR(p_ingest, byte_idx, pdu_len, sa_ptr);
        // Crypto_TM_Print_CLCW(p_ingest, byte_idx, pdu_len, sa_ptr);

        // Get Key
        status = Crypto_TM_Get_Keys(&ekp, &akp, sa_ptr);
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
        /**
         * Begin Authentication / Encryption
         **/

        // if(sa_service_type != SA_PLAINTEXT)
        // {
        // status = CRYPTO_LIB_ERR_NULL_CIPHERS;
        // mc_if->mc_log(status);
        // return status;
        // }

        // Parse MAC, prepare AAD
        Crypto_TM_Parse_Mac_Prep_AAD(sa_service_type, p_ingest, mac_loc, sa_ptr, &aad_len, byte_idx, aad);

        if (sa_ptr->sa_state != SA_OPERATIONAL)
        {
#ifdef DEBUG
            printf(KRED "Error: SA Not Operational \n" RESET);
#endif
            return CRYPTO_LIB_ERR_SA_NOT_OPERATIONAL;
        }

        status = Crypto_TM_Do_Decrypt(sa_service_type, sa_ptr, ecs_is_aead_algorithm, byte_idx, p_new_dec_frame,
                                      pdu_len, p_ingest, ekp, akp, iv_loc, mac_loc, aad_len, aad, pp_processed_frame,
                                      p_decrypted_length);
    }

    return status;
}

void Crypto_TM_Print_CLCW(uint8_t *p_ingest, uint16_t byte_idx, uint16_t pdu_len, SecurityAssociation_t *sa_ptr)
{
    if (current_managed_parameters_struct.has_ocf == TM_HAS_OCF)
    {
        byte_idx += (pdu_len + sa_ptr->stmacf_len);
        Telemetry_Frame_Ocf_Clcw_t clcw;
        clcw.cwt = (p_ingest[byte_idx] >> 7) & 0x0001;
        clcw.cvn = (p_ingest[byte_idx] >> 5) & 0x0003;
        clcw.sf  = (p_ingest[byte_idx] >> 2) & 0x0007;
        clcw.cie = (p_ingest[byte_idx] >> 0) & 0x0003;
        byte_idx += 1;
        clcw.vci    = (p_ingest[byte_idx] >> 2) & 0x003F;
        clcw.spare0 = (p_ingest[byte_idx] >> 0) & 0x0003;
        byte_idx += 1;
        clcw.nrfaf  = (p_ingest[byte_idx] >> 7) & 0x0001;
        clcw.nblf   = (p_ingest[byte_idx] >> 6) & 0x0001;
        clcw.lof    = (p_ingest[byte_idx] >> 5) & 0x0001;
        clcw.waitf  = (p_ingest[byte_idx] >> 4) & 0x0001;
        clcw.rtf    = (p_ingest[byte_idx] >> 3) & 0x0001;
        clcw.fbc    = (p_ingest[byte_idx] >> 1) & 0x0003;
        clcw.spare1 = (p_ingest[byte_idx] >> 0) & 0x0001;
        byte_idx += 1;
        clcw.rv = (p_ingest[byte_idx]);
        byte_idx += 1;

        Crypto_clcwPrint(&clcw);
    }
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
/**
void Crypto_TM_updatePDU(uint8_t* ingest, int len_ingest)
{ // Copy ingest to PDU
    int x = 0;
    // int y = 0;
    // int fill_size = 0;
    SecurityAssociation_t* sa_ptr;

    // Consider a helper function here, or elsewhere, to do all the 'math' in one spot as a global accessible list of
variables if (sa_if->sa_get_from_spi(tm_frame[0], &sa_ptr) != CRYPTO_LIB_SUCCESS) // modify
    {
        // TODO - Error handling
        printf(KRED"Update PDU Error!\n");
        return; // Error -- unable to get SA from SPI.
    }
    if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
    {
        // fill_size = 1129 - MAC_SIZE - IV_SIZE + 2; // +2 for padding bytes
    }
    else
    {
        // fill_size = 1129;
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
    // Copy actual packet
    while (x < len_ingest + tm_offset)
    {
        // printf("%s, Line: %d\n", __FILE__, __LINE__);
        // printf("ingest[x - tm_offset] = 0x%02x \n", (uint8_t)ingest[x - tm_offset]);
        printf("%02X", (uint8_t)ingest[x - tm_offset]);
        // tm_frame.tm_pdu[x] = (uint8_t)ingest[x - tm_offset];
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
  **/
/**
 * @brief Function: Crypto_TM_updateOCF
 * Update the TM OCF
 **/

void Crypto_TM_updateOCF(Telemetry_Frame_Ocf_Fsr_t *report, TM_t *tm_frame)
{
    // TODO
    tm_frame->tm_sec_trailer.ocf[0] = (report->cwt << 7) | (report->fvn << 4) | (report->af << 3) |
                                      (report->bsnf << 2) | (report->bmacf << 1) | (report->bsaf);
    tm_frame->tm_sec_trailer.ocf[1] = (report->lspi & 0xFF00) >> 8;
    tm_frame->tm_sec_trailer.ocf[2] = (report->lspi & 0x00FF);
    tm_frame->tm_sec_trailer.ocf[3] = (report->snval);
    // Alternate OCF
    // ocf = 0;
#ifdef OCF_DEBUG
    Crypto_fsrPrint(report);
#endif
}

/**
 * @brief Function: Crypto_Prepare_TM_AAD
 * Bitwise ANDs buffer with abm, placing results in aad buffer
 * @param buffer: uint8_t*
 * @param len_aad: uint16_t
 * @param abm_buffer: uint8_t*
 * @param aad: uint8_t*
 * @return status: uint32_t
 **/
uint32_t Crypto_Prepare_TM_AAD(const uint8_t *buffer, uint16_t len_aad, const uint8_t *abm_buffer, uint8_t *aad)
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
