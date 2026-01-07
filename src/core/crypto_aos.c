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
    SecurityAssociation_t *sa_ptr      = NULL;
    uint8_t                tfvn        = 0;
    uint16_t               scid        = 0;
    uint16_t               vcid        = 0;
    uint16_t               cbc_padding = 0;

    // Prevent set but unused error
    cbc_padding = cbc_padding;

    // Passed a null, return an error
    if (!pTfBuffer)
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }

    if ((crypto_config_global.init_status == UNINITIALIZED) || (crypto_config_aos.init_status == UNINITIALIZED) ||
        (mc_if == NULL) || (sa_if == NULL))
    {
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        // Can't mc_log since it's not configured
        return status; // return immediately so a NULL crypto_config is not dereferenced later
    }

    tfvn = (pTfBuffer[0] & 0xC0) >> 6;
    scid = ((pTfBuffer[0] & 0x3F) << 2) | ((pTfBuffer[1] & 0xC0) >> 6);
    vcid = (pTfBuffer[1] & 0x3F);

#ifdef AOS_DEBUG
    printf(KYEL "\n----- Crypto_AOS_ApplySecurity START -----\n" RESET);
    printf("The following GVCID parameters will be used:\n");
    printf("\tTVFN: 0x%04X\t", tfvn);
    printf("\tSCID: 0x%04X", scid);
    printf("\tVCID: 0x%04X", vcid);
    printf("\tMAP: %d\n", 0);
    printf("\tPriHdr as follows:\n\t\t");
    for (int i = 0; i < 6; i++)
    {
        printf("%02X", pTfBuffer[i]);
    }
    printf("\n");
#endif

    if (crypto_config_global.sa_type == SA_TYPE_MARIADB)
    {
        mariadb_table_name = MARIADB_AOS_TABLE_NAME;
    }
    status = sa_if->sa_get_operational_sa_from_gvcid(tfvn, scid, vcid, 0, &sa_ptr);

    // No operational/valid SA found
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef AOS_DEBUG
        printf(KRED "Error: Could not retrieve an SA!\n" RESET);
#endif
        mc_if->mc_log(status);
        return status;
    }

    status = Crypto_Get_AOS_Managed_Parameters_For_Gvcid(tfvn, scid, vcid, aos_gvcid_managed_parameters_array,
                                                         &aos_current_managed_parameters_struct);

    // No managed parameters found
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef AOS_DEBUG
        printf(KRED "Error: No managed parameters found!\n" RESET);
#endif
        mc_if->mc_log(status);
        return status;
    }

    if ((len_ingest < aos_current_managed_parameters_struct.max_frame_size) &&
        (sa_ptr->ecs != CRYPTO_CIPHER_AES256_CBC) && (sa_ptr->ecs != CRYPTO_CIPHER_AES256_CBC_MAC))
    {
        status = CRYPTO_LIB_ERR_AOS_FL_LT_MAX_FRAME_SIZE;
        mc_if->mc_log(status);
        return status;
    }
    else if ((sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC) || (sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC_MAC))
    {
        if ((aos_current_managed_parameters_struct.max_frame_size - len_ingest) <= 16)
        {
            cbc_padding = aos_current_managed_parameters_struct.max_frame_size - len_ingest;
        }
        else
        {
            status = CRYPTO_LIB_ERR_AOS_FL_LT_MAX_FRAME_SIZE;
            mc_if->mc_log(status);
            return status;
        }
    }

    /*
    ** CCSDS 732.0-B-4 Compliance:
    ** Section 4.1.1 - AOS frames must have a fixed length for a given physical channel
    ** Special case for CBC mode ciphers that require padding
    */
    if ((sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC || sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC_MAC) &&
        (aos_current_managed_parameters_struct.max_frame_size - len_ingest) <= 16)
    {
        // For CBC mode, allow frames that are slightly shorter to account for padding
        cbc_padding = aos_current_managed_parameters_struct.max_frame_size - len_ingest;
#ifdef AOS_DEBUG
        printf(KYEL "CBC padding of %d bytes will be applied\n" RESET, cbc_padding);
#endif
    }
    else if ((aos_current_managed_parameters_struct.max_frame_size - len_ingest) != 0)
    {
#ifdef AOS_DEBUG
        printf(KRED "Frame length %d does not match required fixed length %d\n" RESET, len_ingest,
               aos_current_managed_parameters_struct.max_frame_size);
#endif
        status = CRYPTO_LIB_ERR_AOS_FL_LT_MAX_FRAME_SIZE;
        mc_if->mc_log(status);
        return status;
    }

#ifdef AOS_DEBUG
    printf(KYEL "AOS BEFORE Apply Sec:\n\t" RESET);
    for (int16_t i = 0; i < aos_current_managed_parameters_struct.max_frame_size - cbc_padding; i++)
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
        mc_if->mc_log(status);
        return status;
    }

    // Determine Algorithm cipher & mode. // TODO - Parse authentication_cipher, and handle AEAD cases properly
    if (sa_service_type != SA_PLAINTEXT)
    {
        ecs_is_aead_algorithm = Crypto_Is_AEAD_Algorithm(sa_ptr->ecs);
    }

#ifdef AOS_DEBUG
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
#endif

    // Increment to end of mandatory 6 byte AOS Pri Hdr
    idx = 6;

    // Detect if optional 2 byte FHEC is present
    if (aos_current_managed_parameters_struct.aos_has_fhec == AOS_HAS_FHEC)
    {
#ifdef AOS_DEBUG
        printf(KYEL "Calculating FHECF...\n" RESET);
#endif
        uint16_t calculated_fhecf = Crypto_Calc_FHECF(pTfBuffer);
        pTfBuffer[idx]            = (calculated_fhecf >> 8) & 0x00FF;
        pTfBuffer[idx + 1]        = (calculated_fhecf)&0x00FF;
        idx                       = 8;
    }

    // Detect if optional variable length Insert Zone is present
    // Per CCSDS 732.0-B-4 Section 4.1.3, Insert Zone is optional but fixed length for a physical channel
    if (aos_current_managed_parameters_struct.aos_has_iz == AOS_HAS_IZ)
    {
        // Section 4.1.3.2 - Validate Insert Zone length
        if (aos_current_managed_parameters_struct.aos_iz_len <= 0)
        {
            status = CRYPTO_LIB_ERR_INVALID_AOS_IZ_LENGTH;
#ifdef AOS_DEBUG
            printf(KRED "Error: Invalid Insert Zone length %d. Must be between 1 and 65535 octets.\n" RESET,
                   aos_current_managed_parameters_struct.aos_iz_len);
#endif
            mc_if->mc_log(status);
            return status;
        }

// Section 4.1.3.2.3 - All bits of the Insert Zone shall be set by the sending end
// Based on the managed parameter configuration, we're not modifying the Insert Zone contents
#ifdef AOS_DEBUG
        printf(KYEL "Insert Zone present with length %d octets\n" RESET,
               aos_current_managed_parameters_struct.aos_iz_len);
#endif

        idx += aos_current_managed_parameters_struct.aos_iz_len;
    }

    // Idx is now at SPI location

    /**
     * Begin Security Header Fields
     * Reference CCSDS SDLP 3550b1 4.1.1.1.3
     **/

    // Set SPI
    pTfBuffer[idx]     = ((sa_ptr->spi & 0xFF00) >> 8);
    pTfBuffer[idx + 1] = (sa_ptr->spi & 0x00FF);
    idx += 2;

    // Set initialization vector if specified
#ifdef SA_DEBUG
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
#endif
    if (sa_service_type != SA_PLAINTEXT && sa_ptr->ecs_len == 0 && sa_ptr->acs_len == 0)
    {
        status = CRYPTO_LIB_ERR_NULL_CIPHERS;
#ifdef AOS_DEBUG
        printf(KRED "CRYPTO_LIB_ERR_NULL_CIPHERS, Invalid cipher lengths, %d\n" RESET, CRYPTO_LIB_ERR_NULL_CIPHERS);
        printf(KRED "\tservice type is: %d\n", sa_service_type);
        printf(KRED "\tsa_ptr->ecs_len is: %d\n", sa_ptr->ecs_len);
        printf(KRED "\tsa_ptr->acs_len is: %d\n", sa_ptr->acs_len);
#endif
        mc_if->mc_log(status);
        return status;
    }

    if (sa_ptr->est == 0 && sa_ptr->ast == 1)
    {
        if (sa_ptr->acs_len > 0)
        {
            if (Crypto_Is_ACS_Only_Algo(sa_ptr->acs) && sa_ptr->iv_len > 0)
            {
                status = CRYPTO_LIB_ERR_IV_NOT_SUPPORTED_FOR_ACS_ALGO;
                mc_if->mc_log(status);
                return status;
            }
        }
    }
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
    int padding_length = 0;
    if (sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC || sa_ptr->ecs == CRYPTO_CIPHER_AES256_CBC_MAC)
    {
        for (i = 0; i < sa_ptr->shplf_len; i++)
        {
            padding_length = (padding_length << 8) | (uint8_t)pTfBuffer[idx];
            idx++;
        }
        pkcs_padding = padding_length;
    }

    if (pkcs_padding < cbc_padding)
    {
        status = CRYPTO_LIB_ERROR;
        printf(KRED "Error: pkcs_padding length %d is less than required %d\n" RESET, pkcs_padding, cbc_padding);
        mc_if->mc_log(status);
        return status;
    }
    /**
     * End Security Header Fields
     **/

    /**
     * ~~~Index currently at start of data field, AKA end of security header~~~
     **/
    data_loc = idx;
    // Calculate size of data to be encrypted
    pdu_len = aos_current_managed_parameters_struct.max_frame_size - idx - sa_ptr->stmacf_len;

    if (aos_current_managed_parameters_struct.max_frame_size < idx - sa_ptr->stmacf_len)
    {
        status = CRYPTO_LIB_ERR_AOS_FRAME_LENGTH_UNDERFLOW;
        mc_if->mc_log(status);
        return status;
    }

    // Check other managed parameter flags, subtract their lengths from data field if present
    if (aos_current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        pdu_len -= 4;
    }
    if (aos_current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        pdu_len -= 2;
    }

    if (aos_current_managed_parameters_struct.max_frame_size < pdu_len)
    {
        status = CRYPTO_LIB_ERR_AOS_FRAME_LENGTH_UNDERFLOW;
        mc_if->mc_log(status);
        return status;
    }

#ifdef AOS_DEBUG
    printf(KYEL "Data location starts at: %d\n" RESET, idx);
    printf(KYEL "Data size is: %d\n" RESET, pdu_len);
    printf(KYEL "Index at end of SPI is: %d\n", idx);
    if (aos_current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        // If OCF exists, comes immediately after MAC
        printf(KYEL "OCF Location is: %d" RESET, idx + pdu_len + sa_ptr->stmacf_len);
    }
    if (aos_current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        // If FECF exists, comes just before end of the frame
        printf(KYEL "FECF Location is: %d\n" RESET, aos_current_managed_parameters_struct.max_frame_size - 2);
    }
#endif

    int padding_location = idx + pdu_len;
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

    // Get Key
    crypto_key_t *ekp = NULL;
    crypto_key_t *akp = NULL;
    if (crypto_config_global.key_type != KEY_TYPE_KMC)
    {
        ekp = key_if->get_key(sa_ptr->ekid);
        akp = key_if->get_key(sa_ptr->akid);

        if (ekp == NULL || akp == NULL)
        {
            status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
            mc_if->mc_log(status);
            return status;
        }
        if (sa_ptr->est == 1)
        {
            if (ekp->key_state != KEY_ACTIVE)
            {
                status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
                mc_if->mc_log(status);
                return status;
            }
        }
        if (sa_ptr->ast == 1)
        {
            if (akp->key_state != KEY_ACTIVE)
            {
                status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
                mc_if->mc_log(status);
                return status;
            }
        }
    }

    /**
     * Begin Authentication / Encryption
     **/

    if (sa_service_type != SA_PLAINTEXT)
    {
        aad_len = 0;

        if (sa_service_type == SA_AUTHENTICATED_ENCRYPTION || sa_service_type == SA_AUTHENTICATION)
        {
            mac_loc = idx + pdu_len;
#ifdef MAC_DEBUG
            printf(KYEL "MAC location is: %d\n" RESET, mac_loc);
            printf(KYEL "MAC size is: %d\n" RESET, sa_ptr->stmacf_len);
#endif

            // Prepare the Header AAD (CCSDS 335.0-B-2 4.2.3.4)
            aad_len = idx; // At the very least AAD includes the header
            if (sa_service_type ==
                SA_AUTHENTICATION) // auth only, we authenticate the payload as part of the AEAD encrypt call here
            {
                aad_len += pdu_len;
            }
#ifdef AOS_DEBUG
            printf("Calculated AAD Length: %d\n", aad_len);
#endif
            if (sa_ptr->abm_len < aad_len)
            {
                status = CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
                printf(KRED "Error: abm_len of %d < aad_len of %d\n" RESET, sa_ptr->abm_len, aad_len);
                mc_if->mc_log(status);
                return status;
            }
            status = Crypto_Prepare_AOS_AAD(&pTfBuffer[0], aad_len, sa_ptr->abm, &aad[0]);
        }
    }

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
        }
    }

    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status; // Cryptography IF call failed, return.
    }

    if (sa_service_type != SA_PLAINTEXT)
    {
#ifdef INCREMENT
        if (crypto_config_aos.crypto_increment_nontransmitted_iv == SA_INCREMENT_NONTRANSMITTED_IV_TRUE)
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

    // Move idx to mac location
    idx += pdu_len;
#ifdef AOS_DEBUG
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

    // Handle OCF (Operational Control Field) per CCSDS 732.0-B-4 Section 4.1.4
    if (aos_current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        // Section 4.1.4.2 - OCF is always 4 octets
        uint16_t ocf_location = idx + pdu_len + sa_ptr->stmacf_len;

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
    }

    /**
     * End Authentication / Encryption
     **/

    // Only calculate & insert FECF if CryptoLib is configured to do so & gvcid includes FECF.
    if (aos_current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
#ifdef FECF_DEBUG
        printf(KCYN "Calcing FECF over %d bytes\n" RESET, aos_current_managed_parameters_struct.max_frame_size - 2);
#endif
        if (crypto_config_aos.crypto_create_fecf == CRYPTO_AOS_CREATE_FECF_TRUE)
        {
            new_fecf = Crypto_Calc_FECF((uint8_t *)pTfBuffer, aos_current_managed_parameters_struct.max_frame_size - 2);
            pTfBuffer[aos_current_managed_parameters_struct.max_frame_size - 2] = (uint8_t)((new_fecf & 0xFF00) >> 8);
            pTfBuffer[aos_current_managed_parameters_struct.max_frame_size - 1] = (uint8_t)(new_fecf & 0x00FF);
        }
        else // CRYPTO_TC_CREATE_FECF_FALSE
        {
            pTfBuffer[aos_current_managed_parameters_struct.max_frame_size - 2] = (uint8_t)0x00;
            pTfBuffer[aos_current_managed_parameters_struct.max_frame_size - 1] = (uint8_t)0x00;
        }
        idx += 2;
    }

#ifdef AOS_DEBUG
    printf(KYEL "Printing new AOS frame:\n\t");
    for (int i = 0; i < aos_current_managed_parameters_struct.max_frame_size; i++)
    {
        printf("%02X", pTfBuffer[i]);
    }
    printf("\n");
#endif

    status = sa_if->sa_save_sa(sa_ptr);

#ifdef DEBUG
    printf(KYEL "----- Crypto_AOS_ApplySecurity END -----\n" RESET);
#endif
    mc_if->mc_log(status);
    return status;
}

// int32_t Crypto_AOS_Nontransmitted_IV_Increment(SecurityAssociation_t *sa_ptr, AOS_t *pp_processed_frame)
// {
//     int32_t status = CRYPTO_LIB_SUCCESS;

//     if (sa_ptr->shivf_len < sa_ptr->iv_len && crypto_config_aos.ignore_anti_replay == AOS_IGNORE_ANTI_REPLAY_FALSE &&
//         crypto_config_aos.crypto_increment_nontransmitted_iv == SA_INCREMENT_NONTRANSMITTED_IV_TRUE)
//     {
//         status = crypto_handle_incrementing_nontransmitted_counter(
//             pp_processed_frame->aos_sec_header.iv, sa_ptr->iv, sa_ptr->iv_len, sa_ptr->shivf_len, sa_ptr->arsnw);
//         if (status != CRYPTO_LIB_SUCCESS)
//         {
//             mc_if->mc_log(status);
//             return status;
//         }
//     }
//     else // Not checking IV ARSNW or only non-transmitted portion is static; Note, non-transmitted IV in SA must
//     match
//          // frame or will fail MAC check.
//     {
//         // Retrieve non-transmitted portion of IV from SA (if applicable)
//         memcpy(pp_processed_frame->aos_sec_header.iv, sa_ptr->iv, sa_ptr->iv_len - sa_ptr->shivf_len);
//     }
//     return status;
// }

// int32_t Crypto_AOS_Nontransmitted_SN_Increment(SecurityAssociation_t *sa_ptr, AOS_t *pp_processed_frame)
// {
//     int32_t status = CRYPTO_LIB_SUCCESS;
//     if (sa_ptr->shsnf_len < sa_ptr->arsn_len && crypto_config_aos.ignore_anti_replay == AOS_IGNORE_ANTI_REPLAY_FALSE)
//     {
//         status =
//             crypto_handle_incrementing_nontransmitted_counter(pp_processed_frame->aos_sec_header.sn, sa_ptr->arsn,
//                                                               sa_ptr->arsn_len, sa_ptr->shsnf_len, sa_ptr->arsnw);
//         if (status != CRYPTO_LIB_SUCCESS)
//         {
//             mc_if->mc_log(status);
//         }
//     }
//     else // Not checking ARSN in ARSNW
//     {
//         // Parse non-transmitted portion of ARSN from SA
//         memcpy(pp_processed_frame->aos_sec_header.sn, sa_ptr->arsn, sa_ptr->arsn_len - sa_ptr->shsnf_len);
//     }
//     return status;
// }

int32_t Crypto_AOS_Check_IV_ARSN(SecurityAssociation_t *sa_ptr, AOS_t *pp_processed_frame)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if (crypto_config_aos.ignore_anti_replay == AOS_IGNORE_ANTI_REPLAY_FALSE)
    {
        status = Crypto_Check_Anti_Replay(sa_ptr, pp_processed_frame->aos_sec_header.sn,
                                          pp_processed_frame->aos_sec_header.iv,
                                          crypto_config_aos.crypto_increment_nontransmitted_iv);

        if (status != CRYPTO_LIB_SUCCESS)
        {
            mc_if->mc_log(status);
        }
        if (status == CRYPTO_LIB_SUCCESS) // else
        {
            // Only save the SA (IV/ARSN) if checking the anti-replay counter; Otherwise we don't update.
            status = sa_if->sa_save_sa(sa_ptr);
            if (status != CRYPTO_LIB_SUCCESS)
            {
                mc_if->mc_log(status);
            }
        }
    }
    else
    {
        if (crypto_config_global.sa_type == SA_TYPE_MARIADB)
        {
            if (sa_ptr->ek_ref[0] != '\0')
                clean_ekref(sa_ptr);
            if (sa_ptr->ak_ref[0] != '\0')
                clean_akref(sa_ptr);
            free(sa_ptr);
        }
    }
    return status;
}


int32_t Crypto_AOS_Verify_Frame_Lengths(uint16_t len_ingest)
{
    uint8_t  fhec_len = aos_current_managed_parameters_struct.aos_has_fhec == AOS_HAS_FHEC ? FHECF_SIZE : 0;
    uint16_t iz_len   = aos_current_managed_parameters_struct.aos_has_iz == AOS_HAS_IZ
                            ? aos_current_managed_parameters_struct.aos_iz_len
                            : 0;
    uint8_t  ocf_len  = aos_current_managed_parameters_struct.has_ocf == AOS_HAS_OCF ? OCF_SIZE : 0;
    uint8_t  fecf_len = aos_current_managed_parameters_struct.has_fecf == AOS_HAS_FECF ? FECF_SIZE : 0;
    uint16_t expected_frame_length = AOS_MIN_SIZE + fhec_len + SPI_LEN + iz_len + ocf_len + fecf_len;
    if (len_ingest < expected_frame_length)
    {
        return CRYPTO_LIB_ERR_INVALID_AOS_FRAME_LENGTH;
    }
    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: Crypto_AOS_ProcessSecurity
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @return int32: Success/Failure
 *
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 5 (AOS Protocol), CCSDS 732.0-B-4
 **/
int32_t Crypto_AOS_ProcessSecurity(uint8_t *p_ingest, uint16_t len_ingest, AOS_t *pp_processed_frame,
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
    uint8_t                spi               = -1;
    uint8_t                aos_hdr_len       = 6;

    // Bit math to give concise access to values in the ingest
    pp_processed_frame->aos_header.tfvn = ((uint8_t)p_ingest[0] & 0xC0) >> 6;
    pp_processed_frame->aos_header.scid = (((uint16_t)p_ingest[0] & 0x3F) << 2) | (((uint16_t)p_ingest[1] & 0xC0) >> 6);
    pp_processed_frame->aos_header.vcid = ((uint8_t)p_ingest[1] & 0x3F);

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_AOS_ProcessSecurity START -----\n" RESET);
#endif

    if (len_ingest < aos_hdr_len) // Frame length doesn't even have enough bytes for header -- error out.
    {
        status = CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_AOS_STANDARD;
        mc_if->mc_log(status);
        return status;
    }

    if ((crypto_config_global.init_status == UNINITIALIZED) || (crypto_config_aos.init_status == UNINITIALIZED) ||
        (mc_if == NULL) || (sa_if == NULL))
    {
#ifdef AOS_DEBUG
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
#endif
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        // Can't mc_log if it's not configured
        if (mc_if != NULL)
        {
            mc_if->mc_log(status);
        }
        return status;
    }

    // Query SA DB for active SA / SDLS parameters
    if (sa_if == NULL) // This should not happen, but tested here for safety
    {
        printf(KRED "ERROR: SA DB Not initalized! -- CRYPTO_LIB_ERR_NO_INIT, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_INIT;
        return status;
    }

#ifdef AOS_DEBUG
    printf(KGRN "AOS Process Using following parameters:\n\t" RESET);
    printf(KGRN "tvfn: %d\t scid: %d\t vcid: %d\n" RESET, pp_processed_frame->aos_header.tfvn,
           pp_processed_frame->aos_header.scid, pp_processed_frame->aos_header.vcid);
#endif

    // Lookup-retrieve managed parameters for frame via gvcid:
    status = Crypto_Get_AOS_Managed_Parameters_For_Gvcid(
        pp_processed_frame->aos_header.tfvn, pp_processed_frame->aos_header.scid, pp_processed_frame->aos_header.vcid,
        aos_gvcid_managed_parameters_array, &aos_current_managed_parameters_struct);

    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef AOS_DEBUG
        printf(KRED "**NO LUCK WITH GVCID!\n" RESET);
#endif
        mc_if->mc_log(status);
        return status;
    } // Unable to get necessary Managed Parameters for AOS TF -- return with error.

    status = Crypto_AOS_Verify_Frame_Lengths(len_ingest);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    // Increment to end of Primary Header start, depends on FHECF presence
    byte_idx = 6;
    if (aos_current_managed_parameters_struct.aos_has_fhec == AOS_HAS_FHEC)
    {
        uint16_t recieved_fhecf = (((p_ingest[aos_hdr_len] << 8) & 0xFF00) | (p_ingest[aos_hdr_len + 1] & 0x00FF));
#ifdef AOS_DEBUG
        printf("Recieved FHECF: %04x\n", recieved_fhecf);
        printf(KYEL "Calculating FHECF...\n" RESET);
#endif
        uint16_t calculated_fhecf = Crypto_Calc_FHECF(p_ingest);

        if (recieved_fhecf != calculated_fhecf)
        {
            status = CRYPTO_LIB_ERR_INVALID_FHECF;
            mc_if->mc_log(status);
            return status;
        }

        p_ingest[byte_idx]     = (calculated_fhecf >> 8) & 0x00FF;
        p_ingest[byte_idx + 1] = (calculated_fhecf)&0x00FF;
        byte_idx               = 8;
        aos_hdr_len            = byte_idx;
    }

    // Detect if optional variable length Insert Zone is present
    // Per CCSDS 732.0-B-4 Section 4.1.3, Insert Zone is optional but fixed length for a physical channel
    if (aos_current_managed_parameters_struct.aos_has_iz == AOS_HAS_IZ)
    {
        // Section 4.1.3.2 - Validate Insert Zone length
        if (aos_current_managed_parameters_struct.aos_iz_len <= 0)
        {
            status = CRYPTO_LIB_ERR_INVALID_AOS_IZ_LENGTH;
#ifdef AOS_DEBUG
            printf(KRED "Error: Invalid Insert Zone length %d. Must be between 1 and 65535 octets.\n" RESET,
                   aos_current_managed_parameters_struct.aos_iz_len);
#endif
            mc_if->mc_log(status);
            return status;
        }

// Section 4.1.3.2.3 - All bits of the Insert Zone shall be set by the sending end
// Based on the managed parameter configuration, we're not modifying the Insert Zone contents
#ifdef AOS_DEBUG
        printf(KYEL "Insert Zone present with length %d octets\n" RESET,
               aos_current_managed_parameters_struct.aos_iz_len);
#endif

        byte_idx += aos_current_managed_parameters_struct.aos_iz_len;
    }

    /**
     * Begin Security Header Fields
     * Reference CCSDS SDLP 3550b1 4.1.1.1.3
     **/
    // Get SPI
    spi = (uint8_t)p_ingest[byte_idx] << 8 | (uint8_t)p_ingest[byte_idx + 1];
    // Move index to past the SPI
    byte_idx += 2;

    pp_processed_frame->aos_sec_header.spi = spi;

    if (crypto_config_global.sa_type == SA_TYPE_MARIADB)
    {
        mariadb_table_name = MARIADB_AOS_TABLE_NAME;
    }
    status = sa_if->sa_get_from_spi(spi, &sa_ptr);
    // If no valid SPI, return
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
        if (crypto_config.sa_type == SA_TYPE_MARIADB)
        {
            free(sa_ptr);
        }
        return status;
    }

    if (len_ingest <
        aos_hdr_len + Crypto_Get_Security_Header_Length(sa_ptr) + Crypto_Get_Security_Trailer_Length(sa_ptr))
    {
        return CRYPTO_LIB_ERR_AOS_FRAME_LENGTH_UNDERFLOW;
    }

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
#ifdef SA_DEBUG
        printf(KRED "Error: SA Service Type is not defined! \n" RESET);
#endif
        status = CRYPTO_LIB_ERROR;
        mc_if->mc_log(status);
        if (crypto_config.sa_type == SA_TYPE_MARIADB)
        {
            free(sa_ptr);
        }
        return status;
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
        mc_if->mc_log(status);
        if (crypto_config.sa_type == SA_TYPE_MARIADB)
        {
            free(sa_ptr);
        }
        return status;
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

    if (len_ingest < aos_current_managed_parameters_struct.max_frame_size)
    {
        status = CRYPTO_LIB_ERR_AOS_FL_LT_MAX_FRAME_SIZE;
        mc_if->mc_log(status);
        if (crypto_config.sa_type == SA_TYPE_MARIADB)
        {
            free(sa_ptr);
        }
        return status;
    }

    // Parse & Check FECF, if present, and update fecf length
    if (aos_current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        uint16_t received_fecf = (((p_ingest[len_ingest - 2] << 8) & 0xFF00) | (p_ingest[len_ingest - 1] & 0x00FF));
#ifdef FECF_DEBUG
        printf("Received FECF is 0x%04X\n", received_fecf);
#endif

        if (crypto_config_aos.crypto_check_fecf == AOS_CHECK_FECF_TRUE)
        {
            // Calculate our own
            uint16_t calculated_fecf = Crypto_Calc_FECF(p_ingest, len_ingest - 2);
#ifdef FECF_DEBUG
            printf("Calculated FECF is 0x%04X\n", calculated_fecf);
            printf("FECF was Calced over %d bytes\n", len_ingest - 2);
#endif
            // Compare FECFs
            // Invalid FECF
            if (received_fecf != calculated_fecf)
            {
                status = CRYPTO_LIB_ERR_INVALID_FECF;
                mc_if->mc_log(status);
                if (crypto_config.sa_type == SA_TYPE_MARIADB)
                {
                    free(sa_ptr);
                }
                return status;
            }
            // Valid FECF, zero out the field
            else
            {
#ifdef FECF_DEBUG
                printf(KYEL "FECF CALC MATCHES! - GOOD\n" RESET);
#endif
                pp_processed_frame->aos_sec_trailer.fecf = received_fecf;
            }
        }
    }
    // Needs to be AOS_HAS_FECF (checked above, or AOS_NO_FECF)
    else if (aos_current_managed_parameters_struct.has_fecf != AOS_NO_FECF)
    {
#ifdef AOS_DEBUG
        printf(KRED "AOS_Process Error...tfvn: %d scid: 0x%04X vcid: 0x%02X fecf_enum: %d\n" RESET,
               aos_current_managed_parameters_struct.tfvn, aos_current_managed_parameters_struct.scid,
               aos_current_managed_parameters_struct.vcid, aos_current_managed_parameters_struct.has_fecf);
#endif
        status = CRYPTO_LIB_ERR_TC_ENUM_USED_FOR_AOS_CONFIG;
        mc_if->mc_log(status);
        if (crypto_config.sa_type == SA_TYPE_MARIADB)
        {
            free(sa_ptr);
        }
        return status;
    }

    // Accio buffer
    p_new_dec_frame = (uint8_t *)calloc(1, (len_ingest) * sizeof(uint8_t));
    if (!p_new_dec_frame)
    {
#ifdef DEBUG
        printf(KRED "Error: Calloc for decrypted output buffer failed! \n" RESET);
#endif
        status = CRYPTO_LIB_ERROR;
        mc_if->mc_log(status);
        if (crypto_config.sa_type == SA_TYPE_MARIADB)
        {
            free(sa_ptr);
        }
        return status;
    }

    // Copy over AOS Primary Header (6-8 bytes)
    memcpy(p_new_dec_frame, &p_ingest[0], aos_hdr_len);

    // Copy over insert zone data, if it exists
    if (aos_current_managed_parameters_struct.aos_has_iz == AOS_HAS_IZ)
    {
        memcpy(p_new_dec_frame + aos_hdr_len, &p_ingest[aos_hdr_len], aos_current_managed_parameters_struct.aos_iz_len);
#ifdef AOS_DEBUG
        printf("Copied over the following:\n\t");
        for (int i = 0; i < aos_current_managed_parameters_struct.aos_iz_len; i++)
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
    memcpy((pp_processed_frame->aos_sec_header.iv + (sa_ptr->iv_len - sa_ptr->shivf_len)), &(p_ingest[byte_idx]),
           sa_ptr->shivf_len);
    byte_idx += sa_ptr->shivf_len;

    memcpy((pp_processed_frame->aos_sec_header.sn + (sa_ptr->arsn_len - sa_ptr->shsnf_len)), &(p_ingest[byte_idx]),
           sa_ptr->shsnf_len);
    byte_idx += sa_ptr->shsnf_len;

    memcpy(&(pp_processed_frame->aos_sec_header.pad), &(p_ingest[byte_idx]), sa_ptr->shplf_len);
    byte_idx += sa_ptr->shplf_len;

#ifdef SA_DEBUG
    printf(KYEL "IV length of %d bytes\n" RESET, sa_ptr->shivf_len);
    printf(KYEL "SHSNF length of %d bytes\n" RESET, sa_ptr->shsnf_len);
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
    pdu_len = aos_current_managed_parameters_struct.max_frame_size - byte_idx - sa_ptr->stmacf_len;

    /*
    ** CCSDS 732.0-B-4 Section 4.1.5 - Operational Control Field (OCF)
    ** The OCF contains real-time Control Commands, reports, or status that may be required for
    ** the operation of the AOS Space Data Link Protocol.
    */
    if (aos_current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        pdu_len -= 4;
    }

    /*
    ** CCSDS 732.0-B-4 Section 4.1.6 - Frame Error Control Field (FECF)
    ** The FECF shall contain a sequence of 16 parity bits for error detection.
    */
    if (aos_current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        pdu_len -= 2;
    }

    if (pdu_len >= aos_current_managed_parameters_struct.max_frame_size)
    {
        return CRYPTO_LIB_ERR_AOS_FRAME_LENGTH_UNDERFLOW;
    }

    // If MAC exists, comes immediately after pdu
    if (sa_ptr->stmacf_len > 0)
    {
        mac_loc = byte_idx + pdu_len;
        memcpy((pp_processed_frame->aos_sec_trailer.mac + (MAC_SIZE - sa_ptr->stmacf_len)), &(p_ingest[mac_loc]),
               sa_ptr->stmacf_len);
    }
    Crypto_Set_FSR(p_ingest, byte_idx, pdu_len, sa_ptr);

#ifdef AOS_DEBUG
    printf(KYEL "Index / data location starts at: %d\n" RESET, byte_idx);
    printf(KYEL "Data size is: %d\n" RESET, pdu_len);
    if (aos_current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        // If OCF exists, comes immediately after MAC
        printf(KYEL "OCF Location is: %d" RESET, byte_idx + pdu_len + sa_ptr->stmacf_len);
    }
    if (aos_current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        // If FECF exists, comes just before end of the frame
        printf(KYEL "FECF Location is: %d\n" RESET, aos_current_managed_parameters_struct.max_frame_size - 2);
    }
#endif

    // // Increment IV/ARSN
    // memcpy((pp_processed_frame->aos_sec_header.iv + (sa_ptr->iv_len - sa_ptr->shivf_len)),
    //        &(p_ingest[aos_hdr_len + SPI_LEN]), sa_ptr->shivf_len);

    // // Handle non-transmitted IV increment case (transmitted-portion roll-over)
    // status = Crypto_AOS_Nontransmitted_IV_Increment(sa_ptr, pp_processed_frame);
    // if (status != CRYPTO_LIB_SUCCESS)
    // {
    //     return status;
    // }

    // // Parse transmitted portion of ARSN
    // memcpy((pp_processed_frame->aos_sec_header.sn + (sa_ptr->arsn_len - sa_ptr->shsnf_len)),
    //        &(p_ingest[aos_hdr_len + SPI_LEN + sa_ptr->shivf_len]), sa_ptr->shsnf_len);

    // // Handle non-transmitted SN increment case (transmitted-portion roll-over)
    // status = Crypto_AOS_Nontransmitted_SN_Increment(sa_ptr, pp_processed_frame);
    // if (status != CRYPTO_LIB_SUCCESS)
    // {
    //     return status;
    // }

    // Get Key
    crypto_key_t *ekp = NULL;
    crypto_key_t *akp = NULL;

    if (sa_ptr->est == 1)
    {
        if (crypto_config_global.key_type != KEY_TYPE_KMC)
        {
            ekp = key_if->get_key(sa_ptr->ekid);
            if (ekp == NULL)
            {
                status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
                mc_if->mc_log(status);
                free(p_new_dec_frame);
                if (crypto_config.sa_type == SA_TYPE_MARIADB)
                {
                    free(sa_ptr);
                }
                return status;
            }
            if (ekp->key_state != KEY_ACTIVE)
            {
                status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
                mc_if->mc_log(status);
                free(p_new_dec_frame);
                if (crypto_config.sa_type == SA_TYPE_MARIADB)
                {
                    free(sa_ptr);
                }
                return status;
            }
        }
    }
    if (sa_ptr->ast == 1)
    {
        if (crypto_config_global.key_type != KEY_TYPE_KMC)
        {
            akp = key_if->get_key(sa_ptr->akid);
            if (akp == NULL)
            {
                status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
                mc_if->mc_log(status);
                free(p_new_dec_frame);
                if (crypto_config.sa_type == SA_TYPE_MARIADB)
                {
                    free(sa_ptr);
                }
                return status;
            }
            if (akp->key_state != KEY_ACTIVE)
            {
                status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
                mc_if->mc_log(status);
                free(p_new_dec_frame);
                if (crypto_config.sa_type == SA_TYPE_MARIADB)
                {
                    free(sa_ptr);
                }
                return status;
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
            aad_len = iv_loc + sa_ptr->shivf_len;
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
            mc_if->mc_log(status);
            if (crypto_config.sa_type == SA_TYPE_MARIADB)
            {
                free(sa_ptr);
            }
            return status;
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
        if (crypto_config.sa_type == SA_TYPE_MARIADB)
        {
            free(sa_ptr);
        }
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
                mc_if->mc_log(status);
                if (crypto_config.sa_type == SA_TYPE_MARIADB)
                {
                    free(sa_ptr);
                }
                return status;
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

    // Now that MAC has been verified, check IV & ARSN if applicable
    status = Crypto_AOS_Check_IV_ARSN(sa_ptr, pp_processed_frame);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        // Crypto_TC_Safe_Free_Ptr(aad);
        mc_if->mc_log(status);
        return status; // Cryptography IF call failed, return.
    }

#ifdef AOS_DEBUG
    printf(KYEL "\nPrinting received frame:\n\t" RESET);
    for (int i = 0; i < aos_current_managed_parameters_struct.max_frame_size; i++)
    {
        printf(KYEL "%02X", p_ingest[i]);
    }
    printf(KYEL "\nPrinting PROCESSED frame:\n\t" RESET);
    for (int i = 0; i < aos_current_managed_parameters_struct.max_frame_size; i++)
    {
        printf(KYEL "%02X", p_new_dec_frame[i]);
    }
    printf("\n");
#endif

    // TODO maybe not just return this without doing the math ourselves
    *p_decrypted_length = aos_current_managed_parameters_struct.max_frame_size;

    // Copy data into struct
    byte_idx = 0;

    // Primary Header
    pp_processed_frame->aos_header.tfvn = (p_new_dec_frame[0] & 0xC0) >> 6;
    pp_processed_frame->aos_header.scid =
        (((uint16_t)p_new_dec_frame[0] & 0x3F) << 2) | (((uint16_t)p_new_dec_frame[1] & 0xC0) >> 6);
    pp_processed_frame->aos_header.vcid = (p_new_dec_frame[1] & 0x3F);
    pp_processed_frame->aos_header.vcfc = (p_new_dec_frame[2] << 16) | (p_new_dec_frame[3] << 8) | (p_new_dec_frame[4]);
    pp_processed_frame->aos_header.rf   = (p_new_dec_frame[5] & 0x80) >> 7;
    pp_processed_frame->aos_header.sf   = (p_new_dec_frame[5] & 0x40) >> 6;
    pp_processed_frame->aos_header.spare = (p_new_dec_frame[5] & 0x30) >> 4;
    pp_processed_frame->aos_header.vfcc  = (p_new_dec_frame[5] & 0x0F);
    if (aos_current_managed_parameters_struct.aos_has_fhec == AOS_HAS_FHEC)
    {
        pp_processed_frame->aos_header.fhecf = (p_new_dec_frame[6] << 8) | p_new_dec_frame[7];
        byte_idx += 8;
    }
    else
    {
        byte_idx += 6;
    }

    // Security Header
    if (aos_current_managed_parameters_struct.aos_has_iz == AOS_HAS_IZ)
    {
        for (int i = 0; i < aos_current_managed_parameters_struct.aos_iz_len; i++)
        {
            memcpy(pp_processed_frame->aos_sec_header.iz + i, &p_new_dec_frame[byte_idx + i], 1);
        }
        byte_idx += aos_current_managed_parameters_struct.aos_iz_len;
    }

    pp_processed_frame->aos_sec_header.spi = (((uint16_t)p_ingest[byte_idx]) << 8) | ((uint16_t)p_ingest[byte_idx + 1]);
    byte_idx += 2;

    for (int i = 0; i < sa_ptr->shivf_len; i++)
    {
        memcpy(pp_processed_frame->aos_sec_header.iv + i, &p_ingest[byte_idx + i], 1);
    }
    byte_idx += sa_ptr->shivf_len;
    pp_processed_frame->aos_sec_header.iv_field_len = sa_ptr->shivf_len;

    for (int i = 0; i < sa_ptr->shsnf_len; i++)
    {
        memcpy(pp_processed_frame->aos_sec_header.sn + i, &p_ingest[byte_idx + i], 1);
    }
    byte_idx += sa_ptr->shsnf_len;
    pp_processed_frame->aos_sec_header.sn_field_len = sa_ptr->shsnf_len;

    for (int i = 0; i < sa_ptr->shplf_len; i++)
    {
        pp_processed_frame->aos_sec_header.pad += (p_new_dec_frame[byte_idx + i] << ((sa_ptr->shplf_len - 1 - i) * 8));
    }
    byte_idx += sa_ptr->shplf_len;
    pp_processed_frame->aos_sec_header.pad_field_len = sa_ptr->shplf_len;

    // PDU
    memcpy(pp_processed_frame->aos_pdu, &p_new_dec_frame[byte_idx], pdu_len);
    pp_processed_frame->aos_pdu_len = pdu_len;
    byte_idx += pdu_len;

    // Security Trailer
    for (int i = 0; i < sa_ptr->stmacf_len; i++)
    {
        memcpy(pp_processed_frame->aos_sec_trailer.mac + i, &p_ingest[mac_loc + i], 1);
    }
    byte_idx += sa_ptr->stmacf_len;
    pp_processed_frame->aos_sec_trailer.mac_field_len = sa_ptr->stmacf_len;

    if (aos_current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        for (int i = 0; i < OCF_SIZE; i++)
        {
            memcpy(pp_processed_frame->aos_sec_trailer.ocf + i, &p_ingest[byte_idx + i], 1);
        }
        byte_idx += OCF_SIZE;
        pp_processed_frame->aos_sec_trailer.ocf_field_len = OCF_SIZE;
    }
    else
    {
        pp_processed_frame->aos_sec_trailer.ocf_field_len = 0;
    }

    if (aos_current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        pp_processed_frame->aos_sec_trailer.fecf =
            (uint16_t)(p_new_dec_frame[byte_idx] << 8) | p_new_dec_frame[byte_idx + 1];
    }
    free(p_new_dec_frame);
    if (crypto_config.sa_type == SA_TYPE_MARIADB)
    {
        free(sa_ptr);
    }

#ifdef DEBUG
    printf(KYEL "----- Crypto_AOS_ProcessSecurity END -----\n" RESET);
#endif
    mc_if->mc_log(status);
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
 * CCSDS Compliance: CCSDS 355.0-B-2 Section 4.2.3 (AAD Construction)
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
