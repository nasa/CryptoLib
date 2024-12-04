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
 **/
int32_t Crypto_AOS_ApplySecurity(uint8_t *pTfBuffer)
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

    // Passed a null, return an error
    if (!pTfBuffer)
    {
        return CRYPTO_LIB_ERR_NULL_BUFFER;
    }

    if ((crypto_config.init_status == UNITIALIZED) || (mc_if == NULL) || (sa_if == NULL))
    {
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        // Can't mc_log since it's not configured
        return status; // return immediately so a NULL crypto_config is not dereferenced later
    }

    tfvn = ((uint8_t)pTfBuffer[0] & 0xC0) >> 6;
    scid = (((uint16_t)pTfBuffer[0] & 0x3F) << 2) | (((uint16_t)pTfBuffer[1] & 0xC0) >> 6);
    vcid = ((uint8_t)pTfBuffer[1] & 0x3F);

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
        printf("%02X", (uint8_t)pTfBuffer[i]);
    }
    printf("\n");
#endif

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

    status = Crypto_Get_Managed_Parameters_For_Gvcid(tfvn, scid, vcid, gvcid_managed_parameters_array,
                                                     &current_managed_parameters_struct);

    // No managed parameters found
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef AOS_DEBUG
        printf(KRED "Error: No managed parameters found!\n" RESET);
#endif
        mc_if->mc_log(status);
        return status;
    }

#ifdef AOS_DEBUG
    printf(KYEL "AOS BEFORE Apply Sec:\n\t" RESET);
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
    if (current_managed_parameters_struct.aos_has_fhec == AOS_HAS_FHEC)
    {
        idx += 2;
    }

    // Detect if optional variable length Insert Zone is present
    if (current_managed_parameters_struct.aos_has_iz == AOS_HAS_IZ)
    {
        idx += current_managed_parameters_struct.aos_iz_len;
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
            pTfBuffer[idx] = hex_padding[padding_start++];
            idx++;
        }
    }

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
    if (current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        pdu_len -= 4;
    }
    if (current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
        pdu_len -= 2;
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

    // Get Key
    crypto_key_t *ekp = NULL;
    crypto_key_t *akp = NULL;
    ekp               = key_if->get_key(sa_ptr->ekid);
    akp               = key_if->get_key(sa_ptr->akid);

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

    // TODO OCF - ? Here, elsewhere?

    /**
     * End Authentication / Encryption
     **/

    // Only calculate & insert FECF if CryptoLib is configured to do so & gvcid includes FECF.
    if (current_managed_parameters_struct.has_fecf == AOS_HAS_FECF)
    {
#ifdef FECF_DEBUG
        printf(KCYN "Calcing FECF over %d bytes\n" RESET, current_managed_parameters_struct.max_frame_size - 2);
#endif
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
        idx += 2;
    }

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
        // Update AOS First Header Pointer
        aos_frame.tm_header.fhp = 0xFE;
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
        // Update AOS First Header Pointer
        aos_frame.tm_header.fhp = aos_offset;
#ifdef AOS_DEBUG
        printf("tm_offset = %d \n", aos_offset);
#endif
    }
    printf("LINE: %d\n",__LINE__);
    // Update Current Telemetry Frame in Memory
    // Counters
    aos_frame.tm_header.mcfc++;
    aos_frame.tm_header.vcfc++;
    printf("LINE: %d\n",__LINE__);
    // Operational Control Field
    Crypto_AOS_updateOCF();
    printf("LINE: %d\n",__LINE__);
    // Payload Data Unit
    Crypto_AOS_updatePDU(ingest,*len_ingest);
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
        aos_frame.tm_sec_header.spi++;
    }
    if (badIV == 1)
    {
       * (sa_ptr->iv + sa_ptr->shivf_len - 1) =* (sa_ptr->iv + sa_ptr->shivf_len - 1) + 1;
    }
    if (badMAC == 1)
    {
        aos_frame.tm_sec_trailer.mac[MAC_SIZE - 1]++;
    }
    printf("LINE: %d\n",__LINE__);
    // Initialize the temporary AOS frame
    // Header
    tempAOS[count++] = (uint8_t)((tm_frame.tm_header.tfvn << 6) | ((tm_frame.tm_header.scid & 0x3F0) >> 4));
    printf("LINE: %d\n",__LINE__);
    tempAOS[count++] = (uint8_t)(((tm_frame.tm_header.scid & 0x00F) << 4) | (tm_frame.tm_header.vcid << 1) |
                                (tm_frame.tm_header.ocff));
    tempAOS[count++] = (uint8_t)(tm_frame.tm_header.mcfc);
    tempAOS[count++] = (uint8_t)(tm_frame.tm_header.vcfc);
    tempAOS[count++] =
        (uint8_t)((tm_frame.tm_header.tfsh << 7) | (tm_frame.tm_header.sf << 6) | (tm_frame.tm_header.pof << 5) |
                  (tm_frame.tm_header.slid << 3) | ((tm_frame.tm_header.fhp & 0x700) >> 8));
    tempAOS[count++] = (uint8_t)(tm_frame.tm_header.fhp & 0x0FF);
    //	tempAOS[count++] = (uint8_t) ((tm_frame.tm_header.tfshvn << 6) | aos_frame.tm_header.tfshlen);
    // Security Header
    printf("LINE: %d\n",__LINE__);
    tempAOS[count++] = (uint8_t)((spi & 0xFF00) >> 8);
    tempAOS[count++] = (uint8_t)((spi & 0x00FF));
    if(sa_ptr->shivf_len > 0)
    {
        memcpy(tm_frame.tm_sec_header.iv, sa_ptr->iv, sa_ptr->shivf_len);
    }
    printf("LINE: %d\n",__LINE__);
    // TODO: Troubleshoot
    // Padding Length
    // pad_len = Crypto_Get_tmLength(*len_ingest) - AOS_MIN_SIZE + IV_SIZE + AOS_PAD_SIZE -*len_ingest;
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
                tempAOS[count++] =* (sa_ptr->iv + x);
            }
        }
        pdu_loc = count;
        pad_len = pad_len - IV_SIZE - AOS_PAD_SIZE + OCF_SIZE;
        pdu_len =*len_ingest + pad_len;
    }
    else
    {                           // Include padding length bytes - hard coded per ESA testing
        printf("LINE: %d\n",__LINE__);
        tempAOS[count++] = 0x00; // pad_len >> 8;
        tempAOS[count++] = 0x1A; // pad_len
        pdu_loc = count;
        pdu_len =*len_ingest + pad_len;
    }
    printf("LINE: %d\n",__LINE__);
    // Payload Data Unit
    for (x = 0; x < (pdu_len); x++)
    {
        tempAOS[count++] = (uint8_t)tm_frame.tm_pdu[x];
    }
    // Message Authentication Code
    mac_loc = count;
    for (x = 0; x < MAC_SIZE; x++)
    {
        tempAOS[count++] = 0x00;
    }
    printf("LINE: %d\n",__LINE__);
    // Operational Control Field
    for (x = 0; x < OCF_SIZE; x++)
    {
        tempAOS[count++] = (uint8_t)tm_frame.tm_sec_trailer.ocf[x];
    }
    printf("LINE: %d\n",__LINE__);
    // Frame Error Control Field
    fecf_loc = count;
    aos_frame.tm_sec_trailer.fecf = Crypto_Calc_FECF((uint8_t*)tempAOS, count);
    tempAOS[count++] = (uint8_t)((tm_frame.tm_sec_trailer.fecf & 0xFF00) >> 8);
    tempAOS[count++] = (uint8_t)(tm_frame.tm_sec_trailer.fecf & 0x00FF);

    // Determine Mode
    // Clear
    if ((sa_ptr->est == 0) && (sa_ptr->ast == 0))
    {
#ifdef DEBUG
        printf(KBLU "Creating a AOS - CLEAR! \n" RESET);
#endif
        // Copy temporary frame to ingest
        memcpy(ingest, tempAOS, count);
    }
    // Authenticated Encryption
    else if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
    {
#ifdef DEBUG
        printf(KBLU "Creating a AOS - AUTHENTICATED ENCRYPTION! \n" RESET);
#endif

        // Copy AOS to ingest
        memcpy(ingest, tempAOS, pdu_loc);

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
                                                           &(tempAOS[pdu_loc]), // plaintext input
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
authentication cipher NULL // cam_cookies (not supported in AOS functions yet)
                                                           );


        // Update OCF
        y = 0;
        for (x = OCF_SIZE; x > 0; x--)
        {
            ingest[fecf_loc - x] = aos_frame.tm_sec_trailer.ocf[y++];
        }

        // Update FECF
        aos_frame.tm_sec_trailer.fecf = Crypto_Calc_FECF((uint8_t*)ingest, fecf_loc - 1);
        ingest[fecf_loc] = (uint8_t)((tm_frame.tm_sec_trailer.fecf & 0xFF00) >> 8);
        ingest[fecf_loc + 1] = (uint8_t)(tm_frame.tm_sec_trailer.fecf & 0x00FF);
    }
    // Authentication
    else if ((sa_ptr->est == 0) && (sa_ptr->ast == 1))
    {
#ifdef DEBUG
        printf(KBLU "Creating a AOS - AUTHENTICATED! \n" RESET);
#endif
        // TODO: Future work. Operationally same as clear.
        memcpy(ingest, tempAOS, count);
    }
    // Encryption
    else if ((sa_ptr->est == 1) && (sa_ptr->ast == 0))
    {
#ifdef DEBUG
        printf(KBLU "Creating a AOS - ENCRYPTED! \n" RESET);
#endif
        // TODO: Future work. Operationally same as clear.
        memcpy(ingest, tempAOS, count);
    }

#ifdef AOS_DEBUG
    Crypto_tmPrint(&tm_frame);
#endif

#ifdef DEBUG
    printf(KYEL "----- Crypto_AOS_ApplySecurity END -----\n" RESET);
#endif

   *len_ingest = count;
    mc_if->mc_log(status);
    return status;
}  **/

/**
 * @brief Function: Crypto_AOS_ProcessSecurity
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @return int32: Success/Failure
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
    uint8_t                iv_loc;
    int                    mac_loc         = 0;
    uint16_t               pdu_len         = 1;
    uint8_t               *p_new_dec_frame = NULL;
    SecurityAssociation_t *sa_ptr          = NULL;
    uint8_t                sa_service_type = -1;
    uint8_t                spi             = -1;

    // Bit math to give concise access to values in the ingest
    aos_frame_pri_hdr.tfvn = ((uint8_t)p_ingest[0] & 0xC0) >> 6;
    aos_frame_pri_hdr.scid = (((uint16_t)p_ingest[0] & 0x3F) << 4) | (((uint16_t)p_ingest[1] & 0xF0) >> 4);
    aos_frame_pri_hdr.vcid = ((uint8_t)p_ingest[1] & 0x0E) >> 1;

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_AOS_ProcessSecurity START -----\n" RESET);
#endif

    if (len_ingest < 6) // Frame length doesn't even have enough bytes for header -- error out.
    {
        status = CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_AOS_STANDARD;
        mc_if->mc_log(status);
        return status;
    }

    if ((crypto_config.init_status == UNITIALIZED) || (mc_if == NULL) || (sa_if == NULL))
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
        mc_if->mc_log(status);
        return status;
    } // Unable to get necessary Managed Parameters for AOS TF -- return with error.

    // Increment to end of Primary Header start, depends on FHECF presence
    byte_idx = 6;
    if (current_managed_parameters_struct.aos_has_fhec == AOS_HAS_FHEC)
    {
        byte_idx = 8;
    }

    // Determine if Insert Zone exists, increment past it if so
    if (current_managed_parameters_struct.aos_has_iz)
    {
        byte_idx += current_managed_parameters_struct.aos_iz_len;
    }

    /**
     * Begin Security Header Fields
     * Reference CCSDS SDLP 3550b1 4.1.1.1.3
     **/
    // Get SPI
    spi = (uint8_t)p_ingest[byte_idx] << 8 | (uint8_t)p_ingest[byte_idx + 1];
    // Move index to past the SPI
    byte_idx += 2;

    status = sa_if->sa_get_from_spi(spi, &sa_ptr);
    // If no valid SPI, return
    if (status != CRYPTO_LIB_SUCCESS)
    {
        mc_if->mc_log(status);
        return status;
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
                mc_if->mc_log(status);
                return status;
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
    // Needs to be AOS_HAS_FECF (checked above, or AOS_NO_FECF)
    else if (current_managed_parameters_struct.has_fecf != AOS_NO_FECF)
    {
#ifdef AOS_DEBUG
        printf(KRED "AOS_Process Error...tfvn: %d scid: 0x%04X vcid: 0x%02X fecf_enum: %d\n" RESET,
               current_managed_parameters_struct.tfvn, current_managed_parameters_struct.scid,
               current_managed_parameters_struct.vcid, current_managed_parameters_struct.has_fecf);
#endif
        status = CRYPTO_LIB_ERR_TC_ENUM_USED_FOR_AOS_CONFIG;
        mc_if->mc_log(status);
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
        return status;
    }

    // Copy over AOS Primary Header (6 bytes)
    memcpy(p_new_dec_frame, &p_ingest[0], 6);

    // Copy over insert zone data, if it exists
    if (current_managed_parameters_struct.aos_has_iz == AOS_HAS_IZ)
    {
        memcpy(p_new_dec_frame + 6, &p_ingest[6], current_managed_parameters_struct.aos_iz_len);
#ifdef AOS_DEBUG
        printf("Copied over the following:\n\t");
        for (int i = 0; i < current_managed_parameters_struct.aos_iz_len; i++)
        {
            printf("%02X", p_ingest[6 + i]);
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
    pdu_len = current_managed_parameters_struct.max_frame_size - (byte_idx)-sa_ptr->stmacf_len;
    if (current_managed_parameters_struct.has_ocf == AOS_HAS_OCF)
    {
        pdu_len -= 4;
    }
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
        ekp = key_if->get_key(sa_ptr->ekid);
        if (ekp == NULL)
        {
            status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
            mc_if->mc_log(status);
            return status;
        }
        if (ekp->key_state != KEY_ACTIVE)
        {
            status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
            mc_if->mc_log(status);
            return status;
        }
    }
    if (sa_ptr->ast == 1)
    {
        akp = key_if->get_key(sa_ptr->akid);
        if (akp == NULL)
        {
            status = CRYPTO_LIB_ERR_KEY_ID_ERROR;
            mc_if->mc_log(status);
            return status;
        }
        if (akp->key_state != KEY_ACTIVE)
        {
            status = CRYPTO_LIB_ERR_KEY_STATE_INVALID;
            mc_if->mc_log(status);
            return status;
        }
    }

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
        if (sa_ptr->abm_len < aad_len)
        {
            status = CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
            mc_if->mc_log(status);
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
                // free(aad); - non-heap object
                status = CRYPTO_LIB_ERR_KEY_LENGTH_ERROR;
                mc_if->mc_log(status);
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
    }

    // If plaintext, copy byte by byte
    else if (sa_service_type == SA_PLAINTEXT)
    {
        memcpy(p_new_dec_frame + byte_idx, &(p_ingest[byte_idx]), pdu_len);
        byte_idx += pdu_len;
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
    mc_if->mc_log(status);
    return status;
}

/**
 * @brief Function: Crypto_Get_aosLength
 * Returns the total length of the current aos_frame in BYTES!
 * @param len: int
 * @return int32_t Length of AOS
 **/
int32_t Crypto_Get_aosLength(int len)
{
#ifdef FILL
    len = AOS_FILL_SIZE;
#else
    len =
        AOS_FRAME_PRIMARYHEADER_SIZE + AOS_FRAME_SECHEADER_SIZE + len + AOS_FRAME_SECTRAILER_SIZE + AOS_FRAME_CLCW_SIZE;
#endif

    return len;
}

/**
 * @brief Function: Crypto_AOS_updatePDU
 * Update the Telemetry Payload Data Unit
 * @param ingest: uint8_t*
 * @param len_ingest: int
 **/
/**
void Crypto_AOS_updatePDU(uint8_t* ingest, int len_ingest)
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
#ifdef AOS_ZERO_FILL
    for (x = 0; x < AOS_FILL_SIZE; x++)
    {
        if (x < len_ingest)
        { // Fill
            aos_frame.tm_pdu[x] = (uint8_t)ingest[x];
        }
        else
        { // Zero
            aos_frame.tm_pdu[x] = 0x00;
        }
    }
#else
    // Pre-append remaining packet if exist
    // if (tm_offset == 63)
    // {
    //     aos_frame.tm_pdu[x++] = 0xff;
    //     aos_offset--;
    // }
    // if (tm_offset == 62)
    // {
    //     aos_frame.tm_pdu[x++] = 0x00;
    //     aos_offset--;
    // }
    // if (tm_offset == 61)
    // {
    //     aos_frame.tm_pdu[x++] = 0x00;
    //     aos_offset--;
    // }
    // if (tm_offset == 60)
    // {
    //     aos_frame.tm_pdu[x++] = 0x00;
    //     aos_offset--;
    // }
    // if (tm_offset == 59)
    // {
    //     aos_frame.tm_pdu[x++] = 0x39;
    //     aos_offset--;
    // }
    // while (x < aos_offset)
    // {
    //     aos_frame.tm_pdu[x] = 0x00;
    //     x++;
    // }
    // Copy actual packet
    while (x < len_ingest + aos_offset)
    {
        // printf("%s, Line: %d\n", __FILE__, __LINE__);
        // printf("ingest[x - aos_offset] = 0x%02x \n", (uint8_t)ingest[x - aos_offset]);
        printf("%02X", (uint8_t)ingest[x - aos_offset]);
        // aos_frame.tm_pdu[x] = (uint8_t)ingest[x - aos_offset];
        x++;
    }
#ifdef AOS_IDLE_FILL
    // Check for idle frame trigger
    if (((uint8_t)ingest[0] == 0x08) && ((uint8_t)ingest[1] == 0x90))
    {
        // Don't fill idle frames
    }
    else
    {
        // while (x < (fill_size - 64))
        // {
        //     aos_frame.tm_pdu[x++] = 0x07;
        //     aos_frame.tm_pdu[x++] = 0xff;
        //     aos_frame.tm_pdu[x++] = 0x00;
        //     aos_frame.tm_pdu[x++] = 0x00;
        //     aos_frame.tm_pdu[x++] = 0x00;
        //     aos_frame.tm_pdu[x++] = 0x39;
        //     for (y = 0; y < 58; y++)
        //     {
        //         aos_frame.tm_pdu[x++] = 0x00;
        //     }
        // }
        // Add partial packet, if possible, and set offset
        // if (x < fill_size)
        // {
        //     aos_frame.tm_pdu[x++] = 0x07;
        //     aos_offset = 63;
        // }
        // if (x < fill_size)
        // {
        //     aos_frame.tm_pdu[x++] = 0xff;
        //     aos_offset--;
        // }
        // if (x < fill_size)
        // {
        //     aos_frame.tm_pdu[x++] = 0x00;
        //     aos_offset--;
        // }
        // if (x < fill_size)
        // {
        //     aos_frame.tm_pdu[x++] = 0x00;
        //     aos_offset--;
        // }
        // if (x < fill_size)
        // {
        //     aos_frame.tm_pdu[x++] = 0x00;
        //     aos_offset--;
        // }
        // if (x < fill_size)
        // {
        //     aos_frame.tm_pdu[x++] = 0x39;
        //     aos_offset--;
        // }
        // for (y = 0; x < fill_size; y++)
        // {
        //     aos_frame.tm_pdu[x++] = 00;
        //     aos_offset--;
        // }
    }
    // while (x < AOS_FILL_SIZE)
    // {
    //     aos_frame.tm_pdu[x++] = 0x00;
    // }
#endif
#endif

    return;
}
  **/
/**
 * @brief Function: Crypto_AOS_updateOCF
 * Update the AOS OCF
 **/
/**
void Crypto_AOS_updateOCF(void)
{
    // TODO
    if (ocf == 0)
    { // CLCW
        clcw.vci = aos_frame.tm_header.vcid;

        aos_frame.tm_sec_trailer.ocf[0] = (clcw.cwt << 7) | (clcw.cvn << 5) | (clcw.sf << 2) | (clcw.cie);
        aos_frame.tm_sec_trailer.ocf[1] = (clcw.vci << 2) | (clcw.spare0);
        aos_frame.tm_sec_trailer.ocf[2] = (clcw.nrfa << 7) | (clcw.nbl << 6) | (clcw.lo << 5) | (clcw.wait << 4) |
                                         (clcw.rt << 3) | (clcw.fbc << 1) | (clcw.spare1);
        aos_frame.tm_sec_trailer.ocf[3] = (clcw.rv);
        // Alternate OCF
        ocf = 1;
#ifdef OCF_DEBUG
        Crypto_clcwPrint(&clcw);
#endif
    }
    else
    { // FSR
        aos_frame.tm_sec_trailer.ocf[0] = (report.cwt << 7) | (report.vnum << 4) | (report.af << 3) |
                                         (report.bsnf << 2) | (report.bmacf << 1) | (report.ispif);
        aos_frame.tm_sec_trailer.ocf[1] = (report.lspiu & 0xFF00) >> 8;
        aos_frame.tm_sec_trailer.ocf[2] = (report.lspiu & 0x00FF);
        aos_frame.tm_sec_trailer.ocf[3] = (report.snval);
        // Alternate OCF
        ocf = 0;
#ifdef OCF_DEBUG
        Crypto_fsrPrint(&report);
#endif
    }
}
  **/

/**
 * @brief Function: Crypto_Prepare_AOS_AAD
 * Bitwise ANDs buffer with abm, placing results in aad buffer
 * @param buffer: uint8_t*
 * @param len_aad: uint16_t
 * @param abm_buffer: uint8_t*
 * @param aad: uint8_t*
 * @return status: uint32_t
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