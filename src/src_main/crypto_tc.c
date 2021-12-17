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

/**
 * @brief Function: Crypto_TC_ApplySecurity
 * Applies Security to incoming frame.  Encryption, Authentication, and Authenticated Encryption
 * @param p_in_frame: uint8*
 * @param in_frame_length: uint16
 * @param pp_in_frame: uint8_t**
 * @param p_enc_frame_len: uint16
 * @return int32: Success/Failure
 **/
int32_t Crypto_TC_ApplySecurity(const uint8_t *p_in_frame, const uint16_t in_frame_length, uint8_t **pp_in_frame,
                                uint16_t *p_enc_frame_len)
{
    // Local Variables
    int32_t status = CRYPTO_LIB_SUCCESS;
    TC_FramePrimaryHeader_t temp_tc_header;
    SecurityAssociation_t *sa_ptr = NULL;
    uint8_t *p_new_enc_frame = NULL;
    uint8_t sa_service_type = -1;
    uint16_t mac_loc = 0;
    uint16_t tf_payload_len = 0x0000;
    uint16_t new_fecf = 0x0000;
    uint8_t *aad;
    gcry_cipher_hd_t tmp_hd;
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    uint16_t new_enc_frame_header_field_length = 0;
    uint32_t encryption_cipher;
    uint8_t ecs_is_aead_algorithm;

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_TC_ApplySecurity START -----\n" RESET);
#endif

    if (p_in_frame == NULL)
    {
        status = CRYPTO_LIB_ERR_NULL_BUFFER;
        printf(KRED "Error: Input Buffer NULL! \n" RESET);
        return status; // Just return here, nothing can be done.
    }

#ifdef DEBUG
    printf("%d TF Bytes received\n", in_frame_length);
    printf("DEBUG - ");
    for (int i = 0; i < in_frame_length; i++)
    {
        printf("%02X", ((uint8_t *)&*p_in_frame)[i]);
    }
    printf("\nPrinted %d bytes\n", in_frame_length);
#endif

    if (crypto_config == NULL)
    {
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_CONFIG;
    }

    // Primary Header
    temp_tc_header.tfvn = ((uint8_t)p_in_frame[0] & 0xC0) >> 6;
    temp_tc_header.bypass = ((uint8_t)p_in_frame[0] & 0x20) >> 5;
    temp_tc_header.cc = ((uint8_t)p_in_frame[0] & 0x10) >> 4;
    temp_tc_header.spare = ((uint8_t)p_in_frame[0] & 0x0C) >> 2;
    temp_tc_header.scid = ((uint8_t)p_in_frame[0] & 0x03) << 8;
    temp_tc_header.scid = temp_tc_header.scid | (uint8_t)p_in_frame[1];
    temp_tc_header.vcid = ((uint8_t)p_in_frame[2] & 0xFC) >> 2 & crypto_config->vcid_bitmask;
    temp_tc_header.fl = ((uint8_t)p_in_frame[2] & 0x03) << 8;
    temp_tc_header.fl = temp_tc_header.fl | (uint8_t)p_in_frame[3];
    temp_tc_header.fsn = (uint8_t)p_in_frame[4];

    // Lookup-retrieve managed parameters for frame via gvcid:
    status = Crypto_Get_Managed_Parameters_For_Gvcid(temp_tc_header.tfvn, temp_tc_header.scid, temp_tc_header.vcid,
                                                     gvcid_managed_parameters, &current_managed_parameters);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    } // Unable to get necessary Managed Parameters for TC TF -- return with error.

    uint8_t segmentation_hdr = 0x00;
    uint8_t map_id = 0;
    if (current_managed_parameters->has_segmentation_hdr == TC_HAS_SEGMENT_HDRS)
    {
        segmentation_hdr = p_in_frame[5];
        map_id = segmentation_hdr & 0x3F;
    }

    // Check if command frame flag set
    if ((temp_tc_header.cc == 1) && (status == CRYPTO_LIB_SUCCESS))
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
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
        // Query SA DB for active SA / SDLS parameters
        if (sadb_routine == NULL) // This should not happen, but tested here for safety
        {
            printf(KRED "ERROR: SA DB Not initalized! -- CRYPTO_LIB_ERR_NO_INIT, Will Exit\n" RESET);
            status = CRYPTO_LIB_ERR_NO_INIT;
        }
        else
        {
            status = sadb_routine->sadb_get_operational_sa_from_gvcid(temp_tc_header.tfvn, temp_tc_header.scid,
                                                                      temp_tc_header.vcid, map_id, &sa_ptr);
        }

        // If unable to get operational SA, can return
        if (status != CRYPTO_LIB_SUCCESS)
        {
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
            printf(KRED "Error: SA Service Type is not defined! \n" RESET);
            status = CRYPTO_LIB_ERROR;
            return status;
        }

        // Determine Algorithm cipher & mode. // TODO - Parse authentication_cipher, and handle AEAD cases properly
        if (sa_service_type != SA_PLAINTEXT)
        {
            encryption_cipher =
                (sa_ptr->ecs[0] << 24) | (sa_ptr->ecs[1] << 16) | (sa_ptr->ecs[2] << 8) | sa_ptr->ecs[3];
            ecs_is_aead_algorithm = Crypto_Is_AEAD_Algorithm(encryption_cipher);
        }

#ifdef TC_DEBUG
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
#endif

        // Determine length of buffer to be malloced
        // TODO: Determine TC_PAD_SIZE
        // TODO: Note: Currently assumes ciphertext output length is same as ciphertext input length
        switch (sa_service_type)
        {
        case SA_PLAINTEXT:
            // Ingest length + spi_index (2) + some variable length fields
            *p_enc_frame_len = temp_tc_header.fl + 1 + 2 + sa_ptr->shplf_len;
            new_enc_frame_header_field_length = (*p_enc_frame_len) - 1;
            break;
        case SA_AUTHENTICATION:
            // Ingest length + spi_index (2) + shivf_len (varies) + shsnf_len (varies)
            //   + shplf_len + arc_len + pad_size + stmacf_len
            *p_enc_frame_len = temp_tc_header.fl + 1 + 2 + sa_ptr->shivf_len + sa_ptr->shsnf_len + sa_ptr->shplf_len +
                               sa_ptr->arc_len + TC_PAD_SIZE + sa_ptr->stmacf_len;
            new_enc_frame_header_field_length = (*p_enc_frame_len) - 1;
            break;
        case SA_ENCRYPTION:
            // Ingest length + spi_index (2) + shivf_len (varies) + shsnf_len (varies)
            //   + shplf_len + arc_len + pad_size
            *p_enc_frame_len = temp_tc_header.fl + 1 + 2 + sa_ptr->shivf_len + sa_ptr->shsnf_len + sa_ptr->shplf_len +
                               sa_ptr->arc_len + TC_PAD_SIZE;
            new_enc_frame_header_field_length = (*p_enc_frame_len) - 1;
            break;
        case SA_AUTHENTICATED_ENCRYPTION:
            // Ingest length + spi_index (2) + shivf_len (varies) + shsnf_len (varies)
            //   + shplf_len + arc_len + pad_size + stmacf_len
            *p_enc_frame_len = temp_tc_header.fl + 1 + 2 + sa_ptr->shivf_len + sa_ptr->shsnf_len + sa_ptr->shplf_len +
                               sa_ptr->arc_len + TC_PAD_SIZE + sa_ptr->stmacf_len;
            new_enc_frame_header_field_length = (*p_enc_frame_len) - 1;
            break;
        default:
            printf(KRED "Unknown SA Service Type Detected!" RESET);
            break;
        }

#ifdef TC_DEBUG
        printf(KYEL "DEBUG - Total TC Buffer to be malloced is: %d bytes\n" RESET, *p_enc_frame_len);
        printf(KYEL "\tlen of TF\t = %d\n" RESET, temp_tc_header.fl);
        // printf(KYEL "\tsegment hdr\t = 1\n" RESET); // TODO: Determine presence of this so not hard-coded
        printf(KYEL "\tspi len\t\t = 2\n" RESET);
        printf(KYEL "\tshivf_len\t = %d\n" RESET, sa_ptr->shivf_len);
        printf(KYEL "\tshsnf_len\t = %d\n" RESET, sa_ptr->shsnf_len);
        printf(KYEL "\tshplf len\t = %d\n" RESET, sa_ptr->shplf_len);
        printf(KYEL "\tarc_len\t\t = %d\n" RESET, sa_ptr->arc_len);
        printf(KYEL "\tpad_size\t = %d\n" RESET, TC_PAD_SIZE);
        printf(KYEL "\tstmacf_len\t = %d\n" RESET, sa_ptr->stmacf_len);
#endif

        // Accio buffer
        p_new_enc_frame = (uint8_t *)malloc((*p_enc_frame_len) * sizeof(uint8_t));
        if (!p_new_enc_frame)
        {
            printf(KRED "Error: Malloc for encrypted output buffer failed! \n" RESET);
            status = CRYPTO_LIB_ERROR;
            return status;
        }
        memset(p_new_enc_frame, 0, *p_enc_frame_len);

        // Copy original TF header
        memcpy(p_new_enc_frame, p_in_frame, TC_FRAME_PRIMARYHEADER_STRUCT_SIZE);

        // Set new TF Header length
        // Recall: Length field is one minus total length per spec
        *(p_new_enc_frame + 2) =
            ((*(p_new_enc_frame + 2) & 0xFC) | (((new_enc_frame_header_field_length) & (0x0300)) >> 8));
        *(p_new_enc_frame + 3) = ((new_enc_frame_header_field_length) & (0x00FF));

#ifdef TC_DEBUG
        printf(KYEL "Printing updated TF Header:\n\t");
        for (int i = 0; i < TC_FRAME_HEADER_SIZE; i++)
        {
            printf("%02X", *(p_new_enc_frame + i));
        }
        // Recall: The buffer length is 1 greater than the field value set in the TCTF
        printf("\n\tLength set to 0x%02X\n" RESET, new_enc_frame_header_field_length);
#endif

        /*
        ** Start variable length fields
        */
        uint16_t index = TC_FRAME_HEADER_SIZE; // Frame header is 5 bytes

        if (current_managed_parameters->has_segmentation_hdr == TC_HAS_SEGMENT_HDRS)
        {
            index++; // Add 1 byte to index because segmentation header used for this gvcid.
        }

        /*
        ** Begin Security Header Fields
        ** Reference CCSDS SDLP 3550b1 4.1.1.1.3
        */
        // Set SPI
        *(p_new_enc_frame + index) = ((sa_ptr->spi & 0xFF00) >> 8);
        *(p_new_enc_frame + index + 1) = (sa_ptr->spi & 0x00FF);
        index += 2;

        // Set initialization vector if specified
        if ((sa_service_type == SA_AUTHENTICATION) || (sa_service_type == SA_AUTHENTICATED_ENCRYPTION) ||
            (sa_service_type == SA_ENCRYPTION))
        {
#ifdef SA_DEBUG
            printf(KYEL "Using IV value:\n\t");
            for (int i = 0; i < sa_ptr->shivf_len; i++)
            {
                printf("%02x", *(sa_ptr->iv + i));
            }
            printf("\n" RESET);
#endif

            for (int i = 0; i < sa_ptr->shivf_len; i++)
            {
                // TODO: Likely API call
                // Copy in IV from SA
                *(p_new_enc_frame + index) = *(sa_ptr->iv + i);
                index++;
            }
        }

        // Set anti-replay sequence number if specified
        /*
        ** See also: 4.1.1.4.2
        ** 4.1.1.4.4 If authentication or authenticated encryption is not selected
        ** for an SA, the Sequence Number field shall be zero octets in length.
        ** Reference CCSDS 3550b1
        */
        // Determine if seq num field is needed
        // TODO: Likely SA API Call
        if (sa_ptr->shsnf_len > 0)
        {
            // If using anti-replay counter, increment it
            // TODO: API call instead?
            // TODO: Check return code
            Crypto_increment(sa_ptr->arc, sa_ptr->shsnf_len);
            for (int i = 0; i < sa_ptr->shsnf_len; i++)
            {
                *(p_new_enc_frame + index) = *(sa_ptr->arc + i);
                index++;
            }
        }

        // Set security header padding if specified
        /*
        ** 4.2.3.4 h) if the algorithm and mode selected for the SA require the use of
        ** fill padding, place the number of fill bytes used into the Pad Length field
        ** of the Security Header - Reference CCSDS 3550b1
        */
        // TODO: Revisit this
        // TODO: Likely SA API Call
        for (int i = 0; i < sa_ptr->shplf_len; i++)
        {
            /* 4.1.1.5.2 The Pad Length field shall contain the count of fill bytes used in the
            ** cryptographic process, consisting of an integral number of octets. - CCSDS 3550b1
            */
            // TODO: Set this depending on crypto cipher used
            *(p_new_enc_frame + index) = 0x00;
            index++;
        }

        /*
        ** End Security Header Fields
        */

        uint8_t fecf_len = FECF_SIZE;
        if (current_managed_parameters->has_fecf == TC_NO_FECF)
        {
            fecf_len = 0;
        }
        uint8_t segment_hdr_len = SEGMENT_HDR_SIZE;
        if (current_managed_parameters->has_segmentation_hdr == TC_NO_SEGMENT_HDRS)
        {
            segment_hdr_len = 0;
        }
        // Copy in original TF data - except FECF
        // Will be over-written if using encryption later
        // and if it was present in the original TCTF
        // if FECF
        // Even though FECF is not part of apply_security payload, we still have to subtract the length from the
        // temp_tc_header.fl since that includes FECF length & segment header length.
        tf_payload_len = temp_tc_header.fl - TC_FRAME_HEADER_SIZE - segment_hdr_len - fecf_len + 1;
        // if no FECF
        // tf_payload_len = temp_tc_header.fl - TC_FRAME_PRIMARYHEADER_STRUCT_SIZE;
        memcpy((p_new_enc_frame + index), (p_in_frame + TC_FRAME_PRIMARYHEADER_STRUCT_SIZE), tf_payload_len);
        // index += tf_payload_len;

        /*
        ** Begin Security Trailer Fields
        */

        // Set MAC Field if present
        /*
        ** May be present and unused if switching between clear and authenticated
        ** CCSDS 3550b1 4.1.2.3
        */
        // By leaving MAC as zeros, can use index for encryption output
        // for (int i=0; i < temp_SA.stmacf_len; i++)
        // {
        //     // Temp fill MAC
        //     *(p_new_enc_frame + index) = 0x00;
        //     index++;
        // }

        /*
        ** End Security Trailer Fields
        */

        /*
        ** Begin Authentication / Encryption
        */

        if (sa_service_type != SA_PLAINTEXT)
        {
            gcry_error = gcry_cipher_open(&(tmp_hd), GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, GCRY_CIPHER_CBC_MAC);
            if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
                status = CRYPTO_LIB_ERROR;
                return status;
            }
            gcry_error = gcry_cipher_setkey(tmp_hd, &(ek_ring[sa_ptr->ekid].value[0]),
                                            KEY_SIZE // TODO:  look into this
            );
            if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
                status = CRYPTO_LIB_ERROR;
                return status;
            }
            gcry_error = gcry_cipher_setiv(tmp_hd, sa_ptr->iv, sa_ptr->shivf_len);
            if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
                status = CRYPTO_LIB_ERROR;
                return status;
            }

            if ((sa_service_type == SA_ENCRYPTION) || (sa_service_type == SA_AUTHENTICATED_ENCRYPTION))
            {
// TODO: More robust calculation of this location
// uint16_t output_loc = TC_FRAME_PRIMARYHEADER_STRUCT_SIZE + 1 + 2 + temp_SA.shivf_len + temp_SA.shsnf_len +
// temp_SA.shplf_len;
#ifdef TC_DEBUG
                printf("Encrypted bytes output_loc is %d\n", index);
                printf("tf_payload_len is %d\n", tf_payload_len);
                printf(KYEL "Printing TC Frame prior to encryption:\n\t");
                for (int i = 0; i < *p_enc_frame_len; i++)
                {
                    printf("%02X", *(p_new_enc_frame + i));
                }
                printf("\n");
#endif

                if (sa_service_type == SA_AUTHENTICATED_ENCRYPTION &&
                    ecs_is_aead_algorithm == CRYPTO_TRUE) // Algorithm is AEAD algorithm, Add AAD before encrypt!
                {
                    // Prepare the Header AAD (CCSDS 335.0-B-1 4.2.3.2.2.3)
                    uint16_t aad_len = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len +
                                       sa_ptr->shsnf_len + sa_ptr->shplf_len;
                    if (sa_ptr->abm_len < aad_len)
                    {
                        return CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
                    }
                    aad = Crypto_Prepare_TC_AAD(p_new_enc_frame, aad_len, sa_ptr->abm);

                    // Add the AAD to the libgcrypt cipher handle
                    gcry_error = gcry_cipher_authenticate(tmp_hd,
                                                          aad,    // additional authenticated data
                                                          aad_len // length of AAD
                    );
                    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                    {
                        printf(KRED "ERROR: gcry_cipher_authenticate error code %d\n" RESET,
                               gcry_error & GPG_ERR_CODE_MASK);
                        printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
                        status = CRYPTO_LIB_ERR_AUTHENTICATION_ERROR;
                        return status;
                    }

                    free(aad);
                }

                gcry_error =
                    gcry_cipher_encrypt(tmp_hd,
                                        &p_new_enc_frame[index],                               // ciphertext output
                                        tf_payload_len,                                        // length of data
                                        (p_in_frame + TC_FRAME_HEADER_SIZE + segment_hdr_len), // plaintext input
                                        tf_payload_len                                         // in data length
                    );

                if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                {
                    printf(KRED "ERROR: gcry_cipher_encrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
                    status = CRYPTO_LIB_ERROR;
                    return status;
                }

#ifdef TC_DEBUG
                printf("Encrypted bytes output_loc is %d\n", index);
                printf("tf_payload_len is %d\n", tf_payload_len);
                printf(KYEL "Printing TC Frame after encryption:\n\t");
                for (int i = 0; i < *p_enc_frame_len; i++)
                {
                    printf("%02X", *(p_new_enc_frame + i));
                }
                printf("\n");
#endif

                // Get MAC & insert into p_new_enc_frame
                if (sa_service_type == SA_AUTHENTICATED_ENCRYPTION && ecs_is_aead_algorithm == CRYPTO_TRUE)
                {
                    mac_loc = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len +
                              sa_ptr->shplf_len + tf_payload_len;
#ifdef MAC_DEBUG
                    printf(KYEL "MAC location is: %d\n" RESET, mac_loc);
                    printf(KYEL "MAC size is: %d\n" RESET, MAC_SIZE);
#endif
                    gcry_error = gcry_cipher_gettag(
                        tmp_hd,
                        &p_new_enc_frame[mac_loc], // tag output
                        MAC_SIZE // tag size // TODO - use sa_ptr->abm_len instead of hardcoded mac size?
                    );
                    if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                    {
                        printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET,
                               gcry_error & GPG_ERR_CODE_MASK);
                        status = CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR;
                        return status;
                    }
                }

                // Close cipher, so we can authenticate encrypted data
                gcry_cipher_close(tmp_hd);
            }

            // Prepare additional authenticated data, if needed
            if ((sa_service_type == SA_AUTHENTICATION) ||
                ((sa_service_type == SA_AUTHENTICATED_ENCRYPTION) &&
                 ecs_is_aead_algorithm == CRYPTO_FALSE)) // Authenticated Encryption without AEAD algorithm, AEAD
                                                         // algorithms handled in encryption block!
            {
                gcry_error = gcry_cipher_open(&(tmp_hd), GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, GCRY_CIPHER_CBC_MAC);
                if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                {
                    printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
                    status = CRYPTO_LIB_ERROR;
                    return status;
                }
                gcry_error = gcry_cipher_setkey(tmp_hd, &(ek_ring[sa_ptr->ekid].value[0]),
                                                KEY_SIZE // TODO:  look into this
                );
                if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                {
                    printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
                    status = CRYPTO_LIB_ERROR;
                    return status;
                }
                gcry_error = gcry_cipher_setiv(tmp_hd, sa_ptr->iv, sa_ptr->shivf_len);
                if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                {
                    printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
                    status = CRYPTO_LIB_ERROR;
                    return status;
                }

                uint16_t aad_len = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len +
                                   sa_ptr->shsnf_len + sa_ptr->shplf_len + tf_payload_len;
                if (sa_ptr->abm_len < aad_len)
                {
                    return CRYPTO_LIB_ERR_ABM_TOO_SHORT_FOR_AAD;
                }
                aad = Crypto_Prepare_TC_AAD(p_new_enc_frame, aad_len, sa_ptr->abm);

                gcry_error = gcry_cipher_authenticate(tmp_hd,
                                                      aad,    // additional authenticated data
                                                      aad_len // length of AAD
                );
                if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                {
                    printf(KRED "ERROR: gcry_cipher_authenticate error code %d\n" RESET,
                           gcry_error & GPG_ERR_CODE_MASK);
                    printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
                    status = CRYPTO_LIB_ERROR;
                    return status;
                }

                mac_loc = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len +
                          sa_ptr->shplf_len + tf_payload_len;
#ifdef MAC_DEBUG
                printf(KYEL "MAC location is: %d\n" RESET, mac_loc);
                printf(KYEL "MAC size is: %d\n" RESET, MAC_SIZE);
#endif
                gcry_error =
                    gcry_cipher_gettag(tmp_hd,
                                       &p_new_enc_frame[mac_loc], // tag output
                                       MAC_SIZE // tag size // TODO - use sa_ptr->abm_len instead of hardcoded mac size?
                    );
                if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
                {
                    printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
                    status = CRYPTO_LIB_ERR_MAC_RETRIEVAL_ERROR;
                    return status;
                }
                // Zeroise any sensitive information
                gcry_cipher_close(tmp_hd);
            }
        }

        if (sa_service_type != SA_PLAINTEXT)
        {
#ifdef INCREMENT
            if (sa_ptr->iv == NULL)
            {
                printf("\n\nNULL\n\n");
            }
            Crypto_increment(sa_ptr->iv, sa_ptr->shivf_len);
#ifdef SA_DEBUG
            printf(KYEL "Next IV value is:\n\t");
            for (int i = 0; i < sa_ptr->shivf_len; i++)
            {
                printf("%02x", *(sa_ptr->iv + i));
            }
            printf("\n" RESET);
#endif
#endif
        }
        /*
        ** End Authentication / Encryption
        */

        // Only calculate & insert FECF if CryptoLib is configured to do so & gvcid includes FECF.
        if (current_managed_parameters->has_fecf == TC_HAS_FECF)
        {
// Set FECF Field if present
#ifdef FECF_DEBUG
            printf(KCYN "Calcing FECF over %d bytes\n" RESET, new_enc_frame_header_field_length - 1);
#endif
            if (crypto_config->crypto_create_fecf == CRYPTO_TC_CREATE_FECF_TRUE)
            {
                new_fecf = Crypto_Calc_FECF(p_new_enc_frame, new_enc_frame_header_field_length - 1);
                *(p_new_enc_frame + new_enc_frame_header_field_length - 1) = (uint8_t)((new_fecf & 0xFF00) >> 8);
                *(p_new_enc_frame + new_enc_frame_header_field_length) = (uint8_t)(new_fecf & 0x00FF);
            }
            else // CRYPTO_TC_CREATE_FECF_FALSE
            {
                *(p_new_enc_frame + new_enc_frame_header_field_length - 1) = (uint8_t)0x00;
                *(p_new_enc_frame + new_enc_frame_header_field_length) = (uint8_t)0x00;
            }

            index += 2;
        }

#ifdef TC_DEBUG
        printf(KYEL "Printing new TC Frame:\n\t");
        for (int i = 0; i < *p_enc_frame_len; i++)
        {
            printf("%02X", *(p_new_enc_frame + i));
        }
        printf("\n\tThe returned length is: %d\n" RESET, new_enc_frame_header_field_length);
#endif

        *pp_in_frame = p_new_enc_frame;
    }

    status = sadb_routine->sadb_save_sa(sa_ptr);

#ifdef DEBUG
    printf(KYEL "----- Crypto_TC_ApplySecurity END -----\n" RESET);
#endif

    return status;
}

/**
 * @brief Function: Crypto_TC_ProcessSecurity
 * Performs Authenticated decryption, decryption, and authentication
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @param tc_sdls_processed_frame: TC_t*
 * @return int32: Success/Failure
 **/
int32_t Crypto_TC_ProcessSecurity(uint8_t *ingest, int *len_ingest, TC_t *tc_sdls_processed_frame)
// Loads the ingest frame into the global tc_frame while performing decryption
{
    // Local Variables
    int32_t status = CRYPTO_LIB_SUCCESS;
    gcry_cipher_hd_t tmp_hd;
    gcry_error_t gcry_error = GPG_ERR_NO_ERROR;
    SecurityAssociation_t *sa_ptr = NULL;
    uint8_t sa_service_type = -1;
    uint8_t *aad;
    uint32_t encryption_cipher;
    uint8_t ecs_is_aead_algorithm;

    if (crypto_config == NULL)
    {
        printf(KRED "ERROR: CryptoLib Configuration Not Set! -- CRYPTO_LIB_ERR_NO_CONFIG, Will Exit\n" RESET);
        status = CRYPTO_LIB_ERR_NO_CONFIG;
        return status;
    }

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_TC_ProcessSecurity START -----\n" RESET);
#endif

    int byte_idx = 0;
    // Primary Header
    tc_sdls_processed_frame->tc_header.tfvn = ((uint8_t)ingest[byte_idx] & 0xC0) >> 6;
    tc_sdls_processed_frame->tc_header.bypass = ((uint8_t)ingest[byte_idx] & 0x20) >> 5;
    tc_sdls_processed_frame->tc_header.cc = ((uint8_t)ingest[byte_idx] & 0x10) >> 4;
    tc_sdls_processed_frame->tc_header.spare = ((uint8_t)ingest[byte_idx] & 0x0C) >> 2;
    tc_sdls_processed_frame->tc_header.scid = ((uint8_t)ingest[byte_idx] & 0x03) << 8;
    byte_idx++;
    tc_sdls_processed_frame->tc_header.scid = tc_sdls_processed_frame->tc_header.scid | (uint8_t)ingest[byte_idx];
    byte_idx++;
    tc_sdls_processed_frame->tc_header.vcid = (((uint8_t)ingest[byte_idx] & 0xFC) >> 2) & crypto_config->vcid_bitmask;
    tc_sdls_processed_frame->tc_header.fl = ((uint8_t)ingest[byte_idx] & 0x03) << 8;
    byte_idx++;
    tc_sdls_processed_frame->tc_header.fl = tc_sdls_processed_frame->tc_header.fl | (uint8_t)ingest[byte_idx];
    byte_idx++;
    tc_sdls_processed_frame->tc_header.fsn = (uint8_t)ingest[byte_idx];
    byte_idx++;

    // Lookup-retrieve managed parameters for frame via gvcid:
    status = Crypto_Get_Managed_Parameters_For_Gvcid(
        tc_sdls_processed_frame->tc_header.tfvn, tc_sdls_processed_frame->tc_header.scid,
        tc_sdls_processed_frame->tc_header.vcid, gvcid_managed_parameters, &current_managed_parameters);

    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    } // Unable to get necessary Managed Parameters for TC TF -- return with error.

    // Segment Header
    if (current_managed_parameters->has_segmentation_hdr == TC_HAS_SEGMENT_HDRS)
    {
        tc_sdls_processed_frame->tc_sec_header.sh = (uint8_t)ingest[byte_idx];
        byte_idx++;
    }
    // Security Header
    tc_sdls_processed_frame->tc_sec_header.spi = ((uint8_t)ingest[byte_idx] << 8) | (uint8_t)ingest[byte_idx + 1];
    byte_idx += 2;
#ifdef TC_DEBUG
    printf("vcid = %d \n", tc_sdls_processed_frame->tc_header.vcid);
    printf("spi  = %d \n", tc_sdls_processed_frame->tc_sec_header.spi);
#endif

    status = sadb_routine->sadb_get_sa_from_spi(tc_sdls_processed_frame->tc_sec_header.spi, &sa_ptr);
    // If no valid SPI, return
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }

    encryption_cipher = (sa_ptr->ecs[0] << 24) | (sa_ptr->ecs[1] << 16) | (sa_ptr->ecs[2] << 8) | sa_ptr->ecs[3];
    ecs_is_aead_algorithm = Crypto_Is_AEAD_Algorithm(encryption_cipher);

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
    if (sa_service_type != SA_PLAINTEXT)
    {
        encryption_cipher = (sa_ptr->ecs[0] << 24) | (sa_ptr->ecs[1] << 16) | (sa_ptr->ecs[2] << 8) | sa_ptr->ecs[3];
        ecs_is_aead_algorithm = Crypto_Is_AEAD_Algorithm(encryption_cipher);
    }

#ifdef TC_DEBUG
    switch (sa_service_type)
    {
    case SA_PLAINTEXT:
        printf(KBLU "Processing a TC - CLEAR!\n" RESET);
        break;
    case SA_AUTHENTICATION:
        printf(KBLU "Processing a TC - AUTHENTICATED!\n" RESET);
        break;
    case SA_ENCRYPTION:
        printf(KBLU "Processing a TC - ENCRYPTED!\n" RESET);
        break;
    case SA_AUTHENTICATED_ENCRYPTION:
        printf(KBLU "Processing a TC - AUTHENTICATED ENCRYPTION!\n" RESET);
        break;
    }
#endif

    // TODO: Calculate lengths when needed
    uint8_t fecf_len = FECF_SIZE;
    if (current_managed_parameters->has_fecf == TC_NO_FECF)
    {
        fecf_len = 0;
    }

    uint8_t segment_hdr_len = SEGMENT_HDR_SIZE;
    if (current_managed_parameters->has_segmentation_hdr == TC_NO_SEGMENT_HDRS)
    {
        segment_hdr_len = 0;
    }

    // Check FECF
    if (current_managed_parameters->has_fecf == TC_HAS_FECF)
    {
        if (crypto_config->crypto_check_fecf == TC_CHECK_FECF_TRUE)
        {
            uint16_t received_fecf = (((ingest[tc_sdls_processed_frame->tc_header.fl - 1] << 8) & 0xFF00) |
                                      (ingest[tc_sdls_processed_frame->tc_header.fl] & 0x00FF));
            // Calculate our own
            uint16_t calculated_fecf = Crypto_Calc_FECF(ingest, *len_ingest - 2);
            // Compare
            if (received_fecf != calculated_fecf)
            {
                status = CRYPTO_LIB_ERR_INVALID_FECF;
                return status;
            }
        }
    }

    // Parse the security header
    tc_sdls_processed_frame->tc_sec_header.spi =
        (uint16_t)((uint8_t)ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len] |
                   (uint8_t)ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len + 1]);
    // Get SA via SPI
    status = sadb_routine->sadb_get_sa_from_spi(tc_sdls_processed_frame->tc_sec_header.spi, &sa_ptr);
    if (status != CRYPTO_LIB_SUCCESS)
    {
        return status;
    }
    // Parse IV
    memcpy((tc_sdls_processed_frame->tc_sec_header.iv), &(ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN]),
           sa_ptr->shivf_len);
    // Parse Sequence Number
    memcpy((tc_sdls_processed_frame->tc_sec_header.sn) + (TC_SN_SIZE - sa_ptr->shsnf_len),
           &(ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len]), sa_ptr->shsnf_len);
    // Parse pad length
    memcpy((tc_sdls_processed_frame->tc_sec_header.pad) + (TC_PAD_SIZE - sa_ptr->shplf_len),
           &(ingest[TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len]),
           sa_ptr->shplf_len);

    if ((sa_service_type == SA_AUTHENTICATION) || (sa_service_type == SA_AUTHENTICATED_ENCRYPTION) ||
        (sa_service_type == SA_ENCRYPTION))
    {
        gcry_error = gcry_cipher_open(&(tmp_hd), GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, GCRY_CIPHER_CBC_MAC);
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_open error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
            return status;
        }
        gcry_error = gcry_cipher_setkey(tmp_hd, ek_ring[sa_ptr->ekid].value, KEY_SIZE);
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_setkey error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
            return status;
        }
        gcry_error = gcry_cipher_setiv(tmp_hd, tc_sdls_processed_frame->tc_sec_header.iv, sa_ptr->shivf_len);
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_setiv error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            status = CRYPTO_LIB_ERR_LIBGCRYPT_ERROR;
            return status;
        }
    }

    // Check MAC, if applicable
    if ((sa_service_type == SA_AUTHENTICATION) || (sa_service_type == SA_AUTHENTICATED_ENCRYPTION))
    {
        uint16_t tc_mac_start_index = tc_sdls_processed_frame->tc_header.fl + 1 - fecf_len - sa_ptr->stmacf_len;
        // Parse the received MAC
        memcpy((tc_sdls_processed_frame->tc_sec_trailer.mac) + (MAC_SIZE - sa_ptr->stmacf_len),
               &(ingest[tc_mac_start_index]), sa_ptr->stmacf_len);
        if (crypto_config->ignore_anti_replay == TC_IGNORE_ANTI_REPLAY_FALSE)
        {
            // If sequence number field is greater than zero, use as arsn
            if (sa_ptr->shsnf_len > 0)
            {
                // Check Sequence Number is in ARCW
                status = Crypto_window(tc_sdls_processed_frame->tc_sec_header.sn, sa_ptr->arc, sa_ptr->shsnf_len,
                                       sa_ptr->arcw);
                if (status != CRYPTO_LIB_SUCCESS)
                {
                    return status;
                }
                // TODO: Update SA ARC through SADB_Routine function call
            }
            else
            {
                // Check IV is in ARCW
                status = Crypto_window(tc_sdls_processed_frame->tc_sec_header.iv, sa_ptr->iv, sa_ptr->shivf_len,
                                       sa_ptr->arcw);
#ifdef DEBUG
                printf("Received IV is\n\t");
                for (int i = 0; i < sa_ptr->shivf_len; i++)
                // for(int i=0; i<IV_SIZE; i++)
                {
                    printf("%02x", *(tc_sdls_processed_frame->tc_sec_header.iv + i));
                }
                printf("\nSA IV is\n\t");
                for (int i = 0; i < sa_ptr->shivf_len; i++)
                {
                    printf("%02x", *(sa_ptr->iv + i));
                }
                printf("\nARCW is: %d\n", sa_ptr->arcw);
#endif
                if (status != CRYPTO_LIB_SUCCESS)
                {
                    return status;
                }
                // TODO: Update SA IV through SADB_Routine function call
            }
        }

        uint16_t aad_len = tc_mac_start_index;
        if ((sa_service_type == SA_AUTHENTICATED_ENCRYPTION) && (ecs_is_aead_algorithm == CRYPTO_TRUE))
        {
            aad_len = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len + sa_ptr->shsnf_len +
                      sa_ptr->shplf_len;
        }
        aad = Crypto_Prepare_TC_AAD(ingest, aad_len, sa_ptr->abm);

        gcry_error = gcry_cipher_authenticate(tmp_hd,
                                              aad,    // additional authenticated data
                                              aad_len // length of AAD
        );
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_authenticate error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            printf(KRED "Failure: %s/%s\n", gcry_strsource(gcry_error), gcry_strerror(gcry_error));
            status = CRYPTO_LIB_ERR_AUTHENTICATION_ERROR;
            return status;
        }
    }

    // Decrypt, if applicable
    if ((sa_service_type == SA_ENCRYPTION) || (sa_service_type == SA_AUTHENTICATED_ENCRYPTION) ||
        (sa_service_type == SA_AUTHENTICATION))
    {
        uint16_t tc_enc_payload_start_index = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len +
                                              sa_ptr->shsnf_len + sa_ptr->shplf_len;
        tc_sdls_processed_frame->tc_pdu_len =
            tc_sdls_processed_frame->tc_header.fl + 1 - tc_enc_payload_start_index - sa_ptr->stmacf_len - fecf_len;

        if (sa_service_type == SA_AUTHENTICATION)
        { // Authenticate only! No input data passed into decryption function, only AAD.
            gcry_error = gcry_cipher_decrypt(tmp_hd,
                                             NULL, // plaintext output
                                             0,    // length of data
                                             NULL, // ciphertext input
                                             0     // in data length
            );
            // If authentication only, don't decrypt the data. Just pass the data PDU through.
            memcpy(tc_sdls_processed_frame->tc_pdu, &(ingest[tc_enc_payload_start_index]),
                   tc_sdls_processed_frame->tc_pdu_len);
        }
        else
        { // Decrypt
            gcry_error = gcry_cipher_decrypt(tmp_hd,
                                             tc_sdls_processed_frame->tc_pdu,       // plaintext output
                                             tc_sdls_processed_frame->tc_pdu_len,   // length of data
                                             &(ingest[tc_enc_payload_start_index]), // ciphertext input
                                             tc_sdls_processed_frame->tc_pdu_len    // in data length
            );
        }
        if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
        {
            printf(KRED "ERROR: gcry_cipher_decrypt error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
            status = CRYPTO_LIB_ERR_DECRYPT_ERROR;
            return status;
        }

        if ((sa_service_type == SA_AUTHENTICATED_ENCRYPTION) || (sa_service_type == SA_AUTHENTICATION))
        {

            gcry_error = gcry_cipher_checktag(tmp_hd,
                                              tc_sdls_processed_frame->tc_sec_trailer.mac, // Frame Expected Tag
                                              sa_ptr->stmacf_len                           // tag size
            );
            if ((gcry_error & GPG_ERR_CODE_MASK) != GPG_ERR_NO_ERROR)
            {
                printf(KRED "ERROR: gcry_cipher_checktag error code %d\n" RESET, gcry_error & GPG_ERR_CODE_MASK);
                fprintf(stderr, "gcry_cipher_decrypt failed: %s\n", gpg_strerror(gcry_error));
                status = CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR;
                return status;
            }
        }
    }

    if (sa_service_type != SA_PLAINTEXT)
    {
        gcry_cipher_close(tmp_hd);
    }

    if (sa_service_type == SA_PLAINTEXT)
    {
        // TODO: Plaintext ARSN

        uint16_t tc_enc_payload_start_index = TC_FRAME_HEADER_SIZE + segment_hdr_len + SPI_LEN + sa_ptr->shivf_len +
                                              sa_ptr->shsnf_len + sa_ptr->shplf_len;
        tc_sdls_processed_frame->tc_pdu_len =
            tc_sdls_processed_frame->tc_header.fl + 1 - tc_enc_payload_start_index - sa_ptr->stmacf_len - fecf_len;
        memcpy(tc_sdls_processed_frame->tc_pdu, &(ingest[tc_enc_payload_start_index]),
               tc_sdls_processed_frame->tc_pdu_len);
    }

    // Extended PDU processing, if applicable
    if (crypto_config->process_sdls_pdus == TC_PROCESS_SDLS_PDUS_TRUE)
    {
        status = Crypto_Process_Extended_Procedure_Pdu(tc_sdls_processed_frame, ingest);
    }

    return status;
}

/**
 * @brief Function: Crypto_Get_tcPayloadLength
 * Returns the payload length of current tc_frame in BYTES!
 * @param tc_frame: TC_t*
 * @param sa_ptr: SecurityAssociation_t
 * @return int32, Length of TCPayload
 **/
/*
int32_t Crypto_Get_tcPayloadLength(TC_t* tc_frame, SecurityAssociation_t *sa_ptr)
{
    int tf_hdr = 5;
    int seg_hdr = 0;if(current_managed_parameters->has_segmentation_hdr==TC_HAS_SEGMENT_HDRS){seg_hdr=1;}
    int fecf = 0;if(current_managed_parameters->has_fecf==TC_HAS_FECF){fecf=FECF_SIZE;}
    int spi = 2;
    int iv_size = sa_ptr->shivf_len;
    int mac_size = sa_ptr->stmacf_len;

    #ifdef TC_DEBUG
        printf("Get_tcPayloadLength Debug [byte lengths]:\n");
        printf("\thdr.fl\t%d\n", tc_frame->tc_header.fl);
        printf("\ttf_hdr\t%d\n",tf_hdr);
        printf("\tSeg hdr\t%d\t\n",seg_hdr);
        printf("\tspi \t%d\n",spi);
        printf("\tiv_size\t%d\n",iv_size);
        printf("\tmac\t%d\n",mac_size);
        printf("\tfecf \t%d\n",fecf);
        printf("\tTOTAL LENGTH: %d\n", (tc_frame->tc_header.fl - (tf_hdr + seg_hdr + spi + iv_size ) - (mac_size +
fecf))); #endif

    return (tc_frame->tc_header.fl + 1 - (tf_hdr + seg_hdr + spi + iv_size ) - (mac_size + fecf) );
}
*/

/**
 * @brief Function: Crypto_Prepare_TC_AAD
 * Callocs and returns pointer to buffer where AAD is created & bitwise-anded with bitmask!
 * Note: Function caller is responsible for freeing the returned buffer!
 * @param buffer: uint8_t*
 * @param len_aad: uint16_t
 * @param abm_buffer: uint8_t*
 **/
uint8_t *Crypto_Prepare_TC_AAD(uint8_t *buffer, uint16_t len_aad, uint8_t *abm_buffer)
{
    uint8_t *aad = (uint8_t *)calloc(1, len_aad * sizeof(uint8_t));

    for (int i = 0; i < len_aad; i++)
    {
        aad[i] = buffer[i] & abm_buffer[i];
    }

#ifdef MAC_DEBUG
    printf(KYEL "Preparing AAD:\n");
    printf("\tUsing AAD Length of %d\n\t", len_aad);
    for (int i = 0; i < len_aad; i++)
    {
        printf("%02x", aad[i]);
    }
    printf("\n" RESET);
#endif

    return aad;
}
