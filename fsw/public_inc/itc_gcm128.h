/* Copyright (C) 2009 - 2017 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
   limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
   any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
   arising out of, resulting from, or in any way connected with the software or its documentation.  Whether or not based upon warranty,
   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
   documentation or services provided hereunder

   ITC Team
   NASA IV&V
   ivv-itc@lists.nasa.gov
*/

#ifndef ITC_GCM128_H
#define ITC_GCM128_H

// CFS Includes
#ifdef NOS3 //NOS3/cFS build is ready
#include "common_types.h"
#else //Assume build outside of NOS3/cFS infrastructure
#include "common_types_minimum.h"
#endif
// Standard Includes
#include "itc_aes128.h"

/* A lightweight implementation of Galois Counter Mode Authenticated Encryption.
   Supports the following:
    - 128-bit key
    - AES block cipher
    - 96-bit IV
    - 128-bit MAC tag
    - size of AAD limited to 2^32-1 bytes
    - size of Data limited to 2^32-1 bytes
   
   authenticated data - will not require it to be block-divisible
   encrypted data - will not require it to be block-divisible
   need to bounds check lengths of aad/plaintext
*/



/**********************          Error Codes         **************************/

/* Notice: No error codes for NULL parameters (NULL's are assert-checked) */
#define ITC_GCM128_SUCCESS              0  
#define ITC_GCM128_BAD_TAG         -10001  /* Tag is invalid for message */
#define ITC_GCM128_OUT_OF_RANGE    -10002  /* AAD/Data Length is too large */

/**********************        Structs & Stuff        **************************/

/* Context object for GCM operations. 
 * Must be initialized before use!
 * Context should never be manually manipulated - use only the library operations!
*/
struct itc_gcm128_context
{
    /* First two fields are constant for any fixed key */
    struct itc_aes128_context aes_ctx; /* for use with AES cipher */ 
    unsigned char h[16];               /* H subkey for use in GHASH */

    /* Variable fields: */
    unsigned char iv_ctr[16];          /* IV (first 12 bytes) + Counter (last 4, Big-endian) */
    unsigned char base_ectr[16];       /* Encrypted base counter block (needed at end for computing tag) */
    unsigned char ghash[16];           /* running ghash value */
    uint32 aad_length;                 /* length of AAD (in bytes) */
    uint32 length;                     /* data length */
};

/**********************          Operations          **************************/

/* Initializes the context for use with GCM.
 * key must be 128-bit (16 byte).
 * A context should be unique to the key. It can be re-used for multiple messages.
 * A context object is not thread-safe though!
 * 
*/
void itc_gcm128_init(struct itc_gcm128_context *ctx, const unsigned char * key);

/* All-in-one method for encryption and tagging.
 * 
 * \note One of AAD or the plaintext must have size greater than zero
 * \return ITC_GCM128_SUCCESS if successful
 * \return ITC_GCM128_OUT_OF_RANGE if aad or data length is too long
*/
int itc_gcm128_encrypt_and_tag( struct itc_gcm128_context *ctx,
                                const unsigned char * iv,         /* must be 96-bit */                            
                                size_t aad_length,                /* length of AAD */
                                const unsigned char * aad,        /* additional authenticated data */                               
                                size_t length,                    /* length of data */
                                const unsigned char * plaintext,  /* plaintext input */
                                unsigned char * ciphertext,       /* ciphertext output (buffer must have size >= plaintext) */
                                unsigned char * tag );            /* tag output (128-bit) */

/* Performs authenticated decryption.
 *
 * \return ITC_GCM128_SUCCESS if successful and tag matches
 * \return ITC_GCM128_BAD_TAG if tag is invalid for the message 
 * \return ITC_GCM128_OUT_OF_RANGE if aad or data length is too long
*/
int itc_gcm128_decrypt( struct itc_gcm128_context *ctx, 
                        const unsigned char * iv,                 /* must be 96-bit */                       
                        size_t aad_length,                        /* length of AAD */
                        const unsigned char * aad,                /* additional authenticated data */
                        size_t length,                            /* length of data */
                        const unsigned char * ciphertext,         /* ciphertext input */
                        const unsigned char * tag,                /* tag input (128-bit) */
                        unsigned char * plaintext );              /* plaintext output */

/* Streaming functions for encryption:
   - These are to provide flexibility when the plaintext for the message may be fragmented
   - Per message:
     - Call itc_gcm128_encrypt_start first (and only once) with the AAD
     - Call itc_gcm128_encrypt_update repeatedly with the plaintext as needed.
       For each call to update, plaintext must be divisible by 16 bytes, except for the last call (if a partial block).
     - Call itc_gcm128_encrypt_finish to compute the tag.
*/

/* Begin encrypting a message with the Additional Authenticated Data (AAD).
 *
 * 
 * \return ITC_GCM128_SUCCESS if successful
 * \return ITC_GCM128_OUT_OF_RANGE if aad length is too long
*/
int itc_gcm128_encrypt_start( struct itc_gcm128_context *ctx, 
                              const unsigned char * iv,          /* must be 96-bit */
                              size_t aad_length,                 /* length of AAD */
                              const unsigned char * aad );       /* additional authenticated data */
                              

/* Used for streaming encryption.
 *
 * \note Per message, plaintext must be divisible by 16 bytes for each call except for the final update.
 *
 * \return ITC_GCM128_SUCCESS if successful
 * \return ITC_GCM128_OUT_OF_RANGE if cumulative data length is too long
*/
int itc_gcm128_encrypt_update( struct itc_gcm128_context *ctx, 
                               size_t length,                    /* length of data */
                               const unsigned char * plaintext,  /* plaintext input */
                               unsigned char * ciphertext );     /* ciphertext output */

/* Used for streaming encryption. Finishes encryption procedure and computes tag.
 *
 * \return ITC_GCM128_SUCCESS if successful
*/
int itc_gcm128_encrypt_finish(struct itc_gcm128_context *ctx, unsigned char * tag);


/* Begin decrypting a message with the Additional Authenticated Data (AAD).
 *
 * 
 * \return ITC_GCM128_SUCCESS if successful
 * \return ITC_GCM128_OUT_OF_RANGE if aad length is too long
*/
int itc_gcm128_decrypt_start( struct itc_gcm128_context *ctx, 
                              const unsigned char * iv,          /* must be 96-bit */
                              size_t aad_length,                 /* length of AAD */
                              const unsigned char * aad );       /* additional authenticated data */
                              

/* Used for streaming decryption.
 *
 * \note Per message, plaintext must be divisible by 16 bytes for each call except for the final update.
 *
 * \return ITC_GCM128_SUCCESS if successful
 * \return ITC_GCM128_OUT_OF_RANGE if cumulative data length is too long
*/
int itc_gcm128_decrypt_update( struct itc_gcm128_context *ctx, 
                               size_t length,                     /* length of data */
                               const unsigned char * ciphertext,  /* ciphertext input */
                               unsigned char * plaintext );       /* plaintext output */

/* Used for streaming encryption. Finishes encryption procedure and computes tag.
 *
 * \return ITC_GCM128_SUCCESS if successful
 * \return ITC_GCM128_BAD_TAG if tag is invalid
*/
int itc_gcm128_decrypt_finish(struct itc_gcm128_context *ctx, const unsigned char * tag);


#endif /* ITC_GCM128_H */
