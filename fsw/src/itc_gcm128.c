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

#ifndef ITC_GCM128_C
#define ITC_GCM128_C

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "itc_gcm128.h"

/* Representation of 128-bit blocks:
 *   To be as portable as possible, a 128-bit block will be represented as 
 *   a 16-byte unsigned char array.
 *   
 *               MSB                     LSB
 *   Bit string: b0 ,b1, b2, ... , b126, 127 
 *   where b0-b7 would be the bits of block[0], with b0 the MSB and b7 the LSB
 * 
*/

 /* todo: get rid of asserts and use error returns for NULL parameters? */

enum itc_gcm128_mode
{
    ITC_GCM128_ENCRYPT,
    ITC_GCM128_DECRYPT
};

/* compare in constant time. Return zero if equal, non-zero otherwise */
static int compare(const unsigned char * a, const unsigned char * b, size_t length)
{
    size_t i;
    int differ = 0;

    for(i = 0; i < length; ++i)
    {
        differ |= a[i] ^ b[i];
    }

    return differ;
}

static void pack_uint32_big_endian(uint32 x, unsigned char *dest)
{
    dest[0] = (unsigned char) ((x >> 24) & 0xff);
    dest[1] = (unsigned char) ((x >> 16) & 0xff);
    dest[2] = (unsigned char) ((x >> 8)  & 0xff);
    dest[3] = (unsigned char) ((x)       & 0xff);
}

/* get the value of a certain bit ( 0 through 127) from a 128-bit block */
static unsigned char get_bit(const unsigned char *block, unsigned char bit)
{
    assert(bit < 128);

    if(  ( block[bit/8] & (0x01 << (7-(bit%8))) ) > 0)
        return 1;
    else
        return 0;
}

/*
static void set_bit(unsigned char *block, unsigned char bit, unsigned char value)
{
    assert(bit < 128);
    assert(value < 2);

    block[bit/8] |= ( value << (7-(bit%8)) );
}
*/

/* 
  GCM multiplication. x, y, and result must point to valid 16-byte arrays
  It is OK to re-use x or y buffer as the result buffer
  TODO: there are ways to speed up using tables (more memory but faster)
 */
static void gcm_multiply(const unsigned char * x, const unsigned char * y, unsigned char * result)
{
    assert(x != NULL);
    assert(y != NULL);
    assert(result != NULL);

    unsigned char z[16] = { 0 };
    unsigned char v[16];

    memcpy(v, y, 16 * sizeof(unsigned char));

    int i, j;
    unsigned char v_lsb;
    for(i = 0; i < 128; ++i)
    {
        if(get_bit(x, i) == 1)
        {
            for(j = 0; j < 16; ++j)
            {
                z[j] ^= v[j];
            }
        }

        v_lsb = (v[15] & 0x01);

        /* v >> 1 */
        for(j = 15; j > 0; --j)
        {
            v[j] = (v[j] >> 1) | ( (v[j-1] & 0x01) << 7 );
        }
        v[0] >>= 1;

        if(v_lsb)
        {
            v[0] ^= 0xe1;
        }
    }

    memcpy(result, z, 16 * sizeof(unsigned char));
}

/* same function for either encrypt or decrypt */
static int gcm128_crypt_start( struct itc_gcm128_context *ctx,
                                const unsigned char * iv,   
                                size_t aad_length,      
                                const unsigned char * aad )
{    
    assert(ctx != NULL);
    assert(iv != NULL);
    if(aad_length > 0) assert(aad != NULL);

    if(aad_length > 0xffffffff)
        return ITC_GCM128_OUT_OF_RANGE;

    /* zero-out elements for a new message */
    memset(ctx->iv_ctr, 0x00, sizeof(ctx->iv_ctr));
    memset(ctx->ghash, 0x00, sizeof(ctx->ghash));
    ctx->aad_length = 0;
    ctx->length = 0;
    size_t i, temp_length;
    const unsigned char * p;

    /* generate initial counter block (ICB): IV || 31 0's || 1 */
    memcpy(ctx->iv_ctr, iv, 12 * sizeof(unsigned char));
    ctx->iv_ctr[15] = 0x01;

    /* compute base ECNTR (needed to compute tag in last step of algorithm) */
    itc_aes128_encrypt(&(ctx->aes_ctx), ctx->iv_ctr, ctx->base_ectr);

    /* process the AAD */
    ctx->aad_length = (uint32)aad_length;
    p = aad;

    while(aad_length > 0)
    {
        temp_length = (aad_length < 16) ? aad_length : 16;

        /* if temp_length is < 16, algorithm says to pad with zeros to fill block */
        /* zero's would have no effect on the XOR op, so just skip it instead */
        for(i = 0; i < temp_length; ++i)
        {
            ctx->ghash[i] ^= p[i];
        }
        
        gcm_multiply(ctx->ghash, ctx->h, ctx->ghash);

        p += temp_length;
        aad_length -= temp_length;
    }

    return ITC_GCM128_SUCCESS;
}

static int gcm128_crypt_update( struct itc_gcm128_context *ctx, 
                                 enum itc_gcm128_mode mode,
                                 size_t length,
                                 const unsigned char * input,
                                 unsigned char * output )
{
    unsigned char ectr[16];
    size_t i, temp_length;
    const unsigned char *in_p = input;
    unsigned char *out_p = output;
    assert(ctx != NULL);
    if(length > 0)
    {
        assert(input != NULL);
        assert(output != NULL);
    }
    
    if( (0xffffffff - ctx->length) < length )
        return ITC_GCM128_OUT_OF_RANGE;
    /*
      Note: 
       if mode == ENCRYPT, input is plaintext, output is ciphertext
       if mode == DECRYPT, input is ciphertext, output is plaintext
    */

    ctx->length += (uint32)length;
    while(length > 0)
    {
        temp_length = (length < 16) ? length : 16;

        /* increment ctr here; take advantage of unsigned int wrap-around on overflow */
        for(i = 16; i > 12; --i)
        {
            /* increment byte; if equals zero (overflowed), then also have to increment next byte to account for carry */
            if( ++(ctx->iv_ctr[i-1]) != 0)
               break;
        }

        itc_aes128_encrypt(&(ctx->aes_ctx), ctx->iv_ctr, ectr);        

        for(i = 0; i < temp_length; ++i)
        {
            /* check if DECRYPT first in case in_p == out_p */
            if(mode == ITC_GCM128_DECRYPT) /* in_p is ciphertext */
                ctx->ghash[i] ^= in_p[i]; 

            out_p[i] = ectr[i] ^ in_p[i];

            if(mode == ITC_GCM128_ENCRYPT) /* out_p is ciphertext */
                ctx->ghash[i] ^= out_p[i];
        }

        gcm_multiply(ctx->ghash, ctx->h, ctx->ghash);

        in_p += temp_length;
        out_p += temp_length;
        length -= temp_length;
    }
    return ITC_GCM128_SUCCESS;

}

static void gcm128_crypt_finish(struct itc_gcm128_context *ctx, unsigned char * tag)
{
    /* at this point, all data has been encrypted/decrypted and the ghash has been computed through AAD & data */
    /* Need to finish ghash computation with AAD/Data length members, then compute/verify tag */
    assert(ctx != NULL);
    assert(tag != NULL);

    unsigned char buffer[16] = { 0 };
    size_t i;
    uint32 aad_length = ctx->aad_length * 8;
    uint32 data_length = ctx->length * 8;

    /* copy base ectr to tag */
    memcpy(tag, ctx->base_ectr, sizeof(ctx->base_ectr));

    /*
      pack AAD length and data length into two consecutive 64-bit words.
      Since uint32 was chosen as the limit, the upper 32-bits of each 64-bit word are zero
      Combined, looks like this:
    
       0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
      ------------------------------------------------
       0  0  0  0  x  x  x  x  0  0  0  0  y  y  y  y  
    
      Where xxxx is big-endian representation of aad length,
      and yyyy is big-endian representation of data length
    */
    pack_uint32_big_endian(aad_length,  buffer+4);
    pack_uint32_big_endian(data_length, buffer+12);
    
    /* finish hash */
    for(i = 0; i < 16; ++i)
        ctx->ghash[i] ^= buffer[i];

    gcm_multiply(ctx->ghash, ctx->h, ctx->ghash);

    for(i = 0; i < 16; ++i)
    {
        tag[i] ^= ctx->ghash[i];
    }
}

void itc_gcm128_init(struct itc_gcm128_context *ctx, const unsigned char * key)
{
    assert(ctx != NULL);
    assert(key != NULL);
    static const unsigned char zero_block[16] = { 0 };

    /* initialize AES context */
    itc_aes128_init(&(ctx->aes_ctx), key);

    /* calculate GHASH subkey (H) */
    itc_aes128_encrypt(&(ctx->aes_ctx), zero_block, ctx->h);
}

int itc_gcm128_encrypt_start( struct itc_gcm128_context *ctx, 
                              const unsigned char * iv,
                              size_t aad_length,         
                              const unsigned char * aad )
{
    return gcm128_crypt_start(ctx, iv, aad_length, aad);
}

int itc_gcm128_encrypt_update( struct itc_gcm128_context *ctx,                               
                               size_t length,
                               const unsigned char * plaintext,
                               unsigned char * ciphertext )
{
    return gcm128_crypt_update(ctx, ITC_GCM128_ENCRYPT, length, plaintext, ciphertext);
}

int itc_gcm128_encrypt_finish(struct itc_gcm128_context *ctx, unsigned char * tag)
{
    gcm128_crypt_finish(ctx, tag);
    return ITC_GCM128_SUCCESS;
}

int itc_gcm128_encrypt_and_tag( struct itc_gcm128_context *ctx, 
                                const unsigned char * iv, 
                                size_t aad_length, 
                                const unsigned char * aad,                                 
                                size_t length, 
                                const unsigned char * plaintext, 
                                unsigned char * ciphertext, 
                                unsigned char * tag )
{
    int returnCode;

    returnCode = itc_gcm128_encrypt_start(ctx, iv, aad_length, aad);

    if(returnCode == ITC_GCM128_SUCCESS)
    {
        returnCode = itc_gcm128_encrypt_update(ctx, length, plaintext, ciphertext);
    }

    if(returnCode == ITC_GCM128_SUCCESS)
    {
        returnCode = itc_gcm128_encrypt_finish(ctx, tag);
    }

    return returnCode;
}

int itc_gcm128_decrypt_start( struct itc_gcm128_context *ctx, 
                              const unsigned char * iv,
                              size_t aad_length,
                              const unsigned char * aad )
{
    return gcm128_crypt_start(ctx, iv, (uint32)aad_length, aad);
}

int itc_gcm128_decrypt_update( struct itc_gcm128_context *ctx, 
                               size_t length,
                               const unsigned char * ciphertext,
                               unsigned char * plaintext )
{
    return gcm128_crypt_update(ctx, ITC_GCM128_DECRYPT, length, ciphertext, plaintext);
}

int itc_gcm128_decrypt_finish(struct itc_gcm128_context *ctx, const unsigned char * tag)
{
    unsigned char computed_tag[16];
    gcm128_crypt_finish(ctx, computed_tag);

    /* compare tags */
    if(compare(tag, computed_tag, sizeof(computed_tag)) == 0)
    {
        return ITC_GCM128_SUCCESS;
    }
    else
    {
        return ITC_GCM128_BAD_TAG;
    }

}

int itc_gcm128_decrypt( struct itc_gcm128_context *ctx, 
                        const unsigned char * iv,                      
                        size_t aad_length,
                        const unsigned char * aad,
                        size_t length,
                        const unsigned char * ciphertext,
                        const unsigned char * tag,
                        unsigned char * plaintext )
{
    int returnCode;

    returnCode = itc_gcm128_decrypt_start(ctx, iv, aad_length, aad);

    if(returnCode == ITC_GCM128_SUCCESS)
    {
        returnCode = itc_gcm128_decrypt_update(ctx, length, ciphertext, plaintext);
    }

    if(returnCode == ITC_GCM128_SUCCESS)
    {
        returnCode = itc_gcm128_decrypt_finish(ctx, tag);
    }
    
    return returnCode;
}

#endif /* ITC_GCM128_C */
