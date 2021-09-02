#include <assert.h>
#include <string.h>
#include "itc_cmac128.h"

void itc_cmac128_init(struct itc_cmac128_context * ctx, const unsigned char * key)
{
    assert(ctx != NULL);
    assert(key != NULL);

    static const unsigned char zero_block[16] = { 0 };
    unsigned char temp[16];
    size_t i;

    itc_aes128_init(&(ctx->aes_ctx), key);

    // Calculate intermediate value 'L'
    itc_aes128_encrypt(&(ctx->aes_ctx), zero_block, temp);
    
    // left-shift L 1-bit and copy to k1
    for(i = 0; i < 15; ++i)
    {
        ctx->k1[i] = (temp[i] << 1) | ( ( temp[i+1] & 0x80 ) >> 7 );
    }
    ctx->k1[15] = temp[15] << 1;

    if( (temp[0] & 0x80) != 0 )
    {
        ctx->k1[15] ^= 0x87;
    }

    // left-shift k1 1-bit and copy to k2
    for(i = 0; i < 15; ++i)
    {
        ctx->k2[i] = (ctx->k1[i] << 1) | ( ( ctx->k1[i+1] & 0x80 ) >> 7 );
    }
    ctx->k2[15] = ctx->k1[15] << 1;

    if( (ctx->k1[0] & 0x80) != 0 )
    {
        ctx->k2[15] ^= 0x87;
    }
}

int itc_cmac128_generate_tag( struct itc_cmac128_context *ctx, 
                              size_t length, 
                              const unsigned char * message, 
                              unsigned char * tag )
{
    assert(ctx != NULL);
    assert(tag != NULL);
    if(length > 0) assert(message != NULL);

    unsigned char temp_tag[16] = { 0 };
    unsigned char last_block[16];

    size_t i;

    while(length > 16)
    {
        for(i = 0; i < 16; ++i)
        {
            temp_tag[i] ^= message[i];
        }
        itc_aes128_encrypt(&(ctx->aes_ctx), temp_tag, temp_tag);

        message += 16;
        length -= 16;
    }

    // Somewhere between 0 and 16 bytes remains: 0 if empty message, 1-16 for partial/full-block
    if(length == 16) //full block!
    {
        // last_block = last_block ^ K1
        for(i = 0; i < 16; ++i)
        {
            last_block[i] = ctx->k1[i] ^ message[i]; 
        }
    }
    else //partial block! Up to 15 bytes (0 if empty message)
    {
        // copy the bytes of the partial block
        if(length > 0)
            memcpy(last_block, message, length * sizeof(unsigned char));

        // fill remaining bytes
        last_block[length] = 0x80;
        for(i = length+1; i < 16; ++i)
        {
            last_block[i] = 0x00;
        }

        for(i = 0; i < 16; ++i)
        {
            last_block[i] ^= ctx->k2[i]; 
        }
    }

    for(i = 0; i < 16; ++i)
    {
        temp_tag[i] ^= last_block[i];
    }
    itc_aes128_encrypt(&(ctx->aes_ctx), temp_tag, tag);

    return ITC_CMAC128_SUCCESS;
}

int itc_cmac128_validate( struct itc_cmac128_context *ctx, 
                         size_t length, 
                         const unsigned char * message, 
                         const unsigned char *tag )
{
    assert(ctx != NULL);
    assert(tag != NULL);
    if(length > 0) assert(message != NULL);

    int returnCode;
    unsigned char temp_tag[16];
    size_t i;

    returnCode = itc_cmac128_generate_tag(ctx, length, message, temp_tag);

    if(returnCode == ITC_CMAC128_SUCCESS)
    {
        for(i = 0; i < 16; ++i)
        {
            if(tag[i] != temp_tag[i])
            {
                returnCode = ITC_CMAC128_BAD_TAG;
                break;
            }
        }
    }

    return returnCode;
}