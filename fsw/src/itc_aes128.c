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

#ifndef ITC_AES128_C
#define ITC_AES128_C

#include <assert.h>
#include <string.h>
#include <stddef.h>
#include "itc_aes128.h"

#define NB            4    /* Number of columns in state */
#define NK            4    /* Number of 32-bit words in key */
#define KEY_LENGTH   16    /* Key length in bytes */
#define NR           10    /* Number of rounds */

/* Comments:
** - Many of the areas that could use loops have been unrolled manually.
**   This should improve performance at the cost of code size.
*/

/*******************************************************************************
*                                                                                   
*                           Substitution Tables
*
*******************************************************************************/

static const unsigned char sbox[256] = 
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const unsigned char inverse_sbox[256] =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* note: rcon[0] is never used */
static const unsigned char rcon[11] = 
{ 
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

/* TODO: could add lookup tables for multiplication (tables for 2,3,9,11,13,14) */

/* Rotate a word (4 bytes) to the left by 1: {1, 2, 3, 4 } => {2, 3, 4, 1}
** Used for key expansion.
*/
static void rotate_word_left(unsigned char *word)
{
    unsigned char temp;
    temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void itc_aes128_init(struct itc_aes128_context *ctx, const unsigned char *key)
{
    unsigned char temp[4];
    int rcon_iteration = 0;
    int currentSize;

    assert(key != NULL);
    assert(ctx != NULL);

    /* first part is the key itself */
    memcpy(ctx->key_schedule, key, KEY_LENGTH * sizeof(unsigned char));

    currentSize = KEY_LENGTH;
    while(currentSize < KS_LENGTH)
    {
        /* store previous 4 bytes in temp array */
        memcpy(temp, ctx->key_schedule + (currentSize - 4), 4 * sizeof(unsigned char));

        /* every 16 bytes, apply core schedule */
        if(currentSize % KEY_LENGTH == 0)
        {
            rotate_word_left(temp);

            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            temp[0] ^= rcon[++rcon_iteration];
        }

        /* next 4 bytes of key are the temp array XOR'd with 4 byte block 16 bytes back */
        ctx->key_schedule[currentSize + 0] = ctx->key_schedule[currentSize - KEY_LENGTH + 0] ^ temp[0];
        ctx->key_schedule[currentSize + 1] = ctx->key_schedule[currentSize - KEY_LENGTH + 1] ^ temp[1];
        ctx->key_schedule[currentSize + 2] = ctx->key_schedule[currentSize - KEY_LENGTH + 2] ^ temp[2];
        ctx->key_schedule[currentSize + 3] = ctx->key_schedule[currentSize - KEY_LENGTH + 3] ^ temp[3];
        currentSize += 4;
    }
}

/*******************************************************************************
*
*                             State Array Mapping
*
*                        col 0   col 1   col 2   col 3
*                       --------------------------------
*               row 0  |   0   |   4   |   8   |   12   |
*                      |-------|-------|-------|--------|
*               row 1  |   1   |   5   |   9   |   13   |
*                      |-------|-------|-------|--------|
*               row 2  |   2   |   6   |  10   |   14   |
*                      |-------|-------|-------|--------|
*               row 3  |   3   |   7   |  11   |   15   |
*                       --------------------------------        
*
*******************************************************************************/

/* Thank you Sam Trenholme */
static unsigned char g_multiply(unsigned char a, unsigned char b) 
{
    unsigned char p = 0;
    int counter;
    unsigned char hi_bit_set;

    for(counter = 0; counter < 8; ++counter) 
    {
        /* if(b == 0) break; //if b has no more bits set, p is finalized */
        if((b & 1) == 1) 
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if(hi_bit_set == 0x80) 
            a ^= 0x1b;      
        b >>= 1;
    }
    return p;

/*
    alternative form
    while ( b != 0)
    {
        if((b & 1) == 1) 
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if(hi_bit_set == 0x80) 
            a ^= 0x1b;
        b >>= 1;
    }
    return p;  
*/  

}

static void sub_bytes(unsigned char state[4][4])
{
    state[0][0] = sbox[ state[0][0] ];
    state[0][1] = sbox[ state[0][1] ];
    state[0][2] = sbox[ state[0][2] ];
    state[0][3] = sbox[ state[0][3] ];
    state[1][0] = sbox[ state[1][0] ];
    state[1][1] = sbox[ state[1][1] ];
    state[1][2] = sbox[ state[1][2] ];
    state[1][3] = sbox[ state[1][3] ];
    state[2][0] = sbox[ state[2][0] ];
    state[2][1] = sbox[ state[2][1] ];
    state[2][2] = sbox[ state[2][2] ];
    state[2][3] = sbox[ state[2][3] ];
    state[3][0] = sbox[ state[3][0] ];
    state[3][1] = sbox[ state[3][1] ];
    state[3][2] = sbox[ state[3][2] ];
    state[3][3] = sbox[ state[3][3] ];
}

static void inverse_sub_bytes(unsigned char state[4][4])
{
    state[0][0] = inverse_sbox[ state[0][0] ];
    state[0][1] = inverse_sbox[ state[0][1] ];
    state[0][2] = inverse_sbox[ state[0][2] ];
    state[0][3] = inverse_sbox[ state[0][3] ];
    state[1][0] = inverse_sbox[ state[1][0] ];
    state[1][1] = inverse_sbox[ state[1][1] ];
    state[1][2] = inverse_sbox[ state[1][2] ];
    state[1][3] = inverse_sbox[ state[1][3] ];
    state[2][0] = inverse_sbox[ state[2][0] ];
    state[2][1] = inverse_sbox[ state[2][1] ];
    state[2][2] = inverse_sbox[ state[2][2] ];
    state[2][3] = inverse_sbox[ state[2][3] ];
    state[3][0] = inverse_sbox[ state[3][0] ];
    state[3][1] = inverse_sbox[ state[3][1] ];
    state[3][2] = inverse_sbox[ state[3][2] ];
    state[3][3] = inverse_sbox[ state[3][3] ];
}

static void shift_rows(unsigned char state[4][4])
{
    unsigned char temp;
    /* row 0 is not shifted */
    /* row 1 is shifted 1 to the left */
    temp        = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    /* row 2 is shifted 2 to the left */
    temp        = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp        = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    /* row 3 is shifted 3 to the left */
    temp        = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

static void inverse_shift_rows(unsigned char state[4][4])
{
    unsigned char temp;
    /* row 0 is not shifted */
    /* row 1 is shifted 1 to the right */
    temp        = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    /* row 2 is shifted 2 to the right */
    temp        = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp        = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    /* row 3 is shifted 3 to the right */
    temp        = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

/* Mix column multiplies a magic matrix by the column.
**
**    Magic matrix:
**     2  3  1  1
**     1  2  3  1
**     1  1  2  3
**     3  1  1  1
*/
static void mix_column(unsigned char *column)
{
    /* in the galois world, addition is done by XOR */
    /* multiplying n by 1 results in n */
    /* multipling  n by 2 can be shortened to special case of galois_multiply */
    /* multiplying n by 3 is same as 2*n ^ n */
    unsigned char a[4];
    unsigned char b[4];
    int i;

    /* copy column to temp array a */
    memcpy(a, column, 4 * sizeof(unsigned char));

    /* this loop calculates 2*n (in galois field) for all values in column a */
    for(i=0; i<4; i++) 
    {
        b[i] = a[i] << 1;
        if((a[i] & 0x80) == 0x80) 
            b[i] ^= 0x1b;
    }
    
    /*          2*a0 + (  3*a1   ) +  a2  +  a3 */
    column[0] = b[0] ^ b[1] ^ a[1] ^ a[2] ^ a[3];

    /*           a0  + 2*a1 + (   3*a2  ) + a3 */
    column[1] = a[0] ^ b[1] ^ b[2] ^ a[2] ^ a[3];

    /*           a0  +  a1  + 2*a2 + (  3*a3   ) */
    column[2] = a[0] ^ a[1] ^ b[2] ^ b[3] ^ a[3];

    /*          (   3*a0  ) +  a1  +  a2  + 2*a3 */
    column[3] = b[0] ^ a[0] ^ a[1] ^ a[2] ^ b[3];
}

static void mix_columns(unsigned char state[4][4])
{
    unsigned char column[4];
    int i;

    for(i = 0; i < 4; ++i) /* for each column... */
    {
        column[0] = state[0][i];
        column[1] = state[1][i];
        column[2] = state[2][i];
        column[3] = state[3][i];

        mix_column(column);

        state[0][i] = column[0];
        state[1][i] = column[1];
        state[2][i] = column[2];
        state[3][i] = column[3];
    }

}

/* Inverse mix column multiplies a magic matrix by the column.
**
**    Magic matrix:
**     14  11  13   9
**      9  14  11  13
**     13   9  14  11
**     11  13   9  14
*/
static void inverse_mix_columns(unsigned char state[4][4])
{
    int i;

    for(i = 0; i < 4; ++i) /* for each column... */
    {
        unsigned char a0, a1, a2, a3;
        a0 = state[0][i];
        a1 = state[1][i];
        a2 = state[2][i];
        a3 = state[3][i];

        /*            (    14 * a0     ) + (    11 * a1     ) + (    13 * a2     ) + (     9 * a3     ) */
        state[0][i] = g_multiply(a0, 14) ^ g_multiply(a1, 11) ^ g_multiply(a2, 13) ^ g_multiply(a3,  9);

        /*            (     9 * a0     ) + (    14 * a1     ) + (    11 * a2     ) + (    13 * a3     ) */
        state[1][i] = g_multiply(a0,  9) ^ g_multiply(a1, 14) ^ g_multiply(a2, 11) ^ g_multiply(a3, 13);

        /*            (    13 * a0     ) + (     9 * a1     ) + (    14 * a2     ) + (    11 * a3     ) */
        state[2][i] = g_multiply(a0, 13) ^ g_multiply(a1,  9) ^ g_multiply(a2, 14) ^ g_multiply(a3, 11);

        /*            (    11 * a0     ) + (    13 * a1     ) + (     9 * a2     ) + (    14 * a3     ) */
        state[3][i] = g_multiply(a0, 11) ^ g_multiply(a1, 13) ^ g_multiply(a2,  9) ^ g_multiply(a3, 14);
    }
}

/* key_schedule_segment points to beginning of the round key within the key schedule */
static void add_round_key(unsigned char state[4][4], const unsigned char *key_schedule_segment)
{
    /* The round key is a 16-byte block from the key_schedule. */
    /* have to use the same column-wise mapping */
    state[0][0] ^= key_schedule_segment[0];
    state[0][1] ^= key_schedule_segment[4];
    state[0][2] ^= key_schedule_segment[8];
    state[0][3] ^= key_schedule_segment[12];
    state[1][0] ^= key_schedule_segment[1];
    state[1][1] ^= key_schedule_segment[5];
    state[1][2] ^= key_schedule_segment[9];
    state[1][3] ^= key_schedule_segment[13];
    state[2][0] ^= key_schedule_segment[2];
    state[2][1] ^= key_schedule_segment[6];
    state[2][2] ^= key_schedule_segment[10];
    state[2][3] ^= key_schedule_segment[14];
    state[3][0] ^= key_schedule_segment[3];
    state[3][1] ^= key_schedule_segment[7];
    state[3][2] ^= key_schedule_segment[11];
    state[3][3] ^= key_schedule_segment[15];
}

static void aes_round(unsigned char state[4][4], const unsigned char *key_schedule_segment)
{
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, key_schedule_segment);
}

static void aes_inverse_round(unsigned char state[4][4], const unsigned char *key_schedule_segment)
{
    inverse_shift_rows(state);
    inverse_sub_bytes(state);
    add_round_key(state, key_schedule_segment);
    inverse_mix_columns(state);
}

/* TODO: use restrict keyword? */
void itc_aes128_encrypt(const struct itc_aes128_context *ctx, const unsigned char *input, unsigned char *output)
{
    assert(ctx != NULL);
    assert(input != NULL);
    assert(output != NULL);

    unsigned char state[4][4];
    int i;

    {   /* copy input block to state in column-wise order */
        
        state[0][0] = input[0];
        state[0][1] = input[4];
        state[0][2] = input[8];
        state[0][3] = input[12];
        state[1][0] = input[1];
        state[1][1] = input[5];
        state[1][2] = input[9];
        state[1][3] = input[13];
        state[2][0] = input[2];
        state[2][1] = input[6];
        state[2][2] = input[10];
        state[2][3] = input[14];
        state[3][0] = input[3];
        state[3][1] = input[7];
        state[3][2] = input[11];
        state[3][3] = input[15];
    }

    /********************* Start AES Encryption Algorithm **********************/
    
    /* add round key */
    add_round_key(state, ctx->key_schedule);

    /* perform the first (n-1) rounds */
    for(i = 1; i < NR; ++i)
    {
        aes_round(state, ctx->key_schedule + ((i * KEY_LENGTH) * sizeof(unsigned char)) );
    }

    /* ...and then last special round */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx->key_schedule + ((NR * KEY_LENGTH) * sizeof(unsigned char)) );
    
    /********************** End AES Encryption Algorithm ***********************/

    {   /* copy state out */
        output[0]  = state[0][0];
        output[4]  = state[0][1];
        output[8]  = state[0][2];
        output[12] = state[0][3];
        output[1]  = state[1][0];
        output[5]  = state[1][1];
        output[9]  = state[1][2];
        output[13] = state[1][3];
        output[2]  = state[2][0];
        output[6]  = state[2][1];
        output[10] = state[2][2];
        output[14] = state[2][3];
        output[3]  = state[3][0];
        output[7]  = state[3][1];
        output[11] = state[3][2];
        output[15] = state[3][3];
    }
}


void itc_aes128_decrypt(const struct itc_aes128_context *ctx, const unsigned char *input, unsigned char *output)
{
    assert(ctx != NULL);
    assert(input != NULL);
    assert(output != NULL);

    unsigned char state[4][4];
    int i;

    {   /* copy input block to state in column-wise order */
        
        state[0][0] = input[0];
        state[0][1] = input[4];
        state[0][2] = input[8];
        state[0][3] = input[12];
        state[1][0] = input[1];
        state[1][1] = input[5];
        state[1][2] = input[9];
        state[1][3] = input[13];
        state[2][0] = input[2];
        state[2][1] = input[6];
        state[2][2] = input[10];
        state[2][3] = input[14];
        state[3][0] = input[3];
        state[3][1] = input[7];
        state[3][2] = input[11];
        state[3][3] = input[15];
    }

    /********************* Start AES Decryption Algorithm **********************/
    add_round_key(state, ctx->key_schedule + ((NR * KEY_LENGTH) * sizeof(unsigned char)));

    /* perform rounds in reverse */
    for(i = NR-1; i > 0; --i)
    {
        aes_inverse_round(state, ctx->key_schedule + ((i * KEY_LENGTH) * sizeof(unsigned char)) );
    }
    inverse_shift_rows(state);
    inverse_sub_bytes(state);
    add_round_key(state, ctx->key_schedule);

    
    /********************** End AES Decryption Algorithm ***********************/

    {
        /* copy state out */
        output[0]  = state[0][0];
        output[4]  = state[0][1];
        output[8]  = state[0][2];
        output[12] = state[0][3];
        output[1]  = state[1][0];
        output[5]  = state[1][1];
        output[9]  = state[1][2];
        output[13] = state[1][3];
        output[2]  = state[2][0];
        output[6]  = state[2][1];
        output[10] = state[2][2];
        output[14] = state[2][3];
        output[3]  = state[3][0];
        output[7]  = state[3][1];
        output[11] = state[3][2];
        output[15] = state[3][3];
    }
}

#endif /* ITC_AES128_C */