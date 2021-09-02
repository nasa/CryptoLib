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
   
#ifndef ITC_AES128_H
#define ITC_AES128_H

#define KS_LENGTH 176    /* key schedule length for 128-bit AES */

/*******************************************************************************
* 
* A lightweight implementation of AES 128-bit encryption.
*
* This code is meant for prototyping, and has not undergone any efforts
* to be safe from any side channel or timing attacks. It merely provides
* correct output in a small package.
*
* This library will likely misbehave if the target platform implements
* unsigned char with a size not equal to 8 bits.
*******************************************************************************/

struct itc_aes128_context
{
    unsigned char key_schedule[KS_LENGTH];
};

/* Takes a 128-bit key and creates the expanded key schedule.
** The key pointer must reference a a valid 16-byte block.
*/
void itc_aes128_init(struct itc_aes128_context *ctx, const unsigned char *key);

/* Methods for encrypting and decrypting a 128-bit (16 byte) block.
** The input and output pointers must reference a valid 16-byte block. Input same as output is allowed.
** The context pointer must have previously been initialized with a key.
*/
void itc_aes128_encrypt(const struct itc_aes128_context *ctx, const unsigned char *input, unsigned char *output);
void itc_aes128_decrypt(const struct itc_aes128_context *ctx, const unsigned char *input, unsigned char *output);

#endif /* ITC_AES128_H */
