/* Copyright (C) 2009 - 2015 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

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

#ifndef ITC_CMAC128_H
#define ITC_CMAC128_H

#include <stddef.h>
#include "itc_aes128.h"

#define ITC_CMAC128_SUCCESS         0
#define ITC_CMAC128_BAD_TAG    -10011

struct itc_cmac128_context
{
    struct itc_aes128_context aes_ctx;
    unsigned char k1[16];
    unsigned char k2[16];
};

void itc_cmac128_init(struct itc_cmac128_context * ctx, const unsigned char * key);

int itc_cmac128_generate_tag( struct itc_cmac128_context *ctx, 
                              size_t length, 
                              const unsigned char * message, 
                              unsigned char *tag );

int itc_cmac128_validate( struct itc_cmac128_context *ctx, 
                         size_t length, 
                         const unsigned char * message, 
                         const unsigned char *tag );

// todo : methods for streaming tagging/validation



#endif /* ITC_CMAC128_H */