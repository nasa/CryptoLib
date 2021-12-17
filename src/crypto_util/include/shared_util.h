/* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory, including, but not
   limited to, any warranty that the software will conform to specifications, any implied warranties of merchantability, fitness
   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
   any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
   arising out of, resulting from, or in any way connected with the software or its documentation, whether or not based upon warranty,
   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
   documentation or services provided hereunder.

   ITC Team
   NASA IV&V
   jstar-development-team@mail.nasa.gov
*/

#ifndef CRYPTOLIB_SHARED_UTIL_H
#define CRYPTOLIB_SHARED_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypto_error.h"

uint8_t * c_read_file(const uint8_t * f_name, long * f_size);

void debug_printf(const uint8_t* format, ...);
void debug_hexprintf(const uint8_t* bin_data,int size_bin_data);

void hex_conversion(uint8_t *buffer_h, uint8_t **buffer_b, int *buffer_b_length);
int convert_hexstring_to_byte_array(uint8_t* source_str, uint8_t* dest_buffer);

#ifdef __cplusplus
}  /* Close scope of 'extern "C"' declaration which encloses file. */
#endif

#endif //CRYPTOLIB_SHARED_UTIL_H
