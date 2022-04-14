/**
 * @file base64.h
 * @brief Base64 encoding scheme
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2021 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.1.2
 **/

// https://www.oryx-embedded.com/doc/base64_8h_source.html

#ifndef _BASE64URL_H
#define _BASE64URL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

typedef char char_t;
typedef unsigned int uint_t;

//Base64 encoding related functions
void base64urlEncode(const void* input, size_t inputLen, char_t* output,
                  size_t* outputLen);

int32_t base64urlDecode(const char_t* input, size_t inputLen, void* output,
                     size_t* outputLen);

#define ERROR_INVALID_PARAMETER 21
#define ERROR_INVALID_LENGTH 22
#define ERROR_INVALID_CHARACTER 23
#define NO_ERROR 0

// https://stackoverflow.com/questions/13378815/base64-length-calculation
// calculate the size of 'output' buffer required for a 'input' buffer of length x during Base64 encoding operation
#define B64ENCODE_OUT_SAFESIZE(x) ((((x) + 3 - 1)/3) * 4 + 1)

// calculate the size of 'output' buffer required for a 'input' buffer of length x during Base64 decoding operation
#define B64DECODE_OUT_SAFESIZE(x) (((x)*3)/4)

//C++ guard
#ifdef __cplusplus
}
#endif

#endif