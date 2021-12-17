/*
 *  Minimal port of https://github.com/nasa-itc/osal/blob/master/src/os/inc/common_types.h
 *      needed to build standalone crypto library.
 *
 *  Copyright (c) 2019 United States Government as represented by
 *  the Administrator of the National Aeronautics and Space Administration.
 *  All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Filename: common_types.h
 *
 *  Purpose:
 *	    Unit specification for common types.
 *
 *  Design Notes:
 *         Assumes make file has defined processor family
 *
 *  References:
 *     Flight Software Branch C Coding Standard Version 1.0a
 *
 *  Notes:
 */

#ifndef _common_types_minimum_
#define _common_types_minimum_

#ifdef __cplusplus
   extern "C" {
#endif

#include <stdint.h>

/*
 * NOTE - NOT DEFINING STRUCT_LOW_BIT_FIRST or STRUCT_HIGH_BIT_FIRST
 * We should not make assumptions about the bit order here
 */

  typedef int8_t                                int8;
  typedef int16_t                               int16;
  typedef int32_t                               int32;
  typedef int64_t                               int64;
  typedef uint8_t                               uint8;
  typedef uint16_t                              uint16;
  typedef uint32_t                              uint32;
  typedef uint64_t                              uint64;
  typedef intptr_t                              intptr;


#ifdef __cplusplus
   }
#endif

#endif  /* _common_types_ */
