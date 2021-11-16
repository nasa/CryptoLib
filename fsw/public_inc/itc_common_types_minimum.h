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
#ifndef _itc_common_types_minimum_
#define _itc_common_types_minimum_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uintptr_t                             cpuaddr;
typedef size_t                                cpusize;
typedef ptrdiff_t                             cpudiff;

#ifdef __cplusplus
}
#endif


#endif //itc_common_types_minimum_.h
