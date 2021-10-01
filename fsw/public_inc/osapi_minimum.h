/*
 *  Minimal port of https://github.com/nasa-itc/osal/blob/master/src/os/inc/osapi.h
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


#ifndef _osapi_minimum_
#define _osapi_minimum_

#include <stdio.h>
#include <stdlib.h>

#include "common_types_minimum.h"

#ifdef __cplusplus
   extern "C" {
#endif

#define OS_SUCCESS                     (0)
#define OS_ERROR                       (-1)
#define OS_INVALID_POINTER             (-2)
#define OS_ERROR_ADDRESS_MISALIGNED    (-3)
#define OS_ERROR_TIMEOUT               (-4)
#define OS_INVALID_INT_NUM             (-5)
#define OS_SEM_FAILURE                 (-6)
#define OS_SEM_TIMEOUT                 (-7)
#define OS_QUEUE_EMPTY                 (-8)
#define OS_QUEUE_FULL                  (-9)
#define OS_QUEUE_TIMEOUT               (-10)
#define OS_QUEUE_INVALID_SIZE          (-11)
#define OS_QUEUE_ID_ERROR              (-12)
#define OS_ERR_NAME_TOO_LONG           (-13)
#define OS_ERR_NO_FREE_IDS             (-14)
#define OS_ERR_NAME_TAKEN              (-15)
#define OS_ERR_INVALID_ID              (-16)
#define OS_ERR_NAME_NOT_FOUND          (-17)
#define OS_ERR_SEM_NOT_FULL            (-18)
#define OS_ERR_INVALID_PRIORITY        (-19)
#define OS_INVALID_SEM_VALUE           (-20)
#define OS_ERR_FILE                    (-27)
#define OS_ERR_NOT_IMPLEMENTED         (-28)
#define OS_TIMER_ERR_INVALID_ARGS      (-29)
#define OS_TIMER_ERR_TIMER_ID          (-30)
#define OS_TIMER_ERR_UNAVAILABLE       (-31)
#define OS_TIMER_ERR_INTERNAL          (-32)
#define OS_ERR_OBJECT_IN_USE           (-33)
#define OS_ERR_BAD_ADDRESS             (-34)
#define OS_ERR_INCORRECT_OBJ_STATE     (-35)
#define OS_ERR_INCORRECT_OBJ_TYPE      (-36)
#define OS_ERR_STREAM_DISCONNECTED     (-37)

/*
** Defines for Queue Timeout parameters
*/
#define OS_PEND   (-1)
#define OS_CHECK  (0)


#ifdef __cplusplus
   }
#endif

#endif

