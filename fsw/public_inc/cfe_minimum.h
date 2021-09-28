/*
**  Minimal port of https://github.com/nasa-itc/cFE/blob/master/fsw/cfe-core/src/inc/cfe.h
**      needed to build standalone crypto library.
**
**  Copyright (c) 2006-2019 United States Government as represented by
**  the Administrator of the National Aeronautics and Space Administration.
**  All Rights Reserved.
**
**  Licensed under the Apache License, Version 2.0 (the "License");
**  you may not use this file except in compliance with the License.
**  You may obtain a copy of the License at
**
**    http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

/*
** File: cfe.h
**
** Purpose:  cFE header file
**
** Author:   David Kobe, the Hammers Company, Inc.
**
** Notes:    This header file centralizes the includes for all cFE
**           Applications.  It includes all header files necessary
**           to completely define the cFE interface.
**
*/

/*************************************************************************/

/*
** Ensure that header is included only once...
*/
#ifndef _cfe_minimum_
#define _cfe_minimum_

#include "common_types_minimum.h"
#include "osapi_minimum.h"

#define CFE_PSP_MemCpy memcpy
#define CFE_PSP_MemSet memset
#define OS_printf printf

#endif  /* _cfe_ */
