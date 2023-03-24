/* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration.
   All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory,
   including, but not limited to, any warranty that the software will conform to specifications, any implied warranties
   of merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty that the
   documentation will conform to the program, or any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
   consequential damages, arising out of, resulting from, or in any way connected with the software or its
   documentation, whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was sustained
   from, or arose out of the results of, or use of, the software, documentation or services provided hereunder.

   ITC Team
   NASA IV&V
   jstar-development-team@mail.nasa.gov
*/

#ifndef CRYPTOLIB_STANDALONE_H
#define CRYPTOLIB_STANDALONE_H

#ifdef __cplusplus
extern "C"
{
#endif


/*
** Includes
*/
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "shared_util.h"


/*
** Defines
*/
#define TC_APPLY_PORT   76540
#define TC_PROCESS_PORT 76541
#define TM_APPLY_PORT   76542
#define TM_PROCESS_PORT 76543


/*
** Structures
*/
typedef struct 
{
   int sockfd;
   int port;
} udp_info_t;


/*
** Prototypes
*/
int32_t crypto_standalone_udp_init(udp_info_t* sock, int32_t port);


#ifdef __cplusplus
} /* Close scope of 'extern "C"' declaration which encloses file. */
#endif

#endif /* CRYPTOLIB_STANDALONE_H */
