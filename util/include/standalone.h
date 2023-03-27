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
#include <ctype.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
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

#define CRYPTO_PROMPT "cryptolib> "
#define CRYPTO_MAX_INPUT_BUF 512
#define CRYPTO_MAX_INPUT_TOKENS 32
#define CRYPTO_MAX_INPUT_TOKEN_SIZE 64

#define CRYPTO_CMD_UNKNOWN -1
#define CRYPTO_CMD_HELP     0
#define CRYPTO_CMD_EXIT     1
#define CRYPTO_CMD_NOOP     2
#define CRYPTO_CMD_RESET    3


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
int32_t crypto_standalone_check_number_arguments(int actual, int expected);
void crypto_standalone_to_lower(char* str);
void crypto_standalone_print_help(void);
int32_t crypto_standalone_get_command(const char* str);
int32_t crypto_standalone_process_command(int32_t cc, int32_t num_tokens, char* tokens);
int32_t crypto_standalone_udp_init(udp_info_t* sock, int32_t port);
int32_t crypto_standalone_tc_apply(udp_info_t* tc_sock);
void crypto_standalone_cleanup(const int signal);


#ifdef __cplusplus
} /* Close scope of 'extern "C"' declaration which encloses file. */
#endif

#endif /* CRYPTOLIB_STANDALONE_H */
