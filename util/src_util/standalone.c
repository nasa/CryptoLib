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


/*******************************************************************************
** Standalone CryptoLib Implementation
** UDP interfaces to apply / process each frame type and return the result.
*******************************************************************************/

#include "standalone.h"

/*
** Global Variables
*/


/* 
** Functions
*/
int32_t crypto_standalone_udp_init(udp_info_t* sock, int32_t port)
{
    int status = CRYPTO_LIB_SUCCESS;
    int optval;
    socklen_t optlen;

    sock->port = port;

    /* Create */
    sock->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sock->sockfd == -1)
    {
        printf("udp_init:  Socket create error port %d", sock->port);
    }

    /* Bind */
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr("0.0.0.0");
    saddr.sin_port = htons(sock->port);   
    status = bind(sock->sockfd, (struct sockaddr *) &saddr, sizeof(saddr));
    if (status != 0)
    {
        printf(" udp_init:  Socker bind error with port %d", sock->port);
    }
    else
    {
        status = CRYPTO_LIB_ERROR;
    }

    /* Keep Alive */
    optval = 1;
    optlen = sizeof(optval);
    setsockopt(sock->sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);    

    return status;
}

int main(int argc, char* argv[])
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    int32_t run_status = CRYPTO_LIB_SUCCESS;

    //uint8_t tc_apply_in[TC_MAX_FRAME_SIZE] = {0};
    //uint8_t tc_apply_out[TC_MAX_FRAME_SIZE] = {0};

    udp_info_t tc_apply;


    /* Initialize */
    printf("Starting CryptoLib in standalone mode! \n");
    printf("  TC Apply - UDP %d \n", TC_APPLY_PORT);
    //printf("  TC Process - UDP 76541 \n");
    //printf("  TM Apply - UDP 76542 \n");
    //printf("  TM Process - UDP 76543 \n");
    printf("\n");
    if (argc != 1)
    {
        printf("Invalid number of arguments! \n");
        printf("  Expected zero but received: %s \n", argv[1]);
    }
    
    status = Crypto_Init();
    if(status != CRYPTO_LIB_SUCCESS)
    {
        printf("Crypto_Init failed with error %d \n", status);
        run_status = CRYPTO_LIB_ERROR;
    }

    status = crypto_standalone_udp_init(&tc_apply, TC_APPLY_PORT);


    /* Loop for testing */
    while(run_status == CRYPTO_LIB_SUCCESS)
    {
        /* Initialize test data as proof of concept */

        /* Only run once for testing */
        run_status = CRYPTO_LIB_ERROR;
    }


    /* Cleanup */
    close(tc_apply.port);
    Crypto_Shutdown();
    printf("\n");
    return 1;
}