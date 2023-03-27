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
static volatile uint8_t keepRunning = CRYPTO_LIB_SUCCESS;


/* 
** Functions
*/
int32_t crypto_standalone_check_number_arguments(int actual, int expected)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (actual != expected)
    {
        status = CRYPTO_LIB_ERROR;
        printf("Invalid command format or number of arguments, type 'help' for more info\n");
    }
    return status;
}

void crypto_standalone_to_lower(char* str)
{
    char* ptr = str;
    while(*ptr)
    {
        *ptr = tolower((unsigned char) *ptr);
        ptr++;
    }
    return;
}

void crypto_standalone_print_help(void)
{
    printf(CRYPTO_PROMPT "command [args]\n"
            "---------------------------------------------------------------------\n"
            "help                               - Display help                    \n"
            "exit                               - Exit app                        \n"
            "noop                               - No operation command to device  \n"
            "reset cryptolib                    - Reset CryptoLib configuration   \n"
            "\n"
        );   
}

int32_t crypto_standalone_get_command(const char* str)
{
    int32_t status = CRYPTO_CMD_UNKNOWN;
    char lcmd[CRYPTO_MAX_INPUT_TOKEN_SIZE];
    
    strncpy(lcmd, str, CRYPTO_MAX_INPUT_TOKEN_SIZE);
    crypto_standalone_to_lower(lcmd);

    if(strcmp(lcmd, "help") == 0) 
    {
        status = CRYPTO_CMD_HELP;
    }
    else if(strcmp(lcmd, "exit") == 0) 
    {
        status = CRYPTO_CMD_EXIT;
    }
    else if(strcmp(lcmd, "noop") == 0) 
    {
        status = CRYPTO_CMD_NOOP;
    }
    else if(strcmp(lcmd, "reset") == 0) 
    {
        status = CRYPTO_CMD_RESET;
    }
    return status;
}

int32_t crypto_standalone_process_command(int32_t cc, int32_t num_tokens, char* tokens)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    char lcmd[CRYPTO_MAX_INPUT_TOKEN_SIZE];

    /* Process command */
    switch(cc) 
    {	
        case CRYPTO_CMD_HELP:
            crypto_standalone_print_help();
            break;
        
        case CRYPTO_CMD_EXIT:
            keepRunning = CRYPTO_LIB_ERROR;
            break;

        case CRYPTO_CMD_NOOP:
            if (crypto_standalone_check_number_arguments(num_tokens, 0) == CRYPTO_LIB_SUCCESS)
            {
                printf("NOOP command success\n");
            }
            break;
        
        case CRYPTO_CMD_RESET:
            if (crypto_standalone_check_number_arguments(num_tokens, 1) == CRYPTO_LIB_SUCCESS)
            {
                strncpy(lcmd, tokens, CRYPTO_MAX_INPUT_TOKEN_SIZE);
                crypto_standalone_to_lower(lcmd);
                if (strcmp(&tokens[0], "cryptolib") == 0)
                {
                    printf("Reset requested and confirmed!\n");
                }
                else
                {
                    printf("Need to provide additional argument \"confirm\" to reset!\n");
                }
            }
            break;
        
        default: 
            printf("Invalid command format, type 'help' for more info\n");
            status = CRYPTO_LIB_ERROR;
            break;
    }

    return status;
}

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
        status = CRYPTO_LIB_ERROR;
    }

    /* Keep Alive */
    optval = 1;
    optlen = sizeof(optval);
    setsockopt(sock->sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);    

    return status;
}

int32_t crypto_standalone_tc_apply(udp_info_t* tc_sock)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    
    uint8_t tc_apply_in[TC_MAX_FRAME_SIZE] = {0};
    //uint8_t tc_apply_out[TC_MAX_FRAME_SIZE] = {0};

    struct sockaddr_in rcv_addr;
    int sockaddr_size = sizeof(struct sockaddr_in);

    while(keepRunning == CRYPTO_LIB_SUCCESS)
    {
        /* Receive */
        status = recvfrom(tc_sock->sockfd, tc_apply_in, sizeof(tc_apply_in), 0, (struct sockaddr*) &rcv_addr, (socklen_t*) &sockaddr_size);
        if (status != -1)
        {
            //bytes_recvd = status;

            /* Process */

            /* Reply */
        }

        /* Delay */
        usleep(100);
    }
    return status;
}

void crypto_standalone_cleanup(const int signal)
{
    if (signal == SIGINT)
    {
        printf("\n");
        printf("Received CTRL+C, cleaning up... \n");
    }
    /* Signal threads to stop */
    keepRunning = CRYPTO_LIB_ERROR;
    exit(signal);
    return;
}

int main(int argc, char* argv[])
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    
    char input_buf[CRYPTO_MAX_INPUT_BUF];
    char input_tokens[CRYPTO_MAX_INPUT_TOKENS][CRYPTO_MAX_INPUT_TOKEN_SIZE];
    int num_input_tokens;
    int cmd;    
    char* token_ptr;

    udp_info_t tc_apply;
    //pthread_t tc_apply_thread;

    /* Initialize */
    printf("Starting CryptoLib in standalone mode! \n");
    printf("  TC Apply - UDP %d \n", TC_APPLY_PORT);
    //printf("  TC Process - UDP %d \n", TC_PROCESS_PORT);
    //printf("  TM Apply - UDP %d \n", TM_APPLY_PORT);
    //printf("  TM Process - UDP %d \n", TM_PROCESS_PORT);
    printf("\n");
    if (argc != 1)
    {
        printf("Invalid number of arguments! \n");
        printf("  Expected zero but received: %s \n", argv[1]);
    }
    
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    status = Crypto_Init();
    if(status != CRYPTO_LIB_SUCCESS)
    {
        printf("Crypto_Init failed with error %d \n", status);
        keepRunning = CRYPTO_LIB_ERROR;
    }
    else
    {
        keepRunning = crypto_standalone_udp_init(&tc_apply, TC_APPLY_PORT);
        printf("crypto_standalone_udp_init returned %d \n", keepRunning);
    }

    /* Catch CTRL+C */
    signal(SIGINT, crypto_standalone_cleanup);

    /* Main loop */
    while(keepRunning == CRYPTO_LIB_SUCCESS)
    {
        num_input_tokens = -1;
        cmd = CRYPTO_CMD_UNKNOWN;

        /* Read user input */
        printf(CRYPTO_PROMPT);
        fgets(input_buf, CRYPTO_MAX_INPUT_BUF, stdin);

        /* Tokenize line buffer */
        token_ptr = strtok(input_buf, " \t\n");
        while((num_input_tokens < CRYPTO_MAX_INPUT_TOKENS) && (token_ptr != NULL)) 
        {
            if(num_input_tokens == -1) 
            {
                /* First token is command */
                cmd = crypto_standalone_get_command(token_ptr);
            }
            else 
            {
                strncpy(input_tokens[num_input_tokens], token_ptr, CRYPTO_MAX_INPUT_TOKEN_SIZE);
            }
            token_ptr = strtok(NULL, " \t\n");
            num_input_tokens++;
        }

        /* Process command if valid */
        if(num_input_tokens >= 0)
        {
            crypto_standalone_process_command(cmd, num_input_tokens, token_ptr);
        }
    }

    /* Cleanup */
    close(tc_apply.port);

    Crypto_Shutdown();
    
    printf("\n");
    exit(status);
}