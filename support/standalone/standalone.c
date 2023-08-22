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
static volatile uint8_t tc_seq_num = 0;
static volatile uint8_t tc_vcid = CRYPTO_STANDALONE_FRAMING_VCID;
static volatile uint8_t tc_debug = 0;
static volatile uint8_t tm_debug = 0;


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

void crypto_standalone_to_lower(char *str)
{
    char *ptr = str;
    while (*ptr)
    {
        *ptr = tolower((unsigned char)*ptr);
        ptr++;
    }
    return;
}

void crypto_standalone_print_help(void)
{
    printf(CRYPTO_PROMPT "command [args]\n"
                         "----------------------------------------------------------------------\n"
                         "exit                               - Exit app                         \n"
                         "help                               - Display help                     \n"
                         "noop                               - No operation command to device   \n"
                         "reset                              - Reset CryptoLib                  \n"
                         "tc                                 - Toggle TC debug prints           \n"
                         "tm                                 - Toggle TM debug prints           \n"
                         "vcid #                             - Change active TC virtual channel \n"
                         "\n");
}

int32_t crypto_standalone_get_command(const char *str)
{
    int32_t status = CRYPTO_CMD_UNKNOWN;
    char lcmd[CRYPTO_MAX_INPUT_TOKEN_SIZE];

    strncpy(lcmd, str, CRYPTO_MAX_INPUT_TOKEN_SIZE);
    crypto_standalone_to_lower(lcmd);

    if (strcmp(lcmd, "help") == 0)
    {
        status = CRYPTO_CMD_HELP;
    }
    else if (strcmp(lcmd, "exit") == 0)
    {
        status = CRYPTO_CMD_EXIT;
    }
    else if (strcmp(lcmd, "noop") == 0)
    {
        status = CRYPTO_CMD_NOOP;
    }
    else if (strcmp(lcmd, "reset") == 0)
    {
        status = CRYPTO_CMD_RESET;
    }
    else if (strcmp(lcmd, "vcid") == 0)
    {
        status = CRYPTO_CMD_VCID;
    }
    else if (strcmp(lcmd, "tc") == 0)
    {
        status = CRYPTO_CMD_TC_DEBUG;
    }
    else if (strcmp(lcmd, "tm") == 0)
    {
        status = CRYPTO_CMD_TM_DEBUG;
    }
    return status;
}

int32_t crypto_standalone_process_command(int32_t cc, int32_t num_tokens, char *tokens)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    /* Process command */
    switch (cc)
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
        if (crypto_standalone_check_number_arguments(num_tokens, 0) == CRYPTO_LIB_SUCCESS)
        {
            status = crypto_reset();
            printf("Reset command received\n");
        }
        break;

    case CRYPTO_CMD_VCID:
        if (crypto_standalone_check_number_arguments(num_tokens, 1) == CRYPTO_LIB_SUCCESS)
        {
            uint8_t vcid = (uint8_t)atoi(&tokens[0]);
            /* Confirm new VCID valid */
            if (vcid < 64)
            {
                SadbRoutine sadb_routine = get_sadb_routine_inmemory();
                SecurityAssociation_t *test_association = NULL;
                sadb_routine->sadb_get_sa_from_spi(vcid, &test_association);

                /* Handle special case for VCID */
                if (vcid == 1)
                {
                    printf("Special case for VCID 1! \n");
                    vcid = 0;
                }

                if ((test_association->sa_state == SA_OPERATIONAL) &&
                    (test_association->gvcid_blk.mapid == TYPE_TC) &&
                    (test_association->gvcid_blk.scid == SCID))
                {
                    tc_vcid = vcid;
                    printf("Changed active virtual channel (VCID) to %d \n", tc_vcid);
                }
                else
                {
                    printf("Error - virtual channel (VCID) %d is invalid! Sticking with prior vcid %d \n", vcid, tc_vcid);
                }
            }
            else
            {
                printf("Error - virtual channl (VCID) %d must be less than 64! Sticking with prior vcid %d \n", vcid, tc_vcid);
            }
        }
        break;

    case CRYPTO_CMD_TC_DEBUG:
        if (crypto_standalone_check_number_arguments(num_tokens, 0) == CRYPTO_LIB_SUCCESS)
        {
            if (tc_debug == 0)
            {
                tc_debug = 1;
                printf("Enabled TC debug prints! \n");
            }
            else
            {
                tc_debug = 0;
                printf("Disabled TC debug prints! \n");
            }
        }
        break;

    case CRYPTO_CMD_TM_DEBUG:
        if (crypto_standalone_check_number_arguments(num_tokens, 0) == CRYPTO_LIB_SUCCESS)
        {
            if (tm_debug == 0)
            {
                tm_debug = 1;
                printf("Enabled TM debug prints! \n");
            }
            else
            {
                tm_debug = 0;
                printf("Disabled TM debug prints! \n");
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

int32_t crypto_standalone_udp_init(udp_info_t *sock, int32_t port)
{
    int status = CRYPTO_LIB_SUCCESS;
    int optval;
    socklen_t optlen;

    sock->port = port;

    /* Create */
    sock->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock->sockfd == -1)
    {
        printf("udp_init:  Socket create error port %d", sock->port);
    }

    /* Bind */
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr("0.0.0.0");
    saddr.sin_port = htons(sock->port);
    status = bind(sock->sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
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

int32_t crypto_reset(void)
{
    int32_t status;

    status = Crypto_Shutdown();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib initialization failed with error %d \n", status);
    }

    status = Crypto_Init_TM_Unit_Test();
    // TODO: CryptoLib appears to be looking at the second byte and not specficially the SCID bits
    if (status != CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib initialization failed with error %d \n", status);
    }

    return status;
}

void crypto_standalone_tc_frame(uint8_t *in_data, uint16_t in_length, uint8_t *out_data, uint16_t *out_length)
{
    /* TC Length */
    *out_length = (uint16_t)CRYPTO_STANDALONE_FRAMING_TC_DATA_LEN + 6;

    /* TC Header */
    out_data[0] = 0x20;
    out_data[1] = CRYPTO_STANDALONE_FRAMING_SCID;
    out_data[2] = ((tc_vcid << 2) & 0xFC) | (((uint16_t)CRYPTO_STANDALONE_FRAMING_TC_DATA_LEN >> 8) & 0x03);
    out_data[3] = (uint16_t)CRYPTO_STANDALONE_FRAMING_TC_DATA_LEN & 0x00FF;
    out_data[4] = tc_seq_num++;

    /* Segement Header */
    out_data[5] = 0x00;

    /* SDLS Header */

    /* TC Data */
    memcpy(&out_data[6], in_data, in_length);

    /* SDLS Trailer */
}

void *crypto_standalone_tc_apply(void *sock)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    udp_info_t *tc_sock = (udp_info_t *)sock;

    uint8_t tc_apply_in[TC_MAX_FRAME_SIZE];
    uint16_t tc_in_len = 0;
    uint8_t *tc_out_ptr;
    uint16_t tc_out_len = 0;

#ifdef CRYPTO_STANDALONE_HANDLE_FRAMING
    uint8_t tc_framed[TC_MAX_FRAME_SIZE];
#endif

    struct sockaddr_in rcv_addr;
    struct sockaddr_in fwd_addr;
    int sockaddr_size = sizeof(struct sockaddr_in);

    fwd_addr.sin_family = AF_INET;
    fwd_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    fwd_addr.sin_port = htons(TC_APPLY_FWD_PORT);

    /* Prepare */
    memset(tc_apply_in, 0x00, sizeof(tc_apply_in));

    while (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        /* Receive */
        status = recvfrom(tc_sock->sockfd, tc_apply_in, sizeof(tc_apply_in), 0, (struct sockaddr *)&rcv_addr, (socklen_t *)&sockaddr_size);
        if (status != -1)
        {
            tc_in_len = status;
            if (tc_debug == 1)
            {
                printf("crypto_standalone_tc_apply - received[%d]: 0x", tc_in_len);
                for (int i = 0; i < status; i++)
                {
                    printf("%02x", tc_apply_in[i]);
                }
                printf("\n");
            }

/* Frame */
#ifdef CRYPTO_STANDALONE_HANDLE_FRAMING
            crypto_standalone_tc_frame(tc_apply_in, tc_in_len, tc_framed, &tc_out_len);
            memcpy(tc_apply_in, tc_framed, tc_out_len);
            tc_in_len = tc_out_len;
            tc_out_len = 0;
            if (tc_debug == 1)
            {
                printf("crypto_standalone_tc_apply - framed[%d]: 0x", tc_in_len);
                for (int i = 0; i < tc_in_len; i++)
                {
                    printf("%02x", tc_apply_in[i]);
                }
                printf("\n");
            }
#endif

            /* Process */
            status = Crypto_TC_ApplySecurity(tc_apply_in, tc_in_len, &tc_out_ptr, &tc_out_len);
            if (status == CRYPTO_LIB_SUCCESS)
            {
                if (tc_debug == 1)
                {
                    printf("crypto_standalone_tc_apply - status = %d, encrypted[%d]: 0x", status, tc_out_len);
                    for (int i = 0; i < tc_out_len; i++)
                    {
                        printf("%02x", tc_out_ptr[i]);
                    }
                    printf("\n");
                }

                /* Reply */
                status = sendto(tc_sock->sockfd, tc_out_ptr, tc_out_len, 0, (struct sockaddr *)&fwd_addr, sizeof(fwd_addr));
                if ((status == -1) || (status != tc_out_len))
                {
                    printf("crypto_standalone_tc_apply - Reply error %d \n", status);
                }
            }
            else
            {
                printf("crypto_standalone_tc_apply - AppySecurity error %d \n", status);
            }

            /* Reset */
            memset(tc_apply_in, 0x00, sizeof(tc_apply_in));
            tc_in_len = 0;
            tc_out_len = 0;
            free(tc_out_ptr);
            if (tc_debug == 1)
            {
                printf("\n");
            }
        }

        /* Delay */
        usleep(100);
    }
    close(tc_sock->port);
    return tc_sock;
}

void crypto_standalone_tm_frame(uint8_t *in_data, uint16_t in_length, uint8_t *out_data, uint16_t *out_length)
{
    /* TM Length */
    *out_length = (uint16_t)in_length - 10;

    /* TM Header */
    memcpy(out_data, &in_data[10], in_length - 10);
}

void *crypto_standalone_tm_process(void *sock)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    udp_info_t *tm_sock = (udp_info_t *)sock;

    uint8_t tm_process_in[TM_FRAME_DATA_SIZE];
    int tm_process_len = 0;
    uint16_t spp_len = 0;
    uint8_t *tm_ptr;
    uint16_t tm_out_len = 0;

#ifdef CRYPTO_STANDALONE_HANDLE_FRAMING
    uint8_t tm_framed[TM_CADU_SIZE];
    uint16_t tm_framed_len = 0;
#endif

    struct sockaddr_in rcv_addr;
    struct sockaddr_in fwd_addr;
    int sockaddr_size = sizeof(struct sockaddr_in);

    fwd_addr.sin_family = AF_INET;
    fwd_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    fwd_addr.sin_port = htons(TM_PROCESS_FWD_PORT);

    while (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        /* Receive */
        status = recvfrom(tm_sock->sockfd, tm_process_in, sizeof(tm_process_in), 0, (struct sockaddr *)&rcv_addr, (socklen_t *)&sockaddr_size);
        if (status != -1)
        {
            tm_process_len = status;
            if (tm_debug == 1)
            {
                printf("crypto_standalone_tm_process - received[%d]: 0x", tm_process_len);
                for (int i = 0; i < status; i++)
                {
                    printf("%02x", tm_process_in[i]);
                }
                printf("\n");
            }

            /* Process */
#ifdef TM_CADU_HAS_ASM
                // Process Security skipping prepended ASM
            if(tm_debug ==1)
            {
                printf("Printing first bytes of Tf Pri Hdr:\n\t");
                for(int i=0; i < 6 ; i ++)
                {
                    printf("%02X", *(tm_process_in + 4 + i));
                }
                printf("\n");
                printf("Processing frame WITH ASM...\n");
            }
                // Account for ASM length
                status = Crypto_TM_ProcessSecurity(tm_process_in+4, (const uint16_t) tm_process_len-4, &tm_ptr, &tm_out_len);
#else
            if(tm_debug ==1)
            {
                printf("Processing frame without ASM...\n");
            }
            status = Crypto_TM_ProcessSecurity(tm_process_in, (const uint16_t) tm_process_len, &tm_ptr, &tm_out_len);
#endif
            if (status == CRYPTO_LIB_SUCCESS)
            {
                if (tm_debug == 1)
                {
                    printf("crypto_standalone_tm_process - status = %d, decrypted[%d]: 0x", status, tm_process_len);
                    for (int i = 0; i < tm_process_len; i++)
                    {
                        printf("%02x", tm_process_in[i]);
                    }
                    printf("\n");
                }

/* Frame */
#ifdef CRYPTO_STANDALONE_HANDLE_FRAMING
                crypto_standalone_tm_frame(tm_process_in, tm_process_len, tm_framed, &tm_framed_len);
                memcpy(tm_process_in, tm_framed, tm_framed_len);
                tm_process_len = tm_framed_len;
                tm_framed_len = 0;
                if (tm_debug == 1)
                {   printf("crypto_standalone_tm_process - beginning after first header pointer - deframed[%d]: 0x", tm_process_len);
                    for (int i = 0; i < tm_process_len; i++)
                    {
                        printf("%02x", tm_process_in[i]);
                    }
                    printf("\n");
                }
#endif

                /* Space Packet Protocol Loop */
                tm_ptr = &tm_process_in[0];

                while (tm_process_len > 5)
                {
                    if ((tm_ptr[0] >= 0x08) && (tm_ptr[0] < 0x10))
                    {
                        spp_len = ((tm_ptr[4] << 8) | tm_ptr[5]) + 7;
#ifdef CRYPTO_STANDALONE_TM_PROCESS_DEBUG
                        printf("crypto_standalone_tm_process - SPP[%d]: 0x", spp_len);
                        for (int i = 0; i < spp_len; i++)
                        {
                            printf("%02x", tm_ptr[i]);
                        }
                        printf("\n");
#endif
                        status = sendto(tm_sock->sockfd, tm_ptr, spp_len, 0, (struct sockaddr *)&fwd_addr, sizeof(fwd_addr));
                        if ((status == -1) || (status != spp_len))
                        {
                            printf("crypto_standalone_tm_process - Reply error %d \n", status);
                        }
                        tm_ptr = &tm_ptr[spp_len];
                        tm_process_len = tm_process_len - spp_len;
                    }
                    else
                    {
                        // if ( ((tm_ptr[0] != 0x03) && (tm_ptr[1] != 0xFF)) && ((tm_ptr[0] != 0xFF) && (tm_ptr[1] != 0x48)) )
                        //{
                        //     printf("crypto_standalone_tm_process - SPP loop error, expected idle packet or frame! tm_ptr = 0x%02x%02x \n", tm_ptr[0], tm_ptr[1]);
                        // }
                        tm_process_len = 0;
                    }
                }
            }
            else
            {
                printf("crypto_standalone_tm_process - ProcessSecurity error %d \n", status);
            }

            /* Reset */
            memset(tm_process_in, 0x00, sizeof(tm_process_in));
            tm_process_len = 0;
#ifdef CRYPTO_STANDALONE_TM_PROCESS_DEBUG
            printf("\n");
#endif
        }

        /* Delay */
        usleep(100);
    }
    close(tm_sock->port);
    return tm_sock;
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

int main(int argc, char *argv[])
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    char input_buf[CRYPTO_MAX_INPUT_BUF];
    char input_tokens[CRYPTO_MAX_INPUT_TOKENS][CRYPTO_MAX_INPUT_TOKEN_SIZE];
    int num_input_tokens;
    int cmd;
    char *token_ptr;

    udp_info_t tc_apply;
    udp_info_t tm_process;
    pthread_t tc_apply_thread;
    pthread_t tm_process_thread;

    printf("Starting CryptoLib in standalone mode! \n");
    printf("  TC Apply - UDP %d \n", TC_APPLY_PORT);
    printf("  TM Process - UDP %d \n", TM_PROCESS_PORT);
    printf("\n");
    if (argc != 1)
    {
        printf("Invalid number of arguments! \n");
        printf("  Expected zero but received: %s \n", argv[1]);
    }

    /* Initialize CryptoLib */
    status = crypto_reset();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib initialization failed with error %d \n", status);
        keepRunning = CRYPTO_LIB_ERROR;
    }

    /* Initialize sockets */
    if (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        status = crypto_standalone_udp_init(&tc_apply, TC_APPLY_PORT);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            printf("crypto_standalone_udp_init tc_apply failed with status %d \n", status);
            keepRunning = CRYPTO_LIB_ERROR;
        }
        else
        {
            status = crypto_standalone_udp_init(&tm_process, TM_PROCESS_PORT);
            if (status != CRYPTO_LIB_SUCCESS)
            {
                printf("crypto_standalone_udp_init tm_process failed with status %d \n", status);
                keepRunning = CRYPTO_LIB_ERROR;
            }
        }
    }

    /* Catch CTRL+C */
    signal(SIGINT, crypto_standalone_cleanup);

    /* Start threads */
    if (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        status = pthread_create(&tc_apply_thread, NULL, *crypto_standalone_tc_apply, &tc_apply);
        if (status < 0)
        {
            perror("Failed to create tc_apply_thread thread");
            keepRunning = CRYPTO_LIB_ERROR;
        }
        else
        {
            status = pthread_create(&tm_process_thread, NULL, *crypto_standalone_tm_process, &tm_process);
            if (status < 0)
            {
                perror("Failed to create tm_process_thread thread");
                keepRunning = CRYPTO_LIB_ERROR;
            }
        }
    }

    /* Main loop */
    while (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        num_input_tokens = -1;
        cmd = CRYPTO_CMD_UNKNOWN;

        /* Read user input */
        printf(CRYPTO_PROMPT);
        fgets(input_buf, CRYPTO_MAX_INPUT_BUF, stdin);

        /* Tokenize line buffer */
        token_ptr = strtok(input_buf, " \t\n");
        while ((num_input_tokens < CRYPTO_MAX_INPUT_TOKENS) && (token_ptr != NULL))
        {
            if (num_input_tokens == -1)
            {
                /* First token is command */
                cmd = crypto_standalone_get_command(token_ptr);
                // printf("CMD = %s %d\n",token_ptr,cmd);
            }
            else
            {
                strncpy(input_tokens[num_input_tokens], token_ptr, CRYPTO_MAX_INPUT_TOKEN_SIZE);
                // printf("Token[%d] = %s\n",num_input_tokens,token_ptr);
            }
            token_ptr = strtok(NULL, " \t\n");
            num_input_tokens++;
        }

        /* Process command if valid */
        if (num_input_tokens >= 0)
        {
            crypto_standalone_process_command(cmd, num_input_tokens, &input_tokens[0][0]);
        }
    }

    /* Cleanup */
    close(tc_apply.port);
    close(tm_process.port);

    Crypto_Shutdown();

    printf("\n");
    exit(status);
}