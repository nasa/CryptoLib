#include "standalone.h"

#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

static volatile uint8_t keepRunning = CRYPTO_LIB_SUCCESS;

void write_vcid(uint8_t vcid) {
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0660);
    if (fd < 0) { perror("shm_open");}
    if (ftruncate(fd, 1) != 0) { perror("ftruncate"); close(fd);}

    uint8_t *p = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { perror("mmap");}

    *p = vcid;  // write shared byte
    printf("wrote %u\n", *p);
}

uint8_t read_vcid(void)
{
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0660);
    if (fd < 0) { perror("shm_open"); return 1; }
    if (ftruncate(fd, 1) != 0) { perror("ftruncate"); close(fd); return 1; }

    uint8_t *p = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { perror("mmap"); return 1; }

    printf("read %u\n", *p);
    return *p;
}

void crypto_cmd_cleanup(const int signal)
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

int32_t crypto_reset(void)
{
    int32_t status;

    status = Crypto_Shutdown();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib shutdown failed with error %d \n", status);
    }

    status = Crypto_SC_Init();
    if (status != CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib initialization failed with error %d \n", status);
    }

    return status;
}

int32_t crypto_host_to_ip(const char *hostname, char *ip)
{
    struct addrinfo hints, *res, *p;
    int             status;
    void           *addr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET; // Uses IPV4 only.  AF_UNSPEC for IPV6 Support
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0)
    {
        return 1;
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr                     = &(ipv4->sin_addr);

        // Convert IP to String
        if (inet_ntop(p->ai_family, addr, ip, INET_ADDRSTRLEN) == NULL)
        {
            freeaddrinfo(res);
            return 1;
        }

        freeaddrinfo(res);
        return 0; // IP Found
    }
    freeaddrinfo(res);
    return 1; // IP NOT Found
}

int32_t crypto_standalone_set_vcid(uint8_t *cmd_in)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    uint8_t vcid = cmd_in[0];
    /* Confirm new VCID valid */
    if (vcid < 64)
    {
        SaInterface            sa_if            = get_sa_interface_inmemory();
        SecurityAssociation_t *test_association = NULL;

        status = sa_if->sa_get_operational_sa_from_gvcid(0, SCID, vcid, 0, &test_association);
        if (status != CRYPTO_LIB_SUCCESS)
        {
            return status;
        }
        Crypto_saPrint(test_association);
    
        if ((test_association->sa_state == SA_OPERATIONAL) && (test_association->gvcid_blk.mapid == TYPE_TC) && (test_association->gvcid_blk.scid == SCID))
        {
            write_vcid(vcid);
            printf("Changed active virtual channel (VCID) to %d \n", vcid);
        }
        else
        {
            printf("Error - virtual channel (VCID) %d invalid! Sticking with prior vcid %d\n", vcid, read_vcid());
            status = CRYPTO_LIB_SUCCESS;
        }
    }
    else
    {
        printf("Error - virtual channel (VCID) %d must be less than 64! Sticking with prior vcid %d\n", vcid, read_vcid());
    }
    return status;
}

int32_t crypto_standalone_direct_process_command(uint8_t *cmd_in)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    if ((cmd_in[0] << 8 | cmd_in[1]) != 0x1980)
    {
        status = CRYPTO_LIB_ERROR;
        return status;
    }

    // Parse CMD ID
    uint8_t cmd = cmd_in[2];

    switch (cmd)
    {
        case CRYPTO_CMD_EXIT:
            printf("Exit command received\n");
            keepRunning = CRYPTO_LIB_ERROR;
            break;

        case CRYPTO_CMD_NOOP:
            printf("NOOP command received\n");
            break;

        case CRYPTO_CMD_RESET:
            printf("Reset command received\n");
            status = crypto_reset();
            break;

        case CRYPTO_CMD_VCID:
            printf("VCID command received\n");
            status = crypto_standalone_set_vcid(&cmd_in[3]);
            break;

        default:
            printf("CMD not recognized\n");
            status = CRYPTO_LIB_ERROR;
            break;
    }
    return status;
}

void *crypto_standalone_direct_command(void* socks)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    udp_interface_t *cmd_socks     = (udp_interface_t *)socks;
    udp_info_t      *cmd_sock      = &cmd_socks->read;
    udp_info_t      *tlm_sock      = &cmd_socks->write;
    int              sockaddr_size = sizeof(struct sockaddr_in);

    uint8_t  cmd_in[TC_MAX_FRAME_SIZE];
    uint16_t cmd_in_len = 0;
    uint8_t  tlm_out[TC_MAX_FRAME_SIZE];
    uint16_t tlm_out_len = 0;

    memset(cmd_in, 0x00, sizeof(cmd_in));

    while (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        // /* Receive */
        status = recvfrom(cmd_sock->sockfd, cmd_in, sizeof(cmd_in), 0,
                          (struct sockaddr *)&cmd_sock->ip_address, (socklen_t *)&sockaddr_size);
        if (status != -1)
        {
            cmd_in_len = status;
            printf("crypto_standalone_direct_command - received[%d]: 0x", cmd_in_len);
            for (int i = 0; i < status; i++)
            {
                printf("%02x", cmd_in[i]);
            }
            printf("\n");

            status = crypto_standalone_direct_process_command(cmd_in);

            tlm_out_len = cmd_in_len + 1;
            // craft tlm
            memcpy(&tlm_out, &cmd_in, cmd_in_len);

            // set tlm msgid
            tlm_out[0] = 0x09;
            tlm_out[1] = 0x80;

            if (status == CRYPTO_LIB_SUCCESS)
            {
                // set status
                tlm_out[tlm_out_len-1] = 0x01;
            }
            else
            {
                // set status
                tlm_out[tlm_out_len-1] = 0x00;
            }

            sendto(tlm_sock->sockfd, &tlm_out, tlm_out_len, 0, (struct sockaddr *)&tlm_sock->saddr, sizeof(tlm_sock->saddr));
        }
        usleep(100);
    }

    close(cmd_sock->sockfd);
    return cmd_sock;
}

void crypto_standalone_direct_tlm()
{
    // TODO
}

int32_t crypto_standalone_socket_init(udp_info_t *sock, int32_t port, uint8_t bind_sock, int connection)
{
    int       status = CRYPTO_LIB_SUCCESS;
    int       optval;
    socklen_t optlen;

    sock->port = port;

    if (connection == 1)
    {
        /* Creating TCP socket */
        sock->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

        if (sock->sockfd == -1)
        {
            printf("tcp_init: Socket create error on port %d\n", sock->port);
            return CRYPTO_LIB_ERROR;
        }

        /* Determine IP */
        sock->saddr.sin_family = AF_INET;
        if (inet_addr(sock->ip_address) != INADDR_NONE)
        {
            sock->saddr.sin_addr.s_addr = inet_addr(sock->ip_address);
        }
        else
        {
            char ip[16];
            int  check = crypto_host_to_ip(sock->ip_address, ip);
            if (check == 0)
            {
                sock->saddr.sin_addr.s_addr = inet_addr(ip);
            }
            else
            {
                printf("socket_init: Failed to resolve hostname '%s'\n", sock->ip_address);
                return CRYPTO_LIB_ERROR;
            }
        }
        sock->saddr.sin_port = htons(sock->port);
    }
    else
    {
        /* Create UDP socket */
        sock->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock->sockfd == -1)
        {
            printf("udp_init:  Socket create error port %d \n", sock->port);
        }

        /* Determine IP */
        sock->saddr.sin_family = AF_INET;
        if (inet_addr(sock->ip_address) != INADDR_NONE)
        {
            sock->saddr.sin_addr.s_addr = inet_addr(sock->ip_address);
        }
        else
        {
            char ip[16];
            int  check = crypto_host_to_ip(sock->ip_address, ip);
            if (check == 0)
            {
                sock->saddr.sin_addr.s_addr = inet_addr(ip);
            }
        }
        sock->saddr.sin_port = htons(sock->port);
    }

    // UDP: bind only if needed
    if (bind_sock == 0 && sock->port != 6061)
    {
        status = bind(sock->sockfd, (struct sockaddr *)&sock->saddr, sizeof(sock->saddr));
        if (status != 0)
        {
            perror("bind");

            printf("udp_init: Bind failed on port %d\n", sock->port);
            return CRYPTO_LIB_ERROR;
        }
    }
    else
    {
        if (bind_sock == 1 && sock->port == 6061)
        {
            status = bind(sock->sockfd, (struct sockaddr *)&sock->saddr, sizeof(sock->saddr));
            if (status != 0)
            {
                perror("bind");

                printf("udp_init: Bind failed on port %d\n", sock->port);
                return CRYPTO_LIB_ERROR;
            }
        }
    }

    // Keep-alive socket option (not harmful for UDP, useful for TCP)
    optval = 1;
    optlen = sizeof(optval);
    setsockopt(sock->sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);

    return status;
}

int main()
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    udp_interface_t cmd;

    pthread_t cmd_thread;

    cmd.read.ip_address = "cryptolib-cmd";
    cmd.read.port       = CRYPTO_CMD_PORT;

    cmd.write.ip_address = GSW_HOSTNAME;
    cmd.write.port       = CRYPTO_TLM_PORT;

    /* Catch CTRL+C */
    signal(SIGINT, crypto_cmd_cleanup);

    /* Startup delay */
    sleep(10);

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
        status = crypto_standalone_socket_init(&cmd.read, CRYPTO_CMD_PORT, 0, 0); // udp 6060
        if (status != CRYPTO_LIB_SUCCESS)
        {
            printf("crypto_standalone_socket_init cmd.read failed with status %d \n", status);
            keepRunning = CRYPTO_LIB_ERROR;
        }
        else
        {
            status = crypto_standalone_socket_init(&cmd.write, CRYPTO_TLM_PORT, 0, 0); // udp 6061
            if (status != CRYPTO_LIB_SUCCESS)
            {
                printf("crypto_standalone_socket_init cmd.write failed with status %d \n", status);
                keepRunning = CRYPTO_LIB_ERROR;
            }
        }
    }

    /* Start threads */
    if (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        printf("CryptoLib Standalone CMD:\n");
        printf("\tCMD \n");
        printf("\t\tRead, UDP - %s : %d \n", cmd.read.ip_address, cmd.read.port);
        printf("\tTLM \n");
        printf("\t\tWrite, UDP - %s : %d \n", cmd.write.ip_address, cmd.write.port);
        printf("\n");

        status = pthread_create(&cmd_thread, NULL, *crypto_standalone_direct_command, &cmd);
        if (status < 0)
        {
            perror("Failed to create cmd_thread thread");
            keepRunning = CRYPTO_LIB_ERROR;
        }
    }

    /* Main loop */
    while (keepRunning == CRYPTO_LIB_SUCCESS)
    {
        continue;
    }

    /* Cleanup */
    close(cmd.read.sockfd);
    close(cmd.write.sockfd);

    Crypto_Shutdown();
    shm_unlink("/cryptolib_byte");

    printf("\n");
    exit(status);
}