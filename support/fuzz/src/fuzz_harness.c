#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include "crypto.h"

// Global variables
static jmp_buf crash_jmp_buf;

#define TC_MAX_FRAME_SIZE 1024
#define MAX_FRAME_SIZE    1786
static uint8_t tc_frame_buffer[TC_MAX_FRAME_SIZE];
static uint8_t tm_frame_buffer[MAX_FRAME_SIZE];
static uint8_t aos_frame_buffer[MAX_FRAME_SIZE];

// Signal handler for crashes
static void crash_handler(int sig)
{
    signal(sig, SIG_DFL);
    longjmp(crash_jmp_buf, 1);
}

static int32_t init_cryptolib_for_fuzzing(void)
{
    int32_t status;

    // Configure CryptoLib with settings for all protocols
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL,                  // Use internal key management
                            MC_TYPE_INTERNAL,                   // Use internal message counting
                            SA_TYPE_INMEMORY,                   // Use in-memory security associations
                            CRYPTOGRAPHY_TYPE_LIBGCRYPT,        // Use libgcrypt for crypto operations
                            IV_INTERNAL                         // Use internal IV generation
    );

    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE,         // Create FECF for TC frames
                     TC_PROCESS_SDLS_PDUS_TRUE,          // Process SDLS PDUs for TC frames
                     TC_HAS_PUS_HDR,                     // TC frames have PUS headers
                     TC_IGNORE_SA_STATE_FALSE,           // Don't ignore SA state
                     TC_IGNORE_ANTI_REPLAY_FALSE,        // Don't ignore anti-replay
                     TC_UNIQUE_SA_PER_MAP_ID_FALSE,      // Don't use unique SAs per MAP ID
                     TC_CHECK_FECF_TRUE,                 // Check FECF for TC frames
                     0x3F,                               // TC security flags
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE // Increment non-transmitted IV
    );

    Crypto_Config_TM(CRYPTO_TM_CREATE_FECF_TRUE,         // Create FECF for TC frames
                     TM_CHECK_FECF_TRUE,                 // Check FECF for TC frames
                     0x3F,                               // TC security flags
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE // Increment non-transmitted IV
    );

    Crypto_Config_AOS(CRYPTO_AOS_CREATE_FECF_TRUE,         // Create FECF for TC frames
                      AOS_CHECK_FECF_TRUE,                 // Check FECF for TC frames
                      0x3F,                               // TC security flags
                      SA_INCREMENT_NONTRANSMITTED_IV_TRUE // Increment non-transmitted IV
    );

    // Add parameters for TC, TM, and AOS protocols
    TCGvcidManagedParameters_t TC_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024, 1};
    Crypto_Config_Add_TC_Gvcid_Managed_Parameters(TC_Parameters);

    TMGvcidManagedParameters_t TM_Parameters = {
        0, 0x002c, 0, TM_HAS_FECF, 1786, TM_NO_OCF, 1};
    Crypto_Config_Add_TM_Gvcid_Managed_Parameters(TM_Parameters);

    AOSGvcidManagedParameters_t AOS_Parameters = {
        1, 0x0003, 0, AOS_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, 1786, AOS_NO_OCF, 1};
    Crypto_Config_Add_AOS_Gvcid_Managed_Parameters(AOS_Parameters);

    // Initialize the library
    status = Crypto_Init();
    return status;
}

static void reset_cryptolib(void)
{
    Crypto_Shutdown();
    init_cryptolib_for_fuzzing();
}

// Modify create_tc_frame to use static buffer
static uint8_t *create_tc_frame(const uint8_t *data, size_t size, size_t *out_size)
{
    const size_t MIN_TC_SIZE = 6;
    uint16_t     frame_size  = (size < MIN_TC_SIZE) ? MIN_TC_SIZE : size;

    if (frame_size > TC_MAX_FRAME_SIZE)
    {
        frame_size = TC_MAX_FRAME_SIZE - 1;
    }
    *out_size = frame_size;

    if (size < MIN_TC_SIZE)
    {
        memset(tc_frame_buffer, 0, MIN_TC_SIZE);
        tc_frame_buffer[0] = 0x20;                              // Version 1, Type TC
        tc_frame_buffer[1] = 0x03;                              // SCID
        tc_frame_buffer[2] = 0x00 | ((uint8_t)frame_size >> 8); // VCID
        tc_frame_buffer[3] = ((uint8_t)frame_size) & 0xFF;      // Frame length
        tc_frame_buffer[4] = 0x00;                              // Frame Sequence Number
    }
    else
    {
        memcpy(tc_frame_buffer, data, frame_size);
    }
    return tc_frame_buffer;
}

// Similarly modify create_tm_frame and create_aos_frame
static uint8_t *create_tm_frame(const uint8_t *data, size_t size, size_t *out_size)
{
    const size_t MIN_TM_SIZE = 1786;
    size                     = MIN_TM_SIZE;
    size_t frame_size        = (size < MIN_TM_SIZE) ? MIN_TM_SIZE : size;

    if (frame_size > MAX_FRAME_SIZE)
    {
        frame_size = MAX_FRAME_SIZE - 1;
    }
    *out_size = frame_size;

    if (size < MIN_TM_SIZE)
    {
        memset(tm_frame_buffer, 0, MIN_TM_SIZE);
        tm_frame_buffer[0] = 0x02; // Version 1, TM
        tm_frame_buffer[1] = 0xC0; // SCID
        tm_frame_buffer[2] = 0x00; // VCID
        tm_frame_buffer[3] = 0x00; // VC Frame Count
        tm_frame_buffer[4] = 0x00; // TF Data Field Status (upper)
        tm_frame_buffer[5] = 0x00; // TF Data Field Status (lower)
    }
    else
    {
        memcpy(tm_frame_buffer, data, frame_size);
    }
    return tm_frame_buffer;
}

static uint8_t *create_aos_frame(const uint8_t *data, size_t size, size_t *out_size)
{
    const size_t MIN_AOS_SIZE = 1786;
    size                      = MIN_AOS_SIZE;
    size_t frame_size         = (size < MIN_AOS_SIZE) ? MIN_AOS_SIZE : size;

    if (frame_size > MAX_FRAME_SIZE)
    {
        frame_size = MAX_FRAME_SIZE - 1;
    }
    *out_size = frame_size;

    if (size < MIN_AOS_SIZE)
    {
        memset(aos_frame_buffer, 0, MIN_AOS_SIZE);
        aos_frame_buffer[0] = 0x40; // TFVN = 2
        aos_frame_buffer[1] = 0xC0; // SCID = 3, VCID = 0
        aos_frame_buffer[2] = 0x00; // VC Frame Count (1)
        aos_frame_buffer[3] = 0x00; // VC Frame Count (2)
        aos_frame_buffer[4] = 0x00; // VC Frame Count (3)
        aos_frame_buffer[5] = 0x00; // Signaling Field
    }
    else
    {
        memcpy(aos_frame_buffer, data, frame_size);
    }
    return aos_frame_buffer;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Set up crash handling
    if (setjmp(crash_jmp_buf) != 0)
    {
        return 0; // Return if we caught a crash
    }
    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGILL, crash_handler);
    signal(SIGFPE, crash_handler);

    // Initialize on first run
    static int initialized = 0;
    if (!initialized)
    {
        init_cryptolib_for_fuzzing();
        initialized = 1;
    }

    // Need at least one byte for selector
    if (size < 1)
        return 0;

    uint8_t        selector     = data[0];
    const uint8_t *payload      = data + 1;
    size_t         payload_size = size - 1;

    // Select which API to fuzz (7 total functions)
    switch (selector % 7)
    {
        case 0:
        {
            // Crypto_TC_ApplySecurity
            size_t   frame_size = 0;
            uint8_t *frame      = create_tc_frame(payload, payload_size, &frame_size);
            if (frame)
            {
                uint8_t *out_frame = NULL;
                uint16_t out_size  = 0;
                Crypto_TC_ApplySecurity(frame, (uint16_t)frame_size, &out_frame, &out_size);
                if (out_frame)
                    free(out_frame);
            }
            break;
        }
        case 1:
        {
            // Crypto_TC_ProcessSecurity
            size_t   frame_size = 0;
            uint8_t *frame      = create_tc_frame(payload, payload_size, &frame_size);
            if (frame)
            {
                int  len      = frame_size;
                TC_t tc_frame = {0};
                Crypto_TC_ProcessSecurity(frame, &len, &tc_frame);
            }
            break;
        }
        case 2:
        {
            // Crypto_TM_ApplySecurity
            size_t   frame_size = 0;
            uint8_t *frame      = create_tm_frame(payload, payload_size, &frame_size);
            if (frame)
            {
                Crypto_TM_ApplySecurity(frame, (uint16_t)frame_size);
            }
            break;
        }
        case 3:
        {
            // Crypto_AOS_ApplySecurity
            size_t   frame_size = 0;
            uint8_t *frame      = create_aos_frame(payload, payload_size, &frame_size);
            if (frame)
            {
                Crypto_AOS_ApplySecurity(frame, (uint16_t)frame_size);
            }
            break;
        }
        case 4:
        {
            // Crypto_AOS_ProcessSecurity
            size_t   frame_size = 0;
            uint8_t *frame      = create_aos_frame(payload, payload_size, &frame_size);
            if (frame)
            {
                uint8_t *out_frame = NULL;
                uint16_t out_size  = 0;
                Crypto_AOS_ProcessSecurity(frame, (uint16_t)frame_size, &out_frame, &out_size);
                if (out_frame)
                    free(out_frame);
            }
            break;
        }
        case 5:
        {
            // Crypto_TM_ProcessSecurity
            size_t   frame_size = 0;
            uint8_t *frame      = create_tm_frame(payload, payload_size, &frame_size);
            if (frame)
            {
                uint8_t *out_frame = NULL;
                uint16_t out_size  = 0;
                Crypto_TM_ProcessSecurity(frame, (uint16_t)frame_size, &out_frame, &out_size);
                if (out_frame)
                    free(out_frame);
            }
            break;
        }

        case 6:
        {
            // Crypto_Parse_Check_FECF
            size_t   frame_size = 0;
            uint8_t *frame      = create_tc_frame(payload, payload_size, &frame_size);
            if (frame)
            {
                int  len      = frame_size;
                TC_t tc_frame = {0};
                Crypto_TC_Parse_Check_FECF(frame, &len, &tc_frame);
            }
            break;
        }
    }

    reset_cryptolib();

    return 0;
}