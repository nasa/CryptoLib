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

/*
 *  Simple crypto security program that reads files into memory and calls the appropriate Crypto* function on the data.
 */

#include "crypto_sequence.h"

int main(int argc, char* argv[])
{
    char* buffer;
    const char* filename;
    long buffer_size;
    char* security_type;

    if (argc < 3 || argc % 2 == 0)
    {
        fprintf(stderr,
                "Command line usage: \n"
                "\t%s [<tc|tm|aos> <filename>]+\n"
                "specify as many [<tc_a|tm_a|aos_a|tc_p|tm_p|aos_p> <filename>] pairs as necessary to complete your "
                "crypto sequence test. Each file will be loaded and processed in sequence. \n"
                "<tc_a|tm_a|aos_a> : Apply TeleCommand (tc_a) | Telemetry (tm_a) | Advanced Orbiting Systems (aos_a) "
                "Security T\n"
                "<tc_p|tm_p|aos_p> : Process TeleCommand (tc_p) | Telemetry (tm_p) | Advanced Orbiting Systems (aos_p) "
                "Security T\n"
                "<filename> : binary file with telecommand transfer frame bits\n",
                argv[0]);

        return CRYPTO_LIB_ERROR;
    }
    // Setup & Initialize CryptoLib
    Crypto_Init();

    int arg_index = 0;
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len;

    while (arg_index != argc - 1)
    {
        security_type = argv[++arg_index];
        debug_printf("Security Type: %s\n", security_type);
        filename = argv[++arg_index];
        debug_printf("Filename: %s\n", filename);
        buffer = c_read_file(filename, &buffer_size);
        debug_printf("File buffer size:%lu\n", buffer_size);
        int buffer_size_i = (int)buffer_size;
        debug_printf("File buffer size int:%d\n", buffer_size_i);
        debug_printf("File content: \n");
        debug_hexprintf(buffer, buffer_size_i);

        // Call Apply/ProcessSecurity on buffer contents depending on type.
        if (strcmp(security_type, "tc_a") == 0)
        {
            Crypto_TC_ApplySecurity((const uint8_t* )buffer, (const uint16_t)buffer_size_i, &ptr_enc_frame,
                                    &enc_frame_len);
        }
        else if (strcmp(security_type, "tm_a") == 0)
        {
            Crypto_TM_ApplySecurity((uint8_t* )buffer, (int *)&buffer_size_i);
        }
        else if (strcmp(security_type, "aos_a") == 0)
        {
            Crypto_AOS_ApplySecurity((uint8_t* )buffer, (int *)&buffer_size_i);
        }
        else if (strcmp(security_type, "tc_p") == 0)
        {
            TC_t* tc_sdls_processed_frame = malloc(sizeof(TC_t));
            Crypto_TC_ProcessSecurity((uint8_t* )buffer, (int *)&buffer_size_i, tc_sdls_processed_frame);
            free(tc_sdls_processed_frame);
        }
        else if (strcmp(security_type, "tm_p") == 0)
        {
            Crypto_TM_ProcessSecurity((uint8_t* )buffer, (int *)&buffer_size_i);
        }
        else if (strcmp(security_type, "aos_p") == 0)
        {
            Crypto_AOS_ProcessSecurity((uint8_t* )buffer, (int *)&buffer_size_i);
        }
        free(buffer);
    }
}