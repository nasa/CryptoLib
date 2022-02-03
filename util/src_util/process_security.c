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
 *  Simple Process security program that reads a file into memory and calls the Crypto_TC_ProcessSecurity function on
 * the data.
 */

#include "process_security.h"

int main(int argc, char* argv[])
{
    char* buffer;
    const char* filename;
    long buffer_size;
    char* security_type;

    if (argc == 3)
    {
        security_type = argv[1];
        filename = argv[2];
    }
    else
    {
        fprintf(stderr,
                "Command line usage: \n"
                "\t%s <tc|tm|aos> <filename>\n"
                "<tc|tm|aos> : Process TeleCommand (tc) | Telemetry (tm) | Advanced Orbiting Systems (aos) Security T\n"
                "<filename> : binary file with telecommand transfer frame bits\n",
                argv[0]);

        return CRYPTO_LIB_ERROR;
    }
    buffer = c_read_file(filename, &buffer_size);
    debug_printf("File buffer size:%lu\n", buffer_size);
    int buffer_size_i = (int)buffer_size;
    debug_printf("File buffer size int:%d\n", buffer_size_i);
    debug_printf("File content: \n");
    debug_hexprintf(buffer, buffer_size_i);

    // Setup & Initialize CryptoLib
    Crypto_Init();

    // Call ProcessSecurity on buffer contents depending on type.
    if (strcmp(security_type, "tc") == 0)
    {
        TC_t* tc_sdls_processed_frame = malloc(sizeof(TC_t));
        Crypto_TC_ProcessSecurity((uint8_t* )buffer, &buffer_size_i, tc_sdls_processed_frame);
        free(tc_sdls_processed_frame);
    }
    else if (strcmp(security_type, "tm") == 0)
    {
        Crypto_TM_ProcessSecurity((uint8_t* )buffer, &buffer_size_i);
    }
    else if (strcmp(security_type, "aos") == 0)
    {
        Crypto_AOS_ProcessSecurity((uint8_t* )buffer, &buffer_size_i);
    }

    free(buffer);
}