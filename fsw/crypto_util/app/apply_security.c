/* Copyright (C) 2009 - 2017 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
   limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
   any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
   arising out of, resulting from, or in any way connected with the software or its documentation.  Whether or not based upon warranty,
   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
   documentation or services provided hereunder

   ITC Team
   NASA IV&V
   ivv-itc@lists.nasa.gov
*/

/*
 *  Simple apply security program that reads a file into memory and calls the Crypto_TC_ApplySecurity function on the data.
 */ 

#include "apply_security.h"

int main(int argc, char *argv[]) {
    char *buffer;
    char const *filename;
    long buffer_size;
    char *security_type;

    if (argc == 3) {
        security_type = argv[1];
        filename = argv[2];
    } else {
        fprintf(stderr,"Command line usage: \n"\
               "\t%s <tc|tm|aos> <filename>\n"\
               "<tc|tm|aos> : Apply TeleCommand (tc) | Telemetry (tm) | Advanced Orbiting Systems (aos) Security T\n"\
               "<filename> : binary file with telecommand transfer frame bits\n",argv[0]);

        return OS_ERROR;
    }
    buffer = c_read_file(filename,&buffer_size);
    debug_printf("File buffer size:%lu\n",buffer_size);
    uint32 buffer_size_i = (uint32) buffer_size;
    debug_printf("File buffer size int:%d\n",buffer_size_i);
    debug_printf("File content: \n");
    debug_hexprintf(buffer,buffer_size_i);

    //Setup & Initialize CryptoLib
    Crypto_Init();

    uint8 * ptr_enc_frame = NULL;
    uint16 enc_frame_len; 

    //Call ApplySecurity on buffer contents depending on type.
    if (strcmp(security_type,"tc")==0){
        Crypto_TC_ApplySecurity(buffer, buffer_size_i, &ptr_enc_frame, &enc_frame_len);
    } else if (strcmp(security_type,"tm")==0){
        Crypto_TM_ApplySecurity(buffer, &buffer_size_i);
    } else if (strcmp(security_type,"aos")==0){
        Crypto_AOS_ApplySecurity(buffer, &buffer_size_i);
    }

    #ifdef TC_DEBUG
        OS_printf(KYEL "ApplySecurity Output:\n" RESET);
        OS_printf(KYEL "\tBuffer size int:%d\n" RESET, enc_frame_len);
        OS_printf(KYEL "\tEncrypted Frame Contents: \n\t" RESET);
    
        for(int i=0; i < enc_frame_len; i++)
            {
                OS_printf(KYEL "%02X" RESET, *(ptr_enc_frame+i));
            }
        OS_printf("\n");
    #endif

    free(buffer);
    free(ptr_enc_frame);
}