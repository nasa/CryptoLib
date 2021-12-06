/* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory, including, but not
   limited to, any warranty that the software will conform to specifications, any implied warranties of merchantability, fitness
   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
   any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
   arising out of, resulting from, or in any way connected with the software or its documentation, whether or not based upon warranty,
   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
   documentation or services provided hereunder.

   ITC Team
   NASA IV&V
   jstar-development-team@mail.nasa.gov
*/

#include "shared_util.h"

//temp debug, remove later.
#include <string.h>


/*
* Function:  c_read_file
* --------------------
* Reads a file from disk into a char * buffer.
*
*
*  const char* f_name: file name & path to be read
*  long* f_size:
*
*  returns: a malloc'd char* containing the contents of the buffer.
*      Note that this buffer is NOT null terminated and must be free()'d.
*/
char * c_read_file(const char * f_name, long * f_size) {
    char* buffer=0;
    long length;
    FILE* f = fopen(f_name,"rb");
    if (f){
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        buffer = malloc (length);
        if (buffer) {
            fread (buffer, 1, length, f);
        }
        fclose (f);
    }
    if (buffer){
        *f_size = length;
        debug_printf("Buffer Length:%lu\n",length);
        return buffer;
    } else{
        return NULL;
    }

}

int convert_hexstring_to_byte_array(char* source_str, uint8* dest_buffer)
{
    char *line = source_str;
    char *data = line;
    int offset;
    int read_byte;
    int data_len = 0;

    while (sscanf(data, " %02x%n", &read_byte, &offset) == 1) 
    {
        dest_buffer[data_len++] = read_byte;
        data += offset;
    }
    return data_len;
}

void hex_conversion(char *buffer_h, uint8 **buffer_b, int *buffer_b_length)
{
    // Convert input plaintext
    *buffer_b = (uint8*)malloc((strlen(buffer_h) / 2) * sizeof(uint8));
    *buffer_b_length = convert_hexstring_to_byte_array(buffer_h, *buffer_b);
}

#ifdef DEBUG
void debug_printf(const char *format, ...)
{
    va_list args;
    fprintf(stderr, "DEBUG - ");
    va_start(args, format);
    vfprintf(stderr,format, args);
    va_end(args);
}
#else
void debug_printf(const char* format, ...) {
    //Do nothing, DEBUG preprocessor disabled.
}
#endif

#ifdef DEBUG
void debug_hexprintf(const char *bin_data, int size_bin_data)
{
    //https://stackoverflow.com/questions/6357031/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-in-c
    //https://stackoverflow.com/questions/5040920/converting-from-signed-char-to-unsigned-char-and-back-again
    unsigned char* u_bin_data = (unsigned char*)bin_data;
    unsigned char output[(size_bin_data*2)+1];
    char *ptr = &output[0];
    int i;
    for(i=0; i < size_bin_data; i++){
        ptr += sprintf(ptr,"%02X",u_bin_data[i]);
    }
    debug_printf("%s\n",output);
}
#else
void debug_hexprintf(const char* bin_data, int size_bin_data) {
    //Do nothing, DEBUG preprocessor disabled.
}
#endif
