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
#ifndef KEY_INTERFACE_H
#define KEY_INTERFACE_H

#include "crypto_error.h"
#include "crypto_structs.h"

/* Structures */
typedef struct
{
    uint8_t  value[KEY_SIZE];
    uint32_t key_len;
    uint8_t  key_state : 4;
} crypto_key_t;
#define CRYPTO_KEY_SIZE (sizeof(crypto_key_t))

typedef struct
{
    /* Key Interface, SDLS */
    crypto_key_t *(*get_key)(uint32_t key_id);
    int32_t (*key_init)(void);
    int32_t (*key_shutdown)(void);

    /* Key Interface, SDLS-EP */

} KeyInterfaceStruct, *KeyInterface;

/* Prototypes */
KeyInterface get_key_interface_custom(void);
KeyInterface get_key_interface_internal(void);
KeyInterface get_key_interface_kmc(void);

#endif // KEY_INTERFACE_H
