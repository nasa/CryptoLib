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

#include "key_interface.h"

/* Variables */
static crypto_key_t ek_ring[NUM_KEYS] = {0};
static KeyInterfaceStruct key_if_struct;

/* Prototypes */
static int32_t key_init(void);
static int32_t key_shutdown(void);
static crypto_key_t* get_ek_ring(void);

/* Functions */
KeyInterface get_key_interface_kmc(void)
{
    key_if_struct.key_init = key_init;
    key_if_struct.get_ek_ring = get_ek_ring;
    key_if_struct.key_shutdown = key_shutdown;
    return &key_if_struct;
}

static int32_t key_init(void)
{
    return CRYPTO_LIB_SUCCESS;
}

static int32_t key_shutdown(void)
{
    return CRYPTO_LIB_SUCCESS;
}

static crypto_key_t* get_ek_ring(void)
{
    fprintf(stderr, "Attempting to access key ring with KMC Crypto Service. This shouldn't happen!\n ");
    return NULL;
}
