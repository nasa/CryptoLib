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
#include "mc_interface.h"

/* Variables */
static McInterfaceStruct mc_if_struct;

/* Prototypes */
static int32_t mc_initialize(void);
static void    mc_log(int32_t error_code);
static int32_t mc_shutdown(void);

/* Functions */
McInterface get_mc_interface_disabled(void)
{
    /* MC Interface, SDLS */
    mc_if_struct.mc_initialize = mc_initialize;
    mc_if_struct.mc_log        = mc_log;
    mc_if_struct.mc_shutdown   = mc_shutdown;

    return &mc_if_struct;
}

static int32_t mc_initialize(void)
{
    return CRYPTO_LIB_SUCCESS;
}

static void mc_log(int32_t error_code)
{
    error_code = error_code;
    return;
}

static int32_t mc_shutdown(void)
{
    return CRYPTO_LIB_SUCCESS;
}
