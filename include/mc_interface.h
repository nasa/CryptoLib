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
#ifndef MONITORING_AND_CONTROL_INTERFACE_H
#define MONITORING_AND_CONTROL_INTERFACE_H

#include "crypto_error.h"
#include "crypto_structs.h"

/* Structures */
typedef struct
{
    /* MC Interface, SDLS */
    int32_t (*mc_initialize)(void);
    void (*mc_log)(int32_t error_code);
    int32_t (*mc_shutdown)(void);
    
    /* MC Interface, SDLS-EP */
    /*
    int32_t (*mc_ping)();
    int32_t (*mc_log_status)(void);
    int32_t (*mc_dump_log)(void);
    int32_t (*mc_erase_log)(void);
    int32_t (*mc_self_test)(void);
    int32_t (*mc_alarm_reset_flag)(void);
    */
   
}  McInterfaceStruct, *McInterface;

/* Prototypes */
McInterface get_mc_interface_custom(void);
McInterface get_mc_interface_internal(void);

#endif // MONITORING_AND_CONTROL_INTERFACE_H
