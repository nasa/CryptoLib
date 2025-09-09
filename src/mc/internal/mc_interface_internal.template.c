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
#include <time.h>

/* Variables */
static FILE             *mc_file_ptr;
static McInterfaceStruct mc_if_struct;

/* Prototypes */
static int32_t mc_initialize(void);
static void    mc_log(int32_t error_code);
static int32_t mc_shutdown(void);

/* Functions */
McInterface get_mc_interface_internal(void)
{
    /* MC Interface, SDLS */
    mc_if_struct.mc_initialize = mc_initialize;
    mc_if_struct.mc_log        = mc_log;
    mc_if_struct.mc_shutdown   = mc_shutdown;

    return &mc_if_struct;
}

static int32_t mc_initialize(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    /* Open log */
    mc_file_ptr = fopen(MC_LOG_PATH, "a");
    if (mc_file_ptr == NULL)
    {
        status = CRYPTO_LIB_ERR_MC_INIT;
#ifdef DEBUG
        printf(KRED "ERROR: Monitoring and control initialization - internal failed\n" RESET);
#endif
    }

    return status;
}

static void mc_log(int32_t error_code)
{
    time_t     rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    /* Write to log if error code is valid */
    if (error_code != CRYPTO_LIB_SUCCESS)
    {
        fprintf(mc_file_ptr, "[%d%d%d,%d:%d:%d], %d\n", timeinfo->tm_year + 1900, timeinfo->tm_mon + 1,
                timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, error_code);

/* Also print error if debug enabled */
#ifdef DEBUG
        printf("MC_Log: Error, [%d%d%d,%d:%d:%d], %d\n", timeinfo->tm_year + 1900, timeinfo->tm_mon + 1,
               timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, error_code);
#endif
    }

    return;
}

static int32_t mc_shutdown(void)
{
    /* Close log */
    fclose(mc_file_ptr);

    return CRYPTO_LIB_SUCCESS;
}
