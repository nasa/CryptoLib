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
** Includes
*/
#include "crypto.h"

/**
 * @brief Function: Crypto_AOS_ApplySecurity
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @return int32: Success/Failure
 **/
int32_t Crypto_AOS_ApplySecurity(uint8_t* ingest, int *len_ingest)
{
    // Local Variables
    int32_t status = CRYPTO_LIB_SUCCESS;

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_AOS_ApplySecurity START -----\n" RESET);
#endif

    // TODO: This whole function!
    len_ingest = len_ingest;
    ingest[0] = ingest[0];

#ifdef DEBUG
    printf(KYEL "----- Crypto_AOS_ApplySecurity END -----\n" RESET);
#endif

    return status;
}

/**
 * @brief Function: Crypto_AOS_ProcessSecurity
 * @param ingest: uint8_t*
 * @param len_ingest: int*
 * @return int32: Success/Failure
 **/
int32_t Crypto_AOS_ProcessSecurity(uint8_t* ingest, int *len_ingest)
{
    // Local Variables
    int32_t status = CRYPTO_LIB_SUCCESS;

#ifdef DEBUG
    printf(KYEL "\n----- Crypto_AOS_ProcessSecurity START -----\n" RESET);
#endif

    // TODO: This whole function!
    len_ingest = len_ingest;
    ingest[0] = ingest[0];

#ifdef DEBUG
    printf(KYEL "----- Crypto_AOS_ProcessSecurity END -----\n" RESET);
#endif

    return status;
}