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

#ifndef CRYPTO_PRINT_H
#define CRYPTO_PRINT_H

/*
** Includes
*/
#include "crypto.h"
#include "crypto_structs.h"

/*
** Prototypes
*/

/**
 * @brief Function: Crypto_tcPrint
 * @param tc_frame: TC_T*
 * Prints the contents of the tc_frame
 **/
void Crypto_tcPrint(TC_t* tc_frame);

/**
 * @brief Function: Crypto_tmPrint
 * @param tm_frame: TM_T*
 * Prints the contents of the tm_frame
 **/
void Crypto_tmPrint(TM_t* tm_frame);

/**
 * @brief Function: Crypto_clcwPrint
 * @param clcw: Telemetry_Frame_Clcw_t*
 * Prints the contents of the clcw
 **/
void Crypto_clcwPrint(Telemetry_Frame_Clcw_t* clcw);

/**
 * @brief Function: Crypto_fsrPrint
 * @param report: SDLS_FSR_t*
 * Prints the contents of current FSR in memory
 **/
void Crypto_fsrPrint(SDLS_FSR_t* report);

/**
 * @brief Function: Crypto_ccsdsPrint
 * @param sdls_frame: CCSDS_t*
 * Prints the contents of current CCSDS in memory
 **/
void Crypto_ccsdsPrint(CCSDS_t* sdls_frame);

/**
 * @brief Function: Crypto_saPrint
 * @param sa: SecurityAssociation_t*
 * Prints the contents of SA
 **/
void Crypto_saPrint(SecurityAssociation_t* sa);

/**
 * @brief Function: Crypto_hexPrint
 * Prints the array of hex characters.
 * @param c: void*, The hex to be printed.
 * @param n: size_t, The size of the array to be printed.
 **/
void Crypto_hexprint(const void* c, size_t n);

/**
 * @brief Function: Crypto_binprint
 * Prints the array of binary data.
 * @param c: void*, The binary array to be printed.
 * @param n: size_t, The size of the array to be printed.
 **/
void Crypto_binprint(void* c, size_t n);

/**
 * @brief Function: Crypto_mpPrint
 * Prints the array of Managed Parameters.
 * @param managed_parameters: GvcidManagedParameters_t*, The binary array to be printed.
 * @param print_children: uint8_t, The size of the array to be printed.
 **/
void Crypto_mpPrint(GvcidManagedParameters_t* managed_parameters, uint8_t print_children);

#endif //CRYPTO_PRINT_H
