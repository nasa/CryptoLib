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
#ifndef _crypto_error_h_
#define _crypto_error_h_

#include "sadb_mariadb_error.h"

#define SADB_INVALID_SADB_TYPE                                    201
#define CRYPTO_CONFIGURATION_NOT_COMPLETE                         101
#define CRYPTO_MANAGED_PARAM_CONFIGURATION_NOT_COMPLETE           102
#define CRYPTO_MARIADB_CONFIGURATION_NOT_COMPLETE                 103
#define MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND                    104


#define CRYPTO_LIB_SUCCESS                  (0)
#define CRYPTO_LIB_ERROR                    (-1)
#define CRYPTO_LIB_ERR_NO_INIT              (-2)
#define CRYPTO_LIB_ERR_INVALID_TFVN         (-3)
#define CRYPTO_LIB_ERR_INVALID_SCID         (-4)
#define CRYPTO_LIB_ERR_INVALID_VCID         (-5)
#define CRYPTO_LIB_ERR_INVALID_MAPID        (-6)
#define CRYPTO_LIB_ERR_INVALID_CC_FLAG      (-7)
#define CRYPTO_LIB_ERR_NO_OPERATIONAL_SA    (-8)
#define CRYPTO_LIB_ERR_NULL_BUFFER          (-9)
#define CRYPTO_LIB_ERR_UT_BYTE_MISMATCH     (-10)
#define CRYPTO_LIB_ERR_NO_CONFIG            (-11)
#define CRYPTO_LIB_ERR_INVALID_FECF         (-12)
#define CRYPTO_LIB_ERR_BAD_ANTIREPLAY_WINDOW (-13)

#endif //_crypto_error_h_
