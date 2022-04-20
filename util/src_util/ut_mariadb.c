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

/**
 *  Unit Tests that make use of Maria DB
 **/
#include "ut_mariadb.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

#include "crypto.h"
#include "shared_util.h"
#include <stdio.h>

/**
 * @brief Unit Test: Crypto Init with incomplete configuration
 * @note TODO: Not able to force the Crypto_Lib_Error ATM
 **/
UTEST(MARIA_DB, DB_CONNECT)
{
    int32_t status = CRYPTO_LIB_ERROR;
    char* mysql_username = "root";
    char* mysql_password = "itc123!";
    char* mysql_hostname = "localhost";
    char* mysql_database = "sadb";
    uint16_t mysql_port = 3306; //default port
    char* ssl_cert = "NONE";
    char* ssl_key = "NONE";
    char* ssl_ca = "NONE";
    char* ssl_capath = "NONE";
    uint8_t verify_server = 0; 
    char* client_key_password = NULL;

    status = Crypto_Config_MariaDB(mysql_hostname, mysql_database, mysql_port, CRYPTO_FALSE, verify_server, ssl_ca,
                                   ssl_capath, ssl_cert, ssl_key, client_key_password, mysql_username, mysql_password);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);


    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                        TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                        TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);

    status = Crypto_Init();

    SadbRoutine sadb_routine = get_sadb_routine_mariadb();
    //need the sa call
    SecurityAssociation_t* test_sa = NULL;
    test_sa = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));

    status = sadb_routine->sadb_get_sa_from_spi(1, &test_sa);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(test_sa->iv[11] , 0x01);

    test_sa->iv[11] = 0xAB;
    status = sadb_routine->sadb_save_sa(test_sa);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    status = sadb_routine->sadb_get_sa_from_spi(1, &test_sa);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(test_sa->iv[11] , 0xAB);
}

UTEST_MAIN();