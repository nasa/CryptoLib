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

/**
 * @brief Unit Test: Test 
 * 
 * Test TLS connection 
 *1) Required development packages: sudo yum install mariadb-connector-c-devel.x86_64
 * 
  2)IMPORTANT:The .pem files & MySQL MUST be configured and on the host before running this test
 * using this test refer to the guide:https://dev.mysql.com/doc/refman/8.0/en/encrypted-connections.html
 * 
 The program requires these files to establish a TLS connection:
 i) ssl_cert=/etc/pki/tls/certs/ammos-server-cert.pem
 ii) ssl_key=/etc/pki/tls/private/ammos-server-key.pem
 iii) ssl_ca=/etc/pki/tls/certs/ammos-ca-bundle.crt
  3)IMPORTANT:Build with "cmake -DMYSQL=ON ." 
 * 
 IMPORTANT:The database must have similar configuration for this test to succeed:
MariaDB server to use the standard host-based <your_server_hots_name>.
In our case host was asec-cmdenc-dev2.jpl.nasa.gov  
This was done by editing the server configuration file -- /etc/my.cnf.d/mariadb.server -- and adding the following options:

 * For example:
ssl_cert=/etc/pki/tls/certs/ammos-server-cert.pem
ssl_key=/etc/pki/tls/private/ammos-server-key.pem
ssl_ca=/etc/pki/tls/certs/ammos-ca-bundle.crt

This user is setup to allow normal password access. 
This user is allowed to access MariaDB on both the localhost and asec-cmdenc-dev2.jpl.nasa.gov hostnames, 
and *can* use TLS to connect, but is NOT REQUIRED to.  TLS access requires the use of the full hostname, since the server certificate will not validate for 'localhost'.

To connect using TLS (encrypted connection) from the command line client:

mysql -u testuser1 -p -h asec-cmdenc-dev2.jpl.nasa.gov --ssl-ca=/etc/pki/tls/certs/ammos-ca-bundle.crt --ssl-verify-server-cert
Login: testuser1
Password: <PASSWORD> 
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ut_tc_apply.h"
#include "utest.h"
#include "crypto_error.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "crypto_config_structs.h"
#include <mysql/mysql.h>


int32_t Crypto_Init_Unit_Test_For_DB(void);
/*Attempting to test a connection similar to command line authentication: 
mysql -u testuser1 -p -h asec-cmdenc-dev2.jpl.nasa.gov --ssl-ca=/etc/pki/tls/certs/ammos-ca-bundle.crt --ssl-verify-server-cert
However using the MySQL's C API*/
//<PASSWORD> - replace with actual password or test will fail. 
UTEST(MARIA_DB_CONNECTION_TESTS, TLS_TEST) {
    printf("START mariadb connection, TLS test() \n");
    int status = 0;
    /*connection input parameters. 
     Note: username, pass, and paths may differ on your system*/
    char* mysql_username = "testuser1";
    char* password = "l0ngp@ssWord"; //replace with actual password or test will fail.
    char* mysql_hostname = "asec-cmdenc-dev2.jpl.nasa.gov";
    char* mysql_database = NULL;
    uint16_t mysql_port = 3306;
    char* ssl_cert = "/etc/pki/tls/certs/ammos-server-cert.pem";
    char* ssl_key = "/etc/pki/tls/private/ammos-server-key.pem";
    char* ssl_ca = "/etc/pki/tls/certs/ammos-ca-bundle.crt";
    char* ssl_capath = "/etc/pki/tls/certs/";
    uint8_t verify_server = 0;
    char* client_key_password = NULL;

    /*set configuration params*/
    status = Crypto_Config_MariaDB(mysql_hostname, mysql_database, mysql_port, CRYPTO_TRUE, verify_server, ssl_ca,
                                   ssl_capath, ssl_cert, ssl_key, client_key_password, mysql_username, password);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    /*Prepare SADB type from config*/
    status = Crypto_Init_Unit_Test_For_DB();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("END mariadb connection, TLS test() status:%d \n", status);
}

/*Helper Functions:*/

/*
 * Note: SADB_TYPE_INMEMORY was change to SADB_TYPE_MARIADB for this test only. 
 */
int32_t Crypto_Init_Unit_Test_For_DB(void) {
    int32_t status = CRYPTO_LIB_SUCCESS;

    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 1024);
    status = Crypto_Init();
    return status;
}
UTEST_MAIN();
