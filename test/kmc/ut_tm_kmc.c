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
 *  Unit Tests that make use of TM Functionality with KMC Service.
 **/

#include "ut_tm_apply.h"
#include "ut_tm_process.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"

#include <mysql/mysql.h>
#include <stdlib.h>

#define KMC_HOSTNAME           "itc.kmc.nasa.gov"
#define CA_PATH                "/home/itc/Desktop/kmc_oci-3.5.0/files/tls/ammos-ca-bundle.crt"
#define CLIENT_CERTIFICATE     "/home/itc/Desktop/kmc_oci-3.5.0/files/tls/ammos-server-cert.pem"
#define CLIENT_CERTIFICATE_KEY "/home/itc/Desktop/kmc_oci-3.5.0/files/tls/ammos-server-key.pem"

/**
 * @brief Error Function for MDB_DB_RESET
 *
 * @param con
 */
void finish_with_error(MYSQL *con)
{
    fprintf(stderr, "%s\n", mysql_error(con));
    mysql_close(con);
    exit(1);
}

void reload_db(void)
{
    printf("Resetting Database\n");
    system("mysql --host=itc.kmc.nasa.gov -u cryptosvc "
           "--ssl-ca=/home/itc/Desktop/kmc_oci-3.5.0/files/tls/ammos-ca-bundle.crt  --ssl-verify-server-cert "
           "--ssl-cert=/home/itc/Desktop/kmc_oci-3.5.0/files/tls/ammos-server-cert.pem "
           "--ssl-key=/home/itc/Desktop/kmc_oci-3.5.0/files/tls/ammos-server-key.pem < "
           "src/sa/sadb_mariadb_sql/empty_sadb.sql");
    printf("first call done\n");
    system("mysql --host=itc.kmc.nasa.gov -u cryptosvc "
           "--ssl-ca=/home/itc/Desktop/kmc_oci-3.5.0/files/tls/ammos-ca-bundle.crt  --ssl-verify-server-cert "
           "--ssl-cert=/home/itc/Desktop/kmc_oci-3.5.0/files/tls/ammos-server-cert.pem "
           "--ssl-key=/home/itc/Desktop/kmc_oci-3.5.0/files/tls/ammos-server-key.pem < "
           "src/sa/test_sadb_mariadb_sql/create_sadb_ivv_unit_tests.sql");
}

/**
 * @brief MariaDB: Table Cleanup for Unit Tests
 * Be sure to use only after initialization
 * TODO: Move to shared function for all Unit Tests
 */
void MDB_DB_RESET()
{
    MYSQL *con = mysql_init(NULL);
    if (sa_mariadb_config->mysql_mtls_key != NULL)
    {
        mysql_optionsv(con, MYSQL_OPT_SSL_KEY, sa_mariadb_config->mysql_mtls_key);
    }
    if (sa_mariadb_config->mysql_mtls_cert != NULL)
    {
        mysql_optionsv(con, MYSQL_OPT_SSL_CERT, sa_mariadb_config->mysql_mtls_cert);
    }
    if (sa_mariadb_config->mysql_mtls_ca != NULL)
    {
        mysql_optionsv(con, MYSQL_OPT_SSL_CA, sa_mariadb_config->mysql_mtls_ca);
    }
    if (sa_mariadb_config->mysql_mtls_capath != NULL)
    {
        mysql_optionsv(con, MYSQL_OPT_SSL_CAPATH, sa_mariadb_config->mysql_mtls_capath);
    }
    if (sa_mariadb_config->mysql_tls_verify_server != CRYPTO_FALSE)
    {
        mysql_optionsv(con, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &(sa_mariadb_config->mysql_tls_verify_server));
    }
    if (sa_mariadb_config->mysql_mtls_client_key_password != NULL)
    {
        mysql_optionsv(con, MARIADB_OPT_TLS_PASSPHRASE, sa_mariadb_config->mysql_mtls_client_key_password);
    }
    if (sa_mariadb_config->mysql_require_secure_transport == CRYPTO_TRUE)
    {
        mysql_optionsv(con, MYSQL_OPT_SSL_ENFORCE, &(sa_mariadb_config->mysql_require_secure_transport));
    }
    // if encrypted connection (TLS) connection. No need for SSL Key
    if (mysql_real_connect(con, sa_mariadb_config->mysql_hostname, sa_mariadb_config->mysql_username,
                           sa_mariadb_config->mysql_password, sa_mariadb_config->mysql_database,
                           sa_mariadb_config->mysql_port, NULL, 0) == NULL)
    {
        // 0,NULL,0 are port number, unix socket, client flag
        finish_with_error(con);
    }

    printf("Truncating Tables\n");
    char *query = "TRUNCATE TABLE TM_security_associations\n";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to Truncate Table\n");
        finish_with_error(con);
    }
    query =
        "INSERT INTO TM_security_associations "
        "(spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid,"
        "ecs_len, shplf_len) VALUES "
        "(11,'kmc/test/"
        "key130',3,X'02',1,0,16,16,0,X'00000000000000000000000000000001',1024,X'"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000',5,0,0,3,0,0,1,1)";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create TM_security_association table for SPI 11\n");
        finish_with_error(con);
    }
}

/**
 * @brief Unit Test: Nominal Encryption CBC KMC
 **/
UTEST(TM_APPLY_KMC, HAPPY_PATH_ENC_TM_CBC_KMC)
{
    printf("has_fecf: %d\n", current_managed_parameters_struct.has_fecf);
    remove("sa_save_file.bin");
    printf("has_fecf: %d\n", current_managed_parameters_struct.has_fecf);
    reload_db();
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
                            IV_CRYPTO_MODULE, CRYPTO_TM_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB(KMC_HOSTNAME, "sadb", 3306, CRYPTO_TRUE, CRYPTO_TRUE, CA_PATH, NULL, CLIENT_CERTIFICATE,
                          CLIENT_CERTIFICATE_KEY, NULL, "root", "changeit");
    Crypto_Config_Kmc_Crypto_Service("https", "itc.kmc.nasa.gov", 8443, "crypto-service", "/certs/ammos-ca-bundle.crt",
                                     NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    GvcidManagedParameters_t TM_UT_Managed_Parameters = {
        0, 0x002C, 0, TM_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TM_SEGMENT_HDRS_NA, 1786, TM_NO_OCF, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TM_UT_Managed_Parameters);
    
    printf("has_fecf: %d\n", current_managed_parameters_struct.has_fecf);

    int32_t return_val = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);

    char *raw_tm_sdls_ping_h =
        "02C000001800000008010000000F00112233445566778899AABBCCDDEEFFA107FF000006D2ABBABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAA"
        "BBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABBAABB"
        "AABBAABBAABBAABB00000000000000000000000000000000415B";
    char *raw_tm_sdls_ping_b   = NULL;
    int   raw_tm_sdls_ping_len = 0;
    // SaInterface sa_if = get_sa_interface_inmemory();

    hex_conversion(raw_tm_sdls_ping_h, &raw_tm_sdls_ping_b, &raw_tm_sdls_ping_len);

    return_val =
        Crypto_TM_ApplySecurity((uint8_t *)raw_tm_sdls_ping_b);

    printf("has_fecf: %d\n", current_managed_parameters_struct.has_fecf);

    Crypto_Shutdown();
    free(raw_tm_sdls_ping_b);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
}

UTEST_MAIN();