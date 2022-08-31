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


void cleanup_sa(SecurityAssociation_t* test_association)
{
    if (test_association->iv != NULL)
        free(test_association->iv);
    if (test_association->abm != NULL)
        free(test_association->abm);
    if (test_association->arsn != NULL)
        free(test_association->arsn);
    if (test_association->ek_ref != NULL)
        free(test_association->ek_ref);
    if (test_association->ecs != NULL)
        free(test_association->ecs);
    if (test_association->acs != NULL)
        free(test_association->acs);
    if (test_association->ak_ref != NULL)
        free(test_association->ak_ref);
    
    free(test_association);
}

void reload_db(void)
{
    printf("Resetting Database\n");
    system("mysql --host=localhost -uroot -pitc123! < ../../src/crypto_sadb/sadb_mariadb_sql/empty_sadb.sql");
    system("mysql --host=localhost -uroot -pitc123! < ../../src/crypto_sadb/test_sadb_mariadb_sql/create_sadb_ivv_unit_tests.sql");
}


// Global SQL Connection Parameters
// Generic passwords saved in a file = bad ... but this is just for testing

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

/**
 * @brief Unit Test: Nominal SQL Connection
 **/
UTEST(MARIA_DB, DB_CONNECT)
{
    int32_t status = CRYPTO_LIB_ERROR;
    reload_db();
    
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
    SecurityAssociation_t* test_sa;

    status = sadb_routine->sadb_get_sa_from_spi(1, &test_sa);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(test_sa->iv[11] , 0x01);

    test_sa->iv[11] = 0xAB;
    status = sadb_routine->sadb_save_sa(test_sa);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    status = sadb_routine->sadb_get_sa_from_spi(1, &test_sa);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(test_sa->iv[11] , 0xAB); 
    Crypto_Shutdown();      
    cleanup_sa(test_sa);
}

/**
 * @brief Unit Test: Nominal Encryption
 **/
UTEST(MARIA_DB, HAPPY_PATH_ENC)
{
    int32_t status = CRYPTO_LIB_ERROR;
    reload_db();
    
    status = Crypto_Config_MariaDB(mysql_hostname, mysql_database, mysql_port, CRYPTO_FALSE, verify_server, ssl_ca,
                                ssl_capath, ssl_cert, ssl_key, client_key_password, mysql_username, mysql_password);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                        TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                        TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);

    status = Crypto_Init();

    char* raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_mariadb();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t* test_association;

    status = sadb_routine->sadb_get_sa_from_spi(2, &test_association);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    cleanup_sa(test_association);
    status = sadb_routine->sadb_get_sa_from_spi(2, &test_association);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(test_association->iv[test_association->iv_len - 1], 2);  // Verify that IV incremented.   

    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    cleanup_sa(test_association);
    Crypto_Shutdown();  
}

/**
 * @brief Unit Test: Nominal Authorized Encryption
 **/
UTEST(MARIA_DB, HAPPY_PATH_AUTH_ENC)
{
    int32_t status = CRYPTO_LIB_ERROR;
    reload_db();
    
    status = Crypto_Config_MariaDB(mysql_hostname, mysql_database, mysql_port, CRYPTO_FALSE, verify_server, ssl_ca,
                                ssl_capath, ssl_cert, ssl_key, client_key_password, mysql_username, mysql_password);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);


    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                        TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                        TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);

    status = Crypto_Init();

    char* raw_tc_sdls_ping_h = "20030415000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_mariadb();
    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t* test_association;
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(3, &test_association);

    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);
    
    cleanup_sa(test_association);
    status = sadb_routine->sadb_get_sa_from_spi(3, &test_association);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    ASSERT_EQ(test_association->iv[test_association->iv_len - 1], 2);  // Verify that IV incremented.  

    Crypto_Shutdown();    
    cleanup_sa(test_association);
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
}

/**
 * @brief Validation Test: Authorized Decryption
 * Makes use of truth data created from the previous AUTH_ENCRYPTION_TEST, to validate that Crypto_TC_ProcessSecurity(
 *uint8_t* ingest, int* len_ingest,TC_t* tc_sdls_processed_frame) properly decrypts data and returns it to the intial
 *truth data created by the python_auth_encryption(uint8_t* data, uint8_t* key, uint8_t* iv, uint8_t* header, uint8_t*
 *bitmask, uint8_t** expected, long* expected_length) function.
 **/
UTEST(MARIA_DB, AUTH_DECRYPTION_TEST)
{
    char* dec_test_h = "20030433000000030000000000000000000000014ED87188D42B3F36130F355E83F3DE9C5E8F716321145159B41144E5514EBBEA";
    char* enc_test_h = "80d2c70008197f0b00310000b1fe";
    uint8_t* dec_test_b, *enc_test_b = NULL;
    int dec_test_len, enc_test_len = 0;
    int32_t status = CRYPTO_LIB_ERROR;
    reload_db();
    
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

    hex_conversion(dec_test_h, (char**) &dec_test_b, &dec_test_len);
    hex_conversion(enc_test_h, (char**) &enc_test_b, &enc_test_len);
    

    TC_t* tc_sdls_processed_frame;
    tc_sdls_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    memset(tc_sdls_processed_frame, 0, (sizeof(uint8_t) * TC_SIZE));
    
    SecurityAssociation_t* test_association;
    sadb_routine->sadb_get_sa_from_spi(3, &test_association);
    test_association->iv[test_association->iv_len - 1] = 0;
    sadb_routine->sadb_save_sa(test_association);

    Crypto_TC_ProcessSecurity(dec_test_b, &dec_test_len, tc_sdls_processed_frame);
    for (int i = 0; i < tc_sdls_processed_frame->tc_pdu_len; i++)
    {
        ASSERT_EQ(enc_test_b[i], tc_sdls_processed_frame->tc_pdu[i]);
    }

    Crypto_Shutdown();
    free(dec_test_b);
    free(enc_test_b);
    free(tc_sdls_processed_frame->tc_sec_header.iv);
    free(tc_sdls_processed_frame->tc_sec_header.sn);
    free(tc_sdls_processed_frame->tc_sec_header.pad);
    free(tc_sdls_processed_frame->tc_sec_trailer.mac); // TODO:  Is there a method to free all of this?
    free(tc_sdls_processed_frame);
}

/**
 * @brief Unit Test: Nominal Authorized Encryption With Partial IV Rollover, increment static IV
 **/
UTEST(MARIA_DB, HAPPY_PATH_APPLY_NONTRANSMITTED_INCREMENTING_IV_ROLLOVER)
{
    int32_t status = CRYPTO_LIB_ERROR;
    reload_db();
    
    status = Crypto_Config_MariaDB(mysql_hostname, mysql_database, mysql_port, CRYPTO_FALSE, verify_server, ssl_ca,
                                ssl_capath, ssl_cert, ssl_key, client_key_password, mysql_username, mysql_password);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);


    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                        TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                        TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);

    status = Crypto_Init();

    char* raw_tc_sdls_ping_h = "20030815000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;

    char* new_iv_h = "FFFFFFFFFFFC";
    char* new_iv_b = NULL;

    char* expected_iv_h = "000000000001000000000001";
    char* expected_iv_b = NULL;

    int raw_tc_sdls_ping_len = 0;
    int new_iv_len = 0;
    int expected_iv_len = 0;

    SadbRoutine sadb_routine = get_sadb_routine_mariadb();
    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    hex_conversion(new_iv_h, &new_iv_b, &new_iv_len);
    hex_conversion(expected_iv_h, &expected_iv_b, &expected_iv_len);
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t* test_association;

    sadb_routine->sadb_get_sa_from_spi(4, &test_association);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;    
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    
    
    cleanup_sa(test_association);
    sadb_routine->sadb_get_sa_from_spi(4, &test_association);    
    for (int i = 0; i < test_association->iv_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", i, expected_iv_b[i], *(test_association->iv + i)); 
        ASSERT_EQ(expected_iv_b[i], *(test_association->iv + i));
    }

    Crypto_Shutdown();
    cleanup_sa(test_association);
    free(expected_iv_b);
    free(new_iv_b);
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);  
}

/**
 * @brief Unit Test: Nominal Authorized Encryption With Partial IV Rollover, Static IV
 **/
UTEST(MARIA_DB, HAPPY_PATH_APPLY_STATIC_IV_ROLLOVER)
{
    int32_t status = CRYPTO_LIB_ERROR;
    reload_db();
    
    status = Crypto_Config_MariaDB(mysql_hostname, mysql_database, mysql_port, CRYPTO_FALSE, verify_server, ssl_ca,
                                ssl_capath, ssl_cert, ssl_key, client_key_password, mysql_username, mysql_password);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);


    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                        TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                        TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 2, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);

    status = Crypto_Init();

    char* raw_tc_sdls_ping_h = "20030815000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;

    char* new_iv_h = "FFFFFFFFFFFC";
    char* new_iv_b = NULL;

    char* expected_iv_h = "000000000000000000000001";
    char* expected_iv_b = NULL;

    int raw_tc_sdls_ping_len = 0;
    int new_iv_len = 0;
    int expected_iv_len = 0;

    SadbRoutine sadb_routine = get_sadb_routine_mariadb();
    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    hex_conversion(new_iv_h, &new_iv_b, &new_iv_len);
    hex_conversion(expected_iv_h, &expected_iv_b, &expected_iv_len);
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t* test_association;

    sadb_routine->sadb_get_sa_from_spi(4, &test_association);
    memcpy(test_association->iv, new_iv_b, new_iv_len);
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);  
    free(ptr_enc_frame);
    ptr_enc_frame = NULL; 
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    return_val =
        Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len); 

    cleanup_sa(test_association);
    sadb_routine->sadb_get_sa_from_spi(4, &test_association);    
    for (int i = 0; i < test_association->iv_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", i, expected_iv_b[i], *(test_association->iv + i)); 
        ASSERT_EQ(expected_iv_b[i], *(test_association->iv + i));
    }

    Crypto_Shutdown();
    cleanup_sa(test_association);
    free(expected_iv_b);
    free(new_iv_b);
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, return_val);  
}


/**
 * @brief Unit Test: Nominal Authorized Encryption With Partial ARSN Rollover, increment static ARSN
 **/
UTEST(MARIA_DB, HAPPY_PATH_APPLY_NONTRANSMITTED_INCREMENTING_ARSN_ROLLOVER)
{
    int32_t status = CRYPTO_LIB_ERROR;
    reload_db();
    
    status = Crypto_Config_MariaDB(mysql_hostname, mysql_database, mysql_port, CRYPTO_FALSE, verify_server, ssl_ca,
                                ssl_capath, ssl_cert, ssl_key, client_key_password, mysql_username, mysql_password);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);


    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                        TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                        TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);

    status = Crypto_Init();

    char* raw_tc_sdls_ping_h = "20030C15000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;

    char* new_arsn_h = "05FFFC";
    char* new_arsn_b = NULL;

    char* expected_arsn_h = "060001";
    char* expected_arsn_b = NULL;

    int raw_tc_sdls_ping_len = 0;
    int new_arsn_len = 0;
    int expected_arsn_len = 0;

    SadbRoutine sadb_routine = get_sadb_routine_mariadb();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    hex_conversion(new_arsn_h, &new_arsn_b, &new_arsn_len);
    hex_conversion(expected_arsn_h, &expected_arsn_b, &expected_arsn_len);
    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    SecurityAssociation_t* test_association;
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(5, &test_association);

    return_val =
            Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS,return_val);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    cleanup_sa(test_association);
    sadb_routine->sadb_get_sa_from_spi(5, &test_association);
    return_val =
            Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS,return_val);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    cleanup_sa(test_association);
    sadb_routine->sadb_get_sa_from_spi(5, &test_association);
    return_val =
            Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS,return_val);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    cleanup_sa(test_association);
    sadb_routine->sadb_get_sa_from_spi(5, &test_association);
    return_val =
            Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS,return_val);
    free(ptr_enc_frame);
    ptr_enc_frame = NULL;
    cleanup_sa(test_association);
    sadb_routine->sadb_get_sa_from_spi(5, &test_association);
    return_val =
            Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS,return_val);
    
    cleanup_sa(test_association);

    printf("Expected ARSN:\n");
    Crypto_hexprint(expected_arsn_b,expected_arsn_len);
    printf("Actual SA ARSN:\n");
    sadb_routine->sadb_get_sa_from_spi(5, &test_association);
    Crypto_hexprint(test_association->arsn,test_association->arsn_len);

    for (int i = 0; i < test_association->arsn_len; i++)
    {
        printf("[%d] Truth: %02x, Actual: %02x\n", i, expected_arsn_b[i], *(test_association->arsn + i));
        ASSERT_EQ(expected_arsn_b[i], *(test_association->arsn + i));
    }

    //Must shutdown after checking test_association ARSN since that will get freed!
    
    cleanup_sa(test_association);
    free(expected_arsn_b);
    free(new_arsn_b);
    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
}

/**
 * @brief Unit Test: Bad Spacecraft ID
 * This should pass the flawed hex string, and return CRYPTO_LIB_ERR_INVALID_SCID
 * Bad Space Craft ID.  This should pass the flawed .dat file, and return MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND
 **/
UTEST(MARIA_DB, BAD_SPACE_CRAFT_ID)
{
    int32_t status = CRYPTO_LIB_ERROR;
    reload_db();
    
    status = Crypto_Config_MariaDB(mysql_hostname, mysql_database, mysql_port, CRYPTO_FALSE, verify_server, ssl_ca,
                                ssl_capath, ssl_cert, ssl_key, client_key_password, mysql_username, mysql_password);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);


    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                        TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                        TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_FALSE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 3, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_SIZE);

    status = Crypto_Init();

    char* raw_tc_sdls_ping_bad_scid_h = "20010015000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_bad_scid_b = NULL;
    int raw_tc_sdls_ping_bad_scid_len = 0;

    hex_conversion(raw_tc_sdls_ping_bad_scid_h, &raw_tc_sdls_ping_bad_scid_b, &raw_tc_sdls_ping_bad_scid_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_bad_scid_b, raw_tc_sdls_ping_bad_scid_len,
                                                 &ptr_enc_frame, &enc_frame_len);
    free(raw_tc_sdls_ping_bad_scid_b);
    free(ptr_enc_frame);
    Crypto_Shutdown();
    ASSERT_EQ(MANAGED_PARAMETERS_FOR_GVCID_NOT_FOUND, return_val);
}
UTEST_MAIN();