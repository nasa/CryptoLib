# Copyright (C) 2009 - 2022 National Aeronautics and Space Administration.
# All Foreign Rights are Reserved to the U.S. Government.
# 
# This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory,
# including, but not limited to, any warranty that the software will conform to specifications, any implied warranties
# of merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty that the
# documentation will conform to the program, or any warranty that the software will be error free.
# 
# In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
# consequential damages, arising out of, resulting from, or in any way connected with the software or its
# documentation, whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was sustained
# from, or arose out of the results of, or use of, the software, documentation or services provided hereunder.
# 
# ITC Team
# NASA IV&V
# jstar-development-team@mail.nasa.gov

set(PROJECT_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# add_test(NAME Process_Security
#          COMMAND ${PROJECT_BINARY_DIR}/bin/process_security tc ${PROJECT_TEST_DIR}/data/tc4.1.dat
#          WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_TC_APPLY
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_tc_apply 
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_TC_PROCESS
        COMMAND ${PROJECT_BINARY_DIR}/bin/ut_tc_process
        WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_CRYPTO_CONFIG
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_crypto_config 
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_CRYPTO
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_crypto 
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_CRYPTO_AOS
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_crypto_aos 
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_CRYPTO_MC
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_crypto_mc 
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_TM_APPLY
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_tm_apply 
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_TM_PROCESS
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_tm_process 
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

# add_test(NAME UT_MARIADB
#          COMMAND ${PROJECT_BINARY_DIR}/bin/ut_mariadb
#          WORKING_DIRECTORY ${PROJECT_TEST_DIR})

if(${ENCTEST})
    add_test(NAME ET_DT_VALIDATION
             COMMAND ${PROJECT_BINARY_DIR}/bin/et_dt_validation 
             WORKING_DIRECTORY ${PROJECT_TEST_DIR})
endif()

if(${KMC_MDB_RH} OR ${KMC_MDB_DB})
    add_test(NAME UT_TC_KMC
             COMMAND ${PROJECT_BINARY_DIR}/bin/ut_tc_kmc
             WORKING_DIRECTORY ${PROJECT_TEST_DIR})
             
    add_test(NAME UT_SADB_ERR_CASES_KMC_CRYPTO
             COMMAND ${PROJECT_BINARY_DIR}/bin/ut_sadb_err_cases_kmc_crypto
             WORKING_DIRECTORY ${PROJECT_TEST_DIR})
    
    add_test(NAME UT_MYSQL_TLS_CONNECTION
             COMMAND ${PROJECT_BINARY_DIR}/bin/ut_mysql_tls_connection
             WORKING_DIRECTORY ${PROJECT_TEST_DIR})

    #add_test(NAME UT_MYSQL_M_TLS_CONNECTION
    #         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_mysql_m_tls_connection
    #         WORKING_DIRECTORY ${PROJECT_TEST_DIR})
             
    add_test(NAME UT_MARIADB
             COMMAND ${PROJECT_BINARY_DIR}/bin/ut_mariadb
             WORKING_DIRECTORY ${PROJECT_TEST_DIR})
    
    add_test(NAME UT_KMC_CRYPTO
             COMMAND ${PROJECT_BINARY_DIR}/bin/ut_kmc_crypto
             WORKING_DIRECTORY ${PROJECT_TEST_DIR})

    add_test(NAME UT_KMC_CRYPTO_WITH_MTLS_SADB
             COMMAND ${PROJECT_BINARY_DIR}/bin/ut_kmc_crypto_with_mtls_sadb
             WORKING_DIRECTORY ${PROJECT_TEST_DIR})
    
    # This Test cannot yet be accomplished.  Need CAM
    #add_test(NAME UT_KMC_CRYPTO_CAM
    #         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_kmc_crypto_cam
    #         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

    add_test(NAME UT_KMC_CRYPTO_AUTH_ONLY
             COMMAND ${PROJECT_BINARY_DIR}/bin/ut_kmc_crypto_auth_only
             WORKING_DIRECTORY ${PROJECT_TEST_DIR})
endif()