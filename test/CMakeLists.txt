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

set(PROJECT_TEST_DIR ${CMAKE_BINARY_DIR})

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

add_test(NAME UT_AOS_APPLY
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_aos_apply
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_AOS_PROCESS
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_aos_process
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_TM_APPLY
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_tm_apply 
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

add_test(NAME UT_TM_PROCESS
         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_tm_process 
         WORKING_DIRECTORY ${PROJECT_TEST_DIR})
if(CRYPTO_EPROC)        
    add_test(NAME UT_EP_MC
            COMMAND ${PROJECT_BINARY_DIR}/bin/ut_ep_mc 
            WORKING_DIRECTORY ${PROJECT_TEST_DIR})
            
    add_test(NAME UT_EP_SA_MGMT
            COMMAND ${PROJECT_BINARY_DIR}/bin/ut_ep_sa_mgmt 
            WORKING_DIRECTORY ${PROJECT_TEST_DIR})
            
    add_test(NAME UT_EP_KEY_MGMT
            COMMAND ${PROJECT_BINARY_DIR}/bin/ut_ep_key_mgmt 
            WORKING_DIRECTORY ${PROJECT_TEST_DIR})
endif()

if(NOT ${CRYPTO_WOLFSSL})
    add_test(NAME UT_AES_GCM_SIV
            COMMAND ${PROJECT_BINARY_DIR}/bin/ut_aes_gcm_siv
            WORKING_DIRECTORY ${PROJECT_TEST_DIR})
endif()

if(SA_FILE)
    add_test(NAME UT_SA_SAVE
            COMMAND ${PROJECT_BINARY_DIR}/bin/ut_sa_save 
            WORKING_DIRECTORY ${PROJECT_TEST_DIR})
endif()

# add_test(NAME UT_MARIADB
#          COMMAND ${PROJECT_BINARY_DIR}/bin/ut_mariadb
#          WORKING_DIRECTORY ${PROJECT_TEST_DIR})

if((KMC_MDB_DB OR KMC_MDB_RH))
    add_test(NAME UT_TC_KMC
             COMMAND ${PROJECT_BINARY_DIR}/bin/ut_tc_kmc
             WORKING_DIRECTORY ${PROJECT_TEST_DIR})
          
endif()
    # add_test(NAME UT_SADB_ERR_CASES_KMC_CRYPTO
    #          COMMAND ${PROJECT_BINARY_DIR}/bin/ut_sa_err_cases_kmc_crypto
    #          WORKING_DIRECTORY ${PROJECT_TEST_DIR})
    
    # add_test(NAME UT_MYSQL_TLS_CONNECTION
    #          COMMAND ${PROJECT_BINARY_DIR}/bin/ut_mysql_tls_connection
    #          WORKING_DIRECTORY ${PROJECT_TEST_DIR})

    #add_test(NAME UT_MYSQL_M_TLS_CONNECTION
    #         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_mysql_m_tls_connection
    #         WORKING_DIRECTORY ${PROJECT_TEST_DIR})
             
    # add_test(NAME UT_MARIADB
    #          COMMAND ${PROJECT_BINARY_DIR}/bin/ut_mariadb
    #          WORKING_DIRECTORY ${PROJECT_TEST_DIR})
    
    # add_test(NAME UT_KMC_CRYPTO
    #          COMMAND ${PROJECT_BINARY_DIR}/bin/ut_kmc_crypto
    #          WORKING_DIRECTORY ${PROJECT_TEST_DIR})

    # add_test(NAME UT_KMC_CRYPTO_WITH_MTLS_SADB
    #          COMMAND ${PROJECT_BINARY_DIR}/bin/ut_kmc_crypto_with_mtls_sadb
    #          WORKING_DIRECTORY ${PROJECT_TEST_DIR})
    
    # This Test cannot yet be accomplished.  Need CAM
    #add_test(NAME UT_KMC_CRYPTO_CAM
    #         COMMAND ${PROJECT_BINARY_DIR}/bin/ut_kmc_crypto_cam
    #         WORKING_DIRECTORY ${PROJECT_TEST_DIR})

    # add_test(NAME UT_KMC_CRYPTO_AUTH_ONLY
    #          COMMAND ${PROJECT_BINARY_DIR}/bin/ut_kmc_crypto_auth_only
    #          WORKING_DIRECTORY ${PROJECT_TEST_DIR})
#endif()

# if(TEST_ENC)
#     add_test(NAME ET_DT_VALIDATION
#              COMMAND ${PROJECT_BINARY_DIR}/bin/et_dt_validation 
#              WORKING_DIRECTORY ${PROJECT_TEST_DIR})
# endif()

include_directories(include)
include_directories(../include) 

# if(TEST_ENC)
#     set(Python3_FIND_STRATEGY VERSION)
#     find_package (Python3 REQUIRED COMPONENTS Interpreter Development)
#     execute_process(COMMAND pip3 show pycryptodome RESULT_VARIABLE EXIT_CODE OUTPUT_QUIET)
#     if(NOT ${EXIT_CODE} EQUAL 0)
#         message(FATAL_ERROR "The \"pycryptodome\" Python3 package is not installed, and is required for TEST_ENC.")
#     endif()
# endif()

file( GLOB UNIT_FILES unit/*.c)
foreach(SOURCE_PATH ${UNIT_FILES})
    get_filename_component(EXECUTABLE_NAME ${SOURCE_PATH} NAME_WE)

    # if((NOT TEST_ENC) AND ${EXECUTABLE_NAME} STREQUAL et_dt_validation)
    #     continue()
    # else()
    add_executable(${EXECUTABLE_NAME} ${SOURCE_PATH}) 
    target_sources(${EXECUTABLE_NAME} PRIVATE core/shared_util.c)
    target_link_libraries(${EXECUTABLE_NAME} LINK_PUBLIC crypto pthread)
    # endif()

    # if(TEST_ENC AND ${EXECUTABLE_NAME} STREQUAL et_dt_validation)
    #     target_link_libraries(${EXECUTABLE_NAME} PUBLIC ${Python3_LIBRARIES}) 
    #     target_include_directories(${EXECUTABLE_NAME} PUBLIC ${Python3_INCLUDE_DIRS}) 
    #     find_library(${Python3_LIBRARIES} pycryptodome)
    # endif()

    add_custom_command(TARGET ${EXECUTABLE_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${EXECUTABLE_NAME}> ${PROJECT_BINARY_DIR}/bin/${EXECUTABLE_NAME}
            COMMAND ${CMAKE_COMMAND} -E remove $<TARGET_FILE:${EXECUTABLE_NAME}>
            COMMENT "Created ${PROJECT_BINARY_DIR}/bin/${EXECUTABLE_NAME}"
            )
endforeach(SOURCE_PATH ${UNIT_FILES}) 

if(${KMC_MDB_RH} OR ${KMC_MDB_DB})
    file( GLOB KMC_FILES kmc/*.c)
    foreach(SOURCE_PATH ${KMC_FILES})
        get_filename_component(EXECUTABLE_NAME ${SOURCE_PATH} NAME_WE)

        add_executable(${EXECUTABLE_NAME} ${SOURCE_PATH}) 
        target_sources(${EXECUTABLE_NAME} PRIVATE core/shared_util.c)
        target_link_libraries(${EXECUTABLE_NAME} LINK_PUBLIC crypto pthread)

        add_custom_command(TARGET ${EXECUTABLE_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${EXECUTABLE_NAME}> ${PROJECT_BINARY_DIR}/bin/${EXECUTABLE_NAME}
                COMMAND ${CMAKE_COMMAND} -E remove $<TARGET_FILE:${EXECUTABLE_NAME}>
                COMMENT "Created ${PROJECT_BINARY_DIR}/bin/${EXECUTABLE_NAME}"
                )
    endforeach(SOURCE_PATH ${KMC_FILES}) 
endif()

target_include_directories (crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set(OBJECT_DIR ${PROJECT_BINARY_DIR}/src/CMakeFiles/crypto.dir/core)

if(${CODECOV})
    # Create the gcov target. Run coverage tests with 'make gcov'
    add_custom_target(gcov
        COMMAND mkdir -p coverage
        COMMAND ${CMAKE_MAKE_PROGRAM} test
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        )
    add_custom_command(TARGET gcov
        COMMAND echo "=================== GCOV ===================="
        #COMMAND gcov -b -o ${OBJECT_DIR} crypto_aos.c.gnco crypto_config.c.gnco crypto_key_mgmt.c.gnco crypto_mc.c.gnco crypto_print.c.gnco crypto_tc.c.gnco crypto_tm.c.gnco crypto_user.c.gnco crypto.c.gnco sa_routine_inmemory.template.c.gnco sa_routine.c.gnco
        COMMAND gcov -b -o ${OBJECT_DIR} crypto_aos.c.gnco crypto_config.c.gnco crypto_key_mgmt.c.gnco crypto_mc.c.gnco crypto_tc.c.gnco crypto_tm.c.gnco crypto_user.c.gnco crypto.c.gnco sa_routine_inmemory.template.c.gnco 
        # | grep -A 5 "Adder.cpp" > CoverageSummary.tmp
        #COMMAND cat CoverageSummary.tmp
        #COMMAND echo "-- Coverage files have been output to ${PROJECT_BINARY_DIR}/coverage"
        COMMAND lcov -c --directory ${OBJECT_DIR} --output-file ${PROJECT_BINARY_DIR}/coverage/results.info
        COMMAND genhtml ${PROJECT_BINARY_DIR}/coverage/results.info --output-directory ${PROJECT_BINARY_DIR}/coverage/results
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/coverage
        )
    add_dependencies(gcov ut_tc_apply)
    # Make sure to clean up the coverage folder
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES coverage)

    # Create the gcov-clean target. This cleans the build as well as generated 
    # .gcda and .gcno files.
    add_custom_target(scrub
    COMMAND ${CMAKE_MAKE_PROGRAM} clean
    COMMAND rm -f ${OBJECT_DIR}/*.gcno
    COMMAND rm -f ${OBJECT_DIR}/*.gcda
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    )
endif(${CODECOV})
