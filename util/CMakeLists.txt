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

include_directories(include)
include_directories(../include) 

if(${ENCTEST})
    find_package (Python3 REQUIRED COMPONENTS Interpreter Development)
    execute_process(COMMAND pip3 show pycryptodome RESULT_VARIABLE EXIT_CODE OUTPUT_QUIET)
    if(NOT ${EXIT_CODE} EQUAL 0)
        message(FATAL_ERROR "The \"pycryptodome\" Python3 package is not installed, and is required for ENCTEST.")
    endif()
endif(${ENCTEST})

aux_source_directory(core UTIL_SRC_FILES)
aux_source_directory(src_util APP_SRC_FILES) 

file( GLOB SOURCE_FILES src_util/*.c )
foreach(SOURCE_PATH ${SOURCE_FILES})
    get_filename_component(EXECUTABLE_NAME ${SOURCE_PATH} NAME_WE)

    if((NOT ${ENCTEST}) AND ${EXECUTABLE_NAME} STREQUAL et_dt_validation)
        continue()
    else()
        add_executable(${EXECUTABLE_NAME} ${SOURCE_PATH}) 
        target_sources(${EXECUTABLE_NAME} PRIVATE core/shared_util.c)
        target_link_libraries(${EXECUTABLE_NAME} LINK_PUBLIC Crypto)
    endif()

    if(${ENCTEST} AND ${EXECUTABLE_NAME} STREQUAL et_dt_validation)
        target_link_libraries(${EXECUTABLE_NAME} PUBLIC ${Python3_LIBRARIES}) 
        target_include_directories(${EXECUTABLE_NAME} PUBLIC ${Python3_INCLUDE_DIRS}) 
        find_library(${Python3_LIBRARIES} pycryptodome)
        
    endif()

    add_custom_command(TARGET ${EXECUTABLE_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${EXECUTABLE_NAME}> ${PROJECT_BINARY_DIR}/bin/${EXECUTABLE_NAME}
            COMMAND ${CMAKE_COMMAND} -E remove $<TARGET_FILE:${EXECUTABLE_NAME}>
            COMMENT "Created ${PROJECT_BINARY_DIR}/bin/${EXECUTABLE_NAME}"
            )
endforeach(SOURCE_PATH ${SOURCE_FILES}) 

target_include_directories (Crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set(OBJECT_DIR ${PROJECT_BINARY_DIR}/src/CMakeFiles/Crypto.dir/src_main)

if(${CODECOV})
    # Create the gcov target. Run coverage tests with 'make gcov'
    add_custom_target(gcov
        COMMAND mkdir -p coverage
        COMMAND ${CMAKE_MAKE_PROGRAM} test
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        )
    add_custom_command(TARGET gcov
        COMMAND echo "=================== GCOV ===================="
        #COMMAND gcov -b -o ${OBJECT_DIR} crypto_aos.c.gnco crypto_config.c.gnco crypto_key_mgmt.c.gnco crypto_mc.c.gnco crypto_print.c.gnco crypto_tc.c.gnco crypto_tm.c.gnco crypto_user.c.gnco crypto.c.gnco sadb_routine_inmemory.template.c.gnco sadb_routine.c.gnco
        COMMAND gcov -b -o ${OBJECT_DIR} crypto_aos.c.gnco crypto_config.c.gnco crypto_key_mgmt.c.gnco crypto_mc.c.gnco crypto_tc.c.gnco crypto_tm.c.gnco crypto_user.c.gnco crypto.c.gnco sadb_routine_inmemory.template.c.gnco 
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
