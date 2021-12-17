#   Copyright (C) 2009 - 2022 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.
#
#   This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory, including, but not
#   limited to, any warranty that the software will conform to specifications, any implied warranties of merchantability, fitness
#   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
#   any warranty that the software will be error free.
#
#   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
#   arising out of, resulting from, or in any way connected with the software or its documentation, whether or not based upon warranty,
#   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
#   documentation or services provided hereunder.
#
#   ITC Team
#   NASA IV&V
#   jstar-development-team@mail.nasa.gov

 

include_directories(include)
include_directories(../crypto/public_inc) 

if(${ENCTEST})
    find_package (Python3 REQUIRED COMPONENTS Interpreter Development)
    execute_process(COMMAND pip3 show pycryptodome RESULT_VARIABLE EXIT_CODE OUTPUT_QUIET)
    if(NOT ${EXIT_CODE} EQUAL 0)
        message(FATAL_ERROR "The \"pycryptodome\" Python3 package is not installed, and is required for ENCTEST.")
    endif()
endif(${ENCTEST})

aux_source_directory(src UTIL_SRC_FILES)
aux_source_directory(app APP_SRC_FILES) 

file( GLOB SOURCE_FILES app/*.c )
foreach(SOURCE_PATH ${SOURCE_FILES})
    get_filename_component(EXECUTABLE_NAME ${SOURCE_PATH} NAME_WE)

    if((NOT ${ENCTEST}) AND ${EXECUTABLE_NAME} STREQUAL et_dt_validation)
        continue()
    else()
        add_executable(${EXECUTABLE_NAME} ${SOURCE_PATH}) 
        target_sources(${EXECUTABLE_NAME} PRIVATE src/shared_util.c)
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
