#  Copyright (C) 2009 - 2017 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.
#
#   This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
#   limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
#   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
#   any warranty that the software will be error free.
#
#   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
#   arising out of, resulting from, or in any way connected with the software or its documentation.  Whether or not based upon warranty,
#   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
#   documentation or services provided hereunder
#
#   ITC Team
#   NASA IV&V
#   ivv-itc@lists.nasa.gov

include_directories(include)
include_directories(../crypto/public_inc)

aux_source_directory(src UTIL_SRC_FILES)
aux_source_directory(app APP_SRC_FILES)

file( GLOB SOURCE_FILES app/*.c )
foreach(SOURCE_PATH ${SOURCE_FILES})

    get_filename_component(EXECUTABLE_NAME ${SOURCE_PATH} NAME_WE)

    add_executable(${EXECUTABLE_NAME} ${SOURCE_PATH})

    target_sources(${EXECUTABLE_NAME} PRIVATE src/shared_util.c)
    target_link_libraries(${EXECUTABLE_NAME} LINK_PUBLIC Crypto)

    add_custom_command(TARGET ${EXECUTABLE_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${EXECUTABLE_NAME}> ${PROJECT_BINARY_DIR}/bin/${EXECUTABLE_NAME}
            COMMAND ${CMAKE_COMMAND} -E remove $<TARGET_FILE:${EXECUTABLE_NAME}>
            COMMENT "Created ${PROJECT_BINARY_DIR}/bin/${EXECUTABLE_NAME}"
            )
endforeach(SOURCE_PATH ${SOURCE_FILES})

target_include_directories (Crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

