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


#cmake_minimum_required(VERSION 2.6.4)
cmake_minimum_required(VERSION 3.14.0)
project(CRYPTO C)

set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")

OPTION(DEBUG "Debug" OFF) # Disabled by default, enable with: -DDEBUG=ON
OPTION(MYSQL "Mysql" OFF) # Disabled by default, enable with: -DMYSQL=ON

IF(DEBUG)
    ADD_DEFINITIONS(-DDEBUG -DOCF_DEBUG -DFECF_DEBUG -DSA_DEBUG -DPDU_DEBUG -DCCSDS_DEBUG -DTC_DEBUG -DMAC_DEBUG -DTM_DEBUG)
    add_compile_options(-ggdb)
ENDIF(DEBUG)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
    enable_testing()
endif()

include_directories(fsw/public_inc)

# The shared OSAL and cFE include directories should always be used
# Note that this intentionally does NOT include PSP-specific includes, just the generic
# Only include cFS/NOS3 directories if env var is defined
if(DEFINED ENV{CFECORE_SOURCE_DIR}) #if ${CFECORE_SOURCE_DIR} is set, expect cFS build infrastructure to be in place.
    include_directories(${CFECORE_SOURCE_DIR}/src/inc)
    include_directories(${CFEPSP_SOURCE_DIR}/fsw/inc)
    ADD_DEFINITIONS(-DNOS3)
else()
    #pass
endif()

if(NOT DEFINED ${PROJECT_BINARY_DIR})
    set(PROJECT_BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build)
endif()

add_subdirectory(fsw)
