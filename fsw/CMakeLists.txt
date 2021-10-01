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

include_directories(public_inc)

aux_source_directory(src LIB_SRC_FILES)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
    enable_testing()
endif()

# Create the app module
if(DEFINED ENV{CFECORE_SOURCE_DIR}) #if ${CFECORE_SOURCE_DIR} is set, expect cFS build infrastructure to be in place.
    add_cfe_app(Crypto ${LIB_SRC_FILES})
else() #standalone build
    add_library(Crypto SHARED ${LIB_SRC_FILES})
endif()

# Add libgcrypt
target_link_libraries(Crypto gcrypt)

#Include cmake install module - todo
#include(GNUInstallDirs)

add_custom_command(TARGET Crypto POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:Crypto> ${PROJECT_BINARY_DIR}/lib/libCrypto.so
        COMMENT "Created ${PROJECT_BINARY_DIR}/lib/libCrypto.so"
        )

add_subdirectory(crypto_util)

if((CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR MYPROJECT_BUILD_TESTING) AND BUILD_TESTING)
    add_subdirectory(crypto_tests)
endif()
