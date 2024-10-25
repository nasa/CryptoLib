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

cmake_minimum_required(VERSION 3.14.0)
project(crypto C)

#
# CUSTOM PATH Definiton
#
set(SA_CUSTOM_PATH_DEFAULT "../../sa/custom")
set(KEY_CUSTOM_PATH_DEFAULT "../../key/custom")
set(MC_CUSTOM_PATH_DEFAULT "../../mc/custom")
set(MC_LOG_PATH_DEFAULT "log.txt")
set(CRYPTO_CUSTOM_PATH_DEFAULT "../../crypto/custom")



#
# Define Build Flags
# The default value is captured in line, change with flag `-DXYZ=1`
# For flags with the same prefix, one or more may be enabled
#
option(CODECOV "Code Coverage" OFF)
option(CRYPTO_LIBGCRYPT "Cryptography Module - Libgcrypt" ON)
option(CRYPTO_KMC "Cryptography Module - KMC" OFF)
option(CRYPTO_WOLFSSL "Cryptography Module - WolfSSL" OFF)
option(CRYPTO_CUSTOM "Cryptography Module - CUSTOM" OFF)
option(CRYPTO_CUSTOM_PATH "Cryptography Module - CUSTOM PATH" OFF)
option(DEBUG "Debug" OFF)
option(KEY_CUSTOM "Key Module - Custom" OFF)
option(KEY_CUSTOM_PATH "Custom Key Path" OFF)
option(KEY_INTERNAL "Key Module - Internal" ON)
option(KEY_KMC "Key Module - KMC" OFF)
option(MC_CUSTOM "Monitoring and Control - Custom" OFF)
option(MC_CUSTOM_PATH "Custom Monitoring and Control path" OFF)
option(MC_DISABLED "Monitoring and Control - Disabled" OFF)
option(MC_INTERNAL "Monitoring and Control - Internal" ON)
option(SA_CUSTOM "Security Association - Custom" OFF)
option(SA_CUSTOM_PATH "Custom Security Association Path" OFF)
option(SA_INTERNAL "Security Association - Internal" ON)
option(SA_MARIADB "Security Association - MariaDB" OFF)
option(SUPPORT "Support" OFF)
option(SYSTEM_INSTALL "SystemInstall" OFF)
option(TEST "Test" OFF)
# option(TEST_ENC "Tests - Encryption" OFF)
option(SA_FILE "Save Security Association to File" OFF)
option(KEY_VALIDATION "Validate existance of key duplication" OFF)

OPTION(KMC_MDB_RH "KMC-MDB-RedHat-Integration-Testing" OFF) #Disabled by default, enable with: -DKMC_MDB_RH=ON
OPTION(KMC_MDB_DB "KMC-MDB-Debian-Integration-Testing" OFF) #Disabled by default, enable with: -DKMC_MDB_DB=ON
OPTION(KMC_CFFI_EXCLUDE "KMC-Exclude-Problematic-CFFI-Code" OFF) #Disabled by default, enable with: -DKMC_CFFI_EXCLUDE=ON


#
# Custom Module Paths
#
if(KEY_CUSTOM)
    if(NOT DEFINED KEY_CUSTOM_PATH)
        set(KEY_CUSTOM_PATH ${KEY_CUSTOM_PATH_DEFAULT})
        message(STATUS "Default path set for KEY_CUSTOM_PATH")
    endif()
    message(STATUS "KEY_CUSTOM being utilized.  Path set to: ${KEY_CUSTOM_PATH}")
endif()

if(MC_CUSTOM)
    if(NOT DEFINED MC_CUSTOM_PATH)
        set(MC_CUSTOM_PATH ${MC_CUSTOM_PATH_DEFAULT})
        message(STATUS "Default path set for MC_CUSTOM_PATH")
    endif()
    message(STATUS "MC_CUSTOM being utilized.  Path set to: ${MC_CUSTOM_PATH}")
endif()

if(SA_CUSTOM)
    if(NOT DEFINED SA_CUSTOM_PATH)
        set(SA_CUSTOM_PATH ${SA_CUSTOM_PATH_DEFAULT})
        message(STATUS "Default path set for SA_CUSTOM_PATH")
    endif()
    message(STATUS "SA_CUSTOM being utilized.  Path set to: ${SA_CUSTOM_PATH}")
endif()

if(CRYPTO_CUSTOM)
    if(NOT DEFINED CRYPTO_CUSTOM_PATH)
        set(CRYPTO_CUSTOM_PATH ${CRYPTO_CUSTOM_PATH_DEFAULT})
        message(STATUS "Default path set for CRYPTO_CUSTOM_PATH")
    endif()
    message(STATUS "CRYPTO_CUSTOM being utilized.  Path set to: ${CRYPTO_CUSTOM_PATH}")
endif()


#
# Build Flag Logic
#
if(CODECOV)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
endif()

if(SA_FILE)
    add_definitions(-DSA_FILE)
endif()

if(KEY_VALIDATION)
    add_definitions(-DKEY_VALIDATION)
endif()

if(DEBUG)
    add_definitions(-DDEBUG -DOCF_DEBUG -DFECF_DEBUG -DSA_DEBUG -DPDU_DEBUG -DCCSDS_DEBUG -DTC_DEBUG -DMAC_DEBUG -DTM_DEBUG -DAOS_DEBUG)
    add_compile_options(-ggdb)
endif()

if(DEFINED MC_LOG_CUSTOM_PATH)
    message(STATUS "MC_LOG_CUSTOM_PATH set to: ${MC_LOG_CUSTOM_PATH}")
    add_compile_definitions(MC_LOG_PATH="${MC_LOG_CUSTOM_PATH}")
else()
    add_compile_definitions(MC_LOG_PATH="${MC_LOG_PATH_DEFAULT}")
endif()

IF(KMC_MDB_RH)
    ADD_DEFINITIONS(-DKMC_MDB_RH)
    ADD_DEFINITIONS(-DKMC_CFFI_EXCLUDE)
ENDIF(KMC_MDB_RH)

IF(KMC_MDB_DB)
    ADD_DEFINITIONS(-DKMC_MDB_DB)
    ADD_DEFINITIONS(-DKMC_CFFI_EXCLUDE)
ENDIF(KMC_MDB_DB)

if(SYSTEM_INSTALL)
    # The library will be installed to /usr/local unless overridden with
    # -DCMAKE_INSTALL_PREFIX=/some/path
    # See https://cmake.org/cmake/help/latest/variable/CMAKE_INSTALL_PREFIX.html
elseif(CRYPTO_SUBMODULE_INSTALL)
    set(CMAKE_INSTALL_PREFIX ${CRYPTO_SUBMODULE_INSTALL})
elseif(NOT DEFINED CFE_SYSTEM_PSPNAME)
    # Not cFE / cFS
    set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
    set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR}/install)
endif()

# if(TEST_ENC)
#     # Can't run an additional set of tests without `TEST` enabled
#     set(TEST ON)
# endif()

if(TEST)
    include(CTest)
    enable_testing()
endif()

#
# Project Specifics
#
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -g -O0")

include_directories(include)
add_subdirectory(src)

if(SUPPORT)
    add_subdirectory(support)
endif()

if(TEST)
    add_subdirectory(test)
endif()
