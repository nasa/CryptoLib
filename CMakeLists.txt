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
project(CRYPTO C)

#
# Define Build Flags
# The default value is captured in line, change with flag `-DXYZ=1`
# For flags with the same prefix, one or more may be enabled
#
option(CODECOV "Code Coverage" OFF)
option(CRYPTO_LIBGCRYPT "Cryptography Module - Libgcrypt" ON)
option(CRYPTO_KMC "Cryptography Module - KMC" OFF)
option(DEBUG "Debug" OFF)
option(KEY_CUSTOM "Key Module - Custom" OFF)
option(KEY_INTERNAL "Key Module - Internal" ON)
option(KEY_KMC "Key Module - KMC OFF")
option(SA_CUSTOM "Security Association - Custom" OFF)
option(SA_INTERNAL "Security Association - Internal" ON)
option(SA_MARIADB "Security Association - MariaDB" OFF)
option(SUPPORT "Support" OFF)
option(SYSTEM_INSTALL "SystemInstall" OFF)
option(TEST "Test" OFF)
option(TEST_ENC "Tests - Encryption" OFF)

OPTION(KMC_MDB_RH "KMC-MDB-RedHat-Integration-Testing" OFF) #Disabled by default, enable with: -DKMC_MDB_RH=ON
OPTION(KMC_MDB_DB "KMC-MDB-Debian-Integration-Testing" OFF) #Disabled by default, enable with: -DKMC_MDB_DB=ON

#
# Build Flag Logic
#
if(CODECOV)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
endif()

if(DEBUG)
    add_definitions(-DDEBUG -DOCF_DEBUG -DFECF_DEBUG -DSA_DEBUG -DPDU_DEBUG -DCCSDS_DEBUG -DTC_DEBUG -DMAC_DEBUG -DTM_DEBUG)
    add_compile_options(-ggdb)
endif()

IF(KMC_MDB_RH)
    ADD_DEFINITIONS(-DKMC_MDB_RH)
ENDIF(KMC_MDB_RH)

IF(KMC_MDB_DB)
    ADD_DEFINITIONS(-DKMC_MDB_DB)
ENDIF(KMC_MDB_DB)

if(SYSTEM_INSTALL)
    set(CMAKE_INSTALL_PREFIX /usr/local)
elseif(NOT DEFINED CFE_SYSTEM_PSPNAME)
    # Not cFE / cFS
    set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
    set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR}/install)
endif()

if(TEST_ENC)
    # Can't run an additional set of tests without `TEST` enabled
    set(TEST ON)
endif()

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
