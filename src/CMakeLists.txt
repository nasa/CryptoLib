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

include_directories(../include)

aux_source_directory(core LIB_SRC_FILES)

if(CRYPTO_CUSTOM)
    aux_source_directory(${CRYPTO_CUSTOM_PATH} CRYPTO_FILES)
    list(APPEND LIB_SRC_FILES ${CRYPTO_FILES})
else()
    aux_source_directory(crypto/custom_stub CRYPTO_FILES)
    list(APPEND LIB_SRC_FILES ${CRYPTO_FILES})
endif()

if(CRYPTO_LIBGCRYPT)
    aux_source_directory(crypto/libgcrypt LIBGCRYPT_FILES)
    list(APPEND LIB_SRC_FILES ${LIBGCRYPT_FILES})
else()
    aux_source_directory(crypto/libgcrypt_stub LIBGCRYPT_FILES)
    list(APPEND LIB_SRC_FILES ${LIBGCRYPT_FILES})
endif()

if(CRYPTO_KMC)
    aux_source_directory(crypto/kmc KMC_FILES)
    list(APPEND LIB_SRC_FILES ${KMC_FILES})
else()
    aux_source_directory(crypto/kmc_stub KMC_FILES)
    list(APPEND LIB_SRC_FILES ${KMC_FILES})
endif()

if(CRYPTO_WOLFSSL)
    aux_source_directory(crypto/wolfssl WOLFSSL_FILES)
    list(APPEND LIB_SRC_FILES ${WOLFSSL_FILES})
else()
    aux_source_directory(crypto/wolfssl_stub WOLFSSL_FILES)
    list(APPEND LIB_SRC_FILES ${WOLFSSL_FILES})
endif()

if(KEY_CUSTOM)
    # Assumes CryptoLib is a Git submodule to project and custom directories and definitions exist at top level
    aux_source_directory(${KEY_CUSTOM_PATH} KEY_CUSTOM_FILES)
    list(APPEND LIB_SRC_FILES ${KEY_CUSTOM_FILES})
else()
    aux_source_directory(key/custom_stub KEY_CUSTOM_FILES)
    list(APPEND LIB_SRC_FILES ${KEY_CUSTOM_FILES})
endif()

if(KEY_INTERNAL)
    aux_source_directory(key/internal KEY_INTERNAL_FILES)
    list(APPEND LIB_SRC_FILES ${KEY_INTERNAL_FILES})
else()
    aux_source_directory(key/internal_stub KEY_INTERNAL_FILES)
    list(APPEND LIB_SRC_FILES ${KEY_INTERNAL_FILES})
endif()

if(KEY_KMC)
    aux_source_directory(key/kmc KEY_KMC_FILES)
    list(APPEND LIB_SRC_FILES ${KEY_KMC_FILES})
else()
    aux_source_directory(key/kmc_stub KEY_KMC_FILES)
    list(APPEND LIB_SRC_FILES ${KEY_KMC_FILES})
endif()

if(MC_CUSTOM)
    # Assumes CryptoLib is a Git submodule to project and custom directories and definitions exist at top level
    aux_source_directory(${MC_CUSTOM_PATH} MC_CUSTOM_FILES)
    list(APPEND LIB_SRC_FILES ${MC_CUSTOM_FILES})
else()
    aux_source_directory(mc/custom_stub MC_CUSTOM_FILES)
    list(APPEND LIB_SRC_FILES ${MC_CUSTOM_FILES})
endif()

if(MC_DISABLED)
    aux_source_directory(mc/disabled MC_DISABLED_FILES)
    list(APPEND LIB_SRC_FILES ${MC_DISABLED_FILES})
else()
    aux_source_directory(mc/disabled_stub MC_DISABLED_FILES)
    list(APPEND LIB_SRC_FILES ${MC_DISABLED_FILES})
endif()

if(MC_INTERNAL)
    aux_source_directory(mc/internal MC_INTERNAL_FILES)
    list(APPEND LIB_SRC_FILES ${MC_INTERNAL_FILES})
else()
    aux_source_directory(mc/internal_stub MC_INTERNAL_FILES)
    list(APPEND LIB_SRC_FILES ${MC_INTERNAL_FILES})
endif()

if(SA_CUSTOM)
    # Assumes CryptoLib is a Git submodule to project and custom directories and definitions exist at top level
    aux_source_directory(${SA_CUSTOM_PATH} SA_CUSTOM_FILES)
    list(APPEND LIB_SRC_FILES ${SA_CUSTOM_FILES})
else()
    aux_source_directory(sa/custom_stub SA_CUSTOM_FILES)
    list(APPEND LIB_SRC_FILES ${SA_CUSTOM_FILES})
endif()

if(SA_INTERNAL)
    aux_source_directory(sa/internal SA_INTERNAL_FILES)
    list(APPEND LIB_SRC_FILES ${SA_INTERNAL_FILES})
else()
    aux_source_directory(sa/internal_stub SA_INTERNAL_FILES)
    list(APPEND LIB_SRC_FILES ${SA_INTERNAL_FILES})
endif()

if(SA_MARIADB)
    aux_source_directory(sa/mariadb MARIADB_FILES)
    list(APPEND LIB_SRC_FILES ${MARIADB_FILES})
else()
    aux_source_directory(sa/mariadb_stub MARIADB_FILES)
    list(APPEND LIB_SRC_FILES ${MARIADB_FILES})
endif()

# Create the app module
if(DEFINED CFE_SYSTEM_PSPNAME)
    set(CMAKE_INSTALL_RPATH "./${INSTALL_SUBDIR}")
    add_cfe_app(crypto ${LIB_SRC_FILES})
    target_include_directories(crypto PUBLIC ../include)
    if(NOT CMAKE_CROSSCOMPILING)
        install(TARGETS crypto RUNTIME_DEPENDENCIES DESTINATION ${CMAKE_INSTALL_PREFIX}/${TGTSYS_${SYSVAR}}/${INSTALL_SUBDIR})
    else()
        install(TARGETS crypto)
    endif()
else() 
    # Standalone build
    add_library(crypto SHARED ${LIB_SRC_FILES})
endif()

if(CRYPTO_LIBGCRYPT)
    target_link_libraries(crypto gcrypt)
endif()

if(CRYPTO_KMC)
    target_link_libraries(crypto curl)
endif()

if(CRYPTO_WOLFSSL)
    target_link_libraries(crypto wolfssl)
endif()

if(SA_MARIADB)
    execute_process(COMMAND mysql_config --cflags
            OUTPUT_VARIABLE MYSQL_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND mysql_config --libs
            OUTPUT_VARIABLE MYSQL_LIBS OUTPUT_STRIP_TRAILING_WHITESPACE)
    target_compile_options(crypto PUBLIC ${MYSQL_CFLAGS})
    target_link_libraries(crypto ${MYSQL_LIBS})
endif()

file(GLOB CRYPTO_INCLUDES ../include/*.h)
set_target_properties(crypto PROPERTIES PUBLIC_HEADER "${CRYPTO_INCLUDES}")
# This causes the library to be installed as libcryptolib.so while still being
# referred to as crypto from CMake. Without this, the library filename would be
# libcrypto.so which would conflict with openssl
set_target_properties(crypto PROPERTIES OUTPUT_NAME "cryptolib")

add_custom_command(TARGET crypto POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:crypto> ${PROJECT_BINARY_DIR}/lib/libcrypto.so
        COMMENT "Created ${PROJECT_BINARY_DIR}/lib/libCrypto.so"
        )

if(DEFINED CFE_SYSTEM_PSPNAME)
    install(TARGETS crypto 
            DESTINATION ${CMAKE_INSTALL_PREFIX}/${TGTSYS_${SYSVAR}}/${INSTALL_SUBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/host)
else()
    install(TARGETS crypto
            DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
endif()

if(SA_MARIADB)
    file(GLOB MYSQL_SCRIPTS sa/sadb_mariadb_sql/*.sql)
    file(GLOB MYSQL_TEST_SCRIPTS sa/test_sadb_mariadb_sql/*.sql)
    install(FILES ${MYSQL_SCRIPTS}
            DESTINATION ${CMAKE_INSTALL_PREFIX}/etc/sa_mariadb_sql)
    install(FILES ${MYSQL_TEST_SCRIPTS}
            DESTINATION ${CMAKE_INSTALL_PREFIX}/test/test_sa_mariadb_sql)
endif()
