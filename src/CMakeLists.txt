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

if(KEY_CUSTOM)
    # Assumes CryptoLib is a Git submodule to project and custom directories and definitions exist at top level
    aux_source_directory(../../key/custom KEY_CUSTOM_FILES)
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

if(SA_CUSTOM)
    # Assumes CryptoLib is a Git submodule to project and custom directories and definitions exist at top level
    aux_source_directory(../../sa/custom SA_CUSTOM_FILES)
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
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/cpu${TGTSYS_${SYSVAR}}/${INSTALL_SUBDIR}")
    add_cfe_app(Crypto ${LIB_SRC_FILES})
else() 
    # Standalone build
    add_library(Crypto SHARED ${LIB_SRC_FILES})
endif()

if(CRYPTO_LIBGCRYPT)
    target_link_libraries(Crypto gcrypt)
endif()

if(CRYPTO_KMC)
    target_link_libraries(Crypto curl)
endif()

if(SA_MARIADB)
    execute_process(COMMAND mysql_config --cflags
            OUTPUT_VARIABLE MYSQL_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND mysql_config --libs
            OUTPUT_VARIABLE MYSQL_LIBS OUTPUT_STRIP_TRAILING_WHITESPACE)
    target_compile_options(Crypto PUBLIC ${MYSQL_CFLAGS})
    target_link_libraries(Crypto ${MYSQL_LIBS})
endif()

file(GLOB CRYPTO_INCLUDES ../include/*.h)
set_target_properties(Crypto PROPERTIES PUBLIC_HEADER "${CRYPTO_INCLUDES}")

add_custom_command(TARGET Crypto POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:Crypto> ${PROJECT_BINARY_DIR}/lib/libCrypto.so
        COMMENT "Created ${PROJECT_BINARY_DIR}/lib/libCrypto.so"
        )

if(DEFINED CFE_SYSTEM_PSPNAME)
    install(TARGETS Crypto 
            DESTINATION ${CMAKE_INSTALL_PREFIX}/cpu${TGTSYS_${SYSVAR}}/${INSTALL_SUBDIR})
else()
    install(TARGETS Crypto
            DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
endif()

if(SA_MARIADB)
    file(GLOB MYSQL_SCRIPTS sa/sa_mariadb_sql/*.sql)
    file(GLOB MYSQL_TEST_SCRIPTS sa/test_sa_mariadb_sql/*.sql)
    install(FILES ${MYSQL_SCRIPTS}
            DESTINATION ${CMAKE_INSTALL_PREFIX}/etc/sa_mariadb_sql)
    install(FILES ${MYSQL_TEST_SCRIPTS}
            DESTINATION ${CMAKE_INSTALL_PREFIX}/test/test_sa_mariadb_sql)
endif()
