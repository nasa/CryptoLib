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

aux_source_directory(src_main LIB_SRC_FILES)
if(MYSQL)
    aux_source_directory(sa/mariadb MARIADB_FILES)
    list(APPEND LIB_SRC_FILES ${MARIADB_FILES})
else()
    aux_source_directory(sa/mariadb_stub MARIADB_FILES)
    list(APPEND LIB_SRC_FILES ${MARIADB_FILES})
endif()

if(SA_INTERNAL)
    aux_source_directory(sa/internal SA_INTERNAL_FILES)
    list(APPEND LIB_SRC_FILES ${SA_INTERNAL_FILES})
else()
    aux_source_directory(sa/internal_stub SA_INTERNAL_FILES)
    list(APPEND LIB_SRC_FILES ${SA_INTERNAL_FILES})
endif()

if(LIBGCRYPT)
    aux_source_directory(crypto/libgcrypt LIBGCRYPT_FILES)
    list(APPEND LIB_SRC_FILES ${LIBGCRYPT_FILES})
else()
    aux_source_directory(crypto/libgcrypt_stub LIBGCRYPT_FILES)
    list(APPEND LIB_SRC_FILES ${LIBGCRYPT_FILES})
endif()

if(KMCCRYPTO)
    aux_source_directory(crypto/kmc KMC_FILES)
    list(APPEND LIB_SRC_FILES ${KMC_FILES})
else()
    aux_source_directory(crypto/kmc_stub KMC_FILES)
    list(APPEND LIB_SRC_FILES ${KMC_FILES})
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
    enable_testing()
endif()

# Create the app module
IF(DEFINED CFE_SYSTEM_PSPNAME)
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/cpu${TGTSYS_${SYSVAR}}/${INSTALL_SUBDIR}")
    add_cfe_app(Crypto ${LIB_SRC_FILES})
ELSE() 
    # Standalone build
    add_library(Crypto SHARED ${LIB_SRC_FILES})
ENDIF()

if(LIBGCRYPT)
    target_link_libraries(Crypto gcrypt)
endif()

if(KMCCRYPTO)
    target_link_libraries(Crypto curl)
endif()

if(MYSQL)
    execute_process(COMMAND mysql_config --cflags
            OUTPUT_VARIABLE MYSQL_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND mysql_config --libs
            OUTPUT_VARIABLE MYSQL_LIBS OUTPUT_STRIP_TRAILING_WHITESPACE)

    target_compile_options(Crypto PUBLIC ${MYSQL_CFLAGS})
    target_link_libraries(Crypto ${MYSQL_LIBS})
endif()

set_target_properties(Crypto PROPERTIES PUBLIC_HEADER "../include/crypto.h;../include/crypto_config_structs.h;../include/crypto_error.h;../include/crypto_print.h;../include/crypto_structs.h;../include/crypto_config.h;")

add_custom_command(TARGET Crypto POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:Crypto> ${PROJECT_BINARY_DIR}/lib/libCrypto.so
        COMMENT "Created ${PROJECT_BINARY_DIR}/lib/libCrypto.so"
        )

        
IF(DEFINED CFE_SYSTEM_PSPNAME)
    install(TARGETS Crypto 
            DESTINATION ${CMAKE_INSTALL_PREFIX}/cpu${TGTSYS_${SYSVAR}}/${INSTALL_SUBDIR})
ELSE()
    install(TARGETS Crypto
            DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
ENDIF()

IF(MYSQL)
    file(GLOB MYSQL_SCRIPTS sa/sadb_mariadb_sql/*.sql)
    file(GLOB MYSQL_TEST_SCRIPTS sa/test_sadb_mariadb_sql/*.sql)
    install(FILES ${MYSQL_SCRIPTS}
            DESTINATION ${CMAKE_INSTALL_PREFIX}/etc/sadb_mariadb_sql)
    install(FILES ${MYSQL_TEST_SCRIPTS}
            DESTINATION ${CMAKE_INSTALL_PREFIX}/test/test_sadb_mariadb_sql)
endif()