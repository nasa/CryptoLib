# Environment

Environment and dependency details may be found within `./support/Dockerfile`. If running via docker, dependencies will be installed automatically.

If building locally, ensure all dependencies below are met.


*Note:* Theses dependencies are for the default internal build, other builds may vary.

## Dependencies
### Running
| __Apt:__        |                       |
|-----------------|-----------------------|
| autoconf        | automake              |
| ca-certificates | cmake                 |
| curl            | g++-multilib          |
| gcc-multilib    | gettext               |
| git             | gdb                   |
| lcov            | libcurl4-openssl-dev  | 
| libmariadb-dev  | libmariadb-dev-compat |
| libtool         | unzip                 |
| make            | python3-dev           |
| python3-pip     | build-essential       |

<br />

| __Web:__           |                       |
|--------------------|-----------------------|
| libgpg-error 1.50  | libgcrypt 1.11.0      |

<br />
<br />

### Documentation
| __Apt:__            |                          |
|---------------------|--------------------------|
| python3-sphinx      | python3-sphinx-rtd-theme |
| python3-myst-parser | 

<br />
<br />

## Building
There are numerous configurations when building CryptoLib.  References to necessary build flags can be found within `./support/scripts/`.  For example to build the current internal build:

> Clone the CryptoLib repo. Switch to the desired branch. Currently, integration efforts are occurring in the _main_ branch.
> * cd Cryptolib
> * cmake -DCODECOV=1 -DDEBUG=1 -DTEST=1 -DTEST_ENC=1 .
> * make
> * make test

This will build the internal debug environment, with code coverage, testing, and encryption testing.

*Other Build Configurations:*
> * KMC, Minimal, WolfSSL, and other configurations have convenience scripts which can be referenced within the `./support/scripts/` directory.

*Code Coverage:*
With the DCODECOV Flag set, users may produce code coverage results similarly to the code below:
> * cmake -DMYSQL=1 -DENCTEST=1 -DDEBUG=1 -DCODECOV=1 ../
> * make
> * make gcov

This will produce local coverage reports in /build/coverage, with the HTML results within /build/coverage/results/index.html

*Cleanup:*
> * make clean  -- Cleans Build
> * make scrub  -- Cleans Code Coverage

The two flags (DEBUG and TEST_ENC) can be used simultaneously, or separately. 

*All Build Flags:*
> * CODECOV -- "Code Coverage" -- Default OFF
> * CRYPTO_LIBGCRYPT -- "Cryptography Module - Libgcrypt" -- Default ON
> * CRYPTO_KMC -- "Cryptography Module - KMC" -- Default OFF
> * CRYPTO_WOLFSSL -- "Cryptography Module - WolfSSL" -- Default OFF
> * CRYPTO_CUSTOM -- "Cryptography Module - CUSTOM" -- Default OFF
> * CRYPTO_CUSTOM_PATH -- "Cryptography Module - CUSTOM PATH" -- Default OFF
> * DEBUG -- "Debug" -- Default OFF
> * KEY_CUSTOM -- "Key Module - Custom"-- Default  OFF
> * KEY_CUSTOM_PATH -- "Custom Key Path" -- Default OFF
> * KEY_INTERNAL -- "Key Module - Internal" -- Default ON
> * KEY_KMC -- "Key Module - KMC"-- Default  OFF
> * MC_CUSTOM -- "Monitoring and Control - Custom" -- Default OFF
> * MC_CUSTOM_PATH -- "Custom Monitoring and Control path" -- Default OFF
> * MC_DISABLED -- "Monitoring and Control - Disabled" -- Default OFF
> * MC_INTERNAL -- "Monitoring and Control - Internal" -- Default ON
> * SA_CUSTOM -- "Security Association - Custom" -- Default OFF
> * SA_CUSTOM_PATH -- "Custom Security Association Path" -- Default OFF
> * SA_INTERNAL -- "Security Association - Internal" -- Default ON
> * SA_MARIADB -- "Security Association - MariaDB" -- Default OFF
> * SUPPORT -- "Support" -- Default OFF
> * SYSTEM_INSTALL -- "SystemInstall" -- Default OFF
> * TEST -- "Test" -- Default OFF
> * SA_FILE -- "Save Security Association to File" -- Default OFF
> * KEY_VALIDATION -- "Validate existence of key duplication"-- Default OFF

> * KMC_MDB_RH "KMC-MDB-RedHat-Integration-Testing" -- Default OFF 
> * KMC_MDB_DB "KMC-MDB-Debian-Integration-Testing" -- Default OFF 
> * KMC_CFFI_EXCLUDE "KMC-Exclude-Problematic-CFFI-Code" -- Default OFF

> * CRYPTO_EPROC "Enables building of Extended Procedures -- Default OFF (CURRENTLY A WIP - Not ready for Operations)