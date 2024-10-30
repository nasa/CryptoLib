/* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration.
   All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory,
   including, but not limited to, any warranty that the software will conform to specifications, any implied warranties
   of merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty that the
   documentation will conform to the program, or any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
   consequential damages, arising out of, resulting from, or in any way connected with the software or its
   documentation, whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was sustained
   from, or arose out of the results of, or use of, the software, documentation or services provided hereunder.

   ITC Team
   NASA IV&V
   jstar-development-team@mail.nasa.gov
*/

/**
 *  Unit Tests that macke use of CRYPTO_C functionality on the data.
 **/
#include "ut_crypto.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"

/**
 * @brief Unit Test: Crypto Calc/Verify CRC16
 **/
UTEST(CRYPTO_C, CALC_CRC16)
{
    remove("sa_save_file.bin");
    char    *data_h     = "2003002000ff000100001880d2c9000e197f0b001b0004000400003040d95e";
    uint8_t *data_b     = NULL;
    int      data_b_len = 0;
    Crypto_Init_TC_Unit_Test();

    hex_conversion(data_h, (char **)&data_b, &data_b_len);

    int      size          = 31;
    uint16_t crc           = 0x00;
    uint16_t validated_crc = 0xA61A;
    crc                    = Crypto_Calc_CRC16(data_b, size);

    // printf("CRC = 0x%04x\n", crc);
    ASSERT_EQ(crc, validated_crc);
}

/**
 * @brief Unit Test: Crypto Bad CC Flag
 **/
UTEST(CRYPTO_C, BAD_CC_FLAG)
{
    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF,
    // TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_NO_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);

    Crypto_Init();
    char *raw_tc_sdls_ping_h   = "3003002000ff000100001880d2c9000e197f0b001b0004000400003040d95ea61a";
    char *raw_tc_sdls_ping_b   = NULL;
    int   raw_tc_sdls_ping_len = 0;

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t *ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    int32_t return_val = CRYPTO_LIB_ERROR;

    return_val =
        Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_INVALID_CC_FLAG, return_val);
}

/**
 * @brief Unit Test: PDU Switch testing
 * @note: TODO: This needs to be reworked to actually better test.
 **/
UTEST(CRYPTO_C, PDU_SWITCH)
{
    remove("sa_save_file.bin");
    int32_t status = CRYPTO_LIB_ERROR;

    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0); Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF,
    // TC_HAS_SEGMENT_HDRS, TC_OCF_NA, 1024, AOS_FHEC_NA, AOS_IZ_NA, 0);

    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_HAS_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    TC_UT_Managed_Parameters.vcid = 1;
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);

    Crypto_Init();

    sdls_frame.pdu.hdr.type = PDU_TYPE_COMMAND;
    sdls_frame.pdu.hdr.uf = PDU_USER_FLAG_FALSE;
    printf("SG_KEY_MGMT\n");
    sdls_frame.pdu.hdr.sg  = SG_KEY_MGMT;
    sdls_frame.pdu.hdr.pid = PID_OTAR;
    uint8_t *ingest        = NULL;

    TC_t tc_frame;
    status = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_KEY_ACTIVATION;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_KEY_DEACTIVATION;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid     = PID_KEY_VERIFICATION;
    status                     = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_KEY_DESTRUCTION;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_KEY_INVENTORY;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTOGRAPHY_UNSUPPORTED_OPERATION_FOR_KEY_RING);

    sdls_frame.pdu.hdr.pid = SG_KEY_MGMT;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    printf("SG_SA_MGMT\n");
    sdls_frame.pdu.hdr.sg  = SG_SA_MGMT;
    sdls_frame.pdu.hdr.pid = PID_CREATE_SA;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_DELETE_SA;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_SET_ARSNW;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_REKEY_SA;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_EXPIRE_SA;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_SET_ARSN;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_START_SA;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_STOP_SA;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_READ_ARSN;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.hdr.pid = PID_SA_STATUS;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.hdr.pid = 0b111;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    printf("SG_SEC_MON_CTRL\n");
    sdls_frame.pdu.hdr.sg  = SG_SEC_MON_CTRL;
    sdls_frame.pdu.hdr.pid = PID_LOG_STATUS;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.hdr.pid = PID_DUMP_LOG;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.hdr.pid = PID_ERASE_LOG;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.hdr.pid = PID_SELF_TEST;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.hdr.pid = PID_ALARM_FLAG;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = 0b1111;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    printf("UF_TRUE\n");
    sdls_frame.pdu.hdr.uf  = PDU_USER_FLAG_TRUE;
    sdls_frame.pdu.hdr.pid = PID_IDLE_FRAME_TRIGGER;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_TOGGLE_BAD_SPI;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_TOGGLE_BAD_IV;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_TOGGLE_BAD_MAC;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_TOGGLE_BAD_FECF;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_MODIFY_KEY;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_MODIFY_ACTIVE_TM;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.hdr.pid = PID_MODIFY_VCID;
    status = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.hdr.pid = 8;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.hdr.type    = PDU_TYPE_REPLY;
    sdls_frame.pdu.hdr.pid = 8;
    status                 = Crypto_PDU(ingest, &tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);
}

/**
 * @brief Unit Test: Crypto Extended Procedures PDU Test
 **/
UTEST(CRYPTO_C, EXT_PROC_PDU)
{
    remove("sa_save_file.bin");
    uint8_t *ingest           = NULL;
    TC_t    *tc_frame         = NULL;
    tc_frame                  = malloc(sizeof(uint8_t) * TC_SIZE);
    int32_t status            = CRYPTO_LIB_ERROR;
    crypto_config.has_pus_hdr = TC_NO_PUS_HDR;
    tc_frame->tc_header.vcid  = TC_SDLS_EP_VCID;
    tc_frame->tc_header.fl    = 1;

    status = Crypto_Process_Extended_Procedure_Pdu(tc_frame, ingest);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);
}

/**
 * @brief Unit Test: Crypto ACS Get Algorithm response
 **/
UTEST(CRYPTO_C, GET_ACS_ALGO)
{
    remove("sa_save_file.bin");
    Crypto_Init_TC_Unit_Test();
    int32_t libgcrypt_algo = -1;
    uint8_t crypto_algo    = CRYPTO_MAC_CMAC_AES256;

    //// Convert CRYPTOAES enum to GCRY_MAC_CMAC_AES
    // libgcrypt_algo = cryptography_if->cryptography_get_acs_algo(crypto_algo);
    // ASSERT_EQ(libgcrypt_algo, GCRY_MAC_CMAC_AES);

    crypto_algo    = 99; // Invalid / unsupported
    libgcrypt_algo = cryptography_if->cryptography_get_acs_algo(crypto_algo);
    ASSERT_EQ(libgcrypt_algo, CRYPTO_LIB_ERR_UNSUPPORTED_ACS);
}

/**
 * @brief Unit Test: Crypto ACS Get Algorithm key length response
 **/
UTEST(CRYPTO_C, GET_ACS_ALGO_KEY_LEN)
{
    remove("sa_save_file.bin");
    int32_t algo_keylen = -1;
    uint8_t crypto_algo = CRYPTO_MAC_CMAC_AES256;
    algo_keylen         = Crypto_Get_ACS_Algo_Keylen(crypto_algo);
    ASSERT_EQ(algo_keylen, 32);

    crypto_algo = CRYPTO_MAC_HMAC_SHA256;
    algo_keylen = Crypto_Get_ACS_Algo_Keylen(crypto_algo);
    ASSERT_EQ(algo_keylen, 32);

    crypto_algo = CRYPTO_MAC_HMAC_SHA512;
    algo_keylen = Crypto_Get_ACS_Algo_Keylen(crypto_algo);
    ASSERT_EQ(algo_keylen, 64);
}

/**
 * @brief Unit Test: Crypto ECS Get Algorithm response
 **/
UTEST(CRYPTO_C, GET_ECS_ALGO)
{
    remove("sa_save_file.bin");
    Crypto_Init_TC_Unit_Test();
    int32_t libgcrypt_algo = -1;
    int8_t  crypto_algo    = CRYPTO_CIPHER_AES256_GCM;

    // Convert CRYPTOAES enum to GCRY_CIPHER_AES256
    // libgcrypt_algo = cryptography_if->cryptography_get_ecs_algo(crypto_algo);
    // ASSERT_EQ(libgcrypt_algo, GCRY_CIPHER_AES256);

    crypto_algo    = 99; // Invalid / unsupported
    libgcrypt_algo = cryptography_if->cryptography_get_ecs_algo(crypto_algo);
    ASSERT_EQ(libgcrypt_algo, CRYPTO_LIB_ERR_UNSUPPORTED_ECS);
}

/**
 * @brief Unit Test: Crypto ECS Get Algorithm key length response
 **/
UTEST(CRYPTO_C, GET_ECS_ALGO_KEY_LEN)
{
    remove("sa_save_file.bin");
    int32_t algo_keylen = -1;
    uint8_t crypto_algo = CRYPTO_CIPHER_AES256_GCM;
    algo_keylen         = Crypto_Get_ACS_Algo_Keylen(crypto_algo);
    ASSERT_EQ(algo_keylen, 32);
}

UTEST(CRYPTO_C, STRUCT_SIZE_VERIFICATION)
{
    ASSERT_EQ(CRYPTO_GVCID_SIZE, (size_t)4);
    ASSERT_EQ(SA_SIZE, (size_t)2348);
    ASSERT_EQ(SDLS_FSR_SIZE, (size_t)4);
    ASSERT_EQ(SDLS_TLV_HDR_SIZE, (size_t)3);
    ASSERT_EQ(SDLS_TLV_SIZE, (size_t)497);
    ASSERT_EQ(SDLS_EKB_SIZE, (size_t)514);
    ASSERT_EQ(SDLS_OTAR_SIZE, (size_t)(2 + 16 + 30*514 + 16));
    ASSERT_EQ(SDLS_KEY_SIZE, (size_t)2);
    ASSERT_EQ(SDLS_KEY_INVENTORY_CMD_SIZE, (size_t)4);
    ASSERT_EQ(SDLS_KEY_INVENTORY_RPLY_SIZE, (size_t)3);
    ASSERT_EQ(SDLS_KEYV_CMD_BLK_SIZE, (size_t)18);
    ASSERT_EQ(SDLS_KEYV_CMD_SIZE, (size_t)(29*18));
    ASSERT_EQ(SDLS_KEYV_RPLY_BLK_SIZE, (size_t)50);
    ASSERT_EQ(SDLS_KEYV_RPLY_SIZE, (size_t)(50*29));
    ASSERT_EQ(SDLS_KEYDB_CMD_SIZE, (size_t)12);
    ASSERT_EQ(SDLS_KEYDB_RPLY_SIZE, (size_t)38);
    ASSERT_EQ(SDLS_SA_STATUS_RPLY_SIZE, (size_t)3);
    ASSERT_EQ(SDLS_SA_READ_ARSN_RPLY_SIZE, (size_t)22);
    ASSERT_EQ(SDLS_MC_LOG_RPLY_SIZE, (size_t)4);
    ASSERT_EQ(SDLS_MC_DUMP_RPLY_SIZE, (size_t)7);
    ASSERT_EQ(SDLS_MC_DUMP_BLK_RPLY_SIZE, (size_t)(7*50));
    ASSERT_EQ(SDLS_MC_ST_RPLY_SIZE, (size_t)1);
    ASSERT_EQ(SDLS_MC_SN_RPLY_SIZE, (size_t)16);
    ASSERT_EQ(TC_FRAME_PRIMARYHEADER_STRUCT_SIZE, (size_t)5);
    ASSERT_EQ(TC_FRAME_SECHEADER_SIZE, (size_t)70);
    ASSERT_EQ(TC_FRAME_SECTRAILER_SIZE, (size_t)19);
    ASSERT_EQ(TC_SIZE, (size_t)(5 + 70 + 19 + 2 + 1019));
    ASSERT_EQ(CCSDS_HDR_SIZE, (size_t)6);
    ASSERT_EQ(CCSDS_PUS_SIZE, (size_t)4);
    ASSERT_EQ(CCSDS_SIZE, (size_t)(6 + 4 + 497));
    ASSERT_EQ(TELEMETRY_FRAME_OCF_CLCW_SIZE, (size_t)4);
    ASSERT_EQ(TELEMETRY_FRAME_OCF_FSR_SIZE, (size_t)4);
    ASSERT_EQ(TM_FRAME_PRIMARYHEADER_SIZE, (size_t)6);
    ASSERT_EQ(TM_FRAME_SECHEADER_SIZE, (size_t)18);
    ASSERT_EQ(TM_FRAME_SECTRAILER_SIZE, (size_t)22);
    ASSERT_EQ(TM_SIZE, (size_t)(6 + 18 + 1786 + 22));
    ASSERT_EQ(AOS_FRAME_PRIMARYHEADER_SIZE, (size_t)8);
    ASSERT_EQ(AOS_FRAME_SECHEADER_SIZE, (size_t)18);
    ASSERT_EQ(AOS_FRAME_SECTRAILER_SIZE, (size_t)22);
    ASSERT_EQ(AOS_SIZE, (size_t)(8 + 18 + 1786 + 22));
}

UTEST_MAIN();