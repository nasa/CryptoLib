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
#include "sadb_routine.h"
#include "utest.h"

UTEST(CRYPTO_C, CALC_CRC16)
{
    char *data_h = "2003002000ff000100001880d2c9000e197f0b001b0004000400003040d95e";
    uint8_t *data_b = NULL;
    int data_b_len = 0;
    Crypto_Init_Unit_Test();

    hex_conversion(data_h, (char **)&data_b, &data_b_len);

    int size = 31;
    uint16_t crc = 0x00;
    uint16_t validated_crc = 0xA61A;
    crc = Crypto_Calc_CRC16(data_b, size);
    
    //printf("CRC = 0x%04x\n", crc);
    ASSERT_EQ(crc, validated_crc);
}

UTEST(CRYPTO_C, HAPPY_BAD_CC)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_NO_FECF, TC_NO_SEGMENT_HDRS);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_NO_FECF, TC_NO_SEGMENT_HDRS);
    Crypto_Init();
    char *raw_tc_sdls_ping_h = "3003002000ff000100001880d2c9000e197f0b001b0004000400003040d95ea61a";
    char *raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;

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

//TODO:  This needs to be reworked to actually better test.
UTEST(CRYPTO_C, PDU_SWITCH)
{
    int32_t status = CRYPTO_LIB_ERROR;

    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS);
    Crypto_Init();

    sdls_frame.pdu.type = 0;
    sdls_frame.pdu.uf = 0;
    sdls_frame.pdu.sg = SG_KEY_MGMT;
    sdls_frame.pdu.pid = PID_OTAR;
    uint8_t *ingest = NULL;

    TC_t *tc_frame;
    tc_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_KEY_ACTIVATION;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_KEY_DEACTIVATION;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pdu_len = 0;
    sdls_frame.pdu.pid = PID_KEY_VERIFICATION;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_KEY_DESTRUCTION;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_KEY_INVENTORY;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTOGRAPHY_UNSUPPORTED_OPERATION_FOR_KEY_RING);
    
    sdls_frame.pdu.pid = SG_KEY_MGMT;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.sg = SG_SA_MGMT;
    sdls_frame.pdu.pid = PID_CREATE_SA;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_DELETE_SA;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_SET_ARSNW;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_REKEY_SA;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_EXPIRE_SA;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_SET_ARSN;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_START_SA;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_STOP_SA;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = PID_READ_ARSN;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.pid = PID_SA_STATUS;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.pid = 0b111;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.sg = SG_SEC_MON_CTRL;
    sdls_frame.pdu.pid = PID_LOG_STATUS;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.pid = PID_DUMP_LOG;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.pid = PID_ERASE_LOG;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.pid = PID_SELF_TEST;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_ERROR);

    sdls_frame.pdu.pid = PID_ALARM_FLAG;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = 0b1111;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.sg = PID_LOG_STATUS;
    sdls_frame.pdu.pid = PID_LOG_STATUS;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.uf = 1;
    sdls_frame.pdu.pid = 0;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = 1;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = 2;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = 3;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = 4;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = 5;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = 6;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = 7;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.pid = 8;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);

    sdls_frame.pdu.type = 1;
    sdls_frame.pdu.pid = 8;
    status = Crypto_PDU(ingest, tc_frame);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);
}

UTEST(CRYPTO_C, EXT_PROC_PDU)
{
    uint8_t *ingest = NULL;
    TC_t *tc_frame = NULL;
    tc_frame = malloc(sizeof(uint8_t) * TC_SIZE);
    int32_t status = CRYPTO_LIB_ERROR;
    crypto_config->has_pus_hdr = TC_NO_PUS_HDR;
    tc_frame->tc_header.vcid = TC_SDLS_EP_VCID;
    tc_frame->tc_header.fl = 1;

    status = Crypto_Process_Extended_Procedure_Pdu(tc_frame, ingest);
    ASSERT_EQ(status, CRYPTO_LIB_SUCCESS);
}


//TODO: Move these to their own unit test files.

//TODO:  This test will need to be reworked when this functionality exists.
UTEST(CRYPTO_AOS, APPLY_SECURITY)
{
    int32_t status = CRYPTO_LIB_ERROR;
    uint8_t ingest[1024] = {0};
    int len_ingest = 0;

    status = Crypto_AOS_ApplySecurity(&ingest[0], &len_ingest);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(CRYPTO_AOS, PROCESS_SECURITY)
{
    int32_t status = CRYPTO_LIB_ERROR;
    uint8_t ingest[1024] = {0};
    int len_ingest = 0;

    status = Crypto_AOS_ProcessSecurity(&ingest[0], &len_ingest);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(CRYPTO_MC, STATUS)
{
    int count = 0;
    uint8_t ingest[1024] = {0};

    count = Crypto_MC_status(ingest);
    ASSERT_EQ(11, count);
}

UTEST(CRYPTO_MC, DUMP)
{
    int count = 0;
    uint8_t ingest[1024] = {0};

    count = Crypto_MC_dump(ingest);
    ASSERT_EQ(((log_count * 4) + (log_count * 2) + 9), count);
}

UTEST(CRYPTO_MC, ERASE)
{
    int count = 0;
    uint8_t ingest[1024] = {0};

    count = Crypto_MC_erase(ingest);
    ASSERT_EQ(11, count);
}

UTEST(CRYPTO_MC, SELFTEST)
{
    int count = 0;
    uint8_t ingest[1024] = {0};

    count = Crypto_MC_selftest(ingest);
    ASSERT_EQ(10, count);
}

UTEST(CRYPTO_MC, READARSN)
{
    int count = 0;
    uint8_t ingest[1024] = {0};

    count = Crypto_SA_readARSN(ingest);
    ASSERT_EQ(11, count);
}

UTEST(CRYPTO_MC, PROCESS)
{
    uint8_t ingest[1024] = {0};
    int len_ingest = 0;
    int32_t status = CRYPTO_LIB_ERROR;

    status = Crypto_TM_ProcessSecurity(ingest, &len_ingest);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(CRYPTO_MC, TMLENGTH)
{
    int length = 0;

    length = Crypto_Get_tmLength(length);
    ASSERT_EQ(1145, length);
}



UTEST_MAIN();