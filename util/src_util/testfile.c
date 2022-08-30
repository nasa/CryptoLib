#include "ut_tc_apply.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

int main()
{    
    Crypto_Init_Unit_Test();
    char* raw_tc_sdls_ping_h = "20030015000080d2c70008197f0b00310000b1fe3128";
    char* raw_tc_sdls_ping_b = NULL;
    int raw_tc_sdls_ping_len = 0;
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();

    hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    SecurityAssociation_t* test_association;
    // Expose the SADB Security Association for test edits.
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sadb_routine->sadb_get_sa_from_spi(4, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ast = 0;
    test_association->arsn_len = 0;
    Crypto_TC_ApplySecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    Crypto_Shutdown();
    free(raw_tc_sdls_ping_b);
    free(ptr_enc_frame);
    return 0;
}