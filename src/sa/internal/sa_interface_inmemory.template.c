/*
 * Copyright 2021, by the California Institute of Technology.
 * ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
 * Any commercial use must be negotiated with the Office of Technology
 * Transfer at the California Institute of Technology.
 *
 * This software may be subject to U.S. export control laws. By accepting
 * this software, the user agrees to comply with all applicable U.S.
 * export laws and regulations. User has the responsibility to obtain
 * export licenses, or other export authority as may be required before
 * exporting such information to foreign countries or providing access to
 * foreign persons.
 */

#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>

// Security Association Initialization Functions
static int32_t sa_config(void);
static int32_t sa_init(void);
static int32_t sa_close(void);
// Security Association Interaction Functions
static int32_t sa_get_from_spi(uint16_t, SecurityAssociation_t **);
static int32_t sa_get_operational_sa_from_gvcid(uint8_t, uint16_t, uint16_t, uint8_t, SecurityAssociation_t **);
static int32_t sa_save_sa(SecurityAssociation_t *sa);
// Security Association Utility Functions
static int32_t sa_stop(void);
static int32_t sa_start(TC_t *tc_frame);
static int32_t sa_expire(void);
static int32_t sa_rekey(void);
static int32_t sa_status(uint8_t *);
static int32_t sa_create(void);
static int32_t sa_setARSN(void);
static int32_t sa_setARSNW(void);
static int32_t sa_delete(void);

/*
** Global Variables
*/
// Security
static SaInterfaceStruct     sa_if_struct;
static SecurityAssociation_t sa[NUM_SA];

/**
 * @brief Function: get_sa_interface_inmemory
 * @return SaInterface
 **/
SaInterface get_sa_interface_inmemory(void)
{
    sa_if_struct.sa_config                        = sa_config;
    sa_if_struct.sa_init                          = sa_init;
    sa_if_struct.sa_close                         = sa_close;
    sa_if_struct.sa_get_from_spi                  = sa_get_from_spi;
    sa_if_struct.sa_get_operational_sa_from_gvcid = sa_get_operational_sa_from_gvcid;
    sa_if_struct.sa_stop                          = sa_stop;
    sa_if_struct.sa_save_sa                       = sa_save_sa;
    sa_if_struct.sa_start                         = sa_start;
    sa_if_struct.sa_expire                        = sa_expire;
    sa_if_struct.sa_rekey                         = sa_rekey;
    sa_if_struct.sa_status                        = sa_status;
    sa_if_struct.sa_create                        = sa_create;
    sa_if_struct.sa_setARSN                       = sa_setARSN;
    sa_if_struct.sa_setARSNW                      = sa_setARSNW;
    sa_if_struct.sa_delete                        = sa_delete;
    return &sa_if_struct;
}

/**
 * @brief Function: sa_load_file
 * Loads saved sa_file
 **/
int32_t sa_load_file()
{
    FILE   *sa_save_file;
    int32_t status       = CRYPTO_LIB_SUCCESS;
    int     success_flag = 0;

    sa_save_file = fopen(CRYPTO_SA_SAVE, "rb+"); // Should this be rb instead of wb+

    if (sa_save_file == NULL)
    {
#ifdef SA_DEBUG
        printf("Unable to open sa_save_file!\n");
#endif
        status = CRYPTO_LIB_ERR_FAIL_SA_LOAD;
    }
    else
    {
#ifdef SA_DEBUG
        printf("Opened sa_save_file successfully!\n");
#endif
    }
    if (status == CRYPTO_LIB_SUCCESS)
    {
        success_flag = fread(&sa[0], SA_SIZE, NUM_SA, sa_save_file);
        if (success_flag)
        {
            status = CRYPTO_LIB_SUCCESS;
#ifdef SA_DEBUG
            printf("SA Load Successfull!\n");
#endif
        }
        else
        {
            status = CRYPTO_LIB_ERR_FAIL_SA_LOAD;
#ifdef SA_DEBUG
            printf("SA Load Failure!\n");
#endif
        }
    }

    if (sa_save_file != NULL)
        fclose(sa_save_file);
    return status;
}

/**
 * @brief Function: update_sa_from_ptr
 * Updates SA Array with individual SA pointer.
 **/
void update_sa_from_ptr(SecurityAssociation_t *sa_ptr)
{
    int location      = sa_ptr->spi;
    sa[location].spi  = sa_ptr->spi;
    sa[location].ekid = sa_ptr->ekid;
    sa[location].akid = sa_ptr->akid;
    memcpy(sa[location].ek_ref, sa_ptr->ek_ref, REF_SIZE);
    memcpy(sa[location].ak_ref, sa_ptr->ak_ref, REF_SIZE);
    sa[location].sa_state   = sa_ptr->sa_state;
    sa[location].gvcid_blk  = sa_ptr->gvcid_blk;
    sa[location].lpid       = sa_ptr->lpid;
    sa[location].est        = sa_ptr->est;
    sa[location].ast        = sa_ptr->ast;
    sa[location].shivf_len  = sa_ptr->shivf_len;
    sa[location].shsnf_len  = sa_ptr->shsnf_len;
    sa[location].shplf_len  = sa_ptr->shplf_len;
    sa[location].stmacf_len = sa_ptr->stmacf_len;
    sa[location].ecs        = sa_ptr->ecs;
    sa[location].ecs_len    = sa_ptr->ecs_len;
    for (int i = 0; i < sa_ptr->iv_len; i++)
    {
        sa[location].iv[i] = sa_ptr->iv[i];
    }
    sa[location].iv_len  = sa_ptr->iv_len;
    sa[location].acs_len = sa_ptr->acs_len;
    sa[location].acs     = sa_ptr->acs;
    sa[location].abm_len = sa_ptr->abm_len;
    for (int i = 0; i < sa_ptr->abm_len; i++)
    {
        sa[location].abm[i] = sa_ptr->abm[i];
    }
    sa[location].arsn_len = sa_ptr->arsn_len;
    for (int i = 0; i < sa_ptr->arsn_len; i++)
    {
        sa[location].arsn[i] = sa_ptr->arsn[i];
    }
    sa[location].arsnw_len = sa_ptr->arsnw_len;
    sa[location].arsnw     = sa_ptr->arsnw;
}

/**
 * @brief Function: sa_perform_save
 * Saves SA Array to file
 **/
int32_t sa_perform_save(SecurityAssociation_t *sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    FILE   *sa_save_file;
    int     success_flag = 0;

    update_sa_from_ptr(sa_ptr);

    sa_save_file = fopen(CRYPTO_SA_SAVE, "wb");

    if (sa_save_file == NULL)
    {
        status = CRYPTO_LIB_ERR_FAIL_SA_SAVE;
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
        success_flag = fwrite(sa, SA_SIZE, NUM_SA, sa_save_file);

        if (success_flag)
        {
            status = CRYPTO_LIB_SUCCESS;

#ifdef SA_DEBUG
            printf("SA Written Successfully to file!\n");
#endif
        }
        else
        {
            status = CRYPTO_LIB_ERR_FAIL_SA_SAVE;
#ifdef SA_DEBUG
            printf("ERROR: SA Write FAILED!\n");
#endif
        }
    }
    fclose(sa_save_file);

    return status;
}

/**
 * @brief Function: sa_save_sa
 * @param sa: SecurityAssociation_t*
 * @return int32: Success/Failure
 **/
static int32_t sa_save_sa(SecurityAssociation_t *sa)
{
    int32_t status      = CRYPTO_LIB_SUCCESS;
    int     ignore_save = 1;

#ifdef SA_FILE
    status      = sa_perform_save(sa);
    ignore_save = 0;
#endif
    if (ignore_save)
        sa = sa;
    return status;
}

/**
 * @brief Function: sa_populate
 * Populates in-memory SA
 **/
void sa_populate(void)
{
    // Security Associations
    sa[0].spi             = 0;
    sa[0].sa_state        = SA_UNKEYED;
    sa[0].est             = 0;
    sa[0].ast             = 0;
    sa[0].shivf_len       = 0;
    sa[0].iv_len          = 0;
    sa[0].shsnf_len       = 0;
    sa[0].arsn_len        = 0;
    sa[0].arsnw_len       = 0;
    sa[0].arsnw           = 0;
    sa[0].gvcid_blk.tfvn  = 0;
    sa[0].gvcid_blk.scid  = 0;
    sa[0].gvcid_blk.vcid  = 0;
    sa[0].gvcid_blk.mapid = TYPE_TC;

    // TC - CLEAR MODE (Operational)
    // IV = 0 ... 0, IV-Len = 12, TFVN = 0, VCID = 0, MAC-Len = 0, ARSNW = 5
    // EKID = 1
    sa[1].spi             = 1;
    sa[1].sa_state        = SA_OPERATIONAL;
    sa[1].est             = 0;
    sa[1].ast             = 0;
    sa[1].shivf_len       = 12;
    sa[1].iv_len          = 12;
    sa[1].shsnf_len       = 2;
    sa[1].arsnw           = 5;
    sa[1].arsnw_len       = 1;
    sa[1].arsn_len        = 2;
    sa[1].gvcid_blk.tfvn  = 0;
    sa[1].gvcid_blk.scid  = SCID & 0x3FF;
    sa[1].gvcid_blk.vcid  = 0;
    sa[1].gvcid_blk.mapid = TYPE_TC;

    // TC - Encryption Only - AES-GCM-256 (Keyed)
    // IV = 0...0, IV-Len = 12, TFVN = 0, VCID = 0; MAC-Len = 0, ARSNW = 5
    // EKID = 2
    sa[2].spi             = 2;
    sa[2].ekid            = 2;
    sa[2].sa_state        = SA_KEYED;
    sa[2].ecs_len         = 1;
    sa[2].ecs             = CRYPTO_CIPHER_AES256_GCM;
    sa[2].est             = 1;
    sa[2].ast             = 0;
    sa[2].shivf_len       = 12;
    sa[2].iv_len          = 12;
    sa[2].arsnw_len       = 1;
    sa[2].arsnw           = 5;
    sa[2].arsn_len        = ((sa[2].arsnw * 2) + 1);
    sa[2].gvcid_blk.tfvn  = 0;
    sa[2].gvcid_blk.scid  = SCID & 0x3FF;
    sa[2].gvcid_blk.vcid  = 0;
    sa[2].gvcid_blk.mapid = TYPE_TC;

    // TC - Authentication Only - HMAC_SHA512 (Keyed)
    // IV = 0...0, IV-Len = 12, MAC-Len = 16, TFVN = 0, VCID = 0, ARSNW = 5
    // AKID = 3
    sa[3].spi             = 3;
    sa[3].akid            = 3;
    sa[3].sa_state        = SA_KEYED;
    sa[3].acs_len         = 1;
    sa[3].acs             = CRYPTO_MAC_HMAC_SHA512;
    sa[3].est             = 0;
    sa[3].ast             = 1;
    sa[3].shivf_len       = 12;
    sa[3].iv_len          = 12;
    sa[3].shsnf_len       = 2;
    sa[3].arsn_len        = 2;
    sa[3].arsnw_len       = 1;
    sa[3].arsnw           = 5;
    sa[3].stmacf_len      = 16;
    sa[3].gvcid_blk.tfvn  = 0;
    sa[3].gvcid_blk.scid  = SCID & 0x3FF;
    sa[3].gvcid_blk.vcid  = 0;
    sa[3].gvcid_blk.mapid = TYPE_TC;

    // TC - Authenticated Encryption - AES-GCM-256 (Keyed)
    // IV = 0 ... 0, IV-Len = 12, MAC-Len = 16, TFVN = 0, VCID = 0, ARSNW = 5
    // EKID = 4
    sa[4].spi             = 4;
    sa[4].ekid            = 4;
    sa[4].sa_state        = SA_KEYED;
    sa[4].ecs_len         = 1;
    sa[4].ecs             = CRYPTO_CIPHER_AES256_GCM;
    sa[4].est             = 1;
    sa[4].ast             = 1;
    sa[4].shivf_len       = 12;
    sa[4].iv_len          = 12;
    sa[4].abm_len         = ABM_SIZE;
    sa[4].arsnw_len       = 1;
    sa[4].arsnw           = 5;
    sa[4].arsn_len        = ((sa[4].arsnw * 2) + 1);
    sa[4].stmacf_len      = 16;
    sa[4].gvcid_blk.tfvn  = 0;
    sa[4].gvcid_blk.scid  = SCID & 0x3FF;
    sa[4].gvcid_blk.vcid  = 0;
    sa[4].gvcid_blk.mapid = TYPE_TC;

    // TM - CLEAR MODE (Keyed)
    // IV = 0...0, IV-Len = 12, MAC-Len = 0, TFVN = 0, VCID = 0, ARSNW = 5
    // EKID = 5
    sa[5].spi             = 5;
    sa[5].sa_state        = SA_KEYED;
    sa[5].est             = 0;
    sa[5].ast             = 0;
    sa[5].shivf_len       = 12;
    sa[5].iv_len          = 12;
    sa[5].shsnf_len       = 2;
    sa[5].arsnw           = 5;
    sa[5].arsnw_len       = 1;
    sa[5].arsn_len        = 2;
    sa[5].gvcid_blk.tfvn  = 0;
    sa[5].gvcid_blk.scid  = SCID & 0x3FF;
    sa[5].gvcid_blk.vcid  = 1;
    sa[5].gvcid_blk.mapid = TYPE_TM;

    // TM - Encryption Only - AES-CBC-256 (Keyed)
    // IV = 0...0, IV-Len = 16, TFVN = 0, VCID = 0; MAC-Len = 0, ARSNW = 5
    // EKID = 6
    sa[6].spi             = 6;
    sa[6].ekid            = 6;
    sa[6].sa_state        = SA_KEYED;
    sa[6].ecs_len         = 1;
    sa[6].ecs             = CRYPTO_CIPHER_AES256_CBC;
    sa[6].est             = 1;
    sa[6].ast             = 0;
    sa[6].shivf_len       = 16;
    sa[6].iv_len          = 16;
    sa[6].shplf_len       = 1;
    sa[6].stmacf_len      = 0;
    sa[6].arsn_len        = 2;
    sa[6].arsnw_len       = 1;
    sa[6].arsnw           = 5;
    sa[6].gvcid_blk.tfvn  = 0;
    sa[6].gvcid_blk.scid  = SCID & 0x3FF;
    sa[6].gvcid_blk.vcid  = 0;
    sa[6].gvcid_blk.mapid = TYPE_TM;

    // TM - Authentication Only HMAC_SHA512 (Keyed)
    // IV = 0...0, IV-Len = 12, MAC-Len = 16, TFVN = 0, VCID = 0, ARSNW = 5
    // AKID = 7
    sa[7].spi             = 7;
    sa[7].akid            = 7;
    sa[7].sa_state        = SA_KEYED;
    sa[7].acs_len         = 1;
    sa[7].acs             = CRYPTO_MAC_HMAC_SHA512;
    sa[7].est             = 0;
    sa[7].ast             = 1;
    sa[7].shivf_len       = 12;
    sa[7].iv_len          = 12;
    sa[7].shsnf_len       = 2;
    sa[7].arsn_len        = 2;
    sa[7].arsnw_len       = 1;
    sa[7].arsnw           = 5;
    sa[7].stmacf_len      = 16;
    sa[7].gvcid_blk.tfvn  = 0;
    sa[7].gvcid_blk.scid  = SCID & 0x3FF;
    sa[7].gvcid_blk.vcid  = 0;
    sa[7].gvcid_blk.mapid = TYPE_TM;

    // TM - Authenticated Encryption AES-CBC-256 (Keyed)
    // IV = 0...0, IV-Len = 16, MAC-Len = 16, TFVN = 0, VCID = 0, ARSNW = 5
    // EKID = 8
    sa[8].spi             = 8;
    sa[8].ekid            = 8;
    sa[8].sa_state        = SA_KEYED;
    sa[8].ecs_len         = 1;
    sa[8].ecs             = CRYPTO_CIPHER_AES256_CBC;
    sa[8].est             = 1;
    sa[8].ast             = 1;
    sa[8].shplf_len       = 1;
    sa[8].shivf_len       = 16;
    sa[8].iv_len          = 16;
    sa[8].shsnf_len       = 2;
    sa[8].arsn_len        = 2;
    sa[8].arsnw_len       = 1;
    sa[8].arsnw           = 5;
    sa[8].stmacf_len      = 16;
    sa[8].gvcid_blk.tfvn  = 0;
    sa[8].gvcid_blk.scid  = SCID & 0x3FF;
    sa[8].gvcid_blk.vcid  = 0;
    sa[8].gvcid_blk.mapid = TYPE_TM;

    // AOS - Clear Mode
    // IV = 0...0, IV-Len = 12, MAC-Len = 0, TFVN = 1, VCID = 0, ARSNW = 5
    // EKID = 9
    sa[9].spi             = 9;
    sa[9].sa_state        = SA_KEYED;
    sa[9].est             = 0;
    sa[9].ast             = 0;
    sa[9].shivf_len       = 12;
    sa[9].iv_len          = 12;
    sa[9].shsnf_len       = 2;
    sa[9].arsnw           = 5;
    sa[9].arsnw_len       = 1;
    sa[9].arsn_len        = 2;
    sa[9].gvcid_blk.tfvn  = 0x01;
    sa[9].gvcid_blk.scid  = SCID & 0x3FF;
    sa[9].gvcid_blk.vcid  = 0;
    sa[9].gvcid_blk.mapid = 0;

    // AOS - Authentication Only, HMAC_SHA512 (Keyed)
    // IV = 0...0, IV-Len = 16, MAC-Len = 16, TFVN = 1, VCID = 0, ARSNW = 5
    // AKID = 10
    sa[10].spi             = 10;
    sa[10].akid            = 10;
    sa[10].sa_state        = SA_OPERATIONAL;
    sa[10].est             = 0;
    sa[10].ast             = 1;
    sa[10].acs_len         = 1;
    sa[10].acs             = CRYPTO_MAC_HMAC_SHA512;
    sa[10].stmacf_len      = 16;
    sa[10].arsnw           = 5;
    sa[10].arsnw_len       = 1;
    sa[10].arsn_len        = 2;
    sa[10].abm_len         = ABM_SIZE;
    sa[10].gvcid_blk.tfvn  = 0x01;
    sa[10].gvcid_blk.scid  = SCID & 0x3FF;
    sa[10].gvcid_blk.vcid  = 0;
    sa[10].gvcid_blk.mapid = 0;

    // AOS  - Encryption Only, AES-GCM-256 (Keyed)
    // IV = 0...0, IV-Len = 16, MAC-Len = 0, TFVN = 1, VCID = 0, ARSNW = 5
    // EKID = 11
    sa[11].spi             = 11;
    sa[11].ekid            = 11;
    sa[11].sa_state        = SA_KEYED;
    sa[11].est             = 1;
    sa[11].ast             = 0;
    sa[11].ecs_len         = 1;
    sa[11].shplf_len       = 1;
    sa[11].ecs             = CRYPTO_CIPHER_AES256_CBC;
    sa[11].iv_len          = 16;
    sa[11].shivf_len       = 16;
    sa[11].stmacf_len      = 0;
    sa[11].shsnf_len       = 2;
    sa[11].arsn_len        = 2;
    sa[11].arsnw_len       = 1;
    sa[11].arsnw           = 5;
    sa[11].gvcid_blk.tfvn  = 0x01;
    sa[11].gvcid_blk.scid  = SCID & 0x3FF;
    sa[11].gvcid_blk.vcid  = 0;
    sa[11].gvcid_blk.mapid = 0;

    // AOS - Authenticated Encryption, AES-CBC-256 (Keyed)
    // IV = 0...0, IV-Len = 16, MAC-Len = 16, TFVN = 1, VCID = 0, ARSNW = 5
    // EKID = 12
    sa[12].spi            = 12;
    sa[12].ekid           = 12;
    sa[12].sa_state       = SA_KEYED;
    sa[12].est            = 1;
    sa[12].ast            = 1;
    sa[12].ecs_len        = 1;
    sa[12].ecs            = CRYPTO_CIPHER_AES256_GCM;
    sa[12].iv_len         = 16;
    sa[12].shivf_len      = 16;
    sa[12].stmacf_len     = 16;
    sa[12].shsnf_len      = 2;
    sa[12].arsn_len       = 2;
    sa[12].arsnw_len      = 1;
    sa[12].arsnw          = 5;
    sa[12].gvcid_blk.tfvn = 0x01;
    sa[12].gvcid_blk.scid = SCID & 0x3FF;
    sa[12].gvcid_blk.vcid = 0;

    // EP - Testing SAs

    // TC - NULL (SA_None)
    sa[13].spi             = 13;
    sa[13].sa_state        = SA_NONE;
    sa[13].est             = 0;
    sa[13].ast             = 0;
    sa[13].shivf_len       = 12;
    sa[13].iv_len          = 12;
    sa[13].shsnf_len       = 2;
    sa[13].arsnw           = 5;
    sa[13].arsnw_len       = 1;
    sa[13].arsn_len        = 2;
    sa[13].gvcid_blk.tfvn  = 2;
    sa[13].gvcid_blk.scid  = SCID & 0x3FF;
    sa[13].gvcid_blk.vcid  = 0;
    sa[13].gvcid_blk.mapid = TYPE_TC;

    // TC - Unkeyed
    sa[14].spi             = 14;
    sa[14].ekid            = 14;
    sa[14].sa_state        = SA_UNKEYED;
    sa[14].est             = 0;
    sa[14].ast             = 0;
    sa[14].shivf_len       = 12;
    sa[14].iv_len          = 12;
    sa[14].shsnf_len       = 2;
    sa[14].arsnw           = 5;
    sa[14].arsnw_len       = 1;
    sa[14].arsn_len        = 2;
    sa[14].gvcid_blk.tfvn  = 2;
    sa[14].gvcid_blk.scid  = SCID & 0x3FF;
    sa[14].gvcid_blk.vcid  = 2;
    sa[14].gvcid_blk.mapid = TYPE_TC;

    // TC - Operational
    sa[15].spi             = 15;
    sa[15].ekid            = 15;
    sa[15].sa_state        = SA_OPERATIONAL;
    sa[15].est             = 0;
    sa[15].ast             = 0;
    sa[15].shivf_len       = 12;
    sa[15].iv_len          = 12;
    sa[15].shsnf_len       = 2;
    sa[15].arsnw           = 5;
    sa[15].arsnw_len       = 1;
    sa[15].arsn_len        = 2;
    sa[15].gvcid_blk.tfvn  = 2;
    sa[15].gvcid_blk.scid  = SCID & 0x3FF;
    sa[15].gvcid_blk.vcid  = 3;
    sa[15].gvcid_blk.mapid = TYPE_TC;

    sa_perform_save(&sa[0]);
}

/**
 * @brief Function Key_Validation()
 * Validates the use of a single key per encryption type per SA
 * At most an SA can contain 2 unique Keys.  These my not be utilized in another SA
 */
int32_t key_validation(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    int     i      = 0;
    int     j      = 0;
    for (i = 0; i < NUM_SA; i++)
    {
        uint16_t i_ekid = sa[i].ekid;
        uint16_t i_akid = sa[i].akid;

        if (i_ekid == i_akid)
        {
            status = CRYPTO_LIB_ERR_KEY_VALIDATION;
#ifdef DEBUG
            printf(KRED "SA Key Validation FAILURE!\n");
            printf("Key Duplication: SA #%d, EKID: %d, AKID: %d\n", i, i_ekid, i_akid);
            printf("\n" RESET);
#endif
            break;
        }

        for (j = i + 1; j < NUM_SA; j++)
        {
            uint16_t j_ekid = sa[j].ekid;
            uint16_t j_akid = sa[j].akid;

            if ((i_ekid == j_ekid) || (i_ekid == j_akid) || (i_akid == j_ekid) || (i_akid == j_akid) ||
                (j_ekid == j_akid))
            {
                status = CRYPTO_LIB_ERR_KEY_VALIDATION;
#ifdef DEBUG
                printf(KRED "SA Key Validation FAILURE!\n");
                printf("Key Duplication SA: %d, EKID: %d, AKID: %d\n\tSA: %d, EKID: %d, AKID: %d\n", i, i_ekid, i_akid,
                       j, j_ekid, j_akid);
                printf("\n" RESET);
#endif
                break;
            }
        }
    }
    return status;
}

/**
 * @brief Function; sa_config
 * @return int32: Success/Failure
 **/
int32_t sa_config(void)
{
    int32_t status       = CRYPTO_LIB_SUCCESS;
    int     use_internal = 1;

#ifdef SA_FILE
    use_internal = 0;
#endif

    if (use_internal)
    {
        sa_populate();
#ifdef KEY_VALIDATION
        status = key_validation();
#endif
    }

    return status;
}

/**
 * @brief Function: sa_init
 * @return int32: Success/Failure
 **/
int32_t sa_init(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    int use_internal = 1;

#ifdef SA_FILE
    use_internal = 0;
    status       = sa_load_file();
    if (status != CRYPTO_LIB_SUCCESS)
    {
#ifdef DEBUG
        printf("SA Load Failure!\n");
        printf("Falling back to in-memory SA!\n");
        use_internal = 1;
        status       = CRYPTO_LIB_SUCCESS;
#endif
    }
#endif

    if (use_internal)
    {
        for (int x = 0; x < NUM_SA; x++)
        {
            sa[x].spi       = x;
            sa[x].ekid      = x;
            sa[x].akid      = x;
            sa[x].sa_state  = SA_NONE;
            sa[x].ecs_len   = 0;
            sa[x].ecs       = 0;
            sa[x].shivf_len = 0;
            for (int y = 0; y < IV_SIZE; y++)
            {
                sa[x].iv[y] = 0;
            }
            sa[x].iv_len = 0;
            for (int y = 0; y < ABM_SIZE; y++)
            {
                sa[x].abm[y] = 0;
            }
            for (int y = 0; y < REF_SIZE; y++)
            {
                sa[x].ek_ref[y] = '\0';
                sa[x].ak_ref[y] = '\0';
            }
            sa[x].abm_len    = 0;
            sa[x].acs_len    = 0;
            sa[x].acs        = 0;
            sa[x].shsnf_len  = 0;
            sa[x].arsn_len   = 0;
            sa[x].stmacf_len = 0;
            for (int y = 0; y < ARSN_SIZE; y++)
            {
                sa[x].arsn[y] = 0;
            }
        }

        sa_populate();
#ifdef KEY_VALIDATION
        status = key_validation();
#endif
    }
    return status;
}

/**
 * @brief Function: sa_close
 * @return int32: Success/Failure
 **/
static int32_t sa_close(void)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    return status;
}

/*
** Security Association Interaction Functions
*/
/**
 * @brief Function: sa_get_from_spi
 * @param spi: uint16
 * @param security_association: SecurityAssociation_t**
 * @return int32: Success/Failure
 **/
static int32_t sa_get_from_spi(uint16_t spi, SecurityAssociation_t **security_association)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    // Check if spi index in sa array
    if (spi >= NUM_SA)
    {
#ifdef SA_DEBUG
        printf(KRED "sa_get_from_spi: SPI: %d > NUM_SA: %d.\n" RESET, spi, NUM_SA);
#endif
        return CRYPTO_LIB_ERR_SPI_INDEX_OOB;
    }
    *security_association = &sa[spi];
    // if (sa[spi].shivf_len > 0 && crypto_config.cryptography_type != CRYPTOGRAPHY_TYPE_KMCCRYPTO)
    // {
    //     return CRYPTO_LIB_ERR_NULL_IV;
    // } // Must have IV if doing encryption or authentication

    if ((sa[spi].abm_len == 0) && sa[spi].ast)
    {
        return CRYPTO_LIB_ERR_NULL_ABM;
    } // Must have abm if doing authentication
#ifdef SA_DEBUG
    printf(KYEL "DEBUG - Printing local copy of SA Entry for current SPI.\n" RESET);
    Crypto_saPrint(*security_association);
#endif
    return status;
}

int32_t sa_get_operational_sa_from_gvcid_find_iv(uint8_t tfvn, uint16_t scid, uint16_t vcid, uint8_t mapid,
                                                 SecurityAssociation_t **security_association)
{
    int32_t status = CRYPTO_LIB_ERR_NO_OPERATIONAL_SA;
    int     i      = 0;

    for (i = 0; i < NUM_SA; i++)
    {
        // If valid match found
        if ((sa[i].gvcid_blk.tfvn == tfvn) && (sa[i].gvcid_blk.scid == scid) && (sa[i].gvcid_blk.vcid == vcid) &&
            (sa[i].sa_state == SA_OPERATIONAL) &&
            (crypto_config.unique_sa_per_mapid == TC_UNIQUE_SA_PER_MAP_ID_FALSE || sa[i].gvcid_blk.mapid == mapid))
        // only require MapID match is unique SA per MapID set (only relevant
        // when using segmentation hdrs)
        {
            *security_association = &sa[i];

            // Must have IV if using libgcrypt and auth/enc
            // if (sa[i].iv == NULL && (sa[i].ast == 1 || sa[i].est == 1) && crypto_config.cryptography_type !=
            // CRYPTOGRAPHY_TYPE_KMCCRYPTO)
            // {
            //     //status =  CRYPTO_LIB_ERR_NULL_IV;
            //     //return status;
            // }
            // Must have ABM if doing authentication
            if (sa[i].ast && sa[i].abm_len <= 0)
            {
                status = CRYPTO_LIB_ERR_NULL_ABM;
                return status;
            }

#ifdef SA_DEBUG
            printf("Valid operational SA found at index %d.\n", i);
            printf("\t Tfvn: %d\n", tfvn);
            printf("\t Scid: %d\n", scid);
            printf("\t Vcid: %d\n", vcid);
#endif

            status = CRYPTO_LIB_SUCCESS;
            break;
        }
    }
    return status;
}

void sa_mismatched_tfvn_error(int *i_p, int32_t *status, uint8_t tfvn, uint16_t scid, uint16_t vcid, uint8_t mapid)
{
    int i = *i_p;
    if ((sa[i].gvcid_blk.tfvn != tfvn) && (sa[i].gvcid_blk.scid == scid) && (sa[i].gvcid_blk.vcid == vcid) &&
        (sa[i].gvcid_blk.mapid == mapid && sa[i].sa_state == SA_OPERATIONAL))
    {
#ifdef SA_DEBUG
        printf(KRED "An operational SA was found - but mismatched tfvn.\n" RESET);
        printf(KRED "SA is %d\n", i);
        printf(KRED "Incoming tfvn is %d\n", tfvn);
        printf(KRED "SA tfvn is %d\n", sa[i].gvcid_blk.tfvn);
#endif
        *status = CRYPTO_LIB_ERR_INVALID_TFVN;
    }
    *i_p = i;
}

void sa_mismatched_scid(int *i_p, int32_t *status, uint8_t tfvn, uint16_t scid, uint16_t vcid, uint8_t mapid)
{
    int i = *i_p;
    if ((sa[i].gvcid_blk.tfvn == tfvn) && (sa[i].gvcid_blk.scid != scid) && (sa[i].gvcid_blk.vcid == vcid) &&
        (sa[i].gvcid_blk.mapid == mapid && sa[i].sa_state == SA_OPERATIONAL))
    {
#ifdef SA_DEBUG
        printf(KRED "An operational SA was found - but mismatched scid.\n" RESET);
        printf(KRED "SA is %d\n", i);
        printf(KRED "SCID is %d\n", scid);
        printf(KRED "gvcid_blk SCID is %d\n", sa[i].gvcid_blk.scid);
#endif
        *status = CRYPTO_LIB_ERR_INVALID_SCID;
    }
    *i_p = i;
}

void sa_mismatched_vcid(int *i_p, int32_t *status, uint8_t tfvn, uint16_t scid, uint16_t vcid, uint8_t mapid)
{
    int i = *i_p;
    if ((sa[i].gvcid_blk.tfvn == tfvn) && (sa[i].gvcid_blk.scid == scid) && (sa[i].gvcid_blk.vcid != vcid) &&
        (sa[i].gvcid_blk.mapid == mapid && sa[i].sa_state == SA_OPERATIONAL))
    {
#ifdef SA_DEBUG
        printf(KRED "An operational SA was found - but mismatched vcid.\n" RESET);
        printf(KRED "SA is %d\n", i);
#endif
        *status = CRYPTO_LIB_ERR_INVALID_VCID;
    }
    *i_p = i;
}

void sa_mismatched_mapid(int *i_p, int32_t *status, uint8_t tfvn, uint16_t scid, uint16_t vcid, uint8_t mapid)
{
    int i = *i_p;
    if ((sa[i].gvcid_blk.tfvn == tfvn) && (sa[i].gvcid_blk.scid == scid) && (sa[i].gvcid_blk.vcid == vcid) &&
        (sa[i].gvcid_blk.mapid != mapid && sa[i].sa_state == SA_OPERATIONAL))
    {
#ifdef SA_DEBUG
        printf(KRED "An operational SA was found - but mismatched mapid.\n" RESET);
#endif
        *status = CRYPTO_LIB_ERR_INVALID_MAPID;
    }
    *i_p = i;
}

void sa_non_operational_sa(int *i_p, int32_t *status, uint8_t tfvn, uint16_t scid, uint16_t vcid, uint8_t mapid)
{
    int i = *i_p;
    if ((sa[i].gvcid_blk.tfvn == tfvn) && (sa[i].gvcid_blk.scid == scid) && (sa[i].gvcid_blk.vcid == vcid) &&
        (sa[i].gvcid_blk.mapid == mapid && sa[i].sa_state != SA_OPERATIONAL))
    {
#ifdef SA_DEBUG
        printf(KRED "A valid but non-operational SA was found: SPI: %d.\n" RESET, sa[i].spi);
#endif
        *status = CRYPTO_LIB_ERR_NO_OPERATIONAL_SA;
    }
    *i_p = i;
}

void sa_debug_block(uint8_t tfvn, uint16_t scid, uint16_t vcid, uint8_t mapid)
{
// Detailed debug block
#ifdef SA_DEBUG
    printf(KYEL "Incoming frame parameters:\n" RESET);
    printf(KYEL "\ttfvn %02X\n" RESET, tfvn);
    printf(KYEL "\tscid %d\n" RESET, scid);
    printf(KYEL "\tvcid %d\n" RESET, vcid);
    printf(KYEL "\tmapid %02X\n" RESET, mapid);
#endif
    // Ignore Unused Variables
    (void)tfvn;
    (void)scid;
    (void)vcid;
    (void)mapid;
}

int32_t sa_get_operational_sa_from_gvcid_generate_error(int32_t *status, uint8_t tfvn, uint16_t scid, uint16_t vcid,
                                                        uint8_t mapid)
{
    int i = 0;

    if (*status != CRYPTO_LIB_SUCCESS)
    {
#ifdef SA_DEBUG
        printf(KRED "Error - Making best attempt at a useful error code:\n\t" RESET);
#endif
        for (i = 0; i < NUM_SA; i++)
        {
            // Could possibly have more than one field mismatched,
            // ordering so the 'most accurate' SA's error is returned
            // (determined by matching header fields L to R)
            sa_mismatched_tfvn_error(&i, status, tfvn, scid, vcid, mapid);
            if (*status != CRYPTO_LIB_SUCCESS)
            {
                sa_debug_block(tfvn, scid, vcid, mapid);
                return *status;
            }
            sa_mismatched_scid(&i, status, tfvn, scid, vcid, mapid);
            if (*status != CRYPTO_LIB_SUCCESS)
            {
                sa_debug_block(tfvn, scid, vcid, mapid);
                return *status;
            }
            sa_mismatched_vcid(&i, status, tfvn, scid, vcid, mapid);
            if (*status != CRYPTO_LIB_SUCCESS)
            {
                sa_debug_block(tfvn, scid, vcid, mapid);
                return *status;
            }
            sa_mismatched_mapid(&i, status, tfvn, scid, vcid, mapid);
            if (*status != CRYPTO_LIB_SUCCESS)
            {
                sa_debug_block(tfvn, scid, vcid, mapid);
                return *status;
            }
            sa_non_operational_sa(&i, status, tfvn, scid, vcid, mapid);
            if (*status != CRYPTO_LIB_SUCCESS)
            {
                sa_debug_block(tfvn, scid, vcid, mapid);
                return *status;
            }
        }
    }
    return *status;
}

/**
 * @brief Function: sa_get_operational_sa_from_gvcid
 * @param tfvn: uint8
 * @param scid: uint16
 * @param vcid: uint16
 * @param mapid: uint8 // tc only
 * @param security_association: SecurityAssociation_t**
 * @return int32: Success/Failure
 **/
static int32_t sa_get_operational_sa_from_gvcid(uint8_t tfvn, uint16_t scid, uint16_t vcid, uint8_t mapid,
                                                SecurityAssociation_t **security_association)
{
    int32_t status = CRYPTO_LIB_ERR_NO_OPERATIONAL_SA;

    status = sa_get_operational_sa_from_gvcid_find_iv(tfvn, scid, vcid, mapid, security_association);

    // If not a success, attempt to generate a meaningful error code
    status = sa_get_operational_sa_from_gvcid_generate_error(&status, tfvn, scid, vcid, mapid);

    return status;
}

/*
** Security Association Management Services
*/
/**
 * @brief sa_start
 * @param tc_frame: TC_t
 * @return int32: Success/Failure
 **/
static int32_t sa_start(TC_t *tc_frame)
{
    // Local variables
    uint8_t        count = 0;
    uint16_t       spi   = 0x0000;
    crypto_gvcid_t gvcid;
    int            x;
    int            i;

    // Read ingest
    spi = ((uint8_t)sdls_frame.pdu.data[0] << 8) | (uint8_t)sdls_frame.pdu.data[1];

    // Check SPI exists and in 'Keyed' state
    if (spi < NUM_SA)
    {
        // Overwrite last PID : 8 bits
        // Bits from L-R
        //   1 : Procedure Type Flag (type)
        //   2 : User Flag (uf)
        // 3-4 : Service Group Field (sg)
        // 5-8 : Procedure Identification Field (pid)
        sa[spi].lpid = (sdls_frame.pdu.hdr.type << 7) | (sdls_frame.pdu.hdr.uf << 6) | (sdls_frame.pdu.hdr.sg << 4) |
                       sdls_frame.pdu.hdr.pid;

        if (sa[spi].sa_state == SA_KEYED)
        {
            count = 2;

            for (x = 0; x <= ((sdls_frame.pdu.hdr.pdu_len - 2) / 4); x++)
            { // Read in GVCID
                gvcid.tfvn = (sdls_frame.pdu.data[count] >> 4);
                gvcid.scid = (sdls_frame.pdu.data[count] << 12) | (sdls_frame.pdu.data[count + 1] << 4) |
                             (sdls_frame.pdu.data[count + 2] >> 4);
                gvcid.vcid = (sdls_frame.pdu.data[count + 2] << 4) | (sdls_frame.pdu.data[count + 3] && 0x3F);
                if (current_managed_parameters_struct.has_segmentation_hdr == TC_HAS_SEGMENT_HDRS)
                {
                    gvcid.mapid = (sdls_frame.pdu.data[count + 3]);
                }
                else
                {
                    gvcid.mapid = 0;
                }

                // TC
                if (gvcid.vcid != tc_frame->tc_header.vcid)
                { // Clear all GVCIDs for provided SPI
                    if (gvcid.mapid == TYPE_TC)
                    {
                        sa[spi].gvcid_blk.tfvn  = 0;
                        sa[spi].gvcid_blk.scid  = 0;
                        sa[spi].gvcid_blk.vcid  = 0;
                        sa[spi].gvcid_blk.mapid = 0;
                    }
                    // Write channel to SA
                    if (gvcid.mapid != TYPE_MAP)
                    { // TC
                        sa[spi].gvcid_blk.tfvn  = gvcid.tfvn;
                        sa[spi].gvcid_blk.scid  = gvcid.scid;
                        sa[spi].gvcid_blk.mapid = gvcid.mapid;
                    }
                    else
                    {
                        // TODO: Handle TYPE_MAP
                    }
                }
                // TM
                if (gvcid.vcid != tm_frame_pri_hdr.vcid) // TODO Check this tm_frame.tm_header.vcid)
                {                                        // Clear all GVCIDs for provided SPI
                    if (gvcid.mapid == TYPE_TM)
                    {
                        for (i = 0; i < NUM_GVCID; i++)
                        { // TM
                            sa[spi].gvcid_blk.tfvn  = 0;
                            sa[spi].gvcid_blk.scid  = 0;
                            sa[spi].gvcid_blk.vcid  = 0;
                            sa[spi].gvcid_blk.mapid = 0;
                        }
                    }
                    // Write channel to SA
                    if (gvcid.mapid != TYPE_MAP)
                    {                                          // TM
                        sa[spi].gvcid_blk.tfvn  = gvcid.tfvn;  // Hope for the best
                        sa[spi].gvcid_blk.scid  = gvcid.scid;  // Hope for the best
                        sa[spi].gvcid_blk.vcid  = gvcid.vcid;  // Hope for the best
                        sa[spi].gvcid_blk.mapid = gvcid.mapid; // Hope for the best
                    }
                    else
                    {
                        // TODO: Handle TYPE_MAP
                    }
                }

#ifdef PDU_DEBUG
                printf("SPI %d changed to OPERATIONAL state. \n", spi);
                switch (gvcid.mapid)
                {
                    case TYPE_TC:
                        printf("Type TC, ");
                        break;
                    case TYPE_MAP:
                        printf("Type MAP, ");
                        break;
                    case TYPE_TM:
                        printf("Type TM, ");
                        break;
                    default:
                        printf("Type Unknown, ");
                        break;
                }
#endif

                // Change to operational state
                sa[spi].sa_state = SA_OPERATIONAL;
            }
        }
        else
        {
            printf(KRED "ERROR: SPI %d is not in the KEYED state.\n" RESET, spi);
        }
    }
    else
    {
        printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

#ifdef DEBUG
    printf("\t spi = %d \n", spi);
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sa_stop
 * @return int32: Success/Failure
 **/
static int32_t sa_stop(void)
{
    // Local variables
    uint16_t spi = 0x0000;
    int      x;

    // Read ingest
    spi = ((uint8_t)sdls_frame.pdu.data[0] << BYTE_LEN) | (uint8_t)sdls_frame.pdu.data[1];
    printf("spi = %d \n", spi);

    // Check SPI exists and in 'Active' state
    if (spi < NUM_SA)
    {
        // Overwrite last PID : 8 bits
        // Bits from L-R
        //   1 : Procedure Type Flag (type)
        //   2 : User Flag (uf)
        // 3-4 : Service Group Field (sg)
        // 5-8 : Procedure Identification Field (pid)
        sa[spi].lpid = (sdls_frame.pdu.hdr.type << 7) | (sdls_frame.pdu.hdr.uf << 6) | (sdls_frame.pdu.hdr.sg << 4) |
                       sdls_frame.pdu.hdr.pid;

        if (sa[spi].sa_state == SA_OPERATIONAL)
        {
            // Remove all GVC/GMAP IDs
            sa[spi].gvcid_blk.tfvn  = 0;
            sa[spi].gvcid_blk.scid  = 0;
            sa[spi].gvcid_blk.vcid  = 0;
            sa[spi].gvcid_blk.mapid = 0;
            for (x = 0; x < NUM_GVCID; x++)
            {
                // TM
                sa[spi].gvcid_blk.tfvn  = 0; // TODO REVISIT
                sa[spi].gvcid_blk.scid  = 0; // TODO REVISIT
                sa[spi].gvcid_blk.vcid  = 0; // TODO REVISIT
                sa[spi].gvcid_blk.mapid = 0; // TODO REVISIT
            }

            // Change to operational state
            sa[spi].sa_state = SA_KEYED;
#ifdef PDU_DEBUG
            printf("SPI %d changed to KEYED state. \n", spi);
#endif
        }
        else
        {
            printf(KRED "ERROR: SPI %d is not in the OPERATIONAL state.\n" RESET, spi);
        }
    }
    else
    {
        printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

#ifdef DEBUG
    printf("\t spi = %d \n", spi);
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sa_rekey
 * @return int32: Success/Failure
 **/
static int32_t sa_rekey(void)
{
    // Local variables
    uint16_t spi   = 0x0000;
    int      count = 0;
    int      x     = 0;

    // Read ingest
    spi   = ((uint8_t)sdls_frame.pdu.data[count] << BYTE_LEN) | (uint8_t)sdls_frame.pdu.data[count + 1];
    count = count + 2;

    // Check SPI exists and in 'Unkeyed' state
    if (spi < NUM_SA)
    {
        // Overwrite last PID : 8 bits
        // Bits from L-R
        //   1 : Procedure Type Flag (type)
        //   2 : User Flag (uf)
        // 3-4 : Service Group Field (sg)
        // 5-8 : Procedure Identification Field (pid)
        sa[spi].lpid = (sdls_frame.pdu.hdr.type << 7) | (sdls_frame.pdu.hdr.uf << 6) | (sdls_frame.pdu.hdr.sg << 4) |
                       sdls_frame.pdu.hdr.pid;

        if (sa[spi].sa_state == SA_UNKEYED)
        { // Encryption Key
            sa[spi].ekid = ((uint8_t)sdls_frame.pdu.data[count] << BYTE_LEN) | (uint8_t)sdls_frame.pdu.data[count + 1];
            count        = count + 2;

            // Authentication Key
            // sa[spi].akid = ((uint8_t)sdls_frame.pdu.data[count] << 8) | (uint8_t)sdls_frame.pdu.data[count+1];
            // count = count + 2;

            // Anti-Replay Seq Num
#ifdef PDU_DEBUG
            printf("SPI %d IV updated to: 0x", spi);
#endif
            if (sa[spi].shivf_len > 0)
            { // Set IV - authenticated encryption
                for (x = count; x < (sa[spi].shivf_len + count); x++)
                {
                    // TODO: Uncomment once fixed in ESA implementation
                    // TODO: Assuming this was fixed...
                    *(sa[spi].iv + x - count) = (uint8_t)sdls_frame.pdu.data[x];
#ifdef PDU_DEBUG
                    printf("%02x", sdls_frame.pdu.data[x]);
#endif
                }
            }
            else
            { // Set SN
              // TODO
            }
#ifdef PDU_DEBUG
            printf("\n");
#endif

            // Change to keyed state
            sa[spi].sa_state = SA_KEYED;
#ifdef PDU_DEBUG
            printf("SPI %d changed to KEYED state with encrypted Key ID %d. \n", spi, sa[spi].ekid);
#endif
        }
        else
        {
#ifdef PDU_DEBUG
            printf(KRED "ERROR: SPI %d is not in the UNKEYED state.\n" RESET, spi);
#endif
        }
    }
    else
    {
#ifdef PDU_DEBUG
        printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
#endif
    }

#ifdef PDU_DEBUG
    printf("\t spi  = %d \n", spi);
    printf("\t ekid = %d \n", sa[spi].ekid);
    // printf("\t akid = %d \n", sa[spi].akid);
#endif

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sa_expire
 * @return int32: Success/Failure
 **/
static int32_t sa_expire(void)
{
    // Local variables
    uint16_t spi = 0x0000;

    // Read ingest
    spi = ((uint8_t)sdls_frame.pdu.data[0] << BYTE_LEN) | (uint8_t)sdls_frame.pdu.data[1];
    printf("spi = %d \n", spi);

    // Check SPI exists and in 'Keyed' state
    if (spi < NUM_SA)
    {
        // Overwrite last PID : 8 bits
        // Bits from L-R
        //   1 : Procedure Type Flag (type)
        //   2 : User Flag (uf)
        // 3-4 : Service Group Field (sg)
        // 5-8 : Procedure Identification Field (pid)
        sa[spi].lpid = (sdls_frame.pdu.hdr.type << 7) | (sdls_frame.pdu.hdr.uf << 6) | (sdls_frame.pdu.hdr.sg << 4) |
                       sdls_frame.pdu.hdr.pid;

        if (sa[spi].sa_state == SA_KEYED)
        { // Change to 'Unkeyed' state
            sa[spi].sa_state = SA_UNKEYED;
#ifdef PDU_DEBUG
            printf("SPI %d changed to UNKEYED state. \n", spi);
#endif
        }
        else
        {
            printf(KRED "ERROR: SPI %d is not in the KEYED state.\n" RESET, spi);
        }
    }
    else
    {
        printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sa_create
 * @return int32: Success/Failure
 **/
static int32_t sa_create(void)
{
    // Local variables
    uint8_t  count = 6;
    uint16_t spi   = 0x0000;
    int      x;

    // Read sdls_frame.pdu.data
    spi = ((uint8_t)sdls_frame.pdu.data[0] << BYTE_LEN) | (uint8_t)sdls_frame.pdu.data[1];
#ifdef DEBUG
    printf("spi = %d \n", spi);
#endif

    // Check if valid SPI
    if (spi < NUM_SA)
    {
        // Overwrite last PID : 8 bits
        // Bits from L-R
        //   1 : Procedure Type Flag (type)
        //   2 : User Flag (uf)
        // 3-4 : Service Group Field (sg)
        // 5-8 : Procedure Identification Field (pid)
        sa[spi].lpid = (sdls_frame.pdu.hdr.type << 7) | (sdls_frame.pdu.hdr.uf << 6) | (sdls_frame.pdu.hdr.sg << 4) |
                       sdls_frame.pdu.hdr.pid;

        // Write SA Configuration
        sa[spi].est        = ((uint8_t)sdls_frame.pdu.data[2] & 0x80) >> 7;
        sa[spi].ast        = ((uint8_t)sdls_frame.pdu.data[2] & 0x40) >> 6;
        sa[spi].shivf_len  = ((uint8_t)sdls_frame.pdu.data[2] & 0x3F);
        sa[spi].shsnf_len  = ((uint8_t)sdls_frame.pdu.data[3] & 0xFC) >> 2;
        sa[spi].shplf_len  = ((uint8_t)sdls_frame.pdu.data[3] & 0x03);
        sa[spi].stmacf_len = ((uint8_t)sdls_frame.pdu.data[4]);
        sa[spi].ecs_len    = ((uint8_t)sdls_frame.pdu.data[5]);
        for (x = 0; x < sa[spi].ecs_len; x++)
        {
            sa[spi].ecs = ((uint8_t)sdls_frame.pdu.data[count++]);
        }
        sa[spi].shivf_len = ((uint8_t)sdls_frame.pdu.data[count++]);
        for (x = 0; x < sa[spi].shivf_len; x++)
        {
            sa[spi].iv[x] = ((uint8_t)sdls_frame.pdu.data[count++]);
        }
        sa[spi].acs_len = ((uint8_t)sdls_frame.pdu.data[count++]);
        for (x = 0; x < sa[spi].acs_len; x++)
        {
            sa[spi].acs = ((uint8_t)sdls_frame.pdu.data[count++]);
        }
        sa[spi].abm_len = (uint8_t)((sdls_frame.pdu.data[count] << BYTE_LEN) | (sdls_frame.pdu.data[count + 1]));
        count           = count + 2;
        for (x = 0; x < sa[spi].abm_len; x++)
        {
            sa[spi].abm[x] = ((uint8_t)sdls_frame.pdu.data[count++]);
        }
        sa[spi].arsn_len = ((uint8_t)sdls_frame.pdu.data[count++]);
        for (x = 0; x < sa[spi].arsn_len; x++)
        {
            *(sa[spi].arsn + x) = ((uint8_t)sdls_frame.pdu.data[count++]);
        }
        sa[spi].arsnw_len = ((uint8_t)sdls_frame.pdu.data[count++]);
        for (x = 0; x < sa[spi].arsnw_len; x++)
        {
            sa[spi].arsnw = sa[spi].arsnw | (((uint8_t)sdls_frame.pdu.data[count++]) << (sa[spi].arsnw_len - x));
        }

        // TODO: Checks for valid data

        // Set state to unkeyed
        sa[spi].sa_state = SA_UNKEYED;

#ifdef PDU_DEBUG
        Crypto_saPrint(&sa[spi]);
#endif
    }
    else
    {
#ifdef DEBUG
        printf(KRED "ERROR: SPI %d cannot be created.\n" RESET, spi);
#endif
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sa_delete
 * @return int32: Success/Failure
 **/
static int32_t sa_delete(void)
{
    // Local variables
    uint16_t spi = 0x0000;

    // Read ingest
    spi = ((uint8_t)sdls_frame.pdu.data[0] << BYTE_LEN) | (uint8_t)sdls_frame.pdu.data[1];
#ifdef DEBUG
    printf("spi = %d \n", spi);
#endif

    // Check SPI exists and in 'Unkeyed' state
    if (spi < NUM_SA)
    {
        // Overwrite last PID : 8 bits
        // Bits from L-R
        //   1 : Procedure Type Flag (type)
        //   2 : User Flag (uf)
        // 3-4 : Service Group Field (sg)
        // 5-8 : Procedure Identification Field (pid)
        sa[spi].lpid = (sdls_frame.pdu.hdr.type << 7) | (sdls_frame.pdu.hdr.uf << 6) | (sdls_frame.pdu.hdr.sg << 4) |
                       sdls_frame.pdu.hdr.pid;

        if (sa[spi].sa_state == SA_UNKEYED)
        { // Change to 'None' state
            sa[spi].sa_state = SA_NONE;
#ifdef PDU_DEBUG
            printf("SPI %d changed to NONE state. \n", spi);
#endif

            // TODO: Zero entire SA
        }
        else
        {
            printf(KRED "ERROR: SPI %d is not in the UNKEYED state.\n" RESET, spi);
        }
    }
    else
    {
        printf(KRED "ERROR: SPI %d does not exist.\n" RESET, spi);
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sa_setASRN
 * @return int32: Success/Failure
 **/
static int32_t sa_setARSN(void)
{
    // Local variables
    uint16_t spi = 0x0000;
    int      x;

    // Read ingest
    spi = ((uint8_t)sdls_frame.pdu.data[0] << BYTE_LEN) | (uint8_t)sdls_frame.pdu.data[1];
    printf("spi = %d \n", spi);

    // TODO: Check SA type (authenticated, encrypted, both) and set appropriately
    // TODO: Add more checks on bounds

    // Check SPI exists
    if (spi < NUM_SA)
    {
        if (sa[spi].shivf_len > 0 && sa[spi].ecs == 1 && sa[spi].acs == 1)
        { // Set IV - authenticated encryption
#ifdef PDU_DEBUG
            printf("SPI %d IV updated to: 0x", spi);
#endif
            for (x = 0; x < IV_SIZE; x++)
            {
                *(sa[spi].iv + x) = (uint8_t)sdls_frame.pdu.data[x + 2];
#ifdef PDU_DEBUG
                printf("%02x", *(sa[spi].iv + x));
#endif
            }
            Crypto_increment(sa[spi].iv, sa[spi].shivf_len);
        }
        else
        { // Set SN
#ifdef PDU_DEBUG
            printf("SPI %d ARSN updated to: 0x", spi);
#endif
            for (x = 0; x < sa[spi].arsn_len; x++)
            {
                *(sa[spi].arsn + x) = (uint8_t)sdls_frame.pdu.data[x + 2];
#ifdef PDU_DEBUG
                printf("%02x", *(sa[spi].arsn + x));
#endif
            }
        }
#ifdef PDU_DEBUG
        printf("\n");
#endif
    }
    else
    {
        printf("sa_setARSN ERROR: SPI %d does not exist.\n", spi);
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sa_setARSNW
 * @return int32: Success/Failure
 **/
static int32_t sa_setARSNW(void)
{
    // Local variables
    uint16_t spi = 0x0000;

    // Read ingest
    spi = ((uint8_t)sdls_frame.pdu.data[0] << BYTE_LEN) | (uint8_t)sdls_frame.pdu.data[1];
#ifdef PDU_DEBUG
    printf("spi = %d \n", spi);
#endif

    // Check SPI exists
    if (spi < NUM_SA)
    {
        // Check for out of bounds
        if (sa[spi].arsnw_len > (ARSN_SIZE))
        {
            sa[spi].arsnw_len = ARSN_SIZE;
        }

        sa[spi].arsnw = (((uint8_t)sdls_frame.pdu.data[2]));
#ifdef PDU_DEBUG
        printf("ARSN set to: %d\n", sa[spi].arsnw);
#endif
    }
    else
    {
#ifdef PDU_DEBUG
        printf("sa_setARSNW ERROR: SPI %d does not exist.\n", spi);
#endif
    }

    return CRYPTO_LIB_SUCCESS;
}

/**
 * @brief Function: sa_status
 * @param ingest: uint8_t*
 * @return int32: count
 **/
static int32_t sa_status(uint8_t *ingest)
{
    // TODO: Count is not being returned yet
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (ingest == NULL)
    {
        status = CRYPTO_LIB_ERROR;
    }

    if (status == CRYPTO_LIB_SUCCESS)
    {
        // Local variables
        int      count = 0;
        uint16_t spi   = 0x0000;

        // Read ingest
        spi = ((uint8_t)sdls_frame.pdu.data[0] << BYTE_LEN) | (uint8_t)sdls_frame.pdu.data[1];
        printf("spi = %d \n", spi);

        // Check SPI exists
        if (spi < NUM_SA)
        {
            printf("SIZE: %ld\n", SDLS_SA_STATUS_RPLY_SIZE);
            // Prepare for Reply
            sdls_frame.pdu.hdr.pdu_len = SDLS_SA_STATUS_RPLY_SIZE * BYTE_LEN;
            sdls_frame.hdr.pkt_length  = CCSDS_HDR_SIZE + CCSDS_PUS_SIZE + SDLS_TLV_HDR_SIZE + (sdls_frame.pdu.hdr.pdu_len / BYTE_LEN) - 1;
            count                      = Crypto_Prep_Reply(sdls_ep_reply, CRYPTOLIB_APPID);
            // PDU
            sdls_ep_reply[count++] = (spi & 0xFF00) >> BYTE_LEN;
            sdls_ep_reply[count++] = (spi & 0x00FF);
            sdls_ep_reply[count++] = sa[spi].lpid;
        }
        else
        {
            printf("sa_status ERROR: SPI %d does not exist.\n", spi);
            status = CRYPTO_LIB_ERR_SPI_INDEX_OOB;
        }

#ifdef SA_DEBUG
        Crypto_saPrint(&sa[spi]);
        if (status == CRYPTO_LIB_SUCCESS)
        {
            printf("SA Status Reply:   0x");
            for (int x = 0; x < count; x++)
            {
                printf("%02X", sdls_ep_reply[x]);
            }
            printf("\n\n");
        }
#endif
    }

    return status;
}