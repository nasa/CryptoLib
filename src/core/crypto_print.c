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

#ifndef _crypto_print_c_
#define _crypto_print_c_

/*
** Includes
*/
#include "crypto_print.h"
#include "crypto_structs.h"

/**
 * @brief Function: Crypto_tcPrint
 * Prints the current TC in memory.
 * @param tc_frame: TC_t*
 **/
void Crypto_tcPrint(TC_t *tc_frame)
{
    printf("Current TC in memory is: \n");
    printf("\t Header\n");
    printf("\t\t tfvn   = 0x%01x \n", tc_frame->tc_header.tfvn);
    printf("\t\t bypass = 0x%01x \n", tc_frame->tc_header.bypass);
    printf("\t\t cc     = 0x%01x \n", tc_frame->tc_header.cc);
    printf("\t\t spare  = 0x%02x \n", tc_frame->tc_header.spare);
    printf("\t\t scid   = 0x%03x \n", tc_frame->tc_header.scid);
    printf("\t\t vcid   = 0x%02x \n", tc_frame->tc_header.vcid);
    printf("\t\t fl     = 0x%03x \n", tc_frame->tc_header.fl);
    printf("\t\t fsn    = 0x%02x \n", tc_frame->tc_header.fsn);
    printf("\t SDLS Header\n");
    printf("\t\t sh     = 0x%02x \n", tc_frame->tc_sec_header.sh);
    printf("\t\t spi    = 0x%04x \n", tc_frame->tc_sec_header.spi);
    printf("\t\t iv[0]  = 0x%02x \n", tc_frame->tc_sec_header.iv[0]);
    printf("\t Payload \n");
    printf("\t\t data[0]= 0x%02x \n", tc_frame->tc_pdu[0]);
    printf("\t\t data[1]= 0x%02x \n", tc_frame->tc_pdu[1]);
    printf("\t\t data[2]= 0x%02x \n", tc_frame->tc_pdu[2]);
    printf("\t SDLS Trailer\n");
    printf("\t\t FECF   = 0x%04x \n", tc_frame->tc_sec_trailer.fecf);
    printf("\n");
}

/**
 * @brief Function: Crypto_tmPrint
 * Prints the current TM in memory.
 * @param tm_frame: TM_t*
 **/
void Crypto_tmPrint(TM_t *tm_frame)
{
    printf("Current TM in memory is: \n");
    printf("\t Header\n");
    printf("\t\t tfvn   = %d \n", tm_frame->tm_header.tfvn);
    printf("\t\t scid   = %d \n", tm_frame->tm_header.scid);
    printf("\t\t vcid   = %d \n", tm_frame->tm_header.vcid);
    printf("\t\t ocff   = %d \n", tm_frame->tm_header.ocff);
    printf("\t\t mcfc   = %d \n", tm_frame->tm_header.mcfc);
    printf("\t\t vcfc   = %d \n", tm_frame->tm_header.vcfc);
    printf("\t\t sf     = %d \n", tm_frame->tm_header.sf);
    printf("\t\t pof    = %d \n", tm_frame->tm_header.pof);
    printf("\t\t slid   = %d \n", tm_frame->tm_header.slid);
    printf("\t\t fhp    = %d \n", tm_frame->tm_header.fhp);
    printf("\t SDLS Header\n");
    printf("\t\t spi    = %d \n", tm_frame->tm_sec_header.spi);
    printf("\t\t iv     = 0x");
    for (int i = 0; i < tm_frame->tm_sec_header.iv_field_len; i++)
    {
        printf("%02X", tm_frame->tm_sec_header.iv[i]);
    }
    printf("\n");
    printf("\t\t iv_len = %d \n", tm_frame->tm_sec_header.iv_field_len);
    printf("\t\t sn     = 0x");
    for (int i = 0; i < tm_frame->tm_sec_header.sn_field_len; i++)
    {
        printf("%02X", tm_frame->tm_sec_header.sn[i]);
    }
    printf("\n");
    printf("\t\t sn_len = %d \n", tm_frame->tm_sec_header.sn_field_len);
    printf("\t\t pad    = %d \n", tm_frame->tm_sec_header.pad);
    printf("\t\t pad_len= %d \n", tm_frame->tm_sec_header.pad_field_len);
    printf("\t Payload \n");
    printf("\t\t data[0]= 0x%02X \n", tm_frame->tm_pdu[0]);
    printf("\t\t data[1]= 0x%02X \n", tm_frame->tm_pdu[1]);
    printf("\t\t data[2]= 0x%02X \n", tm_frame->tm_pdu[2]);
    printf("\t SDLS Trailer\n");
    printf("\t\t MAC    = 0x");
    for (int i = 0; i < tm_frame->tm_sec_trailer.mac_field_len; i++)
    {
        printf("%02X", tm_frame->tm_sec_trailer.mac[i]);
    }
    printf("\n");
    printf("\t\t MAC_len= %d \n", tm_frame->tm_sec_trailer.mac_field_len);
    printf("\t\t OCF    = 0x");
    for (int i = 0; i < tm_frame->tm_sec_trailer.ocf_field_len; i++)
    {
        printf("%02X", tm_frame->tm_sec_trailer.ocf[i]);
    }
    printf("\n");
    printf("\t\t OCF_len= %d \n", tm_frame->tm_sec_trailer.ocf_field_len);
    printf("\t\t FECF   = 0x%04X \n", tm_frame->tm_sec_trailer.fecf);
    printf("\n");
}

/**
 * @brief Function: Crypto_aosPrint
 * Prints the current AOS in memory.
 * @param aos_frame: AOS_t*
 **/
void Crypto_aosPrint(AOS_t *aos_frame)
{
    printf("Current AOS in memory is: \n");
    printf("\t Header\n");
    printf("\t\t tfvn   = %d \n", aos_frame->aos_header.tfvn);
    printf("\t\t scid   = %d \n", aos_frame->aos_header.scid);
    printf("\t\t vcid   = %d \n", aos_frame->aos_header.vcid);
    printf("\t\t vcfc   = %d \n", aos_frame->aos_header.vcfc);
    printf("\t\t rf     = %d \n", aos_frame->aos_header.rf);
    printf("\t\t sf     = %d \n", aos_frame->aos_header.sf);
    printf("\t\t spare  = %d \n", aos_frame->aos_header.spare);
    printf("\t\t vfcc   = %d \n", aos_frame->aos_header.vfcc);
    printf("\t\t fhecf  = 0x%04X \n", aos_current_managed_parameters_struct.aos_has_fhec ? aos_frame->aos_header.fhecf : 0x0000);
    printf("\t SDLS Header\n");
    printf("\t\t iz[0]  = 0x%02X \n", aos_current_managed_parameters_struct.aos_has_iz ? aos_frame->aos_sec_header.iz[0] : 0x00);
    printf("\t\t iz     = 0x");
    for (int i = 0;
         (i < aos_current_managed_parameters_struct.aos_iz_len) && aos_current_managed_parameters_struct.aos_has_iz;
         i++)
    {
        printf("%02X", aos_frame->aos_sec_header.iz[i]);
    }
    printf("\n");
    printf("\t\t spi    = %d \n", aos_frame->aos_sec_header.spi);
    printf("\t\t iv     = 0x");
    for (int i = 0; i < aos_frame->aos_sec_header.iv_field_len; i++)
    {
        printf("%02X", aos_frame->aos_sec_header.iv[i]);
    }
    printf("\n");
    printf("\t\t iv_len = %d \n", aos_frame->aos_sec_header.iv_field_len);
    printf("\t\t sn     = 0x");
    for (int i = 0; i < aos_frame->aos_sec_header.sn_field_len; i++)
    {
        printf("%02X", aos_frame->aos_sec_header.sn[i]);
    }
    printf("\n");
    printf("\t\t sn_len = %d \n", aos_frame->aos_sec_header.sn_field_len);
    printf("\t\t pad    = %d \n", aos_frame->aos_sec_header.pad_field_len > 0 ? aos_frame->aos_sec_header.pad : 0);
    printf("\t\t pad_len= %d \n", aos_frame->aos_sec_header.pad_field_len);
    printf("\t Payload \n");
    printf("\t\t data[0]= 0x%02X \n", aos_frame->aos_pdu[0]);
    printf("\t\t data[1]= 0x%02X \n", aos_frame->aos_pdu[1]);
    printf("\t\t data[2]= 0x%02X \n", aos_frame->aos_pdu[2]);
    printf("\t SDLS Trailer\n");
    printf("\t\t MAC    = 0x");
    for (int i = 0; i < aos_frame->aos_sec_trailer.mac_field_len; i++)
    {
        printf("%02X", aos_frame->aos_sec_trailer.mac[i]);
    }
    printf("\n");
    printf("\t\t MAC_len= %d \n", aos_frame->aos_sec_trailer.mac_field_len);
    printf("\t\t OCF    = 0x");
    for (int i = 0; i < aos_frame->aos_sec_trailer.ocf_field_len; i++)
    {
        printf("%02X", aos_frame->aos_sec_trailer.ocf[i]);
    }
    printf("\n");
    printf("\t\t OCF_len= %d \n", aos_frame->aos_sec_trailer.ocf_field_len);
    printf("\t\t FECF   = 0x%04X \n", aos_frame->aos_sec_trailer.fecf);
    printf("\n");
}

void Crypto_Print_Sdls_Ep_Reply(void)
{
    // Length to be pulled from packet header
    uint16_t pkt_length = 0;

    pkt_length = ((sdls_ep_reply[4] << 8) | sdls_ep_reply[5]) + 1;

    // Sanity check on length
    if (pkt_length > TC_MAX_FRAME_SIZE)
    {
        printf(KRED "Unable to print SDLS Reply... invalid length of %d\n" RESET, pkt_length);
        return;
    }

    // Do the print
    printf("SDLS Reply Global: 0x");
    for (int i = 0; i < pkt_length; i++)
    {
        printf("%02X", sdls_ep_reply[i]);
    }
    printf("\n\n");

    return;
}

/**
 * @brief Function: Crypto_clcwPrint
 * Prints the current CLCW in memory.
 * @param clcw: Telemetry_Frame_Ocf_Clcw_t*
 **/
void Crypto_clcwPrint(Telemetry_Frame_Ocf_Clcw_t *clcw)
{
    printf("Current CLCW in memory is: \n");
    printf("\t cwt    = 0x%01x \n", clcw->cwt);
    printf("\t cvn    = 0x%01x \n", clcw->cvn);
    printf("\t sf     = 0x%01x \n", clcw->sf);
    printf("\t cie    = 0x%01x \n", clcw->cie);
    printf("\t vci    = 0x%02x \n", clcw->vci);
    printf("\t spare0 = 0x%01x \n", clcw->spare0);
    printf("\t nrfaf  = 0x%01x \n", clcw->nrfaf);
    printf("\t nblf   = 0x%01x \n", clcw->nblf);
    printf("\t lof    = 0x%01x \n", clcw->lof);
    printf("\t waitf  = 0x%01x \n", clcw->waitf);
    printf("\t rtf    = 0x%01x \n", clcw->rtf);
    printf("\t fbc    = 0x%01x \n", clcw->fbc);
    printf("\t spare1 = 0x%01x \n", clcw->spare1);
    printf("\t rv     = 0x%02x \n", clcw->rv);
    printf("\n");
}

/**
 * @brief Function: Crypto_fsrPrint
 * Prints the current FSR in memory.
 * @param report: Telemetry_Frame_Ocf_Fsr_t*
 **/
void Crypto_fsrPrint(Telemetry_Frame_Ocf_Fsr_t *report)
{
    printf("Current FSR in memory is: \n");
    printf("\t cwt    = 0x%01x \n", report->cwt);
    printf("\t fvn    = 0x%01x \n", report->fvn);
    printf("\t af     = 0x%01x \n", report->af);
    printf("\t bsnf   = 0x%01x \n", report->bsnf);
    printf("\t bmacf  = 0x%01x \n", report->bmacf);
    printf("\t bsaf   = 0x%01x \n", report->bsaf);
    printf("\t lspi   = 0x%01x \n", report->lspi);
    printf("\t snval  = 0x%01x \n", report->snval);
    printf("\n");
}

/**
 * @brief Function: Crypto_ccsdsPrint
 * Prints the current CCSDS in memory.
 * @param sdls_frame: CCSDS_t*
 **/
void Crypto_ccsdsPrint(CCSDS_t *sdls_frame)
{
    printf("Current CCSDS in memory is: \n");
    printf("\t Primary Header\n");
    printf("\t\t pvn        = 0x%01x \n", sdls_frame->hdr.pvn);
    printf("\t\t type       = 0x%01x \n", sdls_frame->hdr.type);
    printf("\t\t shdr       = 0x%01x \n", sdls_frame->hdr.shdr);
    printf("\t\t appID      = 0x%03x \n", sdls_frame->hdr.appID);
    printf("\t\t seq        = 0x%01x \n", sdls_frame->hdr.seq);
    printf("\t\t pktid      = 0x%04x \n", sdls_frame->hdr.pktid);
    printf("\t\t pkt_length = 0x%04x \n", sdls_frame->hdr.pkt_length);
    if (crypto_config_tc.has_pus_hdr == TC_HAS_PUS_HDR)
    {
        printf("\t PUS Header\n");
        printf("\t\t shf        = 0x%01x \n", sdls_frame->pus.shf);
        printf("\t\t pusv       = 0x%01x \n", sdls_frame->pus.pusv);
        printf("\t\t ack        = 0x%01x \n", sdls_frame->pus.ack);
        printf("\t\t st         = 0x%02x \n", sdls_frame->pus.st);
        printf("\t\t sst        = 0x%02x \n", sdls_frame->pus.sst);
        printf("\t\t sid        = 0x%01x \n", sdls_frame->pus.sid);
        printf("\t\t spare      = 0x%01x \n", sdls_frame->pus.spare);
    }
    else
    {
        printf("\t PUS Header\n");
        printf("\t\t Config not configured for PUS Header, not printing\n");
    }
    printf("\t TLV PDU \n");
    printf("\t\t type       = 0x%01x \n", sdls_frame->tlv_pdu.hdr.type);
    printf("\t\t uf         = 0x%01x \n", sdls_frame->tlv_pdu.hdr.uf);
    printf("\t\t sg         = 0x%01x \n", sdls_frame->tlv_pdu.hdr.sg);
    printf("\t\t pid        = 0x%01x \n", sdls_frame->tlv_pdu.hdr.pid);
    printf("\t\t pdu_len    = 0x%04x \n", sdls_frame->tlv_pdu.hdr.pdu_len);
    printf("\t\t data[0]    = 0x%02x \n", sdls_frame->tlv_pdu.data[0]);
    printf("\t\t data[1]    = 0x%02x \n", sdls_frame->tlv_pdu.data[1]);
    printf("\t\t data[2]    = 0x%02x \n", sdls_frame->tlv_pdu.data[2]);
    printf("\n");
}

/**
 * @brief Function: Crypto_saPrint
 * Prints the current Security Association in memory.
 * @param sa: SecurityAssociation_t*
 **/
void Crypto_saPrint(SecurityAssociation_t *sa)
{
    int i;

    printf("SA status: \n");
    printf("\t spi   = %d \n", sa->spi);
    printf("\t sa_state   = 0x%01x \n", sa->sa_state);
    printf("\t est        = 0x%01x \n", sa->est);
    printf("\t ast        = 0x%01x \n", sa->ast);
    printf("\t shivf_len  = %d \n", sa->shivf_len);
    printf("\t shsnf_len  = %d \n", sa->shsnf_len);
    printf("\t shplf_len  = %d \n", sa->shplf_len);
    printf("\t stmacf_len = %d \n", sa->stmacf_len);
    printf("\t ecs_len    = %d \n", sa->ecs_len);
    if (sa->ecs_len > 0)
    {
        for (i = 0; i < sa->ecs_len; i++)
        {
            printf("\t ecs[%d]     = 0x%02x \n", i, (sa->ecs + i));
        }
    }
    printf("\t ekid       = %d \n", sa->ekid);
    printf("\t ek_ref     = %s \n", sa->ek_ref);
    printf("\t akid       = %d \n", sa->akid);
    printf("\t ak_ref     = %s \n", sa->ak_ref);
    printf("\t iv_len     = %d \n", sa->iv_len);
    if (sa->iv_len > 0)
    {
        for (i = 0; i < sa->iv_len; i++)
        {
            printf("\t iv[%d]      = 0x%02x \n", i, *(sa->iv + i));
        }
    }
    else
    {
        printf("\t iv        = %s \n", sa->iv);
    }
    printf("\t acs_len    = %d \n", sa->acs_len);
    printf("\t acs        = 0x%02x \n", sa->acs);
    printf("\t abm_len    = %d \n", sa->abm_len);
    if (sa->abm_len > 0)
    {
        printf("\t abm        = ");
        for (i = 0; i < sa->abm_len; i++)
        {
            printf("%02x", *(sa->abm + i));
        }
        printf("\n");
    }
    printf("\t arsn_len    = %d \n", sa->arsn_len);
    if (sa->arsn_len > 0)
    {
        printf("\t arsn        = ");
        for (i = 0; i < sa->arsn_len; i++)
        {
            printf("%02x", *(sa->arsn + i));
        }
        printf("\n");
    }

    printf("\t arsnw_len   = %d \n", sa->arsnw_len);
    printf("\t arsnw       = %d \n", sa->arsnw);
}

/**
 * @brief Function: Crypto_hexPrint
 * Prints the array of hex characters.
 * @param c: void*, The hex to be printed.
 * @param n: size_t, The size of the array to be printed.
 **/
void Crypto_hexprint(const void *c, size_t n)
{
    const uint8_t *t   = c;
    size_t         idx = 0;
    if (c == NULL)
        return;
    while (idx < n)
    {
        printf("%02x", t[idx]);
        idx++;
    }
    printf("\n");
}

/**
 * @brief Function: Crypto_binprint
 * Prints the array of binary data.
 * @param c: void*, The binary array to be printed.
 * @param n: size_t, The size of the array to be printed.
 **/
void Crypto_binprint(void *c, size_t n)
{
    uint8_t *t = c;
    int      q;

    if (c == NULL)
        return;
    while (n > 0)
    {
        --n;
        for (q = 0x80; q; q >>= 1)
            printf("%x", !!(t[n] & q));
    }
    printf("\n");
}

#endif