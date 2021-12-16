/* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory, including, but not
   limited to, any warranty that the software will conform to specifications, any implied warranties of merchantability, fitness
   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
   any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
   arising out of, resulting from, or in any way connected with the software or its documentation, whether or not based upon warranty,
   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
   documentation or services provided hereunder.

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
void Crypto_tcPrint(TC_t* tc_frame)
{
    OS_printf("Current TC in memory is: \n");
    OS_printf("\t Header\n");
    OS_printf("\t\t tfvn   = 0x%01x \n", tc_frame->tc_header.tfvn);
    OS_printf("\t\t bypass = 0x%01x \n", tc_frame->tc_header.bypass);
    OS_printf("\t\t cc     = 0x%01x \n", tc_frame->tc_header.cc);
    OS_printf("\t\t spare  = 0x%02x \n", tc_frame->tc_header.spare);
    OS_printf("\t\t scid   = 0x%03x \n", tc_frame->tc_header.scid);
    OS_printf("\t\t vcid   = 0x%02x \n", tc_frame->tc_header.vcid);
    OS_printf("\t\t fl     = 0x%03x \n", tc_frame->tc_header.fl);
    OS_printf("\t\t fsn    = 0x%02x \n", tc_frame->tc_header.fsn);
    OS_printf("\t SDLS Header\n");
    OS_printf("\t\t sh     = 0x%02x \n", tc_frame->tc_sec_header.sh);
    OS_printf("\t\t spi    = 0x%04x \n", tc_frame->tc_sec_header.spi);
    OS_printf("\t\t iv[0]  = 0x%02x \n", tc_frame->tc_sec_header.iv[0]);
    OS_printf("\t Payload \n");
    OS_printf("\t\t data[0]= 0x%02x \n", tc_frame->tc_pdu[0]);
    OS_printf("\t\t data[1]= 0x%02x \n", tc_frame->tc_pdu[1]);
    OS_printf("\t\t data[2]= 0x%02x \n", tc_frame->tc_pdu[2]);
    OS_printf("\t SDLS Trailer\n");
    OS_printf("\t\t FECF   = 0x%04x \n", tc_frame->tc_sec_trailer.fecf);
    OS_printf("\n");
}

/**
 * @brief Function: Crypto_tmPrint
 * Prints the current TM in memory.
 * @param tm_frame: TM_t*
 **/
void Crypto_tmPrint(TM_t* tm_frame)
{
    OS_printf("Current TM in memory is: \n");
    OS_printf("\t Header\n");
    OS_printf("\t\t tfvn   = 0x%01x \n", tm_frame->tm_header.tfvn);
    OS_printf("\t\t scid   = 0x%02x \n", tm_frame->tm_header.scid);
    OS_printf("\t\t vcid   = 0x%01x \n", tm_frame->tm_header.vcid);
    OS_printf("\t\t ocff   = 0x%01x \n", tm_frame->tm_header.ocff);
    OS_printf("\t\t mcfc   = 0x%02x \n", tm_frame->tm_header.mcfc);
    OS_printf("\t\t vcfc   = 0x%02x \n", tm_frame->tm_header.vcfc);
    OS_printf("\t\t tfsh   = 0x%01x \n", tm_frame->tm_header.tfsh);
    OS_printf("\t\t sf     = 0x%01x \n", tm_frame->tm_header.sf);
    OS_printf("\t\t pof    = 0x%01x \n", tm_frame->tm_header.pof);
    OS_printf("\t\t slid   = 0x%01x \n", tm_frame->tm_header.slid);
    OS_printf("\t\t fhp    = 0x%03x \n", tm_frame->tm_header.fhp);
    //OS_printf("\t\t tfshvn = 0x%01x \n", tm_frame.tm_header.tfshvn);
    //OS_printf("\t\t tfshlen= 0x%02x \n", tm_frame.tm_header.tfshlen);
    OS_printf("\t SDLS Header\n");
    OS_printf("\t\t spi    = 0x%04x \n", tm_frame->tm_sec_header.spi);
    OS_printf("\t\t iv[%d]  = 0x%02x \n", (IV_SIZE - 1), tm_frame->tm_sec_header.iv[IV_SIZE - 1]);
    OS_printf("\t Payload \n");
    OS_printf("\t\t data[0]= 0x%02x \n", tm_frame->tm_pdu[0]);
    OS_printf("\t\t data[1]= 0x%02x \n", tm_frame->tm_pdu[1]);
    OS_printf("\t\t data[2]= 0x%02x \n", tm_frame->tm_pdu[2]);
    OS_printf("\t\t data[3]= 0x%02x \n", tm_frame->tm_pdu[3]);
    OS_printf("\t\t data[4]= 0x%02x \n", tm_frame->tm_pdu[4]);
    OS_printf("\t SDLS Trailer\n");
    OS_printf("\t\t OCF[0] = 0x%02x \n", tm_frame->tm_sec_trailer.ocf[0]);
    OS_printf("\t\t OCF[1] = 0x%02x \n", tm_frame->tm_sec_trailer.ocf[1]);
    OS_printf("\t\t OCF[2] = 0x%02x \n", tm_frame->tm_sec_trailer.ocf[2]);
    OS_printf("\t\t OCF[3] = 0x%02x \n", tm_frame->tm_sec_trailer.ocf[3]);
    OS_printf("\t\t FECF   = 0x%02x \n", tm_frame->tm_sec_trailer.fecf);
    OS_printf("\n");
}

/**
 * @brief Function: Crypto_clcwPrint
 * Prints the current CLCW in memory.
 * @param clcw: TM_FrameCLCW_t*
 **/
void Crypto_clcwPrint(TM_FrameCLCW_t* clcw)
{
    OS_printf("Current CLCW in memory is: \n");
    OS_printf("\t cwt    = 0x%01x \n", clcw->cwt);
    OS_printf("\t cvn    = 0x%01x \n", clcw->cvn);
    OS_printf("\t sf     = 0x%01x \n", clcw->sf);
    OS_printf("\t cie    = 0x%01x \n", clcw->cie);
    OS_printf("\t vci    = 0x%02x \n", clcw->vci);
    OS_printf("\t spare0 = 0x%01x \n", clcw->spare0);
    OS_printf("\t nrfa   = 0x%01x \n", clcw->nrfa);
    OS_printf("\t nbl    = 0x%01x \n", clcw->nbl);
    OS_printf("\t lo     = 0x%01x \n", clcw->lo);
    OS_printf("\t wait   = 0x%01x \n", clcw->wait);
    OS_printf("\t rt     = 0x%01x \n", clcw->rt);
    OS_printf("\t fbc    = 0x%01x \n", clcw->fbc);
    OS_printf("\t spare1 = 0x%01x \n", clcw->spare1);
    OS_printf("\t rv     = 0x%02x \n", clcw->rv);
    OS_printf("\n");
}

/**
 * @brief Function: Crypto_fsrPrint
 * Prints the current FSR in memory.
 * @param report: SDLS_FSR_t*
 **/
void Crypto_fsrPrint(SDLS_FSR_t* report)
{
    OS_printf("Current FSR in memory is: \n");
    OS_printf("\t cwt    = 0x%01x \n", report->cwt);
    OS_printf("\t vnum   = 0x%01x \n", report->vnum);
    OS_printf("\t af     = 0x%01x \n", report->af);
    OS_printf("\t bsnf   = 0x%01x \n", report->bsnf);
    OS_printf("\t bmacf  = 0x%01x \n", report->bmacf);
    OS_printf("\t ispif  = 0x%01x \n", report->ispif);
    OS_printf("\t lspiu  = 0x%01x \n", report->lspiu);
    OS_printf("\t snval  = 0x%01x \n", report->snval);
    OS_printf("\n");
}

/**
 * @brief Function: Crypto_ccsdsPrint
 * Prints the current CCSDS in memory.
 * @param sdls_frame: CCSDS_t*
 **/
void Crypto_ccsdsPrint(CCSDS_t* sdls_frame)
{
    OS_printf("Current CCSDS in memory is: \n");
    OS_printf("\t Primary Header\n");
    OS_printf("\t\t pvn        = 0x%01x \n", sdls_frame->hdr.pvn);
    OS_printf("\t\t type       = 0x%01x \n", sdls_frame->hdr.type);
    OS_printf("\t\t shdr       = 0x%01x \n", sdls_frame->hdr.shdr);
    OS_printf("\t\t appID      = 0x%03x \n", sdls_frame->hdr.appID);
    OS_printf("\t\t seq        = 0x%01x \n", sdls_frame->hdr.seq);
    OS_printf("\t\t pktid      = 0x%04x \n", sdls_frame->hdr.pktid);
    OS_printf("\t\t pkt_length = 0x%04x \n", sdls_frame->hdr.pkt_length);
    OS_printf("\t PUS Header\n");
    OS_printf("\t\t shf        = 0x%01x \n", sdls_frame->pus.shf);
    OS_printf("\t\t pusv       = 0x%01x \n", sdls_frame->pus.pusv);
    OS_printf("\t\t ack        = 0x%01x \n", sdls_frame->pus.ack);
    OS_printf("\t\t st         = 0x%02x \n", sdls_frame->pus.st);
    OS_printf("\t\t sst        = 0x%02x \n", sdls_frame->pus.sst);
    OS_printf("\t\t sid        = 0x%01x \n", sdls_frame->pus.sid);
    OS_printf("\t\t spare      = 0x%01x \n", sdls_frame->pus.spare);
    OS_printf("\t PDU \n");
    OS_printf("\t\t type       = 0x%01x \n", sdls_frame->pdu.type);
    OS_printf("\t\t uf         = 0x%01x \n", sdls_frame->pdu.uf);
    OS_printf("\t\t sg         = 0x%01x \n", sdls_frame->pdu.sg);
    OS_printf("\t\t pid        = 0x%01x \n", sdls_frame->pdu.pid);
    OS_printf("\t\t pdu_len    = 0x%04x \n", sdls_frame->pdu.pdu_len);
    OS_printf("\t\t data[0]    = 0x%02x \n", sdls_frame->pdu.data[0]);
    OS_printf("\t\t data[1]    = 0x%02x \n", sdls_frame->pdu.data[1]);
    OS_printf("\t\t data[2]    = 0x%02x \n", sdls_frame->pdu.data[2]);
    OS_printf("\n");
}

/**
 * @brief Function: Crypto_saPrint
 * Prints the current Security Association in memory.
 * @param sa: SecurityAssociation_t*
 **/
void Crypto_saPrint(SecurityAssociation_t* sa)
{
    OS_printf("SA status: \n");
    OS_printf("\t spi   = 0x%01x \n", sa->spi);
    OS_printf("\t sa_state   = 0x%01x \n", sa->sa_state);
    //OS_printf("\t gvcid[0]   = 0x%02x \n", sa->gvcid_blk[spi].gvcid[0]);
    //OS_printf("\t gvcid[1]   = 0x%02x \n", sa->gvcid_blk[spi].gvcid[1]);
    //OS_printf("\t gvcid[2]   = 0x%02x \n", sa->gvcid_blk[spi].gvcid[2]);
    //OS_printf("\t gvcid[3]   = 0x%02x \n", sa->gvcid_blk[spi].gvcid[3]);
    OS_printf("\t est        = 0x%01x \n", sa->est);
    OS_printf("\t ast        = 0x%01x \n", sa->ast);
    OS_printf("\t shivf_len  = 0x%02x \n", sa->shivf_len);
    OS_printf("\t shsnf_len  = 0x%02x \n", sa->shsnf_len);
    OS_printf("\t shplf_len  = 0x%01x \n", sa->shplf_len);
    OS_printf("\t stmacf_len = 0x%02x \n", sa->stmacf_len);
    OS_printf("\t ecs_len    = 0x%02x \n", sa->ecs_len);
    OS_printf("\t ecs[%d]    = 0x%02x \n", ECS_SIZE-4, sa->ecs[ECS_SIZE - 4]);
    OS_printf("\t ecs[%d]    = 0x%02x \n", ECS_SIZE-3, sa->ecs[ECS_SIZE - 3]);
    OS_printf("\t ecs[%d]    = 0x%02x \n", ECS_SIZE-2, sa->ecs[ECS_SIZE - 2]);
    OS_printf("\t ecs[%d]    = 0x%02x \n", ECS_SIZE-1, sa->ecs[ECS_SIZE - 1]);
    OS_printf("\t iv_len     = 0x%02x \n", sa->shivf_len);
    if(sa->iv != NULL)
    {
        for(int i = 0; i < sa->shivf_len; i++)
        {
            OS_printf("\t iv[%d]     = 0x%02x \n", i, *(sa->iv + i));
        }
    }
    OS_printf("\t acs_len    = 0x%02x \n", sa->acs_len);
    OS_printf("\t acs        = 0x%02x \n", sa->acs);
    OS_printf("\t abm_len    = 0x%04x \n", sa->abm_len);
    if(sa->abm != NULL)
    {
        OS_printf("\t abm: \n");
        for(int i = 0; i < sa->abm_len; i++)
        {
            OS_printf("%02x", *(sa->abm + i));
        }
        OS_printf("\n");
    }
    OS_printf("\t arc_len    = 0x%02x \n", sa->arc_len);
    if(sa->arc != NULL)
    {
        OS_printf("\t arc: \n");
        for(int i = 0; i < sa->arc_len; i++)
        {
            OS_printf("%02x", *(sa->arc + i));
        }
        OS_printf("\n");
    }

    OS_printf("\t arcw_len   = 0x%02x \n", sa->arcw_len);
    OS_printf("\t arcw       = 0x%d \n", sa->arcw);
}

/**
 * @brief Function: Crypto_hexPrint
 * Prints the array of hex characters.
 * @param c: void*, The hex to be printed.
 * @param n: size_t, The size of the array to be printed.
 **/
void Crypto_hexprint(void *c, size_t n)
{
    unsigned char *t = c;
    if (c == NULL)
        return;
    while (n > 0) {
        --n;
        printf("%02x", t[n]);
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
    unsigned char *t = c;
    if (c == NULL)
        return;
    while (n > 0) {
        int q;
        --n;
        for(q = 0x80; q; q >>= 1)
            printf("%x", !!(t[n] & q));
    }
    printf("\n");
}

void Crypto_mpPrint(GvcidManagedParameters_t* managed_parameters, uint8 print_children)
//Prints the currently configured Managed Parameters
{
    if(managed_parameters != NULL){
        OS_printf("Managed Parameter: \n");
        OS_printf("\t tfvn: %d", managed_parameters->tfvn);
        OS_printf("\t scid: %d", managed_parameters->scid);
        OS_printf("\t vcid: %d", managed_parameters->vcid);
        OS_printf("\t has_fecf: %d", managed_parameters->has_fecf);
        OS_printf("\t has_segmentation_headers: %d\n", managed_parameters->has_segmentation_hdr);
    }
    if(managed_parameters->next!=NULL && print_children!=0){
        Crypto_mpPrint(managed_parameters->next,print_children);
    }
}
#endif