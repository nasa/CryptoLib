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

#include "crypto_config.h"
#include "crypto_error.h"
#include "crypto_print.h"
#include "crypto_structs.h"
#include "sadb_routine.h"

#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Security Association Initialization Functions
static int32_t sadb_config(void);
static int32_t sadb_init(void);
static int32_t sadb_close(void);
// Security Association Interaction Functions
static int32_t sadb_get_sa_from_spi(uint16_t, SecurityAssociation_t**);
static int32_t sadb_get_operational_sa_from_gvcid(uint8_t, uint16_t, uint16_t, uint8_t, SecurityAssociation_t**);
static int32_t sadb_save_sa(SecurityAssociation_t* sa);
// Security Association Utility Functions
static int32_t sadb_sa_stop(void);
static int32_t sadb_sa_start(TC_t* tc_frame);
static int32_t sadb_sa_expire(void);
static int32_t sadb_sa_rekey(void);
static int32_t sadb_sa_status(uint8_t* );
static int32_t sadb_sa_create(void);
static int32_t sadb_sa_setARSN(void);
static int32_t sadb_sa_setARSNW(void);
static int32_t sadb_sa_delete(void);
// MySQL local functions
static int32_t finish_with_error(MYSQL **con_loc, int err);
// MySQL Queries
static const char* SQL_SADB_GET_SA_BY_SPI =
        "SELECT "
        "spi,ekid,akid,sa_state,tfvn,scid,vcid,mapid,lpid,est,ast,shivf_len,shsnf_len,shplf_len,stmacf_len,ecs_len,HEX(ecs)"
        ",HEX(iv),iv_len,acs_len,HEX(acs),abm_len,HEX(abm),arsn_len,HEX(arsn),arsnw"
        " FROM security_associations WHERE spi='%d'";
static const char* SQL_SADB_GET_SA_BY_GVCID =
        "SELECT "
        "spi,ekid,akid,sa_state,tfvn,scid,vcid,mapid,lpid,est,ast,shivf_len,shsnf_len,shplf_len,stmacf_len,ecs_len,HEX(ecs)"
        ",HEX(iv),iv_len,acs_len,HEX(acs),abm_len,HEX(abm),arsn_len,HEX(arsn),arsnw"
        " FROM security_associations WHERE tfvn='%d' AND scid='%d' AND vcid='%d' AND mapid='%d' AND sa_state='%d'";
static const char* SQL_SADB_UPDATE_IV_ARC_BY_SPI =
        "UPDATE security_associations"
        " SET iv=X'%s', arsn=X'%s'"
        " WHERE spi='%d' AND tfvn='%d' AND scid='%d' AND vcid='%d' AND mapid='%d'";

// sadb_routine mariaDB private helper functions
static int32_t parse_sa_from_mysql_query(char* query, SecurityAssociation_t** security_association);
static int32_t convert_hexstring_to_byte_array(char* hexstr, uint8_t* byte_array);
static char* convert_byte_array_to_hexstring(void* src_buffer, size_t buffer_length);

/*
** Global Variables
*/
// Security
static SadbRoutineStruct sadb_routine_struct;
static MYSQL *con;

SadbRoutine get_sadb_routine_mariadb(void)
{
    sadb_routine_struct.sadb_config = sadb_config;
    sadb_routine_struct.sadb_init = sadb_init;
    sadb_routine_struct.sadb_close = sadb_close;
    sadb_routine_struct.sadb_get_sa_from_spi = sadb_get_sa_from_spi;
    sadb_routine_struct.sadb_get_operational_sa_from_gvcid = sadb_get_operational_sa_from_gvcid;
    sadb_routine_struct.sadb_sa_stop = sadb_sa_stop;
    sadb_routine_struct.sadb_save_sa = sadb_save_sa;
    sadb_routine_struct.sadb_sa_start = sadb_sa_start;
    sadb_routine_struct.sadb_sa_expire = sadb_sa_expire;
    sadb_routine_struct.sadb_sa_rekey = sadb_sa_rekey;
    sadb_routine_struct.sadb_sa_status = sadb_sa_status;
    sadb_routine_struct.sadb_sa_create = sadb_sa_create;
    sadb_routine_struct.sadb_sa_setARSN = sadb_sa_setARSN;
    sadb_routine_struct.sadb_sa_setARSNW = sadb_sa_setARSNW;
    sadb_routine_struct.sadb_sa_delete = sadb_sa_delete;
    return &sadb_routine_struct;
}

static int32_t sadb_config(void)
{
    return CRYPTO_LIB_SUCCESS;
}

static int32_t sadb_init(void)
{
    int32_t status = CRYPTO_LIB_ERROR;
    if (sadb_mariadb_config != NULL)
    {
        con = mysql_init(con);
        if (con != NULL)
        {
            //mysql_options is removed in MariaDB C connector v3, using mysql_optionsv
            // Lots of small configuration differences between MySQL connector & MariaDB Connector
            // Only MariaDB Connector is implemented here:
            // https://wikidev.in/wiki/C/mysql_mysql_h/mysql_options | https://mariadb.com/kb/en/mysql_optionsv/
            if(sadb_mariadb_config->mysql_mtls_key != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_KEY, sadb_mariadb_config->mysql_mtls_key);
            }
            if(sadb_mariadb_config->mysql_mtls_cert != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_CERT, sadb_mariadb_config->mysql_mtls_cert);
            }
            if(sadb_mariadb_config->mysql_mtls_ca != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_CA, sadb_mariadb_config->mysql_mtls_ca);
            }
            if(sadb_mariadb_config->mysql_mtls_capath != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_CAPATH, sadb_mariadb_config->mysql_mtls_capath);
            }
            if (sadb_mariadb_config->mysql_tls_verify_server != CRYPTO_FALSE)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &(sadb_mariadb_config->mysql_tls_verify_server));
            }
            if (sadb_mariadb_config->mysql_mtls_client_key_password != NULL)
            {
                mysql_optionsv(con, MARIADB_OPT_TLS_PASSPHRASE, sadb_mariadb_config->mysql_mtls_client_key_password);
            }
            if (sadb_mariadb_config->mysql_require_secure_transport == CRYPTO_TRUE)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_ENFORCE,&(sadb_mariadb_config->mysql_require_secure_transport));
            }
            //if encrypted connection (TLS) connection. No need for SSL Key
            if (mysql_real_connect(con, sadb_mariadb_config->mysql_hostname,
                    sadb_mariadb_config->mysql_username,
                    sadb_mariadb_config->mysql_password,
                    sadb_mariadb_config->mysql_database,
                    sadb_mariadb_config->mysql_port, NULL, 0) == NULL)
            {
                //0,NULL,0 are port number, unix socket, client flag
                finish_with_error(&con, SADB_MARIADB_CONNECTION_FAILED);
                status = CRYPTO_LIB_ERROR;
            } else {
                status = CRYPTO_LIB_SUCCESS;
                if (status == CRYPTO_LIB_SUCCESS) {
#ifdef DEBUG
                    printf("sadb_init created mysql connection successfully. \n");
#endif
                }
            }
        }
        else
        {
            //error
            fprintf(stderr, "Error: sadb_init() MySQL API function mysql_init() returned a connection object that is NULL\n");
        }

    }
    return status;
}//end int32_t sadb_init()

static int32_t sadb_close(void)
{
    if(con)
    {
        mysql_close(con);
        con = NULL;
    }
    return CRYPTO_LIB_SUCCESS;
}

// Security Association Interaction Functions
static int32_t sadb_get_sa_from_spi(uint16_t spi, SecurityAssociation_t** security_association)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    char spi_query[2048];
    snprintf(spi_query, sizeof(spi_query), SQL_SADB_GET_SA_BY_SPI, spi);

    status = parse_sa_from_mysql_query(&spi_query[0], security_association);

    return status;
}
static int32_t sadb_get_operational_sa_from_gvcid(uint8_t tfvn, uint16_t scid, uint16_t vcid, uint8_t mapid,
                                                  SecurityAssociation_t** security_association)
{
    int32_t status = CRYPTO_LIB_SUCCESS;

    char gvcid_query[2048];
    snprintf(gvcid_query, sizeof(gvcid_query), SQL_SADB_GET_SA_BY_GVCID, tfvn, scid, vcid, mapid, SA_OPERATIONAL);

    status = parse_sa_from_mysql_query(&gvcid_query[0], security_association);

    return status;
}
static int32_t sadb_save_sa(SecurityAssociation_t* sa)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if (sa == NULL)
    {
        return SADB_NULL_SA_USED;
    }

    char update_sa_query[2048];
    snprintf(update_sa_query, sizeof(update_sa_query), SQL_SADB_UPDATE_IV_ARC_BY_SPI,
             convert_byte_array_to_hexstring(sa->iv, sa->iv_len),
             convert_byte_array_to_hexstring(sa->arsn, sa->arsn_len), sa->spi, sa->gvcid_tc_blk.tfvn,
             sa->gvcid_tc_blk.scid, sa->gvcid_tc_blk.vcid, sa->gvcid_tc_blk.mapid);

#ifdef SA_DEBUG
    fprintf(stderr, "MySQL Insert SA Query: %s \n", update_sa_query);
#endif

    // Crypto_saPrint(sa);
    if (mysql_query(con, update_sa_query))
    {
        status = finish_with_error(&con, SADB_QUERY_FAILED);
        return status;
    }
    // todo - if query fails, need to push failure message to error stack instead of just return code.

    // We free the allocated SA memory in the save function.
    if (sa->iv != NULL)
        free(sa->iv);
    if (sa->abm != NULL)
        free(sa->abm);
    if (sa->arsn != NULL)
        free(sa->arsn);
    free(sa);
    return status;
}
// Security Association Utility Functions
static int32_t sadb_sa_stop(void)
{
    return CRYPTO_LIB_SUCCESS;
}
static int32_t sadb_sa_start(TC_t* tc_frame)
{
    tc_frame = tc_frame;
    return CRYPTO_LIB_SUCCESS;
}
static int32_t sadb_sa_expire(void)
{
    return CRYPTO_LIB_SUCCESS;
}
static int32_t sadb_sa_rekey(void)
{
    return CRYPTO_LIB_SUCCESS;
}
static int32_t sadb_sa_status(uint8_t* ingest)
{
    ingest = ingest;
    return CRYPTO_LIB_SUCCESS;
}
static int32_t sadb_sa_create(void)
{
    return CRYPTO_LIB_SUCCESS;
}
static int32_t sadb_sa_setARSN(void)
{
    return CRYPTO_LIB_SUCCESS;
}
static int32_t sadb_sa_setARSNW(void)
{
    return CRYPTO_LIB_SUCCESS;
}
static int32_t sadb_sa_delete(void)
{
    return CRYPTO_LIB_SUCCESS;
}

// sadb_routine private helper functions
static int32_t parse_sa_from_mysql_query(char* query, SecurityAssociation_t** security_association)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    SecurityAssociation_t* sa = calloc(1,sizeof(SecurityAssociation_t));

#ifdef SA_DEBUG
    fprintf(stderr, "MySQL Query: %s \n", query);
#endif

    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        status = finish_with_error(&con, SADB_QUERY_FAILED);
        return status;
    }
    // todo - if query fails, need to push failure message to error stack instead of just return code.

    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL)
    {
        status = finish_with_error(&con, SADB_QUERY_EMPTY_RESULTS);
        return status;
    }

    int num_rows = mysql_num_rows(result);
    if(num_rows == 0) // No rows returned in query!!
    {
        status = finish_with_error(&con, SADB_QUERY_EMPTY_RESULTS);
        return status;
    }

    int num_fields = mysql_num_fields(result);

    MYSQL_ROW row;
    MYSQL_FIELD *field;

    char* field_names[num_fields]; //[64]; 64 == max length of column name in MySQL

    // TODO -- Need to store mysql query hex string and then malloc sa->iv according to size.
    // TODO -- IV && arsn && abm as uint8_t* instead of uint8[]!!!
    char* iv_byte_str;
    char* arc_byte_str;
    char* abm_byte_str;
    char* ecs_byte_str;
    char* acs_byte_str;
    while ((row = mysql_fetch_row(result)))
    {
        for (int i = 0; i < num_fields; i++)
        {
            // Parse out all the field names.
            if (i == 0)
            {
                int field_idx = 0;
                while ((field = mysql_fetch_field(result)))
                {
                    field_names[field_idx] = field->name;
                    field_idx++;
                }
            }
            // Handle query results
            if (row[i] == NULL)
            {
                continue;
            } // Don't do anything with NULL fields from MySQL query.
            if (strcmp(field_names[i], "spi") == 0)
            {
                sa->spi = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "ekid") == 0)
            {
                if(crypto_config->cryptography_type==CRYPTOGRAPHY_TYPE_LIBGCRYPT)
                {
                    sa->ekid = atoi(row[i]);
                } else // Cryptography Type KMC Crypto Service with PKCS12 String Key References
                {
                    sa->ek_ref = row[i];
                }
                continue;
            }
            if (strcmp(field_names[i], "akid") == 0)
            {
                if(crypto_config->cryptography_type==CRYPTOGRAPHY_TYPE_LIBGCRYPT)
                {
                    sa->akid = atoi(row[i]);
                } else // Cryptography Type KMC Crypto Service with PKCS12 String Key References
                {
                    sa->ak_ref = row[i];
                }
                continue;
            }
            if (strcmp(field_names[i], "sa_state") == 0)
            {
                sa->sa_state = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "tfvn") == 0)
            {
                sa->gvcid_tc_blk.tfvn = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "scid") == 0)
            {
                sa->gvcid_tc_blk.scid = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "vcid") == 0)
            {
                sa->gvcid_tc_blk.vcid = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "mapid") == 0)
            {
                sa->gvcid_tc_blk.mapid = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "lpid") == 0)
            {
                sa->lpid = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "est") == 0)
            {
                sa->est = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "ast") == 0)
            {
                sa->ast = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "shivf_len") == 0)
            {
                sa->shivf_len = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "iv_len") == 0)
            {
                sa->iv_len = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "shsnf_len") == 0)
            {
                sa->shsnf_len = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "shplf_len") == 0)
            {
                sa->shplf_len = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "stmacf_len") == 0)
            {
                sa->stmacf_len = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "ecs_len") == 0)
            {
                sa->ecs_len = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "HEX(ecs)") == 0)
            {
                ecs_byte_str = row[i];
                continue;
            }
            // if(strcmp(field_names[i],"HEX(iv)")==0){memcpy(&(sa->iv),&row[i],IV_SIZE);continue;}
            if (strcmp(field_names[i], "HEX(iv)") == 0)
            {
                iv_byte_str = row[i];
                continue;
            }
            if (strcmp(field_names[i], "acs_len") == 0)
            {
                sa->acs_len = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "HEX(acs)") == 0)
            {
                acs_byte_str = row[i];
                continue;
            }
            if (strcmp(field_names[i], "abm_len") == 0)
            {
                sa->abm_len = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "HEX(abm)") == 0)
            {
                abm_byte_str = row[i];
                continue;
            }
            // if(strcmp(field_names[i],"HEX(abm)")==0){convert_hexstring_to_byte_array(row[i],sa->abm);continue;}
            if (strcmp(field_names[i], "arsn_len") == 0)
            {
                sa->arsn_len = atoi(row[i]);
                continue;
            }
            if (strcmp(field_names[i], "HEX(arsn)") == 0)
            {
                arc_byte_str = row[i];
                continue;
            }
            // if(strcmp(field_names[i],"HEX(arsn)")==0){convert_hexstring_to_byte_array(row[i],sa->arsn);continue;}
            if (strcmp(field_names[i], "arsnw") == 0)
            {
                sa->arsnw = atoi(row[i]);
                continue;
            }
            // printf("%s:%s ",field_names[i], row[i] ? row[i] : "NULL");
        }
        // printf("\n");
    }
    sa->iv = (uint8_t* )calloc(1, sa->iv_len * sizeof(uint8_t));
    sa->arsn = (uint8_t* )calloc(1, sa->arsn_len * sizeof(uint8_t));
    sa->abm = (uint8_t* )calloc(1, sa->abm_len * sizeof(uint8_t));
    sa->ecs = (uint8_t* )calloc(1, sa->ecs_len * sizeof(uint8_t));
    sa->acs = (uint8_t* )calloc(1, sa->acs_len * sizeof(uint8_t));
    convert_hexstring_to_byte_array(iv_byte_str, sa->iv);
    convert_hexstring_to_byte_array(arc_byte_str, sa->arsn);
    convert_hexstring_to_byte_array(abm_byte_str, sa->abm);
    convert_hexstring_to_byte_array(ecs_byte_str, sa->ecs);
    convert_hexstring_to_byte_array(acs_byte_str, sa->acs);

    //arsnw_len is not necessary for mariadb interface, putty dummy/default value for prints.
    sa->arsnw_len = 1;

#ifdef DEBUG
    printf("Parsed SA from SQL Query:\n");
    Crypto_saPrint(sa);
#endif

    *security_association = sa;
    mysql_free_result(result);

    return status;
}
static int32_t convert_hexstring_to_byte_array(char* source_str, uint8_t* dest_buffer)
{ // https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c/56247335#56247335
    char* line = source_str;
    char* data = line;
    int offset;
    unsigned int read_byte;
    uint32_t data_len = 0;

    while (sscanf(data, " %02x%n", &read_byte, &offset) == 1)
    {
        dest_buffer[data_len++] = read_byte;
        data += offset;
    }
    return data_len;
}

static char* convert_byte_array_to_hexstring(void* src_buffer, size_t buffer_length)
{
    if (buffer_length == 0)
    { // Return empty string (with null char!) if buffer is empty
        return "";
    }

    unsigned char* bytes = src_buffer;
    char* hexstr = malloc(buffer_length * 2 + 1);

    if (src_buffer == NULL)
        return NULL;

    for (size_t i = 0; i < buffer_length; i++)
    {
        uint8_t nib1 = (bytes[i] >> 4) & 0x0F;
        uint8_t nib2 = (bytes[i]) & 0x0F;
        hexstr[i * 2 + 0] = nib1 < 0xA ? '0' + nib1 : 'A' + nib1 - 0xA;
        hexstr[i * 2 + 1] = nib2 < 0xA ? '0' + nib2 : 'A' + nib2 - 0xA;
    }
    hexstr[buffer_length * 2] = '\0';
    return hexstr;
}

static int32_t finish_with_error(MYSQL **con_loc, int err)
{
    fprintf(stderr, "%s\n", mysql_error(*con_loc)); // todo - if query fails, need to push failure message to error stack
    mysql_close(*con_loc);
    *con_loc = NULL;
    return err;
}