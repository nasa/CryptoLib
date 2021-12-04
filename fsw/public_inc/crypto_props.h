/*
 This header represents functions required for property management via linked list
 * data structure.  
 */
/* 
 * File:   crypto_props.h
 * Author: Ary Naim (aryan.e.naim@jpl.nasa.gov)
 *
 * Created on November 4, 2021, 9:15 AM
 */

#ifndef CRYPTO_PROPS_H
#define CRYPTO_PROPS_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdlib.h>
#define DEFAULT_MAX_KEY_SIZE_IN_BYTES       256
#define DEFAULT_MAX_VALUE_SIZE_IN_BYTES     4096
    
/*represents a single linked list node with (key,value) pair*/
typedef struct crypto_config_node
{
    char* key; 
    char* value; 
    struct crypto_config_node* p_next; 
    
} crypto_config_node;

/*represents all properties*/
typedef struct crypto_config_list
{
    crypto_config_node* p_head;
    int KEY_SIZE_IN_BYTES; 
    int VALUE_SIZE_IN_BYTES;  
    
} crypto_config_list;

/*===========================================================================
Function:           crypto_config_alloc      
Description:        allocates heap memory for the wrapper crypto_config_list 
 *                  that contains the head node.
Inputs:             max_key_size in bytes. 
 *                  Input of 0 or greater than 4096 will default to 256 bytes 
 *                  length for the key size. 
 * 
 *                  max_value_size in bytes. 
 *                  Input of 0 or greater than 4096 will default to 4096 bytes 
 *                  length for the value size. 
Outputs:            pointer to crypto_config_list
References:
Example call:       crypto_config_list* props = crypto_config_alloc(0,0)
Note:               Passing in max_key_size=0 and/or max_value_size=0 will print 
 *                  a warning just letting you know that defaults values of 
 *                  max_key_size=256 and max_value_size=4096 were used instead. 
==========================================================*/
crypto_config_list* crypto_config_alloc(int max_key_size, int max_value_size, crypto_config_list** props );
/*===========================================================================
Function:           crypto_config_free
Description:        Frees heap memory allocated to crypto_config_list & the
 *                  linked list within crypto_config_list. 
Inputs:             crypto_config_list** pp_self - pass by reference         
Outputs:            void
References: 
Example call:       crypto_config_free(&props); 
==========================================================*/
void crypto_config_free(crypto_config_list** props );
/*===========================================================================
Function:           crypto_config_props_add_property      
Description:        adds a new key & value node to the end of the linkedlist.      
Inputs:             char* key - some string. keys are case sensitive.
 *                  Therefore key_a is different than key_A. 
 *                  char* value- some string          
Outputs:            1 - success 
 *                  0 - fail       
References: 
Example call:       crypto_config_props_add_property("key_a","some value");
Note:               since this is a linked list there is no efficient way to guard against
                    adding the duplicate keys therefore if the key exists just update it using
                    crypto_config_props_set_property_value_helper else add in a new key,value. 
//==========================================================*/
int crypto_config_props_add_property(char* key, char* value, crypto_config_list** props );
/*===========================================================================
Function:           crypto_config_get_property_value      
Description:        if a node exists with that key then the string value is 
                    returned else "/0" string is returned.      
Inputs:             char* key - some string key       
Outputs:            string or "/0"       
References:
Example call:       crypto_config_get_property_value("key_a")
==========================================================*/
char* crypto_config_get_property_value(char* key,crypto_config_list** pp_props);
/*===========================================================================
Function:           crypto_config_set_property_value      
Description:        If a node with the input key exists its value will be
 *                  overwritten with input parameter char* value; 
Inputs:             char* key- some string. keys are case sensitive.   
 *                  Therefore key_a is different than key_A.        
Outputs:            1 - success 
 *                  0 - fail       
References: 
Example call:      crypto_config_set_property_value("key_a","AAA")
==========================================================*/
int crypto_config_set_property_value(char* key, char* value, crypto_config_list** pp_props);
/*===========================================================================
Function:      
Description:        This function will parse files with the format:
                    #Comment#
                    Key=value,
                    key=value,
                    OR:
                    #Comment
 *                  //Comment 
                    Key=value,key=value,key=value
/*Inputs:           char* file_path - path of the file on the filesystem
Outputs:            1 or greater - success. Meaning read & added 1 or more data 
 *                  lines successfully. 
 *                  0 - fail  
References:
Example call:      crypto_config_load_properties("/<your_path>/docs/config_props.txt")
==========================================================*/
int crypto_config_load_properties(char* file_path, crypto_config_list** pp_props);
/*===========================================================================
Function:           crypto_config_print_all_props                 
Description:        Iterates through linkedlist and prints all key & values to 
 *                  system out for debugging.   
Inputs:             crypto_config_list* p_self         
Outputs:            void        
References: 
Example call:       crypto_config_print_all_props(props)
==========================================================*/
void crypto_config_print_all_props(crypto_config_list* p_self);
#ifdef __cplusplus
}
#endif
#endif /* CRYPTO_PROPS_H */
