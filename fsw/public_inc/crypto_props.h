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

/*declare variables*/
extern crypto_config_list* p_self;
/*===========================================================================
Function:           crypto_config_alloc      
Description:        allocates heap memory for the wrapper crypto_config_list 
 *                  that contains the head node. Also sets max key size in bytes 
 *                  & value size in bytes. 
Inputs:             max_key_size in bytes
 *                  max_value_size in bytes
Outputs:            pointer to crypto_config_list
References:
Example call:       crypto_config_list* props = crypto_config_alloc(256,4096)
==========================================================*/
crypto_config_list* crypto_config_alloc(int max_key_size, int max_value_size);

/*===========================================================================
Function:           crypto_config_free
Description:        Frees heap memory allocated to crypto_config_list & the
 *                  linked list within crypto_config_list. 
Inputs:             crypto_config_list** pp_self - pass by reference         
Outputs:            void
References: 
Example call:       crypto_config_free(&props); 
==========================================================*/
void crypto_config_free(crypto_config_list** pp_self);

/*===========================================================================
Function:           crypto_config_props_add_property      
Description:        adds a new key & value node to the end of the linkedlist.      
Inputs:             char* key - some string 
 *                  char* value- some string          
Outputs:            1 - success 
 *                  0 - fail       
References: 
Example call:       crypto_config_props_add_property("key_a","some value");
Note:               since this is a linked list there is no efficient way to guard against
                    adding the duplicate keys therefore if the key exists just update it using
                    crypto_config_props_set_property_value_helper else add in a new key,value. 
==========================================================*/
int crypto_config_props_add_property(char* key, char* value);

/*===========================================================================
Function:           crypto_config_get_property_value      
Description:        if a node exists with that key then the string value is 
                    returned else "/0" string is returned.      
Inputs:             char* key - some string key       
Outputs:            string or "/0"       
References:
Example call:       crypto_config_get_property_value("key_a")
==========================================================*/
char* crypto_config_get_property_value(char* key); 

/*===========================================================================
Function:           crypto_config_set_property_value      
Description:        If a node with the input key exists its value will be
 *                  overwritten with input parameter char* value; 
Inputs:             char* key- some string value         
Outputs:            1 - success 
 *                  0 - fail       
References: 
Example call:      crypto_config_set_property_value("key_a","AAA")
==========================================================*/
int crypto_config_set_property_value(char* key, char* value);

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
Outputs:            1 - success 
 *                  0 - fail  
References:
Example call:      crypto_config_load_properties("/root/Desktop/config_props.txt")
==========================================================*/
int crypto_config_load_properties(char* file_path);

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

