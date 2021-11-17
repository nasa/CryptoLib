/*
 This implementation file implements functions from crypto_props.h
 * which are required for key,value property management via linked list
 * data structure.  
 */
/* 
 * File:   crypto_props.c
 * Author: Ary Naim (aryan.e.naim@jpl.nasa.gov)
 *
 * Created on November 4, 2021, 9:37 AM
 */

#include <stdio.h>
#include <stdlib.h>
#include "stdbool.h"
#include <string.h>
#include "crypto_props.h"

crypto_config_list* p_self = NULL; 
/*=============================================================================
Private Declarations
==============================================================================*/
int crypto_config_props_set_property_value_helper(char* key, char* value, crypto_config_list** props);
char* crypto_config_props_get_property_value_helper(char* key, crypto_config_list** props);
int crypto_config_props_add_property_helper(char* key, char* value,crypto_config_list** pp_self); 
int crypto_config_props_remove_property_helper(char* key,crypto_config_list** pp_self); 
int safe_copy(char* dest, char* src);
/*=============================================================================
 * Implementations
==============================================================================*/
crypto_config_list* crypto_config_alloc(int max_key_size, int max_value_size)
{
    if (NULL==p_self)
    {
        p_self = (crypto_config_list*) calloc(1,sizeof(crypto_config_list));
        p_self->KEY_SIZE_IN_BYTES = max_key_size; 
        p_self->VALUE_SIZE_IN_BYTES = max_value_size; 
        
    }
    return p_self; 
}

void crypto_config_free(crypto_config_list** pp_self)
{
    if (NULL!=pp_self && NULL!=(*pp_self))
    {
        crypto_config_node* p_current = (*pp_self)->p_head; 
        crypto_config_node* p_next = NULL; 
        //iterate and free the nodes 
        while (NULL!=p_current)
        {
            p_next = p_current->p_next; 
            free(p_current);
            p_current = p_next; 
           
        }
        //free the super structure 
        free (*pp_self);
    }
}

int crypto_config_props_add_property(char* key, char* value)
{
    int success = 0; 
    //Note: since this is a linked list there is no efficient way to guard against
    //adding the duplicate keys therefore if the key exists just update it using
    //crypto_config_props_set_property_value_helper else add in a new key,value. 
    success = crypto_config_props_set_property_value_helper(key,value,&p_self);
    if (success)
    {
        return success; 
    }
    else
    {
        return crypto_config_props_add_property_helper(key,value,&p_self);
    }
}
int crypto_config_props_add_property_helper(char* key, char* value, crypto_config_list** pp_self)
{
    int success = 0; 
    if (NULL!=key && strlen(key)> 0 && NULL!=value && NULL!=pp_self && NULL!=(*pp_self))
    {
       
        //is the head NULL?  
        if (NULL==(*pp_self)->p_head)
        {
            //if head is NULL then allocate memory for it 
            (*pp_self)->p_head = calloc(1,sizeof(crypto_config_node)); 
            (*pp_self)->p_head->key = calloc((*pp_self)->KEY_SIZE_IN_BYTES,sizeof(char)); 
            (*pp_self)->p_head->value = calloc((*pp_self)->VALUE_SIZE_IN_BYTES,sizeof(char));
            
            if (safe_copy((*pp_self)->p_head->key,key) && safe_copy((*pp_self)->p_head->value,value))
            {
                //set key & value
                strcpy((*pp_self)->p_head->key,key);
                strcpy((*pp_self)->p_head->value,value);
                success = 1; 
            }
            else
            {
                printf("ERROR crypto_config,crypto_config_props_add_property_helper(), prevented unsafe copy.\n");
                printf("key size=%lu, key destination size=%lu,value size=%lu, value destination size=%lu.\n",sizeof(key),sizeof((*pp_self)->p_head->key),sizeof(value),sizeof((*pp_self)->p_head->value)); 
            }
            
     
        }
        //head is NOT NULL 
        else
        {
            crypto_config_node* p_current = (*pp_self)->p_head; 
            crypto_config_node* p_previous = NULL; 
            while (NULL!=p_current)
            {
                p_previous = p_current; 
                p_current = p_current->p_next; 
                
            }//end while 
            
            //add a new node to the end 
            p_previous->p_next = calloc(1,sizeof(crypto_config_node));
            p_previous->p_next->key = calloc((*pp_self)->KEY_SIZE_IN_BYTES,sizeof(char)); 
            p_previous->p_next->value = calloc((*pp_self)->VALUE_SIZE_IN_BYTES,sizeof(char));
            //set key & value
            if (safe_copy(p_previous->p_next->key,key) && safe_copy(p_previous->p_next->value,value))
            {
                strcpy(p_previous->p_next->key,key);
                strcpy(p_previous->p_next->value,value);
                success = 1;
            }
            else
            {
                printf("ERROR crypto_config,crypto_"
                        "config_props_add_property_helper(), prevented unsafe "
                        "copy.\n");
                printf("key size=%lu, key destination size=%lu,value size=%lu, "
                        "value destination size=%lu.\n",sizeof(key),
                        sizeof((*pp_self)->p_head->key),
                        sizeof(value),
                        sizeof((*pp_self)->p_head->value)); 
            }
           
        }
    }
    else
    {
        printf("ERROR, crypto_config_props_add_property_helper() inputs are empty or null.\n");
    }
    
    return success; 
}

int crypto_config_set_property_value(char* key, char* value)
{
    return crypto_config_props_set_property_value_helper(key,value,&p_self);
}

int crypto_config_props_set_property_value_helper(char* key, char* value, crypto_config_list** pp_self)
{
    int success = 0; 
    //iterate through the link list until you reach the right node
    if (NULL!=key && strlen(key)> 0 && NULL!=value && NULL!=pp_self && NULL!=(*pp_self))
    {
        crypto_config_node* p_current = (*pp_self)->p_head; 
        while (p_current!=NULL)
        {
            //returns 0 if NOT equal 
            if (strcmp(p_current->key,key)!=0)
            {
                p_current= p_current->p_next; 
            }
            else
            {
                if (safe_copy(p_current->value,value))
                {   
                    //reset old values to empty 
                    memset(p_current->value, 0,sizeof((*pp_self)->VALUE_SIZE_IN_BYTES));
                    //replace old value with the new 
                    strcpy(p_current->value,value);  
                    success = 1; 
                }
                else
                {
                    //TODO: print error 
                    printf("ERROR crypto_config_props_set_property_value_helper(),"
                            "unsafe copy source value size=%lu is larger than destination "
                            "size=%lu.\n",sizeof(value),sizeof(p_current->value));
                }
                break; 
                
            }
            
        }//end while 
    }
    else
    {
        printf("ERROR, crypto_config_props_set_property_value_helper() inputs are empty or null.\n");
    }
    return success; 
}

char* crypto_config_get_property_value(char* key)
{
    return crypto_config_props_get_property_value_helper(key,&p_self);
}

char* crypto_config_props_get_property_value_helper(char* key, crypto_config_list** pp_self)
{

    //iterate through the link list until you reach the right node
    if (NULL!=key && strlen(key)> 0 && NULL!=(*pp_self))
    {
        crypto_config_node* p_current = (*pp_self)->p_head; 
        while (p_current!=NULL)
        {
            //returns 0 if NOT equal 
            if (strcmp(p_current->key,key)!=0)
            {
                p_current= p_current->p_next; 
            }
            else
            {
                return p_current->value; 
                
            }
            
        }//end while 
    }
    else
    {
        printf("ERROR, crypto_config_props_get_property_value_helper() inputs are empty or null.\n");
    }
    return "\0"; 
}

int crypto_config_load_properties(char* file_path)
{
    if (NULL!=file_path)
    {
        //open file
        FILE* p_file=NULL;
        p_file=fopen(file_path,"r");
        if (NULL!=p_file)
        {
            char key[p_self->KEY_SIZE_IN_BYTES];
            char val[p_self->VALUE_SIZE_IN_BYTES];
            char current_line[p_self->VALUE_SIZE_IN_BYTES]; 
            const char* line_delimiter = "="; 
            int index =-1;
            //parse the file 
            while(fgets(current_line, p_self->VALUE_SIZE_IN_BYTES-1,p_file))
            {
                // Remove trailing newline
                current_line[strcspn(current_line, "\n")] = 0;
                
                index=strcspn(current_line,line_delimiter);
                if (index>=0)
                {
                    //check for empty commets (lines that start with # or //) and checkf or empty lines
                    if (current_line[0]!='#' && (current_line[0]!='/' || current_line[1]!='/') && 
                            strcmp(current_line,"\n") !=0 && strcmp(current_line,"\r\n") !=0 )
                    {
                        //printf("DEBUG current_line DATA=%s\n",current_line);
                        //1) pass the key 
                        int i=0; 
                        while (i<index)
                        {
                            key[i]=current_line[i];
                            i++; 
                        }
                        key[i] = '\0';
                        //2) parse the value 
                        i=index+1;
                        int j=0;
                        while (current_line[i]!='\0' && j<p_self->VALUE_SIZE_IN_BYTES)
                        {
                            val[j]=current_line[i];
                            i++;
                            j++;
                        }
                        val[j] = '\0'; 
                        //printf("DEBUG key=%s,value=%s\n",key,val);
                        //3) add the key,value to the properties linkedlist
                        crypto_config_props_add_property_helper(key,val,&p_self);
                        
                    }
                    else
                    {   //delimiter was detected but this starts with a comment character therefore it will NOT be parsed
                        //printf("COMMENT=%s\n",current_line);
                    }
                }
                else
                {
                    //do nothing there was no "=" delimiter detected 
                }
                
            }
            if (NULL!=p_file)
            {
                 fclose(p_file);
            }
        }
        else
        {
            //error 
            printf("ERROR, crypto_config_load_properties() error opening file!.\n");
        }

    }
    else
    {
        printf("ERROR, crypto_config_load_properties() file path is NULL.\n");
    }
}

void crypto_config_print_all_props(crypto_config_list* p_self)
{
    if (NULL!=p_self)
    {
         crypto_config_node* p_current = p_self->p_head;
         while (NULL!=p_current)
         {
             printf("key=%s,value=%s\n",p_current->key,p_current->value);
             p_current = p_current->p_next; 
             
         }
    }
}

/*===========================================================================
Function:           safe_copy
Description:        safe_copy is a helper function to guard against unsafe copies.
 *                  strlcp() is not available in all compilers, therefore this 
                    function returns true(1) if destination size >= src.   
Inputs:             dest - string 
 *                  src - string                   
Outputs:            1 or 0 
References: 
==========================================================*/
int safe_copy(char* dest, char* src)
{
    int flag = 0; 
    if (NULL!=dest && NULL!=src)
    {
        if (sizeof(dest)>=sizeof(src))
        {
            flag = 1; 
        }
    }
    return flag; 
}

