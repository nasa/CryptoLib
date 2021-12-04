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
#include <stdbool.h>
#include <string.h>
#include "crypto_props.h"

/*=============================================================================
Private Declarations
==============================================================================*/
crypto_config_list* crypto_config_alloc_helper(int max_key_size, int max_value_size, crypto_config_list** props);
int crypto_config_props_remove_property_helper(char* key,crypto_config_list** pp_self); 
int safe_copy(int destination_size,char* src);

/*=============================================================================
 * Implementations
==============================================================================*/
crypto_config_list* crypto_config_alloc(int max_key_size, int max_value_size, crypto_config_list** props ) {
   return crypto_config_alloc_helper(max_key_size, max_value_size, props );
}

crypto_config_list* crypto_config_alloc_helper(int max_key_size, int max_value_size, crypto_config_list** props)
{
     if (NULL == *props) {
        *props = (crypto_config_list*) calloc(1, sizeof(crypto_config_list));
        (*props)->p_head=NULL; 
        //set max key size
        if (max_key_size > 0 && max_key_size<=4096) {
            (*props)->KEY_SIZE_IN_BYTES = max_key_size;
        } else {
              //defaults to 256 
             (*props)->KEY_SIZE_IN_BYTES = DEFAULT_MAX_KEY_SIZE_IN_BYTES;
             fprintf(stderr,"WARNING crypto_config,crypto_config_alloc_helper(), "
             "max_key_size MUST be 0<max_key_size<=4096.max_key_size is set to "
                     "default 256.\n");
        }
        //set max value size
        if (max_value_size > 0 && max_value_size<=4096) {
            (*props)->VALUE_SIZE_IN_BYTES  = max_value_size;
        } else {
             //defaults to 4096
             (*props)->VALUE_SIZE_IN_BYTES  = DEFAULT_MAX_VALUE_SIZE_IN_BYTES;
             fprintf(stderr,"WARNING crypto_config,crypto_config_alloc_helper(), "
             "max_value_size MUST be 0<max_value_size<=4096.max_value_size is set to "
                     "default 4096.\n");
        }
    }
    return *props;
}

void crypto_config_free(crypto_config_list** props)
{
    if (NULL!=props  && NULL!=*props)
    {
        crypto_config_node* p_current = (*props)->p_head; 
        crypto_config_node* p_next = NULL; 
        //iterate and free the nodes 
        while (NULL!=p_current)
        {
            p_next = p_current->p_next;
            //free child attributes 
            if (NULL!=p_current->key)
            {
                free(p_current->key);
                p_current->key = NULL; 
            }
            if (NULL!=p_current->value)
            {
                free(p_current->value);
                p_current->value = NULL; 
            }
            //free the node 
            free(p_current);
            p_current = p_next; 
           
        }
        //free the super structure
        if (NULL!=*props)
        {
            free (*props);
            *props  = NULL;
        }

    }
}


int crypto_config_props_add_property(char* key, char* value, crypto_config_list** pp_self) {
    int status = false;
    int dest_buffer_size_key = 0;
    int dest_buffer_size_value = 0;
    if (NULL != key && strlen(key) > 0 && NULL != value && strlen(value) > 0 && NULL != pp_self && NULL != (*pp_self)) {

        dest_buffer_size_key = strlen(key);
        dest_buffer_size_value = strlen(value);
        //is the head NULL?  
        if (NULL == (*pp_self)->p_head) {

            //if head is NULL then pre-allocate memory for it 
            (*pp_self)->p_head = calloc(1, sizeof (crypto_config_node));
            (*pp_self)->p_head->key = calloc(dest_buffer_size_key, sizeof (char));
            (*pp_self)->p_head->value = calloc(dest_buffer_size_value, sizeof (char));

            if (safe_copy(dest_buffer_size_key, key)
                    && safe_copy(dest_buffer_size_value, value)) {
                //set key & value
                strcpy((*pp_self)->p_head->key, key);
                strcpy((*pp_self)->p_head->value, value);
                status = true;
            } else {
                //since this was NOT a safe operation free preallocated memory 
                free((*pp_self)->p_head->key);
                free((*pp_self)->p_head->value);
                free((*pp_self)->p_head);
                fprintf(stderr, "ERROR crypto_config,crypto_config_props_add_property_helper(), "
                        "prevented unsafe copy.\n");
                fprintf(stderr, "source key size=%zu, destination key size=%zu,source value size=%zu, "
                        "destination value size=%zu.\n",
                        strlen(key),
                        strlen((*pp_self)->p_head->key),
                        strlen(value),
                        strlen((*pp_self)->p_head->value));
            }
        }//head is NOT NULL 
        else {
            crypto_config_node* p_current = (*pp_self)->p_head;
            crypto_config_node* p_previous = NULL;
            while (NULL != p_current) {
                p_previous = p_current;
                p_current = p_current->p_next;

            }//end while 

            //preallocate  memory for the new node 
            p_previous->p_next = calloc(1, sizeof (crypto_config_node));
            p_previous->p_next->key = calloc(dest_buffer_size_key, sizeof (char));
            p_previous->p_next->value = calloc(dest_buffer_size_value, sizeof (char));

            //set key & value
            if (safe_copy(dest_buffer_size_key, key)
                    && safe_copy(dest_buffer_size_value, value)) {

                //set values 
                strcpy(p_previous->p_next->key, key);
                strcpy(p_previous->p_next->value, value);
                status = true;
            } else {
                //since this was NOT a safe operation free preallocated memory 
                free(p_previous->p_next->value);
                free(p_previous->p_next->key);
                free(p_previous->p_next);

                fprintf(stderr, "ERROR crypto_config,crypto_"
                        "config_props_add_property_helper(), prevented unsafe "
                        "copy.\n");
                fprintf(stderr, "source key size=%zu, destination key size=%zu,source value size=%zu, "
                        "destination value size=%zu.\n", strlen(key),
                        strlen(p_previous->p_next->key),
                        strlen(value),
                        strlen(p_previous->p_next->value));
            }

        }
    } else {
        fprintf(stderr, "ERROR, crypto_config_props_add_property_helper() inputs are empty or null.\n");
    }

    return status;
}

int crypto_config_set_property_value(char* key, char* value, crypto_config_list** pp_props)
{
    int status = false; 
    int dest_buffer_size_value = 0;
    //iterate through the link list until you reach the right node
    if (NULL!=key && strlen(key)> 0 && NULL!=value && strlen(key)> 0 && NULL!=pp_props && NULL!=(*pp_props))
    {
        dest_buffer_size_value = strlen(value);
        crypto_config_node* p_current = (*pp_props)->p_head; 
        while (p_current!=NULL)
        {
            //returns 0 if NOT equal 
            if (strcmp(p_current->key,key)!=0)
            {
                p_current= p_current->p_next; 
            }
            else
            {
                //since the new values length can be larger than older values length then we must free the older buffer & create a new buffer 
                if (NULL!=p_current && NULL!=p_current->value)
                    {
                    free(p_current->value);
                    p_current->value = NULL; 
                    //new size based on new value
                    p_current->value = calloc(dest_buffer_size_value,sizeof (char));
                    if (safe_copy(dest_buffer_size_value,value))
                    {   
                        //replace old value with the new 
                        strcpy(p_current->value,value);  
                        status = true; 
                    }
                    else
                    {
                        //prevented unsafe copy , therefore free that memory
                        if (NULL!=p_current->value)
                        {
                            free(p_current->value);
                        }
                        //TODO: print error 
                        fprintf(stderr,"ERROR crypto_config_props_set_property_value_helper(),"
                                "unsafe copy source value size=%lu is larger than destination "
                                "size=%lu.\n",strlen(value),strlen(p_current->value));
                    }
                }
                break; 
                
                
            }
            
        }//end while 
    }
    else
    {
        fprintf(stderr,"ERROR, crypto_config_props_set_property_value_helper() inputs are empty or null.\n");
    }
    return status; 
}

char* crypto_config_get_property_value(char* key,crypto_config_list** pp_props)
{
    //iterate through the link list until you reach the right node
    if (NULL!=key && strlen(key)> 0 && NULL!=(*pp_props))
    {
        crypto_config_node* p_current = (*pp_props)->p_head; 
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
        fprintf(stderr,"ERROR, crypto_config_props_get_property_value_helper() inputs are empty or null.\n");
    }
    return "\0"; 
}


int crypto_config_load_properties(char* file_path, crypto_config_list** pp_props)
{
    int status = false; 
    if (NULL!=*pp_props)
    {
        if (NULL!=file_path)
        {
            //open file
            FILE* p_file=NULL;
            p_file=fopen(file_path,"r");
            //counter to keep track of the number of parsed key=values that were added successfully 
            int read_added_props_counter = 0; 
            if (NULL!=p_file)
            {
                char key[(*pp_props)->KEY_SIZE_IN_BYTES];
                char val[(*pp_props)->VALUE_SIZE_IN_BYTES];
                char current_line[(*pp_props)->VALUE_SIZE_IN_BYTES]; 
                const char* line_delimiter = "="; 
                int index =-1;
                int add_status = false; 
                //while loop to parse the file 
                while(fgets(current_line, (*pp_props)->VALUE_SIZE_IN_BYTES-1,p_file))
                {
                    // Remove trailing newline
                    current_line[strcspn(current_line, "\n")] = 0;
                    //split the line based on the index of the delimeter "="
                    index=strcspn(current_line,line_delimiter);
                    if (index>=0)
                    {
                        //validate this line valid key=value data line rather than comment or empty line
                        if (strcmp(current_line,"\n") !=0 /*not empty line*/
                                && strcmp(current_line,"\r\n")!=0 /*not empty line*/
                                && strlen(current_line)>=2 /*length must be >=2*/
                                && current_line[0]!='#' /*1st char cannot be #*/
                                &&  (current_line[1]!='/' && current_line[0]!='/') /*1st & 2nd char cannot be '/' */)
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
                            while (current_line[i]!='\0' && j<(*pp_props)->VALUE_SIZE_IN_BYTES)
                            {
                                val[j]=current_line[i];
                                i++;
                                j++;
                            }
                            val[j] = '\0'; 
                            //printf("DEBUG key=%s,value=%s\n",key,val);
                            //3) add the key,value to the properties linkedlist
                            add_status = crypto_config_props_add_property(key,val,pp_props);
                            if (add_status>0)
                            {
                                read_added_props_counter = read_added_props_counter + 1; 
                            }

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

                }//end while loop thats parses the file 
                status = read_added_props_counter; 
                if (NULL!=p_file)
                {
                     fclose(p_file);
                }
            }//end if file pointer is not NULL
            else
            {
                fprintf(stderr,"ERROR, crypto_config_load_properties() error opening file!.\n");
            }

        }//end if file path is not NULL
        else
        {
            fprintf(stderr,"ERROR, crypto_config_load_properties() file path is NULL.\n");
        }
    }
    else
    {
        fprintf(stderr,"ERROR, crypto_config_load_properties() input props is NULL.\n");
    }
    return status; 
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
Note:               since at the time of copy memory has not been allocated for the destination buffer we
 *                  we have to use expected destination size as set by alloc() in comparison to src length. 
==========================================================*/
int safe_copy(int destination_size,char* src) {
    int flag = false;
    if (NULL!= src) {
       if (destination_size >= strlen(src)) {
            flag = true;
        }
    }
    return flag;
}
