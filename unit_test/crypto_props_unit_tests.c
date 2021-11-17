/*
 This file implements unit tests of defined in functions from crypto_props.h
 */
/* 
 * File:   crypto_props_unit_tests.c
 * Author: Ary Naim (aryan.e.naim@jpl.nasa.gov)
 *
 * Created on November 4, 2021, 9:37 AM
 */
#include <stdio.h>
#include <stdlib.h>
#include "crypto_props.h"

void test()
{
    //memory allocation max_key_size=256,max_value_size=4096
    crypto_config_list* props = crypto_config_alloc(256,4096); 
    if (NULL!=props)
    {
        printf("alloc\n");
    }
    //load sample key,values from the file system
    crypto_config_load_properties("<your_path>/docs/config_props.txt");
    //print all values for testing
    crypto_config_print_all_props(props); 
    //manually add key values
    crypto_config_props_add_property("key_a","value_a");
    crypto_config_props_add_property("key_b","value_b");
    crypto_config_props_add_property("key_c","value_c");
    crypto_config_props_add_property("key_e","value_e");
    //print all values for testing 
    crypto_config_print_all_props(props); 
    //update existing key,values with new values
    crypto_config_set_property_value("key_a","AAA");
    crypto_config_set_property_value("key_c","CCC");
    crypto_config_set_property_value("key_b","BBB");
    //test non-existing key 
    crypto_config_set_property_value("key_d","DDD");
    //print all values for testing
    crypto_config_print_all_props(props); 
    //get values based on key 
    printf("%s\n",crypto_config_get_property_value("key_a"));
    printf("%s\n",crypto_config_get_property_value("key_b"));
    printf("%s\n",crypto_config_get_property_value("key_c"));
    //test non-existing keys 
    printf("%s\n",crypto_config_get_property_value("key_d"));
    printf("%s\n",crypto_config_get_property_value("xyz"));
    //print all values for testing
    crypto_config_print_all_props(props); 
    //finally free all memory 
    crypto_config_free(&props);
    printf("free\n");
}