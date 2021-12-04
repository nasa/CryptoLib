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
#include <assert.h>
#include <string.h>

void test()
{

    crypto_config_list* props = NULL;
    props = crypto_config_alloc(0,0,&props); //defaults to max_key_size=256,max_value_size=4096
    assert(props);
    printf("alloc\n");
    //load sample key,values from the file system
    //"/unit_test/config_props/crypto_props.txt"
    int status = 0; 
    status = crypto_config_load_properties("crypto_props.txt",&props);
    assert(status>0);
    //print all values for testing
    crypto_config_print_all_props(props); 
    //manually add key values
    crypto_config_props_add_property("key_a","value_a",&props);
    crypto_config_props_add_property("key_b","value_b",&props);
    crypto_config_props_add_property("key_c","value_c",&props);
    crypto_config_props_add_property("key_e","value_e",&props);
    //print all values for testing 
    crypto_config_print_all_props(props); 
    //update existing key,values with new values
    status=crypto_config_set_property_value("key_a","AAA",&props);
    assert(status>0);
    status=crypto_config_set_property_value("key_c","CCC",&props);
    assert(status>0);
    status=crypto_config_set_property_value("key_b","BBB",&props);
    assert(status>0);
    //test non-existing key 
    status=crypto_config_set_property_value("key_x","DDD",&props);
    assert(status<=0);
    //print all values for visual validation 
    crypto_config_print_all_props(props);    
    //get values based on key 
    char* val = crypto_config_get_property_value("key_a",&props);
    assert(NULL!=val);
    printf("%s\n",crypto_config_get_property_value("key_a",&props)); 
    
    val = crypto_config_get_property_value("key_b",&props); 
    assert(NULL!=val);
    printf("%s\n",crypto_config_get_property_value("key_b",&props)); 
    
    val = crypto_config_get_property_value("ip_address_2_v6",&props); 
    assert(NULL!=val);
    printf("%s\n",crypto_config_get_property_value("ip_address_2_v6",&props)); 
    
    //test non-existing keys 
    val = crypto_config_get_property_value("key_z",&props);
    assert(strcmp(val,"\0")==0);
    
    val = crypto_config_get_property_value("xyz",&props); 
    assert(strcmp(val,"\0")==0);
   
    //print all values for visual validation 
    crypto_config_print_all_props(props); 
   
     //finally free all memory 
    crypto_config_free(&props);
    assert(NULL==props);
    
    printf("free\n");
}