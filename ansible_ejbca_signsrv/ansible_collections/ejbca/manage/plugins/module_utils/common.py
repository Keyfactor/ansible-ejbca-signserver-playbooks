#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
import yaml

def import_yaml(yaml_file:str):
    """ Import yaml file and creates temporary dictionary """
    
    # initialize dict
    imported_vars_dict = dict()

    with open(yaml_file, 'r') as file:
        imported_file = yaml.safe_load(file)
        for key,value in imported_file.items() if imported_file != None else {}:
            imported_vars_dict[key] = value
            
        file.close()
            
    return imported_vars_dict

def output_yaml(yaml_file:str, dictionary:dict, append:bool = False, write:bool = True):
    """ Output yaml file from dictionary """
    
    with open(yaml_file, 'w') as file:
        yaml.dump(dictionary, file) 
