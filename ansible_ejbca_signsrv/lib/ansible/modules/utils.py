#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re

class ListMatch(str):   
    """ Find string match in provided list """
    
    def regex(self,list):
        match = ''.join([m for m in list if re.search(m, self)])
        if match != None:
            return match
    
class StringSplit(str):
    """ Split strings based on different characters and regex.
    
    Regex(optional) - Splits string after matched value
    """

    def comma(self,match=False):
        """ Gets value between first set of commas 
        
        arguments:
            - match: Splits string after matched value fount in string
        """
        regex=r',(.*?),'
        if match:
            string_match=re.findall(regex, self)
            if string_match != None:
                return string_match.group(0).split(',')[1].split(',')[0]
        
        return self.split(',')[1].split(',')[0].strip()
    
    def tuple(self,tuple: tuple):
        """ accepts a tuple with beginning and end split characters """
        
        return self.split(tuple[0])[1].split(tuple[1])[0].strip()
    
    def quotes(self,match: bool=False):
        """ Gets value between first set of commas 
        
        arguments:
            - match: Splits string after matched value fount in string
        """
        if match:
            regex=r'"(.*?)"'
            string_match=re.search(regex, self)
            if string_match != None:
                return string_match.group(0).split('"')[1].split('"')[0]
        return self.split('"')[1].split('"')[0]
    
    def parenthesis(self,match: bool=False):
        """ Gets value between first set of commas 
        
        arguments:
            - match: Splits string after matched value fount in string
        """
        if match:
            regex=r'\((.+)\)'
            string_match=re.search(regex, self)
            if string_match != None:
                return string_match.group(0).split('(')[1].split(')')[0]
            
        return self.split('(')[1].split(')')[0]
