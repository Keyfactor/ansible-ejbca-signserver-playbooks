#!/usr/bin/python

import re

class FilterModule(object):
    def filters(self):
        return {
            'acronym': self.acronym,
            'selection': self.selection,
            'yesno': self.yesno,
            'columnwidth': self.columnwidth,
            'common': self.common,
            'validlist': self.validlist,
            'logical': self.logical,
            'slugify': self.slugify,
        }
        
    def acronym(self, str:str):
        acronym = ""
        words = str.split()
        for word in words:
            acronym += word[0].upper()
        return acronym
    
    def selection(self, choice:int):
        """ Returns True or False value for integer """
        if choice == 1:
            return True
        else:
            return False
    
    def yesno(self, boolean:bool):
        """ Returns Yes or No value for boolean """
        if boolean:
            return 'Yes'
        else:
            return 'No'
        
    def columnwidth(self, list:list, max_width=80, stub_width=15):
        """ Dynamically sets ReStructured table columb width based on list length """
        columns = len(list)
        remaining_width = max_width - stub_width
        if columns > 1:
            length = remaining_width // columns
            column_width = str()
            for i in range(len(list)):
                column_width += f' {length}'
            total_width = str(stub_width) + column_width

        else:
            total_width = str(f'{stub_width} {remaining_width}')
            
        return total_width
    
    def validlist(self, list:list):
        """ Checks if list is not empty, and length is greater than 0 """
        if list != None and len(list) > 0:
            return True
        return False
    
    def common(self, str:str):
        str = str.strip()
        str = re.sub(r'[^\w\s-]', ' ', str)
        str = re.sub(r'[\s_-]+', ' ', str)
        str = re.sub(r'^-+|-+$', ' ', str)
        return str
            
    def logical(self, str:str):
        str = str.strip()
        str = re.sub(r'[^\w\s-]', '', str)
        str = re.sub(r'[\s_-]+', '-', str)
        str = re.sub(r'^-+|-+$', '', str)
        return str
    
    def slugify(self, str:str):
        str = str.lower().strip()
        str = re.sub(r'[^\w\s-]', '', str)
        str = re.sub(r'[\s_-]+', '-', str)
        str = re.sub(r'^-+|-+$', '', str)
        return str
    
    
    
   
        
        
