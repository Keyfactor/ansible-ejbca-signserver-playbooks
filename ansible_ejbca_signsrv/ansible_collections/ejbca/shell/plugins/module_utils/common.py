#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re

COMMON_DEFAULTS = dict(
# Defaults used in different module argument specifications

    ejbca_home = '/opt/ejbca'
) 

COMMON_CHOICES = dict(
# Choices used in different module argument specifications
# If choices are used in multiple modules, set them here and import them into the module where needed
# Update this dict with the module CHOICES dict to override any values in this dict
    crypto_token_types = [
        'AzureCryptoToken',
        'AWSKMSCryptoToken',
        'FortanixCryptoToken',
        'Pkcs11NgCryptoToken',
        'PKCS11CryptoToken',
        'SoftCryptoToken',
    ],
    # tuple required to map CLI required integer to string value
    end_entity_statuses = [ 
        ('NEW','10'),
        ('FAILED','11'),
        ('INITIALIZED','20'),
        ('INPROCESS','30'),
        ('GENERATED','40'),
        ('HISTORICAL','40'),
    ],
    key_algorithms = [
        'RSA',
        'DSA',
        'ECDSA',
        'Ed25519',
        'Ed448'
    ],
    # tuple required to map CLI required integer to string value
    revocation_reasons = [
        ('unspecified','0'),
        ('keyCompromise','1'),
        ('cACompromise','2'),
        ('affiliationChanged','3'),
        ('superseded','4'),
        ('cessationOfOperation','5'),
        ('certificateHold','6'),
        ('removeFromCRL','8'),
        ('privilegeWithdrawn','9'),
        ('aACompromise','10'),
    ],
    sign_algorithms = [
        'SHA1WithRSA',
        'SHA256WithRSA',
        'SHA384WithRSA',
        'SHA512WithRSA',
        'SHA3-256withRSA',
        'SHA3-384withRSA',
        'SHA3-512withRSA',
        'SHA256withRSAandMGF1',
        'SHA384withRSAandMGF1',
        'SHA512withRSAandMGF1',
        'SHA1withECDSA',
        'SHA224withECDSA',
        'SHA256withECDSA',
        'SHA384withECDSA',
        'SHA512withECDS',
        'SHA3-256withECDSA',
        'SHA3-384withECDSA',
        'SHA3-512withECDSA',
        'SHA1WithDSA',
        'SHA256WithDSA',
        'Ed25519',
        'Ed448',
        'FALCON-512',
        'FALCON-1024',
        'DILITHIUM2',
        'DILITHIUM3',
        'DILITHIUM5',
        'LMS'
    ],
    slot_ref_types = [
        'SLOT_NUMBER',
        'SLOT_LABEL',
        'SLOT_INDEX'
    ],
    token_types = [
        'BCFKS',
        'JKS',
        'P12',
        'PEM',
        'USERGENERATED'
    ],
)
class Converter:   
    
    @staticmethod
    def from_milliseconds(value:int):
        """ Convert integer from milliseconds to days, hours, minutes """
        
        return dict(
            days = int(value / 1000 / 60 / 60 / 24),
            hours = int(value / 1000 / 60/ 60),
            minutes = int(value / 1000 / 60)
        )
        
    @staticmethod
    def to_milliseconds(value:int):
        """ Convert integer to milliseconds from days, hours, minutes """
        
        return dict(
            days = int(value * 24 * 60 * 60 * 1000),
            hours = int(value * 60 * 60 * 1000),
            minutes = int(value * 60 * 1000)
        )
            
    @staticmethod
    def from_string(str:str):
        """ Convert string to a type that matches a condition below """
        
        # bool
        if str in ['true','false','True','False']:
            return eval(str.title())
        
        # integer
        elif str.isnumeric():
            return int(str)
        
        # all else
        else:
            return str
        
    @staticmethod
    def bool_to_str(val):
        """ Convert bool to string if val is bool or returns value if not bool """
        
        if isinstance(val, bool):
            return str(val).lower()
        else:
            return val
        
    @staticmethod
    def str_to_bool(val):
        """ Convert string to bool if val is bool or returns value if not str """
    
        if isinstance(val, str):
            if val in ['true','True']:
                return True
            else:
                return False
        else:
            return val
        
    @staticmethod
    def slugify(str:str):
        """ Convert string to slug """
        
        str = str.lower().strip()
        str = re.sub(r'[^\w\s-]', '',str)
        str = re.sub(r'[\s_-]+', '_',str)
        str = re.sub(r'^-+|-+$', '',str)
        return str
            
class StderrParser:
    """ Parse stderr lines """
    
    @staticmethod
    def java_exception(lines):
       for e in lines:
           if 'NullPointerException' in e:
               return e
           elif 'Exception' in e:
               return e.rsplit('Exception:',1)[1].strip() 
           
class StringParser(str):
    """ Customer string parser """
    
    def boolean(self, match):
        """ Returns boolean if string match exists """
        
        return True if re.search(match, self) != None else False
    
    def colon(self, before:bool = False):
        """ Gets boolean value after equal symbol """
        
        if before:
            string = self.strip(' \n\t').split(':')[0].strip()
        else:
            string = self.split(':')[1].split()[0].strip()
        return string_converter(string)
    
    def comma(self,match=False):
        """ Gets value between first set of commas """
        if match:
            regex=r',(.*?),'
            regex_match=re.findall(regex, self)
            if regex_match != None:
                return regex_match.group(0).split(',')[1].split(',')[0]
        
        return self.split(',')[1].split(',')[0].strip()
    
    def dict_key(self):
        string = self.split(':')[0].strip().replace(' ','_').lower()
        return slugify(string)
    
    def dn_common_name(self):
        """ Gets Common Name from DN string """
        
        string = re.split("''|,", self)[0]
        return ' '.join(string.split('CN=')[1].split())

    def equal_sign(self,before=False):
        """ Gets boolean value after equal symbol """
        if before:
            string = self.strip(' \n\t').split('=')[0].strip()
        else:
            string = self.split('=')[1].split()[0].strip()
        return string_converter(string)
    
    def id(self):
        """ Parse ID using regex and if n/a in string, pass to comma function for parsing. """

        regex = r'-?\b\d{7,10}\b'
        string_match = re.search(regex,self)
        if string_match != None:
            return string_match.group(0).strip()
        else:
            return None
            
    def int(self):
        """ Gets number value from line """
        
        match = re.search(r'[0-9]+', self)
        if match != None:
            return int(match.group(0))
        
    def list(self, list:list = None):
        """ Gets matched string from list """
        
        search_string = '|'.join(list)
        match = re.search(search_string, self)
        if match != None:
            return str(match.group(0))

    def parenthesis(self, match:bool = False):
        """ Gets string between first set of commas """
        
        if match:
            regex = r'\((.+)\)'
            string_match = re.search(regex, self)
            if string_match != None:
                return string_match.group(0).split('(')[1].split(')')[0]
            
        return self.split('(')[1].split(')')[0]
    
    def split_strip(self, delimeter, before:bool = True):
        """ Splits line, before or after, delimeter and strips leading and trailing whitespace """
        
        if before:
            string = ''.join(self.split(delimeter)[0])
        else:
            string = ''.join(self.split(delimeter)[1])
        return string.lstrip().strip()
            
    def tuple(self, tuple:tuple):
        """ Parses string using tuple as start and end index values """
        
        return self.split(tuple[0])[1].split(tuple[1])[0].lstrip().strip()
        

    def quotes(self, single:bool = False):
        """ Gets value between first set of commas and strips quotes """

        try:
            if single:
                return self.split("'")[1].split("'")[0].strip()
            else:
                return self.split('"')[1].split('"')[0].strip()
            
        except IndexError:
            return str()
             
class Validate:
    
    def datetime(date_string):
        """ Validate datetime format """
        try:
            if not isinstance(date_string, str):
                raise TypeError('Argument must be string.')

            if len(date_string) != 14:
                raise ValueError(f'Invalid data length: {date_string!r}. Must be 14 digits.')
            
            pass

        except ValueError:
            return "Incorrect data format, should be YYYYMMDDHHMMSS"
        
def argument_spec_common():
    """ Base arguement spec to be included in every module """
    return dict(
        action = dict(
            type = 'str',
            required = True,
            choices = []
        ),
        debug = dict(
            type = 'bool',
            required = False,
            default = False
        ),
        debug_option = dict(
            type = 'str',
            required = False,
            choices = [
                'action',
                'action_items',
                'command',
                'output',
                'params',
                'spec'
            ]
        ),
        path = dict(
            type = 'path',
            required = False,
            default = COMMON_DEFAULTS['ejbca_home']
        ),
        return_output = dict(
            type = 'bool',
            required = False,
            default = True
        ),
    )
    
def slugify(str:str):
    str = str.lower().strip()
    str = re.sub(r'[^\w\s-]', '',str)
    str = re.sub(r'[\s_-]+', '_',str)
    str = re.sub(r'^-+|-+$', '',str)
    return str

def string_converter(str:str):
    """ Convert string to a type that matches a condition below """
    if str in ['true','false','True','False']:
        return eval(str.title())
    elif str.isnumeric():
        return int(str)
    else:
        return str
    
def str2bool(val:str):
    """ Convert string to bool if val is bool or returns value if not str """
    if isinstance(val, str):
        if val in ['true','True']:
            return True
        else:
            return False
    else:
        return val
    
def bool2str(val:bool):
    """ Convert bool to string if val is bool or returns value if not bool """
    if isinstance(val, bool):
        return str(val).lower()
    else:
        return val
