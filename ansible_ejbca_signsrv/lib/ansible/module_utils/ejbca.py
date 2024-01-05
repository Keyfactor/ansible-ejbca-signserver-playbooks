#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import subprocess
import re
import os

class EjbcaCli(object):
    def __init__(self, module): 
        try:
            # create attributes for all module params
            for key in module.params:
                setattr(self, key, module.params[key])
                
            # ejbca path validation
            if os.path.exists(self.path):
                self.path+='/bin/ejbca.sh'
            else:
                module.fail_json(msg=f"The provided path {self.path} does not exist.")
            
            # create base
            self.command=f"{self.path} {self.category}"
            
            # add command if defined in the parameters
            if getattr(self,'cmd',False):
                self.command+=f" {self.cmd}"
                
        except:
            raise KeyError
            
        # initialize result dictinary and changed variable for each method to update
        self.result={}
        self.rc=0
        self.changed=False
        self.failed=False
        self.stdout_lines=[]
        self.stderr_lines=[]
        
        # initialize empty args for adding in execute function
        self.args=str()
        
        # condition evalution matches
        self.condition_ok=['already']
        self.condition_exists=['already exists']
        self.condition_changed=['successfully']
        self.condition_failed=['ERROR','failed','Failure']
        self.condition_exception=None
        
        # initialize fail_json condition return status
        self.condition_failed_msg=str()
    
    def _algorithm_parser(self, val):
        for k in key_algorithms():
            m=re.search(k, val)
            if m != None:
                return m.group()
            else:
                return None
        
    def _check_result(self,output,rc=1):
        # create matching conditions from lists
        condition_ok='|'.join(self.condition_ok)
        condition_exists='|'.join(self.condition_exists)
        condition_changed='|'.join(self.condition_changed)
        condition_failed='|'.join(self.condition_failed)
        
        # initialize result dict
        modify_result=dict(success=False)
        for line in output:
            
            # return ok so task doesnt fail
            if re.findall(condition_ok,line): 
                self.rc=rc
                self.stdout_lines.append(line.strip())
                if re.findall(condition_exists,line):
                    modify_result.update(exists=True)            

            # successful
            elif re.findall(condition_changed,line): 
                self.changed=True
                modify_result.update(success=True)
                self.stdout_lines.append(line)
                id=StringParser(line).id()
                if id != None:
                    modify_result.update(id=int(id))
                
            # failed
            elif re.findall(condition_failed,line):
                self.rc=rc
                self.failed=True
                #self.module.fail_json(msg=self.condition_failed_msg)
                modify_result.update(success=False)
                for l in output:
                    self.stderr_lines.append(l)
                return modify_result
            
            else:
                if rc == 0:
                    self.stdout_lines.append(line.strip())
                else:
                    self.stderr_lines.append(line.strip())
        
        # return updated dictionary
        return modify_result
    
    def _return_results(self):
        self.result.update(
            rc=self.rc,
            failed=self.failed,
            changed=self.changed,
            stdout_lines=self.stdout_lines,
            stderr_lines=self.stderr_lines,
        )
        return self.result
    
    def _shell(self,options=None,command=None):
        if command is None:
            command=self.command
        if options: 
            command+=options
        
        #self.module.fail_json(msg=command)
        rc,stdout,stderr=self.module.run_command(
            args=command
        )
        #self.module.fail_json(msg=stdout)
        if stderr:
            stderr_parser=StderrParser()
            exception=stderr_parser.java_exception(stderr.splitlines())
            if exception:
                self.module.fail_json(msg=exception)
            else:
                return stderr,rc
        else:
            return stdout,rc
    
class AttributeParser:

    @staticmethod
    def distinguished_name(str):
        """ Parse DN using regex and if n/a in string, pass to comma function for parsing. """
            
        regex=r'"CN=(.*?)"'
        if 'n/a' in str:
            return StringParser(str).comma()
        else:
            string_match=re.search(regex, str)
            if string_match != None:
                return string_match.group(0).split('"')[1].split('"')[0]
        return None  
    
    @staticmethod
    def id(str):
        """ Parse ID using regex and if n/a in string, pass to comma function for parsing. """

        regex=r'\([^\d]*(\d+)[^\d]*\)'
        match=re.search(regex,str)
        if match != None:
            return StringParser(str).parenthesis()
        
    @staticmethod
    def serial_hex(str):
        regex=r'/[0-9a-fA-F]+/'
        string_match=re.search(regex, str)
        if string_match != None:
            return string_match.group(0).strip()
        
class StderrParser:
    """ Parse stderr lines f"""
    
    @staticmethod
    def java_exception(lines):
       for e in lines:
           if 'NullPointerException' in e:
               return e
           elif 'Exception' in e:
               return e.rsplit('Exception:',1)[1].strip() 

class StringParser(str):
    
    def colon(self,before=False):
        """ Gets boolean value after equal symbol """
        if before:
            string=self.strip(' \n\t').split(':')[0].strip()
        else:
            string=self.split(':')[1].split()[0].strip()
        return string_converter(string)
    
    def comma(self,match=False):
        """ Gets value between first set of commas """
        if match:
            regex=r',(.*?),'
            regex_match=re.findall(regex, self)
            if regex_match != None:
                return regex_match.group(0).split(',')[1].split(',')[0]
        
        return self.split(',')[1].split(',')[0].strip()
    
    def dict_key(self,match=None):
        string=self.split(':')[0].strip().replace(' ','_').lower()
        return slugify(string)

    def equal_sign(self,before=False):
        """ Gets boolean value after equal symbol """
        if before:
            string=self.strip(' \n\t').split('=')[0].strip()
        else:
            string=self.split('=')[1].split()[0].strip()
        return string_converter(string)
    
    def id(self):
        """ Parse ID using regex and if n/a in string, pass to comma function for parsing. """

        regex=r'-?\b\d{9,10}\b'
        string_match=re.search(regex,self)
        if string_match != None:
            return string_match.group(0).strip()

            
    def int(self):
        """ Gets number value from line """
        
        match=re.search(r'[0-9]+', self)
        if match != None:
            return int(match.group(0))
        
    def list(self,list=None):
        """ Gets matched string from list """
        
        search_string='|'.join(list)
        match=re.search(search_string,self)
        if match != None:
            return str(match.group(0))

    def parenthesis(self,match=False):
        """ Gets string between first set of commas """
        
        if match:
            regex=r'\((.+)\)'
            string_match=re.search(regex, self)
            if string_match != None:
                return string_match.group(0).split('(')[1].split(')')[0]
            
        return self.split('(')[1].split(')')[0]
    
    def split_strip(self,delimeter,before=True):
        """ Splits line, before or after, delimeter and strips leading and trailing whitespace """
        
        if before:
            string=''.join(self.split(delimeter)[0])
        else:
            string=''.join(self.split(delimeter)[1])
        return string.lstrip().strip()
            
    def tuple(self,tuple:tuple):
        """ Parses string using tuple as start and end index values """
        
        return self.split(tuple[0])[1].split(tuple[1])[0].lstrip().strip()
    
    def quotes(self,match=False):
        """ Gets value between first set of commas """

        regex=r'"(.*?)"'
        string_match=re.search(regex, self)
        if string_match != None:
            return string_match.group(0).split('"')[1].split('"')[0]
        else:
            #return None
            return self

    
def crypto_token_types():
    return [
        'AzureCryptoToken',
        'AWSKMSCryptoToken',
        'FortanixCryptoToken',
        'Pkcs11NgCryptoToken',
        'PKCS11CryptoToken',
        'SoftCryptoToken',
    ]  
    
def ee_statuses():
    return [
        ('NEW','10'),
        ('FAILED','11'),
        ('INITIALIZED','20'),
        ('INPROCESS','30'),
        ('GENERATED','40'),
        ('HISTORICAL','40'),
    ]  
    
def ee_token_types():
    return [
        'USERGENERATED','P12',
        'JKS','PEM','BCFKS'
    ]  
    
def key_algorithms():
    return [
        'RSA','ECDSA',
        'Ed448','Ed25519',
        'FALCON-512','FALCON-1024',
        'DILITHIUM2','DILITHIUM3','DILITHIUM5'
    ]  
    
def revocation_reasons():
    return [
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
    ]  

def sign_algorithms():
    return [
        'SHA1WithRSA','SHA256WithRSA','SHA384WithRSA','SHA512WithRSA','SHA3-256withRSA','SHA3-384withRSA','SHA3-512withRSA','SHA256withRSAandMGF1','SHA384withRSAandMGF1','SHA512withRSAandMGF1','SHA1withECDSA','SHA224withECDSA','SHA256withECDSA','SHA384withECDSA','SHA512withECDS',
        'SHA3-256withECDSA','SHA3-384withECDSA','SHA3-512withECDSA','SHA1WithDSA','SHA256WithDSA','Ed25519','Ed448','FALCON-512','FALCON-1024',
        'DIITHIUM2','DILITHIUM3','DILITHIUM5','LMS'
    ]
    
def slot_ref_types():
    return [
        'SLOT_NUMBER',
        'SLOT_LABEL',
        'SLOT_INDEX'
    ]

def slugify(str):
    str=str.lower().strip()
    str=re.sub(r'[^\w\s-]', '',str)
    str=re.sub(r'[\s_-]+', '_',str)
    str=re.sub(r'^-+|-+$', '',str)
    return str

def string_converter(str:str):
    """ Convert string to a type that matches a condition below """
    if str in ['true','false','True','False']:
        return eval(str.title())
    elif str.isnumeric():
        return int(str)
    else:
        return str
    
def bool2str(val):
    """ Convert bool to string if val is bool or returns value if not bool """
    if isinstance(val, bool):
        return str(val).lower()
    else:
        return val