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
                
            # create base command
            self.command=f"{self.path} {self.category} {self.cmd}"
                
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
        
        self.condition_changed=['successfully']
        self.condition_ok=['already']
        self.condition_failed=['failed']
        self.condition_exception=None
    
    def _algorithm_parser(self, val):
        for k in key_algorithms():
            m=re.search(k, val)
            if m != None:
                return m.group()
            else:
                return None
        
    def _check_result(self,output,rc=1):
        # create matching conditions from lists
        self.condition_ok='|'.join(self.condition_ok)
        self.condition_changed='|'.join(self.condition_changed)
        self.condition_failed='|'.join(self.condition_failed)
        
        # initialize result dict
        modify_result=dict(success=False)
        for line in output:
            parser=StringParser(line)
            
            # return ok so task doesnt fail
            if re.findall(self.condition_ok,line): 
                self.rc=rc
                id=parser.id()
                if id !=None:
                    modify_result.update(id=int(id))
                self.stdout_lines.append(line)

            # successful
            elif re.findall(self.condition_changed,line): 
                self.changed=True
                modify_result.update(success=True)
                # add id to dict if exists in stdout line
                id=parser.id()
                if id !=None:
                    modify_result.update(id=int(id))
                
                # add line to stdout
                self.stdout_lines.append(line)
                
            # failed
            elif re.findall(self.condition_failed,line):
                self.rc=1
                self.failed=True
                modify_result.update(success=False)
                for l in output:
                    self.stderr_lines.append(l)
                return modify_result
                
            # catch all remaining lines and add to stderr/stdout
            else:
                if self.rc == 0 and self.return_output:
                    self.stdout_lines.append(line.strip())
                else:
                    self.module.fail_json(msg=line.strip())
        
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
    
    def _shell(self, options=None):
        if options: 
            self.command+=options

        #self.module.fail_json(msg=self.command)
        rc,stdout,stderr=self.module.run_command(
            args=self.command
        )
        #self.module.fail_json(msg=stdout)
        if stderr:
            stderr_parser=StderrParser()
            #self.module.fail_json(msg=stderr)
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
    
    def equal_sign(self,before=False):
        """ Gets boolean value after equal symbol """
        if before:
            string=self.strip(' \n\t').split('=')[0].strip()
        else:
            string=self.split('=')[1].split()[0].strip()
        return string_converter(string)
    
    def id(self):
        """ Parse ID using regex and if n/a in string, pass to comma function for parsing. """

        #regex=r'\([^\d]*(\d+)[^\d]*\)'
        regex=r'-?\b\d{9,10}\b'
        string_match=re.search(regex,self)
        if string_match != None:
            return string_match.group(0).strip()
            #return str.strip()
            #return StringParser(str).parenthesis()
        
    def list(self,list=None):
        """ Gets matched string from list """
        
        match=''.join([m for m in list if re.search(m, self)])
        if match != None:
            return match
    
    def parenthesis(self,match=False):
        """ Gets string between first set of commas """
        
        if match:
            regex=r'\((.+)\)'
            string_match=re.search(regex, self)
            if string_match != None:
                return string_match.group(0).split('(')[1].split(')')[0]
            
        return self.split('(')[1].split(')')[0]
    
    def tuple(self,tuple:tuple):
        """ Parses string using tuple as start and end index values """
        
        
        return self.split(tuple[0])[1].split(tuple[1])[0].strip()
    
    def quotes(self,match=False):
        """ Gets value between first set of commas """
        
        # if match:
        #     regex=r'"(.*?)"'
        #     string_match=re.search(regex, self)
        #     if string_match != None:
        #         return string_match.group(0).split('"')[1].split('"')[0]
        # return self.split('"')[1].split('"')[0]
    
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
    
def validate_cli_path(cli_path):
    if os.path.exists(cli_path):
        
        # check if path is a directory
        # return provided path if path is the binary
        # if binary was not provide, update cli_path and check for existence
        if os.path.isdir(cli_path):
            cli_path+='/bin/ejbca.sh'
            
            if not os.path.exists(cli_path):
                return False
    
        return cli_path
    
    return False

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