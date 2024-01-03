#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ejbca_createcert
description: This module emulates the createcert category of the EJBCA CLI.
author:
    - Jamie Garner (@jtgarner-keyfactor)
'''

import re
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ejbca import (
    EjbcaCli,
    AttributeParser,
    StringParser,
    ee_token_types,
    bool2str
)

def choices_type():
    return [
        0,1,256,512
    ]

def spec_main():
    return dict(
        username=dict(type='str')
        password=dict(
            type='str',
            no_log=False
        ),
        path=dict(
            required=True,
            type='str',
        ),
        return_output=dict(
            default=True,
            type='bool'
        ),
        cert=dict(type='str'),
        csr=dict(
            type='str',
            choices=[k for k in ee_token_types()]
        ),
        type=dict(
            type='int',
            choices=[k for k in choices_type()]
        ),
        
    )
    
class EjbcaCryptoToken(EjbcaCli):
    
    def __init__(self, module):
        self.module=module
        self.category='ra'
        super().__init__(module)
        
    # def _parser_find(self,output,rc=1):
    #     entity={}
    #     self.parser = AttributeParser()
    #     for line in output:
    #         if ('Found end entity' in line):
    #             entity['username'] = line.replace('CA Name:','').strip()
    #             entity['dn'] = int(next(output).replace('Id:','').strip())
    #             entity['alt_name'] = next(output).replace('Issuer DN:','').strip()
    #             entity['directory_attributes'] = next(output).replace('Subject DN:','').strip()
    #             entity['email'] = int(next(output).replace('Type:','').strip())
    #             entity['status'] = next(output).replace('Expire time:','').strip()
    #             entity['type'] = int(next(output).replace('Signed by:','').strip())
    #             entity['token_type'] = int(next(output).replace('Signed by:','').strip())
    #             entity['eep'] = int(next(output).replace('Signed by:','').strip())
    #             entity['cp'] = int(next(output).replace('Signed by:','').strip())
    #             entity['created'] = int(next(output).replace('Signed by:','').strip())
    #             entity['modified'] = int(next(output).replace('Signed by:','').strip())
    #     return entity
                
    def execute(self):
        try:
            self.args+= (
                f' --username "{self.username}"'
            )
            if self.cmd in ['findendentity']:
                self.result.update(tokens=self._parser_find(iter(output.splitlines())))
            
            else:
                
                if self.cmd in ['delendentity']:
                    self.condition_ok=['No such end entity']
                    self.condition_changed=['Deleted end entity with username']
                    self.args+=(
                        ' -force'
                    )
                    
                elif self.cmd in ['addendentity']:
                    self.condition_changed=['has been added']
                    # optinal parameters
                    cert_profile=(
                        f' --certprofile "{self.cp}"' if self.cp != None else ''
                    )
                    ee_profile=(
                        f' --eeprofile "{self.eep}"' if self.eep != None else ''
                    )
                    # build full args string
                    self.args+= (
                        f' --caname "{self.caname}"'
                        f' --dn "{self.subject_dn}"'
                        f' --type {self.type}'
                        f' --token {self.token}'
                        f' --password {self.password}'
                        f'{cert_profile}'
                        f'{ee_profile}'
                    )
                        
                output,rc=self._shell(self.args)
                self.result[self.cmd]=self._check_result(output.splitlines(),rc)

            return self._return_results()
            
        except ValueError as e:
            self.module.fail_json(msg=e)
            
def run_module():

    module_args = spec_main()
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('cmd','addendentity',['caname','password','subject_dn','type','token','username']),
            ('cmd','delendentity',['username']),
            ('cmd','findendentity',['username']),
        ]
    )
    
    if module.check_mode:
        module.exit_json(**result)
        
    # return 
    command = EjbcaCryptoToken(module)
    result=command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()