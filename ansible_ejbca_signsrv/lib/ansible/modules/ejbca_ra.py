#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ejbca_ra
description: This module emulates the ra category of the EJBCA CLI.
author:
    - Jamie Garner (@jtgarner-keyfactor)
'''

import re
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ejbca import (
    EjbcaCli,
    AttributeParser,
    StringParser,
    ee_statuses,
    ee_token_types,
    revocation_reasons
)

def choices_actions():
    return [
        # supported
        'addendentity','delendentity','findendentity','resetendentity',
        'setpwd','setendentitystatus'
        # in progress
        # 'getendentitycert',
        # 'revokecert','revokeendentity','setclearpwd',
        # 'setsubjectdirattr'
    ]

def choices_type():
    return [
        0,1,256,512
    ]

def spec_main():
    return dict(
        cmd=dict(
            required=True,
            type='str',
            choices=[k for k in choices_actions()]
        ),
        cert_profile=dict(type='str'),
        ee_profile=dict(type='str'),
        force_reset=dict(
            default=True,
            type='bool'
        ),
        issuing_ca=dict(type='str'),
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
        revoke_active=dict(
            default=False,
            type='bool'
        ),
        revoke_reason=dict(
            default='unspecified',
            type='str',
            choices=[k for k,v in revocation_reasons()]
        ),
        subject_dn=dict(type='str'),
        status=dict(
            default='NEW',
            type='str',
            choices=[k for k,v in ee_statuses()]
        ),
        token=dict(
            type='str',
            choices=[k for k in ee_token_types()]
        ),
        type=dict(
            type='int',
            choices=[k for k in choices_type()]
        ),
        username=dict(type='str')
    )
    
class EjbcaRa(EjbcaCli):
    
    def __init__(self, module):
        self.module=module
        self.category='ra'
        super().__init__(module)
        
        # get matching number value for provided status and convert to integer
        self.status_value=int(''.join([v for k,v in ee_statuses() if self.status == k]))
        self.revoke_reason_value=int(''.join([v for k,v in revocation_reasons() if self.revoke_reason == k]))
        
        self.command_base=f"{self.path} {self.category}"
        
        #self.module.fail_json(msg=self.status_value)
        
        # if self.cmd in ['resetendentity']:
        #     self.command=f"{self.path} {self.category}"

    def _parser_findendentity(self,output,rc=1):
        entity_dict=dict(
            exists=False
        )
        self.parser = AttributeParser()
        for line in output:
            if ('Found end entity') in line:
                self.changed=True
                entity_dict['exists']=True
                for ee in output:
                    k=StringParser(ee).dict_key()
                    v=ee.split(':')[1].strip()
                    entity_dict[k]=v
                    self.stdout_lines.append(ee)
                return entity_dict
            
            else:
                self.stdout_lines.append(line)
                entity_dict['exists']=False
                return entity_dict

    def _revokeendentity(self):
        self.condition_changed=['New status=50']
        return str(
            f' {self.command_base} revokeendentity'
            f' --username "{self.username}"'
            f' -r {self.revoke_reason_value}'
        )
    
    def _setpwd(self):
        self.condition_changed=['Setting password']
        return str(
            f' {self.command_base} setpwd'
            f' --username "{self.username}"'
            f' --password "{self.password}"'
        )
        
    def _setendentitystatus(self):
        self.condition_changed=['New status for end entity']
        return str(
            f' {self.command_base} setendentitystatus'
            f' --username "{self.username}"'
            f' -S "{self.status_value}"'
        )
 
    def execute(self):
        cmd_results=dict(username=self.username)
        try:
            args=(
                f' --username "{self.username}"'
            )
            
            if self.cmd in ['addendentity']:
                self.condition_ok=['already exists']
                self.condition_changed=['has been added']

                # build full args string
                args+=(
                    f' --certprofile "{self.cert_profile}"'
                    f' --dn "{self.subject_dn}"'
                    f' --eeprofile "{self.ee_profile}"'
                    f' --caname "{self.issuing_ca}"'
                    f' --password "{self.password}"'
                    f' --type {self.type}'
                    f' --token {self.token}'
                )
                    
                output,rc=self._shell(args)                
                self.result[self.cmd]=self._check_result(output.splitlines(),rc)
                self.result[self.cmd].update(
                    username=self.username
                )

            elif self.cmd in ['findendentity']:
                output,rc=self._shell(args)
                self.result.update(entity=self._parser_findendentity(output.splitlines()))
                
            elif self.cmd in ['resetendentity']:
                
                # revoke certificates
                if self.revoke_active:
                    output,rc=self._shell(command=self._revokeendentity())
                    if self._check_result(output.splitlines(),rc)['success']:
                        cmd_results['revoked_certs']=True
                
                # reset password
                output,rc=self._shell(command=self._setpwd())
                if self._check_result(output.splitlines(),rc)['success']:
                    cmd_results['reset_pwd']=True

                # reset status
                output,rc=self._shell(command=self._setendentitystatus())
                if self._check_result(output.splitlines(),rc)['success']:
                    cmd_results['status']=self.status_value
                
                self.result[self.cmd]=cmd_results
        
            else:
                
                if self.cmd in ['delendentity']:
                    self.condition_ok=['No such end entity']
                    self.condition_changed=['Deleted end entity with username']
                    self.args+=(
                        ' -force'
                    )
                    
                elif self.cmd in ['setpwd']:
                    output,rc=self._shell(command=self._setpwd())
                    
                elif self.cmd in ['setendentitystatus']:
                    output,rc=self._shell(command=self._setendentitystatus())

                self.result[self.cmd]=self._check_result(output.splitlines(),rc)
                

            return self._return_results()
            
        except ValueError as e:
            self.module.fail_json(msg='test')
            self.module.fail_json(msg=e)
            
def run_module():

    module_args = spec_main()
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('cmd','addendentity',['cert_profile','ee_profile','issuing_ca','password','subject_dn','type','token','username']),
            ('cmd','delendentity',['username']),
            ('cmd','findendentity',['username']),
            ('cmd','resetendentity',['username','password']),
        ]
    )
    
    if module.check_mode:
        module.exit_json(**result)
        
    # return 
    command=EjbcaRa(module)
    result=command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()