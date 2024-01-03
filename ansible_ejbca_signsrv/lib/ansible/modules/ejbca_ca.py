#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: ejbca_ca
description: This module provide json output for the EJBCA Shell CA command and sub-commands
author:
    - Jamie Garner (@jtgarner-keyfactor)
'''

import subprocess
import os
import sys
from subprocess import Popen, PIPE
from ansible.module_utils.basic import AnsibleModule



def required_arguments_spec():
    return dict(
        cmd = dict(
            type = 'str',
            required = True, 
            choices = [
                'changecatoken','createcrl','editca','exportca',
                'getcafield','importcacert','init','importcrl',
                'listcas','listpublishers','removepublisher','renewca'
            ]
        ),
        path = dict(
            required = False,
            type = 'str',
            default = '/opt/ejbca/bin/ejbca.sh'
        ),
    )

def optional_arguments_spec():
    return dict(
        args = dict(
            type = 'dict',
            required = False,
            options = dict(
                caname = dict(
                    type = 'str',
                    required = False
                ),
                field = dict(
                    descripton = 'CA Field',
                    type = 'str',
                    #choices = [k for k,v in ca_fields]
                    choices = [d for d,n,t in ca_fields]
                ),
                value = dict(
                    type = 'str',
                    default = '',
                    required = False
                ),
                date = dict(
                    type = 'int',
                    default = 0,
                    required = False
                ),
            )
        )
    )
    
def str2bool(val):
    if val in ['true','True']:
        return True
    else:
        return False


ca_fields = [
    # validated - requires succes getcafield and editca
    ('CaIssuerUri','authorityInformationAccess','list'),
    ('CRLIssueInterval','CRLIssueInterval','long'),
    ('CRLOverlapTime','CRLOverlapTime','long'),
    ('CrlExpirePeriod','CRLPeriod','long'),
    ('EnforceUniquePublicKeys','doEnforceUniquePublicKeys','boolean'),
    ('EnforceKeyRenewal','doEnforceKeyRenewal','boolean'),
    ('Status','status','int'),
    
    # need validation
    ('EnforceUniqueSubjectDn','doEnforceUniqueSubjectDNSerialnumber','boolean'),
    ('FinishUser','finishUser','boolean'),
    ('IncludeInHealthCheck','includeInHealthCheck','boolean'),
    ('OcspLocator','defaultOCSPServiceLocator','string'),
    ('ProfileId','certificateProfileId','int'),
    ('Publishers','CRLPublishers','collection'),
]
    
class EjbcaShell(object):
    
    def __init__(self, module, result, **kwargs):
        self.module = module
        self.result = result
        self.path = self.module.params['path']
        self.cmd = self.module.params['cmd']
        self.args = self.module.params['args']
        
        # add argument parameters if argument defined
        if self.args != None:
            self.caname = self.args['caname']
            self.field = self.args['field']
            self.field_name = ''.join(n for d,n,t in ca_fields if d == self.args['field'])
            self.value = self.args['value']
        
        # set base command for the shell
        self.command_base = f"{self.path} ca {self.cmd}"
        
    def _formatter(self, value):
        # get type from tuple for provided field name
        field_type = ''.join(t for d,n,t in ca_fields if d == self.field)
        output = value.split("'")[1].split("'")[0].strip()
        # get value between single quotes
        if field_type in ['long','boolean','int']:
            #output = value.split("'")[1].split("'")[0].strip()
            # convert output depending on type
            if field_type in ['long']:
                return int(output)
            elif field_type in ['boolean']:
                return str2bool(output)
            elif field_type in ['int'] and self.field_name in ['status']:
                if int(output) == 1:
                    return 'active'
                elif int(output) == 5:
                    return 'off-line'
                elif int(output) == 6:
                    return 'external'
                else:
                    return output
                
        else:
            # convert null to none
            if output == 'null' or len(output) == 0:
                return None
            else:
                return output
        
    def _millisecond_converter(self, value, reverse=False):
        if reverse:
            return dict(units={
                'days': int(value * 24 * 60 * 60 * 1000),
                'hours': int(value * 60 * 60 * 1000),
                'minutes': int(value * 60 * 1000),
            })
        else:
            return dict(units={
                'days': int(value / 1000 / 60 / 60 / 24),
                'hours': int(value / 1000 / 60/ 60),
                'minutes': int(value / 1000 / 60),
            })
        
    def _shell(self, options=None):
        if options != None: 
            # add whitepsace in front of options to account for none on provided variable
            self.command_base += f" {options}"
        #self.module.fail_json(msg=self.command_base)
        output = subprocess.run(
            self.command_base,
            shell=True,
            capture_output=True
        )
        if output.returncode != 0:
            # return stderr to execute function for return message
            if output.stderr:
                error = ''.join([e for e in output.stderr.decode().splitlines() if 'Exception' in e])
                return error, output.returncode
            # immediately return error message to console is stderr was not returned
            error = [e for e in output.stdout.decode().splitlines()]
            self.module.fail_json(
                failed= True,
                rc=output.returncode,
                msg=error
            )
        else:
            stdout_lines = iter(output.stdout.decode().splitlines())
            return stdout_lines, output.returncode 
        
    # commands
    def _create_crl(self, output):
        for line in output:
            if 'generated' in line:
                return line.split('number')[1].split('generated')[0].strip()

    def _edit_ca(self, output):
        for line in output:
            if F"Current value of {self.field_name}" in line:
                current = self._formatter(line)
            if F"{self.field_name} returned value" in line:
                new = self._formatter(line)
        return current, new
        
    def _get_ca_field(self, output):
        for line in output:
            if self.field_name in line:
                return self._formatter(line)

    def _list_cas(self, output):
        results = []
        for line in output:
            if ('CA Name' in line):
                ca = {}
                ca['name'] = line.replace('CA Name:','').strip()
                ca['id'] = int(next(output).replace('Id:','').strip())
                ca['issuer_dn'] = next(output).replace('Issuer DN:','').strip()
                ca['subject_dn'] = next(output).replace('Subject DN:','').strip()
                ca['type'] = int(next(output).replace('Type:','').strip())
                ca['expire'] = next(output).replace('Expire time:','').strip()
                ca['signed_by'] = int(next(output).replace('Signed by:','').strip())
                results.append(ca) 
        return results
    
    def execute(self):
        if self.cmd == 'createcrl':
            output,rc = self._shell(f"--caname {self.caname}")
            return dict(
                crl = dict(
                    ca = self.caname,
                    number = self._create_crl(output)
                )
            )
        elif self.cmd == 'editca':
            output,rc = self._shell(f"--caname {self.caname} --field {self.field_name} --value {self.value}")
            if rc != 0:
                if 'java.lang.NullPointerException' in output:
                    error = f"{self.caname} does not exist"

                return dict(
                    failed = True,
                    rc = rc,
                    msg = error
                )
            current,new = self._edit_ca(output) 
            changed = True if current != new else False
            return dict(
                changed = changed,
                values = dict(
                    name = self.field_name,
                    current = current,
                    new = new
                )
            )
        elif self.cmd == 'getcafield':
            output,rc = self._shell(f"--caname {self.caname} --field {self.field_name}")
            return dict(
                field = dict(
                    name = self.field_name,
                    value = self._get_ca_field(output)
                )
            )
        elif self.cmd == 'listcas':
            output,rc = self._shell()
            return dict(
                cas = self._list_cas(output)
            )      
    
def run_module():

    # initialize reults dict
    result = dict(
        changed=False,
        failed=False,
        rc=0
    )
    
    #module_args['args'].update()
    module_args = required_arguments_spec()
    module_args.update(optional_arguments_spec())
    module = AnsibleModule(
        argument_spec = module_args,
        supports_check_mode = True,
        required_if = [
            ('cmd', 'createcrl', ['args']),
            ('cmd', 'editca', ['args']),
            ('cmd', 'getcafield', ['args']),
        ],
    )
    
    if module.check_mode:
        module.exit_json(**result)
        
    # check shell path
    if not os.path.exists(module.params['path']):
        module.fail_json(msg='The provide ejbca.sh path is not valid')
        
    if module.params['cmd'] == 'createcrl':
        module.fail_on_missing_params(required_params=[
            f for f in ['caname'] if f not in module.params['args']
        ])
        
    if module.params['cmd'] == 'editca':
        module.fail_on_missing_params(required_params=[
            f for f in ['caname','field','value'] if f not in module.params['args'] 
        ])

    if module.params['cmd'] == 'getcafield':
        module.fail_on_missing_params(required_params=[
            f for f in ['caname','field'] if f not in module.params['args'] 
        ])
        
    # return 
    command = EjbcaShell(module,result)
    result.update(command.execute())
    module.exit_json(**result)

def main():
    run_module()


if __name__ == '__main__':
    main()