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

import os
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ejbca import (
    EjbcaCli
)

def spec_main():
    return dict(
        cert=dict(
            required=True,
            type='path'
        ),
        csr=dict(
            required=True,
            type='path'
        ),
        password=dict(
            required=True,
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
        username=dict(type='str'),
    )
    
class EjbcaCreateCert(EjbcaCli):
    
    def __init__(self, module):
        self.module=module
        self.category='createcert'
        super().__init__(module)

    def execute(self):
        try:
            self.condition_failed=['Could not create certificate']
            #self.condition_ok=['Got request with status GENERATED']
            self.condition_changed=['certificate written to file']
            self.args+= (
                f' --username "{self.username}"'
                f' --password "{self.password}"'
                f' -c {self.csr}'
                f' -f {self.cert}'
            )

            output,rc=self._shell(self.args)
            self.result['createcert']=self._check_result(output.splitlines(),rc)

            return self._return_results()
            
        except ValueError as e:
            self.module.fail_json(msg=e)
            
def run_module():

    module_args = spec_main()
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )
    
    if module.check_mode:
        module.exit_json(**result)
        
     # validate output/input file path
    if os.path.isdir(module.params['cert']):
        module.fail_json(msg=f"{module.params['cert']} is a directory. A file path to output the signed certificate is required.")
            
    if os.path.isdir(module.params['csr']):
        module.fail_json(msg=f"{module.params['csr']} is a directory. A file path to a PEM encoded PKCS#10 is required.")
        
    # return 
    command=EjbcaCreateCert(module)
    result=command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()