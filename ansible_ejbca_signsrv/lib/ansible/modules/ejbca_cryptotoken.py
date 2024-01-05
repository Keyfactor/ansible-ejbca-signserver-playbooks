#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ejbca_cryptotoken
description: This module emulates the cryptotoken category of the EJBCA CLI.
author:
    - Jamie Garner (@jtgarner-keyfactor)
options:
    auto:
        description: Auto-activate switch for cryptotoken
        default: false
        type: bool 
    cmd:
        description: CLI command to execute
        required: true
        type: str
        choices:
            - activate
            - create
            - delete
            - deactivate
            - generatekey
            - list
            - listkeys
            - removekey
            - testkey
    config_akv:
        description: Azure Key Vault parameeters when created a cryptotoken. Requeired when 'type' is 'akv'
        type: dict
        options:
            client_id:
                description: ''
                required: true
                type: str
            keybinding_name:
                description: ''
                type: str
            premium:
                description: ''
                required: true
                type: bool
            vault_name:
                description: ''
                required: true
                type: str
    config_fortanix:
        description: ''
        required: false
        type: dict
        options:
            dms_api_addr:
                description: ''
                type: str

    config_kms:
        description: ''
        type: dict
        options:
            access_key_id:
                description: ''
                required: true
                type: str
            optional:
                description: ''
                required: false
                type: str
            region:
                description: ''
                required: true
                type: str
    config_pkcs11:
        description: ''
        type: dict
        options:
            attr:
                description: ''
                type: str
            force_used_slots:
                description: ''
                default: false
                type: bool
            lib:
                description: ''
                type: path
            name:
                description: ''
                type: str
            slot_ref:
                description: ''
                type: str
            slot_ref_type:
                description: ''
                required: true
                type: str
                choices:
                    - SLOT_NUMBER
                    - SLOT_LABEL
    config_soft:
        description: ''
        type: dict
        options:
            exportable_keys:
                description: ''
                default: false
                type: bool
        
    key:
        description: ''
        type: dict
        options:
            alias:
                description: ''
                required: true
                type: str
            spec:
                description: ''
                type: str
        path:
            description: ''
            required: true
            type: str
        pin:
            description: ''
            type: str
        stdout:
            description: ''
            default: false
            type: bool
            
        token:
            description: ''
            type: str
        type:
            description: ''
            type: str
            choices:
                - akv
                - kms
                - fortanix
                - p11ng
                - pkcs11
                - soft
            
'''

RETURN = r'''
key:
    description: Dictionary containing results of key operations commands
    returned: generatekey, removekey, testkey
    type: dict
    contains:
        exists:
            description: Status of testkey command
            returned: always
            type: bool
            default: false
        generated:
            description: Status of generatekey command
            returned: always
            type: bool
            default: false
        removed:
            description: Status of removekey command
            returned: always
            type: bool
            default: false
    sample:
        - exists: False
          generated: True
          removed: False

keys:
    description: List containing all the keys in a cryptotoken
    returned: listkeys
    type: dict
    contains:
        algorithm:
            description: Key algorithm.
            type: str
        alias:
            description: Alias of the key in the cryptotoken and HSM.
            type: str
        skid:
            description: Subject Key Identifier. Derived from the private key.
            type: str
        specification:
            description: Key specification.
            type: str
    sample:
        - algorithm: RSA
          alias: signKey
          skid: e10e765ae9dc367766bcd4dce0a2aea915f8ab3a
          specification: 4096
        - algorithm: RSA
          alias: defaultKey
          skid: 9a2dbbe82f3c8d5c6b5e268e8288d2c5fd0e8550
          specification: 4096
        
token:
    description: List containing results of key operations
    returned: activated, created, deactivated, deleted
    type: dict
    contains:
        activated:
            description: Status of activate command
            returned: always
            type: bool
            default: false
        created:
            description: Status of create command
            returned: always
            type: bool
            default: false
        deactivated:
            description: Status of deactivate command
            returned: always
            type: bool
            default: false
        deactivated:
            description: Status of deactivate command
            returned: always
            type: bool
            default: false
        deactivated:
            description: Status of deactivate command
            returned: always
            type: bool
            default: false
        id:
            description: Cryptotoken identifier
            returned: create
            type: str
            default: ''
    sample:
        - activated: False
          created: True
          deactivated: False
          deleted: False
          exists: False
          id: False
          
tokens:
    description: List containing all the cryptotokens in EJBCA
    returned: list
    type: dict
    contains:
        active:
            description: If the token is activated
            type: str
        auto_activate:
            description: If the token should return to an active after becoming inactive
            type: bool
        exportable_keys:
            description: If the private keys are marked as exportable when generated
            type: bool
        id:
            description: Cryptotoken identifier
            type: str
        name:
            description: Cryptotoken name
            type: str
    sample:
        - active: true
          auto_activate: true
          exportable_keys: false
          id: 1761002431
          name: IssuingCA
        - active: true
          auto_activate: true
          exportable_keys: false
          id: -1642218340
          name: ManagementCA
        - active: false
          auto_activate: false
          exportable_keys: false
          id: 1068339725
          name: RootCA
          
stderr_lines:
    description: CLI error output. Not all errors will return a Failed. Some commands, such as generatekey, will be returned OK even though the CLI error output has a returncode of 1.
    returned: always
    type: list
    elements: str
    sample:
        - Key pair generation failed: alias signKeyTest1 is in use
    
stdout_lines:
    description: CLI standard output
    returned: always
    type: list
    elements: str
    sample:
        - CryptoToken deleted successfully
'''

import re
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ejbca import (
    EjbcaCli,
    AttributeParser,
    StringParser,
    crypto_token_types,
    slot_ref_types,
    bool2str
)

def spec_main():
    return dict(
        cmd=dict(
            required=True,
            type='str',
            choices=[
                'activate','create','delete','deactivate',
                'generatekey','list','listkeys','removekey',
                'testkey'
            ]
        ),
        config=dict(
            type='dict',
            apply_defaults=True,
            options=dict(
                attr=dict(type='str'),
                auto=dict(
                    default=True,
                    type='bool'
                ),
                azure_client_id=dict(type='str'),
                azure_keybinding_name=dict(type='str'),
                azure_vault_name=dict(type='str'),
                azure_vault_premium=dict(
                    default=True,
                    type='bool'
                ),
                exportable_keys=dict(type='bool'),
                fortanix_dms_api_addr=dict(type='str'),
                force_used_slots=dict(
                    default=True,
                    type='bool'
                ),
                kms_access_key_id=dict(type='str'),
                kms_region=dict(type='str'),
                lib=dict(type='path'),
                slot_ref=dict(type='str'),
                slot_ref_type=dict(
                    type='str',
                    choices=[k for k in slot_ref_types()]
                ),
            ),
            required_together=[
                ('lib','slot_ref','slot_ref_type'),
                ('kms_access_key_id','kms_region'),
                ('azure_client_id','azure_keybinding_name','azure_vault_name')
            ],
        ),
        key_alias=dict(type='str'),
        key_spec=dict(type='str'),
        path=dict(
            required=True,
            type='str',
        ),
        pin=dict(type='str'),
        return_output=dict(
            default=True,
            type='bool'
        ),
        token=dict(type='str'),
        type=dict(
            default='SoftCryptoToken',
            type='str',
            choices=[k for k in crypto_token_types()]
        ),
    )
    
class EjbcaCryptoToken(EjbcaCli):
    
    def __init__(self, module):
        self.module=module
        self.category='cryptotoken'
        super().__init__(module)
        
        # update the default failed string
        # can be updated again for each operation is necessary
        self.condition_failed.append('You need to activate the CryptoToken before you can interact with its content')

    def _parser_key_list(self,output):
        key_list=[]
        for line in output:
            if ('ALIAS' in line):
                for t in output:
                    # use algorithm regex to define the different key attributes
                    algorithm = self._algorithm_parser(t)
                    keys=dict(
                        # get first value before algorithm
                        alias=t.split(algorithm)[0].strip(),
                        algorithm=algorithm,
                        # get first value after algorithm
                        # split on space between expected specification and skid values
                        # assume first split index is specification and second split index is skid 
                        specification=t.split(algorithm,1)[1].strip().split(' ')[0],
                        skid=t.split(algorithm,1)[1].strip().split(' ')[1]
                    )
                    key_list.append(keys)
                    
                    # zeroize list if no keys exist
                    if 'CryptoToken does not contain any key pairs' in t:
                        key_list.clear()
                    else:
                        self.changed=True
                    
                    if self.return_output:
                        self.stdout_lines.append(t.strip())
                    
        return key_list

    def _parser_token_list(self,output):
        token_list=[]
        self.parser = AttributeParser()
        for line in output:
            if ("NAME" in line):
                for t in output:
                    self.changed=True
                    token=dict(
                        name=StringParser(t).quotes(),
                        id=self.parser.id(t),
                        active=True if re.search('active',t) != None else False,
                        auto_activate=True if re.search('auto',t) != None else False,
                        exportable_keys=False if re.search('non-exportable',t) != None else True
                    )
                    token_list.append(token)
                    
                    if self.return_output:
                        self.stdout_lines.append(t.strip())
                    
        return token_list

    def execute(self):
        try:
            # dictionary building from parsing output
            # cannot use the main key and token parsers
            if self.cmd in ['list','listkeys']:
                
                # add the token argument if listkeys
                if self.cmd in ['listkeys']:
                    self.args+=(
                        f' --token "{self.token}"'
                    )
                
                # submit command
                output=self._shell(self.args)
                
                # parse output
                if self.cmd in ['list']:
                    self.result.update(tokens=self._parser_token_list(iter(output.splitlines())))
                else:
                    self.result.update(keys=self._parser_key_list(iter(output.splitlines())))
                    
            else:
                self.args=(
                    f' --token "{self.token}"'
                )
                    
                if self.cmd in ['create','deactivate','delete','activate']:
                    if self.cmd in ['activate']:
                        self.args+=f" --pin {self.pin}" 

                    elif self.cmd in ['create']:
                        # create exists variable for updating return value
                        self.args+=(
                            f' --pin "{self.pin}"'
                            f' --autoactivate {bool2str(self.config["auto"])}'
                            f' --type {self.type}'
                        )
                        
                        if self.type == 'AWSKMSCryptoToken':
                            self.args+=(
                                f' --awskmsaccesskeyid "{self.config["kms_access_key_id"]}"'
                                f' --awskmsregion "{self.config["kms_region"]}"'
                            )
                        
                        elif self.type == 'AzureCryptoToken':
                            # set akv type to Premium is boolea parameter set to true
                            akv_type='Premium' if self.config['azure_vault_premium'] else 'Standard' 
                            self.args+=(
                                f' --azurevaultclientid "{self.config["azure_client_id"]}"'
                                f' --azurevaultname "{self.config["azure_vault_name"]}"'
                                f' --azurevaulttype {akv_type}'
                            )
                            
                            # if a keybinding name was provided as a parameter
                            if self.config['azure_keybinding_name']:
                                self.args+=(
                                    f' --azurevaultusekeybinding true'
                                    f' --azurevaultkeybinding "{self.config["azure_keybinding_name"]}"'
                            )
                                
                        elif self.type in ['Pkcs11NgCryptoToken','PKCS11CryptoToken']:
                            self.args+=(
                                f' --lib "{self.config["lib"]}"'
                                f' --slotlabel "{self.config["slot_ref"]}"'
                                f' --slotlabeltype "{self.config["slot_ref_type"]}"'
                                f' --forceusedslots {bool2str(self.config["force_used_slots"])}'
                            )
                               
                        elif self.type != 'SoftCryptoToken':
                            self.module.fail_json(msg=F"A matching crypto token type was not found for {self.type}")
                            
                    elif self.cmd in ['delete']:
                        self.condition_ok=['Unknown CryptoToken']
                        
                elif self.cmd in ['removekey','testkey','generatekey']:
                    self.args+=(
                        f' --alias "{self.key_alias}"'
                    )
                    
                    # add the keyspec argument if generatekey
                    if self.cmd in ['generatekey']:
                        # replace exsiting condition list
                        self.condition_ok=['is in use']
                        self.args+=(
                           f' --keyspec "{self.key_spec}"'
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
            ('cmd','activate',['token','pin']),
            ('cmd','create',['token','type','pin']),
            ('cmd','listkeys',['token']),
            ('cmd','deactivate',['token']),
            ('cmd','delete',['token']),
            ('cmd','generatekey',['token','key_alias','key_spec']),
            ('cmd','removekey',['token','key_alias']),
            ('cmd','teskey',['token','key_alias']),
        ]
    )
    
    if module.check_mode:
        module.exit_json(**result)

    if module.params['cmd'] in ['create'] and module.params['type'] != 'SoftCryptoToken':
        
        # fail if list type is empty
        if module.params['config'] is None:
            module.fail_json(msg=f"config is defined but does not include any parameters")
        
        elif module.params['type'] == 'AzureCryptoToken':
            module.fail_on_missing_params(required_params=[
                f for f in ['azure_client_id','azure_vault_name'] if f not in module.params['config']
            ])
            
        elif module.params['type'] == 'AWSKMSCryptoToken':
            module.fail_on_missing_params(required_params=[
                f for f in ['kms_access_key_id','kms_region'] if f not in module.params['config']
            ])
        
        elif module.params['type'] == ('Pkcs11NgCryptoToken' or 'PKCS11CryptoToken'):
            module.fail_on_missing_params(required_params=[
                f for f in ['lib','slot_ref','slot_ref_type'] if f not in module.params['config']
            ])
        
    # return 
    command = EjbcaCryptoToken(module)
    result=command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()