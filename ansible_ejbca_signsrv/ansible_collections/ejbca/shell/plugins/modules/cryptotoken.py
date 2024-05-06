#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: cryptotoken
version_added: "1.0.0"
description: This module emulates the cryptotoken category of the EJBCA Shell.
options:
    action:
        description: Friendly names that map to a valid Shell command
        required: true
        type: str
        choices:
            - activate
            - create-akv
            - create-kms
            - create-fortanix
            - create-pkcs11
            - create-soft
            - delete-key
            - delete-token
            - deactivate
            - gen-key
            - list-keys
            - list-tokens
            - test-key
    auto:
        description: Auto-activate switch for cryptotoken.
        default: true
        type: bool 

    azure_client_id:
        description: The Azure Application ID for a service principal that has permission to perform operations against this Key Vault instance.
        type: str

    azure_keybinding_name:
        description: The Remote Authenticator containing the key and certificate to be used to authenticate to Key Vault.
        type: str

    azure_vault_name:
        description: Auto-activate switch for cryptotoken
        type: str

    azure_vault_premium:
        description: Set to 'true' if Key Vault is Premium, or 'false' if Standard.
        default: true
        type: bool

    exportable_keys:
        description: Set to 'true' to allow EJBCA to set Soft Crypto Token keystores as exportable.
        type: bool

    force_used_slots:
        description: Set to 'true' to allow an HSM slot already in use by a Crypto Token to be used for a second Crypto Token.
        default: true
        type: bool

    fortanix_dms_api_addr:
        description: Fortanix API key value.
        type: str

    key_alias:
        description: Label to use when generating or deleting a key.
        type: str

    key_spec:
        description: Key specification, for example 2048, secp256r1, DSA1024, gost3410, dstu4145.
        type: str

    kms_access_key_id:
        description: AWS IAM users Access key ID.
        type: str

    kms_region:
        description: The region the KMS keys will reside.
        type: str

    library:
        description: PKCS11 shared library configured as available in conf/web.properties.
        type: path
        
    p11ng:
        description: Set to 'true' to use the P11NG implementation of PKCS11 instead of SunPKCS.
        default: true
        type: bool

    path:
        description: Absolute path of EJBCA home directory.
        default: /opt/ejbca
        type: path

    pin:
        description: The PKCS11 slot PIN or the password that will protect the soft keystore.
        type: str

    return_output:
        description: Returns stdout and stderr lines in output. Set to 'false' to limit console output.
        default: true
        type: bool

    slot_ref:
        description: PKCS11 slot number, index or label.
        type: str

    slot_ref_type:
        description: Type of a slot reference described by the PKCS11 Reference.
        choices:
            - SLOT_NUMBER
            - SLOT_LABEL
            - SLOT_INDEX
        type: str

    token:
        description: A user-friendly name for the Crypto Token.
        type: str

    type:
        description: PKCS11 HSM slot mapping or a Soft PKCS12 keystore in the database.
        choices:
            - AzureCryptoTokenG
            - AWSKMSCryptoToken
            - FortanixCryptoToken
            - Pkcs11NgCryptoToken
            - PKCS11CryptoToken
            - SoftCryptoToken
        default: SoftCryptoToken
        type: str
'''

EXAMPLES = r'''
- name: List all crypto tokens
  ejbca.shell.cryptotoken:
    action: list-tokens
        
- name: Delete a crypto token
  ejbca.shell.cryptotoken:
    action: delete-token
    token: RootCA

- name: Create a soft crypto token
  ejbca.shell.cryptotoken:
    action: create-token
    token: ManagementCA
    pin: foo123
    
- name: Create a P11NG crypto token
  ejbca.shell.cryptotoken:
    action: create-token
    token: RootCA
    pin: foo123
    library: /usr/safenet/lunaclient/lib/libCryptoki2_64.so
    slot_ref: ROOT_CA_SLOT
    slot_ref_type: SLOT_LABEL

- name: Deactivate a crypto token
  ejbca.shell.cryptotoken:
    action: deactivate
    token: RootCA
    
- name: Activate crypto token
  ejbca.shell.cryptotoken:
    action: deactivate
    token: RootCA
    pin: foo123
    
- name: List all keys in a crypto token
  ejbca.shell.cryptotoken:
    action: deactivate
    token: RootCA        
    
- name: Generate key
  ejbca.shell.cryptotoken:
    action: gen-key
    token: RootCA
    key_alias: signKey
    key_spec: 4096

- name: Test key
  ejbca.shell.cryptotoken:
    action: test-key
    token: RootCA
    key_alias: signKey
    
- name: Delete key
  ejbca.shell.cryptotoken:
    action: test-key
    token: RootCA
    key_alias: signKey
'''

RETURN = r'''
keys:
    description: List containing all the keys in a crypto token
    returned: success
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
          
tokens:
    description: List containing all the crypto tokens in EJBCA
    returned: success
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
            description: Crypto token identifier
            type: str
        name:
            description: Crypto token name
            type: str
    sample:
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
        - active: true
          auto_activate: true
          exportable_keys: false
          id: 1761002431
          name: IssuingCA
            
stderr_lines:
    description: CLI error output. Not all errors will return a Failed. Some commands, such as generatekey, will be returned OK even though the shell error output has a returncode of 1.
    returned: always
    type: list
    elements: str
    sample:
        - Key pair generation failed: alias signKeyTest1 is in use
    
stdout_lines:
    description: CLI standard output.
    returned: always
    type: list
    elements: str
    sample:
        - CryptoToken deleted successfully
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ejbca.shell.plugins.module_utils.shell import Shell
from ansible_collections.ejbca.shell.plugins.module_utils.common import (
    StringParser,
    argument_spec_common,
    COMMON_CHOICES
)

SHELL_COMMANDS = dict(
    # Dictionary mapping for CLI commands
    activate = 'activate',
    create = 'create',
    delete = 'delete',
    deactivate = 'deactivate',
    generatekey = 'generatekey',
    list = 'list',
    listkeys = 'listkeys',
    removekey = 'removekey',
    testkey = 'testkey'
)

SHELL_ARGUMENTS = dict(
    # Dictionary mapping for available CLI arguments
    # each key maps to a module parameter
    # the value is the parameter value defined by EJBCA CLI
    # to add additional items, use "module_parameter = cli_parameter"
    token = '--token',
    auto = '--autoactivate',
    azure_client_id = '--azurevaultclientid',
    azure_keybinding_name = '--azurevaultusekeybinding',
    azure_vault_name = '--azurevaultname',
    azure_vault_premium = '--azurevaulttype',
    exportable_keys = '--exportkey',
    fortanix_dms_api_addr = '--fortanixaddr',
    key_alias = '--alias',
    key_spec = '--keyspec',
    kms_access_key_id = '--awskmsaccesskeyid',
    kms_region = '--awskmsregion',
    library = '--lib',
    pin = '--pin',
    slot_ref = '--slotlabel',
    slot_ref_type = '--slotlabeltype',
    type = '--type'
)
# cant be added to args list because its a flag on the CLI. needs to be passed as an extra arg
SHELL_ARGUMENTS_FORCEUSEDSLOTS = '--forceusedslots' 

MODULE_ACTIONS = dict(
# Dictionary mapping for module actions
# Available keys for each action
#   category = 'str'
#   cmd = 'str
#   allowed_params = 'list'
#   condition_ok = 'list'
#   condition_changed = 'list'
#   condition_failed = 'list'
#   condition_failed_msg = 'str'
    
    activate = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['activate'],
        allowed_params = [
            'token',
            'pin'
        ],
        condition_failed = [
            'Unknown CryptoToken:'
        ]
    ),
    create_akv = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['create'],
        allowed_params = [
            'token',
            'type',
            'auto',
            'pin',
            'type',
            'azurevaultclientid',
            'azurevaultname',
            'azurevaulttype',
            'azure_vault_premium'
        ],
    ),
    create_kms = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['create'],
        allowed_params = [
            'token',
            'type',
            'auto',
            'pin',
            'type',
            'kms_access_key_id',
            'kms_region'
        ],
    ),
    create_fortanix = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['create'],
        allowed_params = [
            'token',
            'type',
            'auto',
            'pin',
            'type',
            'fortanix_dms_api_addr'
        ],
    ),
    create_pkcs11 = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['create'],
        allowed_params = [
            'token',
            'type',
            'auto',
            'pin',
            'type',
            'library',
            'slot_ref',
            'slot_ref_type',
            'force_used_slots'
        ],
    ),
    create_soft = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['create'],
        allowed_params = [
            'token',
            'type',
            'auto',
            'pin',
            'type',
        ],
    ),
    delete_key = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['removekey'],
        allowed_params = [
            'token',
            'key_alias'
        ],
        condition_changed = [
            '(hashed only)'
        ],
    ),
    delete_token = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['delete'],
        allowed_params = [
            'token'
        ],
        condition_ok = [
            'Unknown CryptoToken:'
        ]
    ),
    deactivate = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['deactivate'],
        allowed_params = [
            'token'
        ],
        condition_failed = [
            'CryptoToken is still active after deactivation request'
        ],
        condition_failed_msg = 'Could not deactivate cryptotoken because it is auto-activated'
    ),
    gen_key = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['generatekey'],
        allowed_params = [
            'token',
            'key_alias',
            'key_spec'
        ],
        condition_ok = [
            'Key pair generation failed: alias','is in use'
        ],
        condition_changed = [
            'Found end entity'
        ],
    ),
    list_keys = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['listkeys'],
        allowed_params = [
            'token'
        ],
        condition_ok = [
            'Unknown CryptoToken:'
        ]
    ),
    list_tokens = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['list'],
        allowed_params = [],
    ),
    test_key = dict(
        category = 'cryptotoken',
        cmd = SHELL_COMMANDS['testkey'],
        allowed_params = [
            'token',
            'key_alias'
        ],
        condition_changed = [
            'clear text password'
        ],
    ),
)

class EjbcaToken(Shell):
    def __init__(self, module:AnsibleModule):
        """ Contstruct subclass 
    
        Description:
            - Superclass the Shell module to contrust the common attributes for this subclass.
            - Convert module parameters from string to integer values.
        
        Arguments:
            - AnsibleModule containing parsed parameters passed from Ansible task.
        """
        self.module = module
        
        # access inherited class to build attributes
        super().__init__(module, MODULE_ACTIONS, SHELL_ARGUMENTS)
        
        # update the default failed string
        self.condition_failed.append('You need to activate the CryptoToken before you can interact with its content') 

    def _parser_key_list(self, output:str):
        """ Create list of crypto tokens.
        
        Description:
            - Initializes list for appending each key dictionary created during loop
            - New iteration is started after condition is met
            - If a line does not me any conditionals, it is assumed its a key
            
        Arguments:
            - output: Shell output string to be spit into separate lines
            
        Conditionals:
            - 'ALIAS':
                - Used to detect the beginning of the key list in the output
            - 'CryptoToken does not contain any key pairs':
                - Exit loop and function if no keys exist
                
        Regex:
            - Reverse split on spacing and tab to account for potential spaces in the key alias.
            - Spaces should not be in the skid, key spec, or key algorithm.
            - Indexes are used to detect skid, key spec, or key algorithm
            - Key alias is found by splitting on '\t' (tab) delimeter created when output is split into lines
            - Splitting on spaces and tab is preferred so a key algorithm list doesnt need to be used in regex
            
        Return: 
            - List consisting of key dictionaries. Will be empty if no keys exist in the crypto token.
        """
        key_list = list()
        output = iter(output.splitlines())
        for line in output:
            if 'ALIAS' in line:
                
                # create new loop for lines after condition is met
                for key in output:
                    
                    # zeroize list if no keys exist amd exit function
                    if 'CryptoToken does not contain any key pairs' in key: 
                        return key_list
                    
                    else:
                        try: # catch index errors when attempting to split on invalid string
                            non_alias_string = key.rsplit('\t')[1].split() # reverse split on tab that exists right after 'alias'
                            keys = dict(
                                alias = StringParser(key).split_strip('\t'),
                                algorithm = non_alias_string[0],
                                spec = non_alias_string[1],
                                skid = non_alias_string[2],
                            )
                            key_list.append(keys)
                        
                        except IndexError:
                            pass
                    
        return key_list

    def _parser_token_list(self,output:str):
        """ Create list of crypto tokens.
        
        Description:
            - Set 'changed' state to True to indicate a successful list operation
            - Initializes list for appending each crypto token dictionary created during loop
            - New iteration is started after condition is met
            
        Conditonals:
            - ('NAME'):
                - Used to detect the beginning of the crypto token list in the output
                - Each line after this condition is met are considered crypto tokens
            
        Return: 
            - token_list: 
                - List consisting of crypto token dictionaries. Will be empty if no crypto tokens exist.
        """
        token_list = list()
        output = iter(output.splitlines())
        for line in output:
            if 'NAME' in line:
                
                # create new loop for lines after condition is met
                for t in output:
                    token = dict(
                        name = StringParser(t).quotes(),
                        id = StringParser(t).id(),
                        active = StringParser(t).boolean('active'),
                        auto_activate = StringParser(t).boolean('auto'),
                        exportable_keys = StringParser(t).boolean('non-exportable')
                    )
                    token_list.append(token)
                    self.stdout_lines.append(t.strip())
                    
        return token_list

    def execute(self):
        """ Execute of passed module parameters 
        
        Description:
            - Two separate blocks exist: 
                - Module actions that need additional items before shell exection
                - Module actions that require additional items based on the results of the executed action.
                
        Conditonals:
            - Module action
                
        Return:
            - results: Dictionary consisting of module execution results.
        """
        # initialize result dictionary
        results = dict()
        
        try:
            # Block ONE - modified execution
            
            # needs different CLI execution so it can pass the 'force_used_slots' parameter
            if self.action in ['create_pkcs11']: 
                # pass force_used_slots parameter value
                pkcs11_extra_args = SHELL_ARGUMENTS_FORCEUSEDSLOTS if self.force_used_slots else ''
                
                # build command line string, passes to shell, and checks output for results
                output, results = self.shell(
                    extra_args = pkcs11_extra_args,
                    command = self.build_command()
                ) 

            # Block TWO - default execution
            else:
                
                # build command line string, passes to shell, and checks output for results
                output, results = self.shell(
                    command = self.build_command()
                )

                # Build dictionary of cryptotokens
                if self.action in ['list_tokens']:
                    tokens = self._parser_token_list(output)
                    
                    # set task to changed if tokens list contains any tokens
                    if len(tokens): 
                        results['changed'] = True
                        
                    # add tokens dictionary to results
                    results['tokens'] = tokens 

                # Build dictionary of cryptotokens key
                elif self.action in ['list_keys']:
                    token_keys = self._parser_key_list(output)
                    
                    # set task to changed if token_keys list contains any keys
                    if len(token_keys): 
                        results['changed'] = True
                    
                    # add keys dictionary to results
                    results['keys'] = token_keys

                # Build dictionary with output values after token creation
                elif self.action in ['create_akv','create_kms','create_fortanix','create_pkcs11','create_soft']:
                    
                    # check changed result and return a dictionary containing the token name and id
                    if results['changed']: 
                        results['token'] = dict(
                            name = self.token,
                            id = int(self.id)
                        )
            
            # pass results through class to modify returned values before returning
            return self.return_results(results)
            
        except ValueError as e:
            self.module.fail_json(msg=e)
            
def arguement_spec_token():
    return dict(
        auto = dict(
            default = True,
            type = 'bool'
        ),
        azure_client_id = dict(
            type = 'str'
        ),
        azure_keybinding_name = dict(
            type = 'str'
        ),
        azure_vault_name = dict(
            type = 'str'
        ),
        azure_vault_premium = dict(
            default = True,
            type = 'bool'
        ),
        exportable_keys = dict(
            type = 'bool'
        ),
        fortanix_dms_api_addr = dict(
            type = 'str'
        ),
        force_used_slots = dict(
            default = True,
            type = 'bool'
        ),
        kms_access_key_id = dict(
            type = 'str'
        ),
        kms_region = dict(
            type = 'str'
        ),
        key_alias = dict(
            type = 'str'
        ),
        key_spec = dict(
            type = 'str'
        ),
        library = dict(
            type = 'path'
        ),
        p11ng = dict(
            type = 'bool',
            default = True
        ),
        pin = dict(
            type = 'str'
        ),
        slot_ref = dict(
            type = 'str'
        ),
        slot_ref_type = dict(
            type = 'str',
            choices = [k for k in COMMON_CHOICES['slot_ref_types']]
        ),
        token = dict(
            type = 'str'
        ),
        type = dict(
            type = 'str',
            default = 'SoftCryptoToken',
            choices = [k for k in COMMON_CHOICES['crypto_token_types']]
        ),
    )
            
def run_module():

    # Load main argument spec into module argument spec
    module_args = argument_spec_common() 
    
    # Update with sub class module argument spec
    module_args.update(arguement_spec_token())
    
    # Update action choices
    # Replace underscore with hyphen for use to provide hyphen in the module action value
    module_args['action'].update(choices = [k.replace('_','-') for k in MODULE_ACTIONS]) 
    
    # Build module opbject
    module = AnsibleModule(
        argument_spec = module_args,
        supports_check_mode = True,
        required_if = [
            ('action','activate',[
                'token',
                'pin'
            ]),
            ('action','create-soft',[
                'token',
                'pin'
            ]),
            ('action','deactivate',[
                'token'
            ]),
            ('action','delete-token',[
                'token'
            ]),
            ('action','delete-key',[
                'token',
                'key_alias'
            ]),
            ('action','gen-key',[
                'token',
                'key_alias',
                'key_spec'
            ]),
            ('action','list-keys',[
                'token'
            ]),
            ('action','test-key',[
                'token',
                'key_alias'
            ]),
            # create token actions
            ('action','create-akv',[
                'token',
                'type',
                'auto',
                'pin',
                'type',
                'azurevaultclientid',
                'azurevaultname',
                'azurevaulttype',
                'azure_vault_premium'
            ]),
            ('action','create-kms',[
                'token',
                'type',
                'auto',
                'pin',
                'type',
                'kms_access_key_id',
                'kms_region'
            ]),
            ('action','create-fortanix',[
                'token',
                'type',
                'auto',
                'pin',
                'type',
                'fortanix_dms_api_addr'
            ]),
            ('action','create-pkcs11',[
                'token',
                'pin',
                'library',
                'slot_ref',
                'slot_ref_type'
            ]),
        ]
    )
    
    if module.check_mode:
        module.exit_json(**result)

    # update type for pkcs11 token based on p11ng parameter
    # used to translate the action provided to the token type parameter
    if module.params['type']:
        action = module.params['action'] # load in temp variable for cleaner condition evaluation
        token_type = str() # load in temp variable for cleaner condition evaluation
        
        # AzureCryptoToken
        if action == 'create-akv': 
            token_type = 'AzureCryptoToken'
            
        # AzureCryptoToken
        elif action == 'create-kms': 
            token_type = 'AWSKMSCryptoToken'
            
        # AzureCryptoToken
        elif action == 'create-fortanix': 
            token_type = 'FortanixCryptoToken'
            
        # Pkcs11NgCryptoToken or PKCS11CryptoToken
        elif action == 'create-pkcs11':
            if module.params['p11ng']:
                token_type = 'Pkcs11NgCryptoToken' 
            else:
                token_type = 'PKCS11CryptoToken'
    
        else:
            token_type = 'SoftCryptoToken'
            
        # store in module param
        module.params['type'] = token_type 
        
    # debug option parameters
    if module.params['debug']:
        if module.params['debug_option'] == 'params': # debug module parameters
            module.fail_json(module.params)
        
        if module.params['debug_option'] == 'spec': # debug module argument spec
            module.fail_json(module.argument_spec)
    
    # return 
    command = EjbcaToken(module)
    result = command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()