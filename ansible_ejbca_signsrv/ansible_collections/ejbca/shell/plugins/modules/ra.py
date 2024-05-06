#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ra
version_added: "1.0.0"
description: This module emulates the ra, createcert, and batch categories of the EJBCA Shell.
options:
    action:
        description: Friendly names that map to a valid Shell command
        required: true
        type: str
        choices:
            - add-entity
            - batch
            - enroll-keystore
            - delete-entity
            - enroll-pkcs10
            - find-entity
            - reset-entity
            - revoke-entity
            - set-pass
            - set-status
    batch:
        description: Set to 'true' configure a new End Entity with a clear password after creation. This is two separate shell executions, but used in a single task.
        default: false
        type: bool 

    cert:
        description: Output location for a certifcate or keystore.
        type: path

    cert_profile:
        description: Certificate profile to set when adding an End Entity.
        type: str

    clear_pass:
        description: Set to 'true' to use a clear password instead of a hashed password when changing the password of an End Entity.
        default: false
        no_log: false
        type: bool

    csr:
        description: PKCS10 file used in signing a certificate.
        type: path

    ee_profile:
        description: End Entity profile to set when adding an End Entity.
        type: str

    force_reset:
        description: Set to 'true' to configure an existing End Entity, with ACTIVE certificates and unknown password, for certificate generation. This is the same as deleting and creating an End Entity, but keeping the UserData and CertData history.
        default: false
        type: bool

    issuing_ca:
        description: Certificate Authority to use for issuance when adding an End Entity.
        type: str

    password:
        description: Password to set when adding an End Entity.
        no_log: false
        type: str

    path:
        description: Absolute path of EJBCA home directory.
        default: /opt/ejbca
        type: path

    return_output:
        description: Returns stdout and stderr lines in output. Set to 'false' to limit console output.
        default: true
        type: bool

    revoke:
        description: Set to 'true' to revoke all active certificate for an existing End Entity.
        default: true
        type: bool

    revoke_reason:
        description: Reason to apply to all active certificates when revoking an existing End Entity.
        choices:
            - unspecified
            - keyCompromise
            - cACompromise
            - affiliationChanged
            - superseded
            - cessationOfOperation
            - certificateHold
            - removeFromCRL
            - privilegeWithdrawn
            - aACompromise
        default: unspecified
        type: str
        
    status:
        description: End Entity status.
        choices:
            - NEW
            - FAILED
            - INITIALIZED
            - INPROCESS
            - GENERATED
            - HISTORICAL
        default: NEW
        type: str

    subject_dn:
        description: DN is of form "C=SE, O=MyOrg, OU=MyOrgUnit, CN=MyName" etc.
        type: str

    token:
        description: Desired token type for the end entity.
        choices:
            - BCFKS
            - JKS
            - P12
            - PEM
            - USERGENERATED
        type: str

    type:
        description: Type (mask) INVALID=0; END-USER=1; SENDNOTIFICATION=256; PRINTUSERDATA=512.
        choices:
            - 0
            - 1
            - 256
            - 512
        default: 1
        type: int

    username:
        description: Username of the End Entity.
        type: str
'''

EXAMPLES = r'''
- name: Find End Entity
  ejbca.shell.ra:
    action: find-entity
    username: ejbca-user
        
- name: Delete End Entity
  ejbca.shell.ra:
    action: delete-entity
    username: ejbca-user

- name: Create End Entity configured for batch (keystore) enrollment
  ejbca.shell.ra:
    action: add-entity
    username: ejbca-user
    issuing_ca: Issuing-CA
    subject_dn: CN=EJBCA User,O=Keyfactor,C=US
    cert_profile: tlsCertAuth-CP
    ee_profile: tlsCertAuth-EEP
    password: foo123
    token: PEM
    batch: true
    
# Reset an End Entity for CSR enrollment
# Only execute if 'force_rest' is true and entity status is not NEW
- name: Change End Entity status to New, revoke active certs, and set password if status is not NEW
  ejbca.shell.ra:
    action: create-token
    username: ejbca-user
    password: foo123
    revoke: true
    clear_pass: false
  when: 
    - force_reset
    - entity.status != '10'

- name: Set clear password if status is NEW
  ejbca.shell.ra:
    action: set-pass
    username: ejbca-user
    password: foo123
    clear_pass: true
    
- name: Set hashed password if status is NEW
  ejbca.shell.ra:
    action: set-pass
    username: ejbca-user
    password: foo123
    clear_pass: false

# Only execute if entity exists and status is not NEW
- name: Change End Entity status to New
  ejbca.shell.ra:
    action: deactivate
    username: ejbca-user
  when:
    - entity.exists
    - entity.status != New

# Only execute if entity exists, a clear password is set, and status is New
- name: Enroll a keystore for an existing End Entity
  ejbca.shell.ra:
    action: deactivate
    username: ejbca-user
    password: foo123
    cert: /path/to/certificate_outfile
  when:
    - entity.exists
    - entity.clear_password
    - entity.status == '10'

# Only execute if entity exists, a clear password is not set, and status is New
- name: Sign CSR for end entity
  ejbca.shell.ra:
    action: gen-key
    username: ejbca-user
    password: foo123
    csr: /path/to/csr_infile
    cert: /path/to/certificate_outfile
  when:
    - entity.exists
    - entity.clear_password is false
    - entity.status == '10'
'''

RETURN = r'''
entity:
    description: Dictionary containing End Entity attributes.
    returned: success
    type: dict
    contains:
        alt_name:
            description: Subject Alternative Name (SAN) value.
            type: str
        certificate_profile_id:
            description: Certificate profile ID currently set on the End Entity.
            type: int
        clear_password:
            description: Used to determine if the End Entity needs to be configured for batch enrollment prior to executing batch enrollment.
            type: bool
        created:
            description: When the End Entity was created.
            type: str
        directory_attributes: 
            description: LDAP attributes
            type: str
        dn:
            description: Distringuished Name of the End Entity defined by configured Subject Name attributes in the End Entity profile.
            type: str
        e_mail:
            description: Email Address
            type: str
        end_entity_profile_id:
            description: Certificate profile ID currently set on the End Entity.
            type: int
        exists:
            description: Used to determine if the End Entity exists or not.
            type: bool
        modified:
            description: When the End Entity was last modified.
            type: str
        password:
            description: Password currently set on the End Entity. If value is '<hidden>', the password is hashed and 'clear-text' means the End Entity if configured for batch enrollment.
            type: str
        status: 
            description: Current status of the End Entity.
            type: int
        token_type:
            description: Current token type of the End Entity.
            type: int
        type:
            description: Current type of the End Entity.
            type: int
        username:
            description: End Entity username.
            type: str

    sample:
        - alt_name: '""'
          certificate_profile_id: '446869351'
          clear_password: false
          created: Sun Feb 04 12
          directory_attributes: '""'
          dn: '"CN=peerClient-ocsp,OU=Peering,O=Organization,C=US"'
          e_mail: 'null'
          end_entity_profile_id: '559695730'
          exists: true
          found_end_entity: ''
          modified: Sun Feb 04 12
          password: <hidden>
          status: '10'
          token_type: '1'
          type: '1'
          username: peerClient-ocsp
            
stderr_lines:
    description: CLI error output. Not all errors will return a Failed. Some commands, such as generatekey, will be returned OK even though the shell error output has a returncode of 1.
    returned: always
    type: list
    elements: str
    sample:
        - End entity with username 'ejbca-server' does not exist
    
stdout_lines:
    description: CLI standard output.
    returned: always
    type: list
    elements: str
    sample:
        - Deleted end entity with username: 'ejbca-server'
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
    addendentity = 'addendentity',
    batch = 'batch',
    createcert = 'createcert',
    delendentity = 'delendentity',
    enroll = 'enroll',
    findendentity = 'findendentity',
    resetendentity = 'resetendentity',
    revokeendentity = 'revokeendentity',
    setpwd = 'setpwd',
    setclearpwd = 'setclearpwd',
    setendentitystatus = 'setendentitystatus',
)

SHELL_ARGUMENTS = dict(
    # Dictionary mapping for available CLI arguments
    # each key maps to a module parameter
    # the value is the parameter value defined by EJBCA CLI
    # to add additional items, use "module_parameter = cli_parameter"
    username = '--username',
    cert_profile = '--certprofile',
    csr = '-c',
    ee_profile = '--eeprofile',
    issuing_ca = '--caname',
    password = '--password',
    revoke_reason = '-r',
    subject_dn = '--dn',
    status = '-S',
    token = '--token',
    type = '--type',
)
# cant be added to args dict because its a flag on the CLI. needs to be passed as an extra arg
SHELL_ARGUMENTS_FORCE = '-force' 
# cat be added to args dict because they use the same module paramter and require additional parsing
SHELL_ARGUMENTS_CERT_FILE = '-f' 
SHELL_ARGUMENTS_CERT_DIR = '-dir'

MODULE_ACTIONS = dict(
    add_entity = dict(
        category = 'ra',
        cmd = SHELL_COMMANDS['addendentity'],
        allowed_params = [
            'cert_profile',
            'ee_profile',
            'issuing_ca',
            'password',
            'subject_dn',
            'type','token',
            'username'
        ],
        condition_ok = [
            'already exists'
        ],
        condition_changed = [
            'has been added'
        ],
    ),
    batch = dict(
        cmd = SHELL_COMMANDS['addendentity'],
        allowed_params = [
            'username',
            'password'
        ],
        condition_changed = [
            'New user generated successfully',
            'Created Keystore'
        ],
        condition_failed = [
            'does not exist'
        ],
    ),
    enroll_keystore = dict(
        cmd = SHELL_COMMANDS['addendentity'],
        allowed_params = [
            'username',
            'cert'
        ],
        condition_changed = [
            'New user generated successfully',
            'Created Keystore'
        ],
        condition_failed = [
            'does not exist'
        ],
        condition_failed_msg = 'Failed to generate keys. The user exists but probably isnt set to NEW or does not have a password set. If the status was already changed to NEW, the password may be empty.'
    ),
    delete_entity = dict(
        category = 'ra',
        cmd = SHELL_COMMANDS['delendentity'],
        allowed_params = [
            'username'
        ],
        condition_ok = [
            'No such end entity'
        ],
        condition_changed = [
            'Deleted end entity with username'
        ]
    ),
    enroll_pkcs10 = dict(
        cmd = SHELL_COMMANDS['addendentity'],
        action = 'enroll-pkcs10',
        allowed_params = [
            'username',
            'password',
            'csr',
            'cert'
        ],
        condition_failed = [
            'Could not create certificate: Could not find username'
        ],
        condition_changed = [
            'PEM certificate written to file'
        ],
        condition_failed_msg = 'Failed to generate certificate because the user does not exist.'
    ),
    find_entity = dict(
        category = 'ra',
        cmd = SHELL_COMMANDS['findendentity'],
        allowed_params = [
            'username'
        ],
        condition_ok = [
            'does not exist'
        ],
        condition_changed = [
            'Found end entity'
        ],
    ),
    reset_entity = dict(
        category = 'ra',
        allowed_params = [
            'username',
            'password'
        ],
        condition_changed = [
            'Found end entity'
        ],
    ),
    revoke_entity = dict(
        category = 'ra',
        cmd = SHELL_COMMANDS['revokeendentity'],
        allowed_params = [
            'username',
            'revoke_reason'
        ],
    ),
    set_pass = dict(
        category = 'ra',
        allowed_params = [
            'username',
            'password'
        ],
        condition_changed = [
            'clear text password',
            '(hashed only)'
        ],
        condition_failed = [
            'does not exist'
        ],
    ),
    set_status = dict(
        category = 'ra',
        cmd = SHELL_COMMANDS['setendentitystatus'],
        allowed_params = [
            'username',
            'status'
        ],
        condition_changed = [
            'New status for end entity'
        ],
    ),
)

# Available choices to select from
CHOICES = dict(
    type = [
        0,1,256,512
    ]
)
CHOICES.update(COMMON_CHOICES) # update choices list with main

class EjbcaRa(Shell):
    def __init__(self, module:AnsibleModule):
        """ Contstruct subclass 
        
        Description:
            - Superclass the Shell module to contrust the common attributes for this subclass.
            - Convert module parameters from string to integer values.
        
        Arguments:
            - AnsibleModule containing parsed parameters passed from Ansible task.
        """
        self.module = module
        # set default set password cmd to 'setpwd'
        self.set_pass_cmd = SHELL_COMMANDS['setpwd']
        
        # access inherited class to build attributes
        super().__init__(module, MODULE_ACTIONS, SHELL_ARGUMENTS)
        
        # update set_pass action cmd based on boolean pass in clear_pass parameter
        if self.action in ['add_entity','enroll_keystore','set_pass','reset_entity'] and (self.clear_pass or self.batch):
            self.set_pass_cmd = SHELL_COMMANDS['setclearpwd']
            
        if self.cert:
            if self.action in ['enroll_keystore','batch']:
                SHELL_ARGUMENTS['cert'] = SHELL_ARGUMENTS_CERT_DIR
            else:
                SHELL_ARGUMENTS['cert'] = SHELL_ARGUMENTS_CERT_FILE
        
        # convert end entity status and revocation_reason strings to integer
        # this is necessary so user can specific string in module but the integer can be passed to the shell
        self.status=int(''.join([v for k,v in COMMON_CHOICES['end_entity_statuses'] if self.status == k])) 
        self.revoke_reason=int(''.join([v for k,v in COMMON_CHOICES['revocation_reasons']  if self.revoke_reason == k]))

    def _parser_findendentity(self,output:str):
        """ Create dynamic dict containing entity values.
        
        Description:
            - Dict will be populated with every line included in CLI output
            - Some additional keys can be added to the dict based on dict values in CLI output
        
        Arguments:
            - output:
                - List of strings split from CLI output.
            
        Conditonals:
            - ('Found end entity'):
                - Used to detect the beginning of the key list in the output.
                - Each line after this condition is met are considered keys in the findendentity output.
            
        Return: 
            - entity_dict:
                - List consisting of key and values of found endentity.
                - List containing exists is false if no entity found.
        """
        entity_dict=dict(
            exists = False,
            clear_password = False
        )
        output = output.splitlines()
        for line in output:
            if ('Found end entity') in line:
                entity_dict.update(exists = True)
                for ee in output:
                    # create keys and values in each line
                    k = StringParser(ee).dict_key() # before colon
                    v = ee.split(':')[1].strip() # after colon
                    entity_dict[k] = v # create dictionary item using key and value
                    
                    # update 'clear_password' in dictionary if 'password' value in output is 'hidden'
                    # assume clear password is not set if 'password' is hidden
                    if k == 'password' and entity_dict[k] != '<hidden>':
                        entity_dict.update(clear_password = True)

                return entity_dict
            
            else:
                self.stdout_lines.append(line)
                return entity_dict
            
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
                        
            # enroll-keystore
            # TWO different shell exectutions can be run
            if self.action in ['enroll_keystore']:
            
                # ONE - setclearpass
                # run shell command to set clear password on end entity if parameter was set to 'true'
                if self.clear_pass:
                    output, results = self.shell(
                        
                        # since enroll-keystore is the passed action,the default 'action' and 'cmd' 
                        # arguments for the build function need to be overridden
                        self.build_command(
                            action = 'set_pass',
                            cmd = self.set_pass_cmd
                        )
                    )
                
                # TWO - batch
                output, results = self.shell(
                    command = self.build_command()
                )
                
                # fail with custom error message if results are not changed
                if not results['changed']:
                    results['failed'] = True
                    self.stderr_lines.append(self.action_items['condition_failed_msg'])
                    
            # reset-entity
            # THREE different shell exectutions can be run
            # initialize dictionary to update based on shell execution results
            elif self.action in ['reset_entity']:
                entity = dict(
                    username = self.username,
                    revoked_certs = False,
                    reset_pwd = False,
                    status = False
                )
            
                # ONE - revoke end entity which includes all certificates
                if self.revoke:
                    output,results=self.shell(self.build_command(action = 'revoke_entity'))
                
                # TWO - set password
                output,results=self.shell(self.build_command(
                    cmd = self.set_pass_cmd))
                
                if results['changed']: # if set password was successful, update boolean to true
                    entity['reset_pwd'] = True

                # THREE - set status
                output,results = self.shell(self.build_command(
                    action = 'set_status'))
                
                if results['changed']: # if successful, convert status int back to string value provided in status parameter
                    entity['status'] = self.status
                
                # load entity dictionary into result entity list
                results['entity'] = entity 
                
            # set-pass
            # needs to override default cmd arguement
            elif self.action in ['set_pass']:
                output, results = self.shell(self.build_command(
                    cmd = self.set_pass_cmd))
                
            # delete-entity
            # needs to pass extra arguments to the shell function
            elif self.action in ['delete_entity']:
                output, results = self.shell(
                    extra_args = SHELL_ARGUMENTS_FORCE,
                    command = self.build_command(),
                )
            
            # Block TWO - default execution
            else:
                output, results = self.shell(self.build_command())
                
                # Add-entity
                # required to pass entity dict in results and rurn shell execution if applicable
                if self.action in ['add_entity']:
                    batch_result = False # initialize batch result for updating and/or adding to entity dictionary
                    
                    # reruns shell execution after adding entity if clear password (batch) is passed as a parameter
                    if not results['failed'] and self.batch: 
                        output, results = self.shell(
                            self.build_command(
                                action = 'set_pass',
                                cmd = self.set_pass_cmd
                        ))
                        if results['changed']: # update batch key to true if successful
                            batch_result = True
                        
                    # add entity dict to results after conditionals evaluated
                    results['entity'] = dict( 
                        username = self.username,
                        batch = batch_result
                    )
                
                # find-entity
                elif self.action in ['find_entity']:
                    results['entity'] = dict( # initialize entity dict for updating after parsing
                        exists = False
                    )
                    
                    # parse found entity so dict can be returned.
                    if results['changed']:
                        results['entity'] = dict(
                            self._parser_findendentity(output)
                        )
            
            # pass results through class to modify returned values before returning
            return self.return_results(results)          
            
        except ValueError as e:
            self.module.fail_json(msg = e)
            
def argument_spec_ra():
    return dict(
        action = dict(
            type = 'str'
        ),
        batch = dict(
            default = False,
            type = 'bool'
        ),
        cert_profile = dict(
            type = 'str'
        ),
        cert = dict(
            type = 'path'
        ),
        csr = dict(
            type = 'path'
        ),
        clear_pass = dict(
            default = False,
            type = 'bool',
            no_log = False
        ),
        ee_profile = dict(
            type = 'str'
        ),
        force_reset = dict(
            default = False,
            type = 'bool'
        ),
        issuing_ca = dict(
            type = 'str'
        ),
        password = dict(
            type = 'str',
            no_log = False
        ),
        revoke = dict(
            default = True,
            type = 'bool'
        ),
        revoke_reason = dict(
            default = 'unspecified',
            type = 'str',
            choices = [k for k,v in CHOICES['revocation_reasons']]
        ),
        subject_dn = dict(
            type = 'str'
        ),
        status = dict(
            default = 'NEW',
            type = 'str',
            choices = [k for k,v in CHOICES['end_entity_statuses']]
        ),
        token = dict(
            type = 'str',
            choices = [k for k in CHOICES['token_types']]
        ),
        type = dict(
            default = 1,
            type = 'int',
            choices = [k for k in CHOICES['type']]
        ),
        username = dict(
            type = 'str'
        )
    )
            
def run_module():
    
    # Load main argument spec into module argument spec
    module_args = argument_spec_common()
    
    # Update with sub class module argument spec
    module_args.update(argument_spec_ra())
    
    # Update action choices
    # Replace underscore with hyphen for use to provide hyphen in the module action value
    module_args['action'].update(choices = [k.replace('_','-') for k in MODULE_ACTIONS])
    
    # Build module opbject
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('action','add-entity',[
                'cert_profile',
                'ee_profile',
                'issuing_ca',
                'password',
                'subject_dn',
                'type',
                'token',
                'username'
            ]),
            # enrolling entity
            ('action','enroll-pkcs10',[
                'username',
                'password',
                'csr',
                'cert'
            ]),
            ('action','enroll-keystore',[
                'username',
                'password',
                'cert'
            ]),
            # modifying entity
            ('action','delete-entity',[
                'username'
            ]),
            ('action','find-entity',[
                'username'
            ]),
            ('action','reset-entity',[
                'username',
                'password'
            ]),
            ('action','set-pass',[
                'username',
                'password'
            ]),
        ]
    )
    
    if module.check_mode:
        module.exit_json(**result)
    
    # debug option parameters
    if module.params['debug']:
        if module.params['debug_option'] == 'params': # debug module parameters
            module.fail_json(module.params)
        
        if module.params['debug_option'] == 'spec': # debug module argument spec
            module.fail_json(module.argument_spec)
    
    # return 
    command=EjbcaRa(module)
    result=command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()