#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ca
version_added: "1.0.0"
description: This module emulates the CA 'publisher' commandsthe EJBCA Shell.
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
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible_collections.ejbca.shell.plugins.module_utils.shell import Shell
from ansible_collections.ejbca.shell.plugins.module_utils.common import (
    StringParser,
    argument_spec_common,
)

SHELL_COMMANDS = dict(
    # Dictionary mapping for CLI commands
    list = 'listpublishers',
    remove = 'removepublisher',
    edit = 'editpublisher',
)

SHELL_ARGUMENTS = dict(
    # Dictionary mapping for available CLI arguments
    # each key maps to a module parameter
    # the value is the parameter value defined by EJBCA CLI
    # to add additional items, use "module_parameter = cli_parameter"
    name = '--name',
    list_refs = '--listref',
    field = '--field',
)

# cant be added to args dict because its a flag on the CLI. needs to be passed as an extra arg
SHELL_ARGUMENTS_FIELD_GET = '-getValue'
SHELL_ARGUMENTS_REMOVE_ALL = '--removeall' 
SHELL_ARGUMENTS_REFS_ONLY = '--removeref' 

MODULE_ACTIONS = dict(
    edit_field = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['edit'],
        allowed_params = [
            'name',
            'field',
            'value'
        ],
    ),
    get_field = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['edit'],
        allowed_params = [
            'name',
            #'field'
        ],
        condition_changed = [
            'returned value'
        ],
    ),
    list_refs = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['remove'],
        allowed_params = [
            'name',
        ],
        condition_failed = [
            'does not exist'
        ]
    ),
    list_pubs = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['list'],
    ),
    remove = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['remove'],
        allowed_params = [
            'name',
        ],
        condition_changed = [
            'Removed publisher'
        ],
        condition_failed = [
            'does not exist'
        ]
    ),
)
CHOICES = dict(
    publishers = dict(
        MultiGroupPublisher = [
            ('publisherId', 'int'),
            ('peerId','string'),
            ('onlyUseQueue', 'boolean'),
            ('useQueueForCRLs', 'boolean'),
            ('useQueueForCertificates', 'boolean'),
            ('safeDirectPublishing', 'boolean'),
            ('description', 'string'),
            ('propertyData', 'string'),
            ('useQueueForOcspResponses', 'boolean'),
            ('keepPublishedInQueue', 'boolean'),
            ('name', 'string'),
            ('properties', 'properties'), 
        ],
        VaPeerPublisher = [
            ('publisherId', 'int'),
            ('onlyUseQueue', 'boolean'),
            ('useQueueForCRLs', 'boolean'),
            ('useQueueForCertificates', 'boolean'),
            ('safeDirectPublishing', 'boolean'),
            ('description', 'string'),
            ('keepPublishedInQueue', 'boolean'),
            ('publisherGroups', 'list'),
            ('keepPublishedInQueue', 'boolean'),
            ('name', 'string'),
        ],
    )
)

class EjbcaPublisher(Shell):
    def __init__(self, module:AnsibleModule):
        """ Contstruct subclass 
        
        Description:
            - Superclass the Shell module to contrust the common attributes for this subclass.
            - Convert module parameters from string to integer values.
        
        Arguments:
            - AnsibleModule containing parsed parameters passed from Ansible task.
        """
        self.module = module
        self.field_list = list()

        # access inherited class to build attributes
        super().__init__(module, MODULE_ACTIONS, SHELL_ARGUMENTS)
        
        # create field list
        # necessary to get out of nested dictionary
        for name, fields in CHOICES['publishers'].items():
            for f in fields if name == module.params['type'] else {}:
                self.field_list.append(f)
        
    def _parser_get_field(self, output:str):
        """ Get field value from output and convert to a human-readable value """
        
        output = output.splitlines()
        for line in output:
            if self.field in line:
                return self.converter(line)
    
    def _parser_list(self, output:str):
        """ Get CA publishers """
        
        output = iter(output.splitlines())
        publisher_list = list()
        for line in output:
            
            if ('Publisher ID' in line):
                publisher = dict(
                    id = int(StringParser(line).split_strip('Publisher ID:', False)),
                    name = StringParser(next(output)).split_strip('Name:', False)
                )
                publisher_list.append(publisher) 
       
        return publisher_list
    
    def _parser_list_refs(self, output:str):
        """ Get Publisher CA and Certificate Profile references """
        
        output = iter(output.splitlines())
        cas = list()
        profiles = list()
        for line in output:
            
            if 'CA' in line:
                cas.append(StringParser(line).quotes(single = True)) # get value between single quotes)
                
            if 'Certificate profile' in line:
                profiles.append(StringParser(line).quotes(single = True)) # get value between single quotes)
       
        return cas, profiles

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
            
            # Block ONE
            # Get field
            if self.action in ['get_field']:
                output, results = self.shell(
                    extra_args = f'{SHELL_ARGUMENTS_FIELD_GET} {self.field}', # pass field name without the swith '-getValue'
                    command = self.build_command()
                )
                
                # update results with field dictionary
                results['field'] = dict(
                    name = self.field,
                    value = self._parser_get_field(output)
                )
                    
                
                #self.module.fail_json(results)
        
            # Edit field
            elif self.action in ['edit_field']:
                pass
                 
            # List references
            elif self.action in ['list_refs']:
                
                # pass extra argument flag 
                output, results = self.shell(
                    extra_args = SHELL_ARGUMENTS['list_refs'],
                    command = self.build_command()
                )
                
                # parse output and build cas and profiles list to return 
                cas, profiles = self._parser_list_refs(output)
                results.update(
                    cas = cas,
                    profiles = profiles
                )
                
                # set changed to 'true' if either list contains at least one reference
                if len(results['cas']) or len(results['profiles']):
                    results['changed'] = True
       
            # Remove
            elif self.action in ['remove']:
                
                # add remove_refs argument to extra args variable if boolean passed as true
                # pass remove_all if boolean not passed or passed as false
                extra_remove = SHELL_ARGUMENTS_REFS_ONLY if self.refs_only else SHELL_ARGUMENTS_REMOVE_ALL
                    
                output, results = self.shell(
                    extra_args = extra_remove,
                    command = self.build_command()
                )

            # Block TWO - default execution
            else:
                output, results = self.shell(self.build_command())
                
                # List publishers
                if self.action in ['list_pubs']:
                    results['publishers'] = self._parser_list(output)
                    
                    # set changed to 'true' if list contains at least one publisher
                    if len(results['publishers']):
                        results['changed'] = True

            # pass results through class to modify returned values before returning
            return self.return_results(results)          
            
        except ValueError as e:
            self.module.fail_json(msg = e)
            
def argument_spec_publisher():
    return dict(
        action = dict(
            type = 'str'
        ),
        field = dict(
            type = 'str',
        ),
        name = dict(
            type = 'str'
        ),
        refs_only = dict(
            default = False,
            type = 'bool'
        ),
        template = dict(
            type = 'path'
        ),
        type = dict(
            type = 'str',
            choices = [type for type in CHOICES['publishers']]
        ),
        value = dict(
            type = 'str'
        ),
    )
           
def run_module():
    
    # Load main argument spec into module argument spec
    module_args = argument_spec_common()
    
    # Update with sub class module argument spec
    module_args.update(argument_spec_publisher())
    
    # Update action choices
    # Replace underscore with hyphen for use to provide hyphen in the module action value
    module_args['action'].update(choices = [action.replace('_','-') for action in MODULE_ACTIONS])
    
    # Build module opbject
    module = AnsibleModule(
        argument_spec = module_args,
        supports_check_mode = True,
        required_if=[
            ('action','edit-field',[
                'name',
                'field',
                'value',
            ]),
            ('action','get-field',[
                'name',
                'field',
                'type'
            ]),
            ('action','list-refs',[
                'name'
            ]),
            ('action','remove',[
                'name'
            ]),
        ]
    )
    
    if module.check_mode:
        module.exit_json(**result)
        
    # store shell version of field name in module parameters
    if module.params['action'] in ['get-field']:
        
        # initialize empty list for appending matching fields for each publisher
        field_choices = [] 

        # loop each publisher item to match the item with the paramter
        # enter second loop to get first element (fieldName) from tuple
        for name, fields in CHOICES['publishers'].items():
            for f in fields if name == module.params['type'] else {}:
                field_choices.append(f[0])
        
        # update argument spec with new choices 
        module.argument_spec['field'].update(choices = field_choices)

        # validate updated choices based on field parameter
        validator = ArgumentSpecValidator(module.argument_spec)
        validator.validate(module.params)
        result = validator.validate(module.params)
        
        # throw error is provide field value is not an available choice
        if result.error_messages:
            module.fail_json("Validation failed: {0}".format(", ".join(result.error_messages)))

    # debug option parameters
    if module.params['debug']:
        if module.params['debug_option'] == 'params': # debug module parameters
            module.fail_json(module.params)
        
        if module.params['debug_option'] == 'spec': # debug module argument spec
            module.fail_json(module.argument_spec)
    
    # return 
    command=EjbcaPublisher(module)
    result=command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()