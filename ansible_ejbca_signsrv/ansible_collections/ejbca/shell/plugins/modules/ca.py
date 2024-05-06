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
description: This module emulates the ca categories of the EJBCA Shell.
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

import re
import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ejbca.shell.plugins.module_utils.shell import Shell
from ansible_collections.ejbca.shell.plugins.module_utils.common import (
    StringParser,Converter,Validate,
    argument_spec_common,
    COMMON_CHOICES
)

SHELL_COMMANDS = dict(
    # Dictionary mapping for CLI commands
    changecatoken = 'changecatoken',
    createcrl = 'createcrl',
    createcert = 'createcert',
    editca = 'editca',
    exportca = 'exportca',
    getcafield = 'getcafield',
    importcacert = 'importcacert',
    init = 'init',
    importcrl = 'importcrl',
    listcas = 'listcas',
    listpublishers = 'listpublishers',
    removepublisher = 'removepublisher',
    renewca = 'renewca',
)

SHELL_ARGUMENTS = dict(
    # Dictionary mapping for available CLI arguments
    # each key maps to a module parameter
    # the value is the parameter value defined by EJBCA CLI
    # to add additional items, use "module_parameter = cli_parameter"
    ca = '--caname',
    field = '--field',
    list_refs = '--listref',
    start_date = '--updateDate',
    publisher = '--name',
    value = '--value',
)

# cant be added to args dict because its a flag on the CLI. needs to be passed as an extra arg
SHELL_ARGUMENTS_REMOVE_ALL = '--removeall' 
SHELL_ARGUMENTS_REFS_ONLY = '--removeref' 

MODULE_ACTIONS = dict(
    edit_field = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['editca'],
        action = 'edit-field',
        allowed_params = [
            'ca',
            'field',
            'value',
        ],
    ),
    gen_crl = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['createcrl'],
        action = 'get-crl',
        allowed_params = [
            'ca',
            'start_date',
        ],
    ),
    get_field = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['getcafield'],
        action = 'get-field',
        allowed_params = [
            'ca',
            'field',
        ],
        condition_ok = [],
        condition_changed = [
            'returned value'
        ],
    ),
    
    list_cas = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['listcas'],
        action = 'list-cas',
    ),
    list_pubs = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['listpublishers'],
    ),
    pub_refs = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['removepublisher'],
        allowed_params = [
            'publisher',
        ],
    ),
    pub_remove = dict(
        category = 'ca',
        cmd = SHELL_COMMANDS['removepublisher'],
        allowed_params = [
            'publisher',
        ],
        condition_failed = [
            'does not exist'
        ]
    ),
)

# Available choices to select from
CHOICES = dict(
    ca_fields = [
        # validated - requires succes getcafield and editca
        ('CaIssuerUri','authorityInformationAccess','list'),
        ('CRL Expire Period','CRLIssueInterval','long'),
        ('CRL Issue Interval','CRLIssueInterval','long'),
        ('CRL Overlap Time','CRLOverlapTime','long'),
        ('Default CRL Issuer','defaultCRLIssuer','string'),
        ('Default CRL Distribution Point','defaultCRLDistPoint','string'),
        ('EnforceUniquePublicKeys','doEnforceUniquePublicKeys','boolean'),
        ('EnforceKeyRenewal','doEnforceKeyRenewal','boolean'),
        ('OCSP service Default URI','defaultOCSPServiceLocator','string'),
        ('Status','status','int'),
        
        # need validation
        # ('EnforceUniqueSubjectDn','doEnforceUniqueSubjectDNSerialnumber','boolean'),
        # ('FinishUser','finishUser','boolean'),
        # ('IncludeInHealthCheck','includeInHealthCheck','boolean'),
        # ('OcspLocator','defaultOCSPServiceLocator','string'),
        # ('ProfileId','certificateProfileId','int'),
        # ('Publishers','CRLPublishers','collection'),
    ],
)
#CHOICES.update(COMMON_CHOICES) # update choices list with main

class EjbcaCa(Shell):
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
        
    def _converter(self, line:str):
        """ Converts value from database into a human-readable value.
         
        Description:
            - Uses database schema provided in tuple to determine how to convert value
        
        Arguments:
            - line:
                - String from output containing value needing to be parsed
                
        Return: Converted value
         """
         
        # get type from tuple for provided field name
        field_type = ''.join(schema for value, field, schema in CHOICES['ca_fields'] if field == self.field)
        value = StringParser(line).quotes(single = True) # get value between single quotes
        if field_type in ['long', 'boolean', 'int']:
            
            # long
            if field_type in ['long']:
                #self.module.fail_json(value)
                return Converter.from_milliseconds(int(value))
            
            # boolean
            elif field_type in ['boolean']:
                return Converter.str_to_bool(value)
            
            # status
            elif field_type in ['int'] and self.field in ['status']:
                # active
                if int(value) == 1:
                    return 'active'
                # off-line
                elif int(value) == 5:
                    return 'off-line'
                # external
                elif int(value) == 6:
                    return 'external'
                return value    
                
        # list
        elif field_type in ['list']:
            # check for empty list as string
            
            if value == '[]': # convert to empty list
                value_list = [] 
                
            else: # convert string to list
                value_list = list(value) 
                
            if not len(value_list):
                return 'undefined'
            return value_list
            
        # string
        elif field_type in ['string']:
            if not len(value):
                return 'undefined'
            return value
            
        # all other types
        else:
            return value
                
    def _parser_get_field(self, output:str):
        """ Get field value from output and convert to a human-readable value """
        
        output = output.splitlines()
        for line in output:
            if self.field in line:
                return self._converter(line)
            
    def _parser_edit_field(self, output:str):
        """ Compares current value with new value 
        
        Return: Tuple of current and new values as string values
        """
        
        output = output.splitlines()
        for line in output:
            # Current value
            if f"Current value of {self.field}" in line:
                current = StringParser(line).quotes(single = True)
            
            # New value
            if f"{self.field} returned value" in line:
                new = StringParser(line).quotes(single = True)
       
        return current, new
            
    def _parser_gen_crl(self, output:str):
        """ Get integer count for CRLs created from output """
        
        output = output.splitlines()
        crls = dict()
        for line in output:
            
            # delta crls
            if 'delta CRLs have been created' in line:
                crls['delta'] = int(line.split()[0])
            
            # regular - assumuption since delta isnt in name
            elif 'CRLs have been created' in line:
                crls['full'] = int(line.split()[0])
       
        return crls
        
    def _parser_list_cas(self, output:str):
        """ Create dynamic dict containing CA values.
        
        Description:
            - Dict will be populated with every line included in shell output
            - Iterator created from output
        
        Arguments:
            - output:
                - List of strings split from shell output.
            
        Conditonals:
            - ('CA Name'):
                - Used to detect the beginning of the key list in the output.
                - Each line after this condition is met are considered keys in each CA.
                - next(output) use to get the next line.
            
        Return: 
            - ca_list:
                - List consisting of key and values of each CA.
        """
        ca_list = []
        output = iter(output.splitlines())
        for line in output:
            if ('CA Name' in line):

                # Get keys
                # Each line must be account for even if not included in return dict because of iteration
                name = StringParser(line).split_strip('CA Name:', False)
                id = StringParser(next(output)).split_strip('Id:', False)
                issuer_dn = StringParser(next(output)).split_strip('Issuer DN:', False)
                subject_dn = StringParser(next(output)).split_strip('Subject DN:', False)
                ca_type = StringParser(next(output)).split_strip('Type:', False)
                expire_time = StringParser(next(output)).split_strip('Expire time:', False)
                signed_by = StringParser(next(output)).split_strip('Signed by:', False)
                ca = dict(
                    name = name,
                    id = int(id),
                    issuer = StringParser(issuer_dn).dn_common_name(), # issuer name derived from DN
                    issuer_dn = issuer_dn,
                    subject_dn = subject_dn,
                    type = int(ca_type),
                    expire = expire_time,
                    self_signed = True if signed_by == '1' else False # self_signed boolean determined by signed_by value
                )
                ca_list.append(ca) 
                
        return ca_list
    
    def _parser_list_pubs(self, output:str):
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
    
    def _parser_pub_references(self, output:str):
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
            output, results = self.shell(self.build_command())
            
            # List
            if self.action in ['list_cas']:
                results['cas'] = self._parser_list_cas(output)
                
            # Edit CA Field
            elif self.action in ['edit_field']:
                current, new = self._parser_edit_field(output)
                
                # set changed to 'true' if current and new are same value
                if current != new:
                    results['changed'] = True
                    
                # return dictionary
                results['field'] = dict(
                    name = self.field,
                    current = current,
                    new = new
                )
            
            # Get CA Field
            elif self.action in ['get_field']:
                results['field'] = dict(
                    name = self.field,
                    value = self._parser_get_field(output)
                )
                
            # Generate CRL
            elif self.action in ['gen_crl']:
                # get counts of CRLs published
                crl_counts = dict(self._parser_gen_crl(output))
                
                
                # if count is more than 1, set result changed to 'true'
                if (crl_counts['full'] or crl_counts['delta']) > 0:
                    results['changed'] = True
                    
                # load CRL dictionary into results
                results['crls'] = crl_counts
                
            # List publishers
            elif self.action in ['list_publishers']:
                results['publishers'] = self._parser_list_pubs(output)
                
                if len(results['publishers']):
                    results['changed'] = True

            # pass results through class to modify returned values before returning
            return self.return_results(results)          
            
        except ValueError as e:
            self.module.fail_json(msg = e)
            
def argument_spec_ca():
    return dict(
        action = dict(
            type = 'str'
        ),
        ca = dict(
            type = 'str'
        ),
        field = dict(
            type = 'str',
            choices = [k for k,v,t in CHOICES['ca_fields']]
            #choices = [k for k,v,t in CHOICES['ca_fields']] + [v for k,v,t in CHOICES['ca_fields']]
        ),
        force = dict(
            default = False,
            type = 'bool'
        ),
        publisher = dict(
            type = 'str'
        ),
        refs_only = dict(
            default = False,
            type = 'bool'
        ),
        start_date = dict(
            type = 'str'
        ),
        value = dict(
            type = 'str'
        ),
    )
           
def run_module():
    
    # Load main argument spec into module argument spec
    module_args = argument_spec_common()
    
    # Update with sub class module argument spec
    module_args.update(argument_spec_ca())
    
    # Update action choices
    # Replace underscore with hyphen for use to provide hyphen in the module action value
    module_args['action'].update(choices = [k.replace('_','-') for k in MODULE_ACTIONS])
    
    # Build module opbject
    module = AnsibleModule(
        argument_spec = module_args,
        supports_check_mode = True,
        required_if=[
            ('action','get-field',[
                'ca',
                'field'
            ]),
            ('action','edit-field',[
                'ca',
                'field',
                'value',
            ]),
            ('action','pub-refs',[
                'publisher'
            ]),
        ]
    )
    
    if module.check_mode:
        module.exit_json(**result)
        
    # check for valid datetime
    if module.params['action'] in ['gen-crl']:
        valid_start_date = Validate.datetime(module.params['start_date'])
        if valid_start_date:
            module.fail_json(valid_start_date)

    # store shell version of field name in module parameters
    elif module.params['action'] in ['get-field', 'edit-field']:
        module.params['field'] = ''.join([v for k,v,t in CHOICES['ca_fields'] if k == module.params['field']])
        #module.params['field'] = ''.join([v for k,v,t in CHOICES['ca_fields'] if (k == module.params['field'] or v == module.params['field'])])

    # debug option parameters
    if module.params['debug']:
        if module.params['debug_option'] == 'params': # debug module parameters
            module.fail_json(module.params)
        
        if module.params['debug_option'] == 'spec': # debug module argument spec
            module.fail_json(module.argument_spec)
    
    # return 
    command=EjbcaCa(module)
    result=command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()