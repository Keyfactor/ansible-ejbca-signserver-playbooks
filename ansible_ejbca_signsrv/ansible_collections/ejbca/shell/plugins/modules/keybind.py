#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ejbca_keybind
description: This module emulates the keyinbding category of the EJBCA CLI.
options:
    action:
        description: Friendly names that map to a valid Shell command
        required: true
        type: str
        choices:
            - create-auth
            - create-ocsp
            - delete
            - export-cert
            - gen-csr
            - import-cert
            - list
            - modify
            - set-status
            
    active:
        description: Sets the state of the keybinding to Active when creating a new binding or modifying an existing binding.
        default: true
        type: bool
        
    add_sign_behalf:
        description: Certificate Authorities the binding can sign respones for.
        type: list
        
    add_trust:
        description: Certificate Authorities the binding explicity trusts.
        options:
            ca:
                description: Certificate Authorities name.
                required: true
                type: str
            serial:
                description: Certificate Authorities certificate serial number.
                required: true
                type: str
        type: dict
        
    bind:
        description: Name of the keybinding
        type: str
        
    bind_output:
        description: Enable the addition of the entire key binding list output to stdout.
        default: false
        type: bool
        
    cert:
        description: Hexidecimal value of the key binding public certificate 
        default: 'null'
        type: str
    
    file:
        description: File path when exporting a public certificate, generating a CSR, or importing a public certificate for a key binding.
        required: false
        default: none
        type: path
        
    key:
        description: Private key alias for the key binding to use in the configured cryptotoken.
        default: none
        type: str
        
    path:
        description: Absolute path of EJBCA home directory.
        default: /opt/ejbca
        type: path
    properties:
        description: Additional properties of the key binding. Will vary based on key binding type.
        mutually_exclusive:
            - - protocol
                - non_good
            - - protocol
                - non_unauthorized
            - - protocol
                - include_chain
            - - protocol
                - include_cert
            - - protocol
                - require_trusted_signer
            - - protocol
                - responder_id
            - - protocol
                - max_age
            - - protocol
                - enable_nonce
            - - protocol
                - omit_reason
        options:
            enableNonce:
                description: When true, if the OCSP request contains a nonce, the response will contain a nonce as well. If false, a nonce will never be in the response, even if one is included in the request.
                aliases:
                    - enable_nonce
                type: bool
            includecertchain:
                description: When true, the entire certificate chain, except for the root CA certificate, will be included in the response (note that this is only applicable if 'Include signing certificate in response' is true).
                aliases:
                    - include_chain
                type: bool
            includesigncert:
                description: When true, the signing certificate will be included in the response.
                aliases:
                    - include_cert
                type: bool
            maxAge:
                description: A hint to caching proxies when using HTTP GET for how long to retain a response, and should be set to a value lesser than or equal to the response validity. A value of 0 means no caching.
                aliases:
                    - max_age
                type: bool
            nonexistingisgood:
                description: If true a certificate that does not exist in the database, but is issued by a CA known to the VA, it will be treated as not revoked.
                aliases:
                    - non_good
                type: bool
            nonexistingisrevoked:
                description: If true a certificate that does not exist in the database, but is issued by a CA known to the VA, it will be treated as revoked.
                aliases:
                    - non_revoked
                type: bool
            nonexistingisunauthorized:
                description: If true a certificate that does not exist in the database, but is issued by a CA known to the VA, the VA will respond with an unsigned "Unauthorized" message to show that it is unable to process the request. 
                aliases:
                    - non_unauthorized
                type: bool
            omitreasoncodewhenrevocationreasonunspecified:
                description: Enabled by default. CA/B Forum Baseline Requirements 1.7.1+ require that reason code is omitted when it is Unspecified. Disable the property to disregard this requirement.
                aliases:
                    - omit_reason
                type: bool
            protocolAndCipherSuite:
                description: The Authentication Key Binding defines a protocol and a cipher suite to use for the outgoing TLS connection. The protocols and cipher suites accessible in EJBCA are configured in cesecore.properties. 
                aliases:
                    - protocol
                choices:
                    - TLSv1.2;TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
                    - TLSv1.2;TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
                    - TLSv1.2;TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    - TLSv1.2;TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                type: str
            requireTrustedSignature:
                description: When true, request signatures will be checked against the list of trusted certificates or trust anchors.
                aliases:
                    - require_trusted_signer
                type: bool
            responderidtype:
                description: Defines the ResponderID type included in the response.
                aliases:
                    - responder_id
                type: bool
            untilNextUpdate:
                description: How long the OCSP response is valid and may be used. A value of 0 means that there is always a newer response available.
                aliases:
                    - next_update
                type: bool
        type: dict
    remove_sign_behalf:
        description: Remove a sign on behalf of setting from thd binding
        type: list
    remove_trust:
        description: Remove a Trust CA from thd binding
        options:
            ca:
                description: Certificate Authority name
                required: true
                type: str
            serial:
                description: Certificate Authority certificate serial number
                required: true
                type: str
        type: dict
    sigalg:
        description: Signature algorithm for the key binding.
        default: SHA256WithRSA
        type: str
        choices:
            - SHA1WithRSA
            - SHA256WithRSA
            - SHA384WithRSA
            - SHA512WithRSA
            - SHA3-256withRSA
            - SHA3-384withRSA
            - SHA3-512withRSA
            - SHA256withRSAandMGF1
            - SHA384withRSAandMGF1
            - SHA512withRSAandMGF1
            - SHA1withECDSA
            - SHA224withECDSA
            - SHA256withECDSA
            - SHA384withECDSA
            - SHA512withECDS
            - SHA3-256withECDSA
            - SHA3-384withECDSA
            - SHA3-512withECDSA
            - SHA1WithDSA
            - SHA256WithDSA
            - Ed25519
            - Ed448
            - FALCON-512
            - FALCON-1024
            - DIITHIUM2
            - DILITHIUM3
            - DILITHIUM5
            - LMS
    status:
        description: Keybinding status
        choices:
            - ACTIVE
            - DISABLED
        default: ACTIVE
        type: str
    token:
        description: Crypto token containing the private key the key binding needs to use.
        default: none
        type: str
    type:
        description: Type of key binding. AuthenticationKeyBinding or OcspKeyBinding.
        default: none
        type: str
        choices:
            - AuthenticationKeyBinding
            - OcspKeyBinding
'''

EXAMPLES = r'''
- name: List all Keybindings
  ejbca_keybind:
    cmd: list
    
- name: Create OCSP Responder key binding
  ejbca_keybind:
    cmd: create-ocsp
    bind: DelegatedOcspSigner
    token: OcspSigning
    key: signKeyIssuingCa
    properties:
      non_good: true
      non_revoked: false

- name: Create Remote Authentication key binding
  ejbca_keybind:
    cmd: create-auth
    bind: RemoteAuth
    token: Peering-Token
    key: peeringSignKey
    
- name: Modify OcspKeyBinding Properties
  ejbca_keybind:
    cmd: modify
    bind: DelegatedOcspSigner
    properties:
      non_good: false
      non_unauthorized: true

- name: Add Authentication Trusted CA
  ejbca_keybind:
    cmd: modify
    bind: RemoteAuth
    trust:
      action: add
      ca: Issuing-CA
      serial: 1E372A7D7BE39757CDC4D5C0D5941D6CF7A300E9
        
- name: Remove Sign On Behalf
  ejbca_keybind:
    cmd: modify
    bind: DelegatedOcspSigner
    trust:
      action: remove
      ca: Development-Issuing-CA

- name: Delete an existing key binding
  ejbca_keybind:
    cmd: delete
    bind: Peering
    
- name: Export a key binding public certificate
  ejbca_keybind:
    cmd: exportcert
    bind: RemoteAuth
    file: /path/to/certificate_outfile

- name: Generate a CSR for a key binding
  ejbca_keybind:
    cmd: gencsr
    bind: RemoteAuth
    file: /path/to/csr_outfile

- name: Import a signed pem file for a key binding
  ejbca_keybind:
    cmd: import
    bind: RemoteAuth
    file: /path/to/certificate_infile
    
- name: Disable keybinding
  ejbca_keybind:
    cmd: setstatus
    bind: RemoteAuth
    active: false
'''

RETURN = r'''
bindings:
    description: Dictionary containing Key Bindings.
    returned: success
    type: dict
    contains:
        active:
            description: If key binding is ACTIVE.
            type: bool
        alias:
            description: Key alias in crypto token.
            type: str
        alias_next:
            description: Key alias for next key to be generated upon renewal.
            type: str
        cert:
            description: Bound certificate.
            type: str
        id: 
            description: Identifer of the key binding.
            type: int
        issuer_dn:
            description: Certificate Authority that signed the bound certificate.
            type: str
        name:
            description: Name of the key binding
            type: str
        ocsp_extensions:
            description: Defined OCSP extensions.
            type: int
        properties:
            description: Additional properties of the key binding. Will vary based on key binding type.
            type: dict
            contains:
                enableNonce:
                    description: When true, if the OCSP request contains a nonce, the response will contain a nonce as well. If false, a nonce will never be in the response, even if one is included in the request.
                    type: bool
                includecertchain:
                    description: When true, the entire certificate chain, except for the root CA certificate, will be included in the response (note that this is only applicable if 'Include signing certificate in response' is true).
                    type: bool
                includesigncert:
                    description: When true, the signing certificate will be included in the response.
                    type: bool
                maxAge:
                    description: A hint to caching proxies when using HTTP GET for how long to retain a response, and should be set to a value lesser than or equal to the response validity. A value of 0 means no caching.
                    type: int
                nonexistingisgood:
                    description: If true a certificate that does not exist in the database, but is issued by a CA known to the VA, it will be treated as not revoked.
                    type: bool
                nonexistingisrevoked:
                    description: If true a certificate that does not exist in the database, but is issued by a CA known to the VA, it will be treated as revoked.
                    type: bool
                nonexistingisunauthorized:
                    description: If true a certificate that does not exist in the database, but is issued by a CA known to the VA, the VA will respond with an unsigned "Unauthorized" message to show that it is unable to process the request. 
                    type: bool
                omitreasoncodewhenrevocationreasonunspecified:
                    description: Enabled by default. CA/B Forum Baseline Requirements 1.7.1+ require that reason code is omitted when it is Unspecified. Disable the property to disregard this requirement.
                    type: bool
                protocol:
                    description: The Authentication Key Binding defines a protocol and a cipher suite to use for the outgoing TLS connection. The protocols and cipher suites accessible in EJBCA are configured in cesecore.properties. 
                    type: str
                requireTrustedSignature:
                    description: When true, request signatures will be checked against the list of trusted certificates or trust anchors.
                    type: bool
                responderidtype:
                    description: Defines the ResponderID type included in the response.
                    type: str
                untilNextUpdate:
                    description: How long the OCSP response is valid and may be used. A value of 0 means that there is always a newer response available.
                    type: int
        sign_algorithm:
            description: The signature algorithm user during signing, for example the signing of an OCSP response. 
            type: str
        sign_on_behalf:
            description: Certificate Authorities the binding can sign respones for.
            type: list
        status: 
            description: ACTIVE or DISABLED
            type: str
        token:
            description: Crypto token containing the key used by the binding.
            type: str
        token_id:
            description: ID of the crypto token containing the key used by the binding.
            type: int
        trusted_cas:
            description: Certificate Authorities the binding explicity trusts.
            type: list
        type:
            description: AuthenticationKeyBinding or OcspKeyBinding
            type: str

    sample:
        - active: true
          alias: peerKeyBindingOcsp0001
          alias_next: 'null'
          cert: 18E3E3BCCF9075CC9C0412953E025D7924CEAC9A
          id: 629947075
          issuer_dn: CN=ManagementCA,OU=ec2-52-71-196-138.compute-1.amazonaws.com,O=ami-09c021bea8d4aa06f
          name: peerClient-ocsp
          ocsp_extensions: []
          properties:
            - enableNonce: true
              includecertchain: true
              includesigncert: true
              maxAge: 0
              nonexistingisgood: true
              nonexistingisrevoked: false
              nonexistingisunauthorized: false
              omitreasoncodewhenrevocationreasonunspecified: true
              requireTrustedSignature: false
              responderidtype: KEYHASH
              untilNextUpdate: 0
          sign_algorithm: SHA256WithRSA
          sign_on_behalf:
            - Only certificates issued by a current CA
          status: DISABLED
          token: peeringCryptoToken
          token_id: 721224992
          trusted_cas: []
          type: OcspKeyBinding
          
stderr_lines:
    description: Shell error output. Not all errors will return a Failed. Some commands, such as generatekey, will be returned OK even though the shell error output has a returncode of 1.
    returned: always
    type: list
    elements: str
    sample:
        - Unknown InternalKeyBinding
    
stdout_lines:
    description: Shell standard output.
    returned: always
    type: list
    elements: str
    sample:
        - Deleted end entity with username: 'ejbca-server'
'''

import re
import os
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ejbca.shell.plugins.module_utils.shell import Shell
from ansible_collections.ejbca.shell.plugins.module_utils.common import (
    StringParser,
    argument_spec_common,
    COMMON_CHOICES
)

SHELL_COMMANDS = dict(
    # Dictionary mapping for CLI commands
    create = 'create',
    delete = 'delete',
    export_cert = 'exportcert',
    gencsr = 'gencsr',
    import_cert = 'import',
    list = 'list',
    modify = 'modify',
    setstatus = 'setstatus',
)

SHELL_ARGUMENTS = dict(
    # Dictionary mapping for available CLI arguments
    # each key maps to a module parameter
    # the value is the parameter value defined by EJBCA CLI
    # to add additional items, use "module_parameter  =  cli_parameter"
    bind = '--name',
    type = '--type', 
    cert = '--cert',
    key = '--alias',
    sigalg = '--sigalg',
    token = '--token',
    file = '-f',
    add_sign_behalf = '--addsignonbehalf',
    remove_sign_behalf = '--removesignonbehalf',
    
    # properties
    enableNonce = '-enableNonce',
    includecertchain = '-includecertchain',
    includesigncert = '-includesigncert',
    maxAge = '-maxAge',
    nonexistingisgood = '-nonexistingisgood',
    nonexistingisrevoked = '-nonexistingisrevoked',
    nonexistingisunauthorized = '-nonexistingisunauthorized',
    omitreasoncodewhenrevocationreasonunspecified = '-omitreasoncodewhenrevocationreasonunspecified',
    protocolAndCipherSuite = '-protocolAndCipherSuite',
    responderidtype = '-responderidtype',
    requireTrustedSignature = '-requireTrustedSignature',
    untilNextUpdate = '-untilNextUpdate',
)
# cat be added to args dict because they use the same module paramter and require additional parsing
SHELL_ARGUMENTS_STATUS_ARG = '--status'
SHELL_ARGUMENTS_STATUS_FLAG = '-v' 

MODULE_ACTIONS = dict(
    create_auth = dict(
        category = 'keybind',
        cmd = SHELL_COMMANDS['create'],
        allowed_params = [
            'bind',
            'token',
            'key',
            'type',
            'status',
            'cert',
            'sigalg',
            'protocolAndCipherSuite' 
        ],
        condition_failed = [
            'Unknown InternalKeyBinding:'
        ]
    ),
    create_ocsp = dict(
        category = 'keybind',
        cmd = SHELL_COMMANDS['create'],
        allowed_params = [
            'bind',
            'token',
            'key',
            'type',
            'status',
            'cert',
            'sigalg',
            'nonexistingisgood',
            'nonexistingisrevoked',
            'nonexistingisunauthorized',
            'omitreasoncodewhenrevocationreasonunspecified',
            'responderidtype',
            'requireTrustedSignature',
            'untilNextUpdate',
        ],
    ),
    delete = dict(
        category = 'keybind',
        cmd = SHELL_COMMANDS['delete'],
        allowed_params = [
            'bind'
        ],
        condition_ok = [
            'Unknown InternalKeyBinding:'
        ],
    ),
    export_cert = dict(
        category = 'keybind',
        cmd = SHELL_COMMANDS['export_cert'],
        action = 'export-cert',
        allowed_params = [
            'bind',
            'file'
        ],
    ),
    gen_csr = dict(
        category = 'keybind',
        cmd = SHELL_COMMANDS['gencsr'],
        action = 'gen-csr',
        allowed_params = [
            'bind',
            'file'
        ],
        condition_failed = [
            'Unknown InternalKeyBinding:'
        ],
        condition_changed = [
            'Stored PEM encoded PKCS#10 request'
        ]
    ),
    import_cert = dict(
        category = 'keybind',
        cmd = SHELL_COMMANDS['import_cert'],
        action = 'import-cert',
        allowed_params = [
            'bind',
            'file'
        ],
        condition_failed = [
            'Unknown InternalKeyBinding:'
        ],
        condition_changed = [
            'Stored PEM encoded PKCS#10 request'
        ]
    ),
    list = dict(
        category = 'keybind',
        cmd = SHELL_COMMANDS['list'],
        action = 'list',
    ),
    modify = dict(
        category = 'keybind',
        cmd = SHELL_COMMANDS['modify'],
        allowed_params = [
            'bind'
        ],
        condition_failed = [
            'Unknown InternalKeyBinding:'
        ]
    ),
    set_status = dict(
        category = 'keybind',
        cmd = SHELL_COMMANDS['setstatus'],
        action = 'set-status',
        allowed_params = [
            'bind',
            'status'
        ],
        condition_changed = [
            'was updated'
        ],
    ),
)

CHOICES = dict(
    cipher_suites = [
        'TLSv1.2;TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLSv1.2;TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLSv1.2;TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLSv1.2;TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    ],
    id = [
        'KEYHASH',
        'NAME'
    ],
    status = [
        'ACTIVE',
        'DISABLED'
    ],
    type = [
        'AuthenticationKeyBinding',
        'OcspKeyBinding'
    ],
)
CHOICES.update(COMMON_CHOICES) # update choices list with main

class EjbcaKeyBind(Shell):
    
    def __init__(self, module):
        """ Contstruct subclass 
    
        Description:
            - Superclass the Shell module to contrust the common attributes for this subclass.
            - Convert module parameters from string to integer values.
        
        Arguments:
            - AnsibleModule containing parsed parameters passed from Ansible task.
        """
        self.module = module
        # set default set password cmd to 'setpwd'
        self.status_extra_arg = SHELL_ARGUMENTS_STATUS_FLAG
        
        # access inherited class to build attributes
        super().__init__(module, MODULE_ACTIONS, SHELL_ARGUMENTS)
        
        # create class attributes for property options
        for key in self.module.params['properties'] if self.action in ['create_ocsp','create_auth'] else {}:
            setattr(self, key, self.module.params['properties'][key])
            
    def _parser_edit(self, output:str):
        """ Update list of key binding configuration booleans from parsed output.
        
        Description:
            - Create dictionary consiting of key binding configurations with a value of False.
            - Values will be updated to True if an update was made to the configration.
            - Locate the boolean value in the matched string and update the dictionary.
            
        Conditionals:
            - Loop keys in dictionary and match the key name with the name in each line.
            
        Return: 
            - Dictionary containing configurations that updated during execute of the command.
        """        
        edit_list = dict({k:False for k,v in CHOICES['properties']})
        output = iter(output.splitlines())
        for line in output:
            for k in edit_list:
                if f'Setting {k}' in line:
                    self.changed = True # update changed status to True if a single setting was updated
                    edit_list[k] = True
                elif ('Added sign on behalf entry') in line:
                    self.changed = True # update changed status to True if a single setting was updated
                    edit_list['addsignonbehalf'] = True
                elif ('Removed sign on behalf entry') in line:
                    self.changed = True # update changed status to True if a single setting was updated
                    edit_list['removesignonbehalf'] = True

        return edit_list
        
    def _parser_list(self,output:str,type:str):
        """ Create list of key bindings.
        
        Description:
            - Set 'changed' state to True to indicate a successful list operation
            - Iterates over list of dicationaries created from parsed stdout
    
        Arguments:
            - bindings
                - List must be split into two types, RemoteAuthenticationKeyBinding and OcspKeyBinding.
                - Each dictionary must consist of the keys: 'type' and 'line'.
            
        Return: 
            - List consisting of key dictionaries. Will be empty if no keys exist in the crypto token.
        """
        
        # create type match for extracting dict value from line 
        bind_list = list()
        properties_search = ('properties={','}')
        protocol_search = ('protocolAndCipherSuite=',' ')
        sign_on_behalf_search = ('signOnBehalfOfCas={','}')
        ocsp_ext_search = ('ocspExtensions={','}')
        archive_cutoff_search = ('archiveCutoff={','}')
        trust_search = ('trust={','}')

        for line in output: # loop output lines
            
            string = line.split('properties = {')[0].strip() # get string value before properties
            regex = r',(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)' # find commands outside of subject dns
            split_lines = re.split(regex,string) # splits on commas outside of subject dn
            properties = StringParser(line).tuple(properties_search)   
            status = split_lines[1].strip()  
            trusted_cas = list()      
            bind = dict(
                type = type,
                name = StringParser(split_lines[0]).quotes(),
                id = int(StringParser(split_lines[0]).id()),
                status = split_lines[1].strip(),
                issuer_dn = StringParser(split_lines[2]).quotes(),
                cert = split_lines[3].strip(),
                token = StringParser(split_lines[4]).quotes(),
                token_id = int(StringParser(split_lines[4]).id()),
                alias = split_lines[5].strip(),
                alias_next = split_lines[6].strip(),
                sign_algorithm = split_lines[7].strip(),
                active = True if status == 'ACTIVE' else False
            )

            # TODO: Old Regex split on string matches
            # New method splits on commas outside of SNDNs
            # # split strings into multiple sections
            # properties=StringParser(line).tuple(properties_search)
            # first_string=line.split(',')[0].strip()
            # second_string=line.split(first_string+', ')[1].split('properties={')[0].strip()
            # #properties=line.split(second_string)[1].split('trust={')[0].splitlines()
            
            # # build dictionary values
            # name=StringParser(first_string).quotes()
            # id=StringParser(first_string).id()
            # status=StringParser(second_string).list(status_search_list)
            # issuer_dn=str(second_string.split(status))
            # #issuer_dn=self.parser.distinguished_name(second_string.split(status)[1])
            # cert=StringParser(second_string.split(issuer_dn,1)[1]).comma()
            # token=StringParser(second_string.split(cert,1)[1]).quotes()
            # token_id=StringParser(second_string).id()
            # alias=StringParser(second_string.split(token_id,1)[1]).comma()
            # alias_next=StringParser(second_string.split(alias,1)[1]).comma()
            # sign_algorithm=StringParser(second_string).list(sign_algo_search_list)
            
            # # store in dictionary
            # bind=dict(
            #     type=bind_type,
            #     name=name,
            #     id=int(id),
            #     status=status,
            #     issuer=None if issuer_dn == 'n/a' else issuer_dn,
            #     cert=None if cert == 'n/a' else cert,
            #     token=token,
            #     token_id=int(token_id),
            #     alias=alias,
            #     alias_next=None if alias_next == 'null' else alias_next,
            #     sign_algorithm=sign_algorithm, 
            # )
            
            # authentication key binding only
            if type == 'AuthenticationKeyBinding':
                trusted = str(StringParser(line).tuple(trust_search)).splitlines()
                # if a CN is not included in the line, add ANY to the ca key
                # if the CA key is ANY, add ANY to serial else add the serial number
                # if the returned serial number is 'ANY certificate', update serial value to be 'ANY'
                for t in trusted:
                    ca = 'ANY known CA' if 'known CA' in StringParser(t).quotes() else StringParser(t).quotes()
                    serial = 'ANY certificate'
                    if 'ANY' not in ca:
                        serial = t.split(ca)[1].split(',')[1].strip()
                    trusted_cas.append(dict(
                        ca = ca,
                        serial = serial
                    ))
                properties_dict=dict(protocol=StringParser(properties).tuple(protocol_search))
                
            else:
                properties_lines = properties.splitlines()
                properties_dict = dict()
                for p in properties_lines:
                    k = StringParser(p).equal_sign(before = True)
                    v = StringParser(p).equal_sign()
                    properties_dict[k] = v
                
                # sign on behalf ca list
                sign_on_behalf_lines = StringParser(line).tuple(sign_on_behalf_search).splitlines()
                bind.update(sign_on_behalf = [StringParser(s).quotes() for s in sign_on_behalf_lines])
                
                # ocsp extensions
                ocsp_ext_lines = StringParser(line).tuple(ocsp_ext_search).splitlines()
                bind.update(ocsp_extensions = [StringParser(s).colon() for s in ocsp_ext_lines])
                
                # archive cutoff
                # only include if line in ocsp binding dump
                # ocsp bindings without the extension enabled will not include the line in the dump
                # remove period at end of sentence
                if 'archiveCutoff' in line:
                    archive_cutoff_lines = StringParser(line).tuple(archive_cutoff_search)
                    bind.update(archive_cutoff = ''.join(archive_cutoff_lines.rsplit('.')))

            bind.update(
                properties = [properties_dict],
                trusted_cas = trusted_cas
            )
            bind_list.append(bind) # add binding to list

        return bind_list

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
        
        # initialize result dictionaries
        results = dict()
        
        try:
            
            # Block ONE - modified execution
            
            # Create
            # required to use the correct status argument
            if self.action in ['create_ocsp','create_auth']:
                output, results = self.shell(
                    extra_args = f"{SHELL_ARGUMENTS_STATUS_ARG} {self.status}",
                    command = self.build_command())
                
            # Set-status
            # required to use the correct status argument
            elif self.action in ['set_status']:
                output, results = self.shell(
                    extra_args = f"{SHELL_ARGUMENTS_STATUS_FLAG} {self.status}",
                    command = self.build_command())

            # Block TWO - default execution
            else:
                
                # default execution
                output, results = self.shell(self.build_command()) # standard execution
                
                # dictionary building from parsing output
                # cannot use the main key and token parsers
                if self.action in ['list','find']:
                    bindings = list()
                    
                    # update return output parameter value if bind_output parameter suppresses it
                    if not self.bind_output: 
                        self.return_output = False

                    # split on OcspKeyBinding
                    ocsp_lines = output.split('OcspKeyBinding')[1:]
                    
                    # create ocsp and auth lines if ocsp lines exist
                    if ocsp_lines: 
                        bindings.extend(self._parser_list(
                            output = ocsp_lines,
                            type = 'OcspKeyBinding'
                        ))
                        authkey_bindings = ''.join(output.split('OcspKeyBinding')[:1])
                        authkey_lines = authkey_bindings.split('AuthenticationKeyBinding')[1:]
                    
                    # create auth lines if ocsp lines dont exist
                    else: 
                        authkey_lines = output.split('AuthenticationKeyBinding')[1:]

                    # parse auth lines if the authkey_lines isnt empty
                    if authkey_lines:
                        bindings.extend(self._parser_list(
                            output = authkey_lines,
                            type = 'AuthenticationKeyBinding'
                        ))

                    if bindings: # set changed to 'true' if list contains any bindings
                        results['changed'] = True
                        
                    results['bindings'] = bindings # update bindings list in results
                
                # create
                # binding dict to results after conditionals evaluated
                elif self.action in ['create']:
                    if results['changed']:
                        results['binding'] = dict(
                            name = self.bind,
                            id = int(self.id)
                        )
                
                # modify 
                elif self.action in ['modify']:
                    
                    # parse modify results so dict can be returned.
                    if not results['failed']:
                        results['updated'] = dict(self._parser_edit(output))

            # pass results through class to modify returned values before returning
            return self.return_results(results)
            
        except ValueError as e:
            self.module.fail_json(msg=e)

def argument_spec_keybind():
    return dict(
        active = dict(
            default = True,
            type = 'bool'
        ),
        add_sign_behalf = dict(
            type = 'list'
        ),
        add_trust = dict(
            type = 'dict',
            options = dict(
                ca = dict(
                    required = True,
                    type = 'str'
                ),
                serial = dict(
                    required = True,
                    type = 'str'
                )
            ),
        ),
        bind = dict(
            type = 'str'
        ),
        bind_output = dict(
            default = False,
            type = 'bool'
        ),
        cert = dict(
            default = 'null',
            type = 'str'
        ),
        key = dict(
            type = 'str'
        ),
        file = dict(
            type = 'path'
        ),
        properties = dict(
            type = 'dict',
            options = dict(
                nonexistingisgood = dict(
                    aliases = ['non_good'],
                    type = 'bool'
                ),
                nonexistingisrevoked = dict(
                    aliases = ['non_revoked'],
                    type = 'bool'
                ),
                nonexistingisunauthorized = dict(
                    aliases = ['non_unauthorized'],
                    type = 'bool'
                ),
                includecertchain = dict(
                    aliases = ['include_chain'],
                    type = 'bool'
                ),
                includesigncert = dict(
                    aliases = ['include_cert'],
                    type = 'bool'
                ),
                responderidtype = dict(
                    aliases = ['responder_id'],
                    type = 'bool'
                ),
                untilNextUpdate = dict(
                    aliases = ['next_update'],
                    type = 'bool'
                ),
                maxAge = dict(
                    aliases = ['max_age'],
                    type = 'bool'
                ),
                enableNonce = dict(
                    aliases = ['enable_nonce'],
                    type = 'bool'
                ),
                omitreasoncodewhenrevocationreasonunspecified = dict(
                    aliases = ['omit_reason'],
                    type = 'bool'
                ),
                protocolAndCipherSuite = dict(
                    aliases = ['protocol'],
                    type = 'str',
                    choices = [k for k in CHOICES['cipher_suites']]
                ),
                requireTrustedSignature = dict(
                    aliases = ['require_trusted_signer'],
                    type = 'bool'
                ),
            ),
            mutually_exclusive = [
                ('protocol','non_good'),
                ('protocol','non_unauthorized'),
                ('protocol','include_chain'),
                ('protocol','include_cert'),
                ('protocol','require_trusted_signer'),
                ('protocol','responder_id'),
                ('protocol','max_age'),
                ('protocol','enable_nonce'),
                ('protocol','omit_reason'),
            ]
        ),
        remove_sign_behalf = dict(
            type = 'list'
        ),
        remove_trust = dict(
            type = 'dict',
            options = dict(
                ca = dict(
                    required = True,
                    type = 'str'
                ),
                serial = dict(
                    required = True,
                    type = 'str'
                )
            ),
        ),
        sigalg = dict(
            default = 'SHA256WithRSA',
            type = 'str',
            choices = [k for k in CHOICES['sign_algorithms']]
        ),
        status = dict(
            type = 'str',
            default = 'ACTIVE',
            choices = [k for k in CHOICES['status']]
        ),
        token = dict(
            type = 'str'
        ),
        type = dict(
            type = 'str',
            choices = [k for k in CHOICES['type']]
        ),
    )
         
def run_module():
    
    # Load main argument spec into module argument spec
    module_args = argument_spec_common()
    
    # Update with sub class module argument spec
    module_args.update(argument_spec_keybind())
    
    # Update action choices
    # Replace underscore with hyphen for use to provide hyphen in the module action value
    module_args['action'].update(choices  =  [k.replace('_','-') for k in MODULE_ACTIONS])
    
    # Build module opbject
    module  =  AnsibleModule(
        argument_spec = module_args,
        supports_check_mode = True,
        required_if = [
            ('action', 'create-auth', [
                'bind',
                'key',
                'token',
            ]), 
            ('action', 'create-ocsp', [
                'bind',
                'key',
                'token'
            ]), 
            ('action', 'delete', [
                'bind'
            ]), 
            ('action', 'export-cert', [
                'bind',
                'file'
            ]), 
            ('action', 'find', [
                'bind'
            ]), 
            ('action', 'gen-csr', [
                'bind',
                'file'
            ]), 
            ('action', 'import-cert', [
                'bind',
                'file'
            ]), 
            ('action', 'modify', [
                'trust',
                'add_sign_behalf',
                'remove_sign_behalf',
                'properties'
            ], True),
            ('action', 'set-status', [
                'bind',
                'active'
            ]), 
        ],
        mutually_exclusive = [
            ('trust','sign_on_behalf','properties')
        ],
    )
    
    if module.check_mode:
        module.exit_json(**result)
        
    # set binding type based on action
    if module.params['action'] == 'create-auth':
        module.params['type'] = 'AuthenticationKeyBinding'
    elif module.params['action'] == 'create-ocsp':
        module.params['type'] = 'OcspKeyBinding'
        
    # set status based on 'active' parameter boolean
    if module.params['action'] == 'set-status':
        if module.params['active']:
            module.params['status'] = 'ACTIVE'
        else:
            module.params['status'] = 'DISABLED'
            
    # validate output/input file path
    if module.params['file'] != None:
        if os.path.isdir(module.params['file']):
            module.fail_json(msg=f"profile file paramater {module.params['file']} is a directory. A file path is required.")
            
        elif module.params['action'] in 'import' and not os.path.exists(module.params['file']):
            module.fail_json(msg=f"provided certificate file {module.params['file']} not found.")
            
    # check for empty list of ocsp configs if list is defined and key binding type is set to 'ocsp'
    if module.params['properties'] and module.params['properties'] is None:
        module.fail_json(msg=F"properties is defined but does not include any parameters")
        
    if module.params['debug']:
        if module.params['debug_option'] == 'params': # debug module parameters
            module.fail_json(module.params)
        
        if module.params['debug_option'] == 'spec': # debug module argument spec
            module.fail_json(module.argument_spec)

    command=EjbcaKeyBind(module)
    result=command.execute()
    module.exit_json(**result)
    
def main():
    run_module()

if __name__ == '__main__':
    main()