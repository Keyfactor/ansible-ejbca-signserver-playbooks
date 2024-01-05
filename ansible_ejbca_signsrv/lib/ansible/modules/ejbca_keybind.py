#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ejbca_keybind
description: This module emulates the keybding category of the EJBCA CLI.
author:
    - Jamie Garner (@jtgarner-keyfactor)
options:
    active:
        description: Sets the state of the keybinding to Active when creating a new binding or modifying an existing binding
        default: true
        type: bool
    bind:
        description: Name of the keybinding
        type: str
    cert:
        description: Hexidecimal value of the key binding public certificate 
        default: 'null'
        type: str
    cmd:
        description: CLI command to execute
        required: true
        type: str
        choices:
            - create
            - delete
            - exportcert
            - gencsr
            - import
            - modify
            - list
            - setstatus
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
        description: EJBCA home directory path
        required: true
        type: path
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
    token:
        description: Cryptotoken containing the private key the key binding needs to use.
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
- name: Create OCSP Responder key binding
  ejbca_keybind:
    cmd: create
    bind: DelegatedOcspSigner
    type: OcspKeyBinding
    token: OcspSigning
    key: signKeyIssuingCa
    properties:
        non_good: true
        non_revoked: false
    path: /opt/ejbca

- name: Create Remote Authentication key binding
  ejbca_keybind:
    cmd: create
    bind: Peering
    type: AuthenticationKeyBinding
    token: Peering-Token
    key: peeringSignKey
    path: /opt/ejbca
    
- name: Modify OcspKeyBinding Properties
    ejbca_keybind:
      cmd: modify
      bind: DelegatedOcspSigner
      properties:
        non_good: false
        non_unauthorized: true
      path: /opt/ejbca
      
- name: Add Authentication Trusted CA
    ejbca_keybind:
      cmd: modify
      bind: Peering
      trust:
        action: add
        ca: Development-Issuing-CA
        serial: 1E372A7D7BE39757CDC4D5C0D5941D6CF7A300E9
      path: /opt/ejbca
      
- name: Remove Sign On Behalf
    ejbca_keybind:
      cmd: modify
      bind: DelegatedOcspSigner
      trust:
        action: remove
        ca: Development-Issuing-CA
      path: /opt/ejbca

- name: Delete an existing key binding
  ejbca_keybind:
    cmd: delete
    bind: Peering
    path: /opt/ejbca

- name: Create dictionary of all existing key bindings
  ejbca_keybind:
    cmd: list
    path: /opt/ejbca
    
- name: Export a key binding public certificate
  ejbca_keybind:
    cmd: exportcert
    bind: RemoteAuth
    file: /var/tmp/RemoteAuth.pem
    path: /opt/ejbca

- name: Generate a CSR for a key binding
  ejbca_keybind:
    cmd: gencsr
    bind: RemoteAuth
    file: "/var/tmp/RemoteAuth.csr"
    path: /opt/ejbca

- name: Import a signed pem file for a key binding
  ejbca_keybind:
    cmd: import
    bind: RemoteAuth
    file: /var/tmp/RemoteAuth.crt
    path: /opt/ejbca
    
- name: Disable keybinding
  ejbca_keybind:
    cmd: setstatus
    bind: Peering
    active: false
    path: /opt/ejbca
    
- name: List all Keybindings
  ejbca_keybind:
    cmd: list
    path: /opt/ejbca
    
- name: List only AuthenticationKeyBindings
  ejbca_keybind:
    cmd: list
    type: AuthenticationKeyBinding
    path: /opt/ejbca
'''

RETURN = r'''
'''

import re
import os
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ejbca import (
    EjbcaCli,
    AttributeParser,
    StringParser,
    sign_algorithms,
    bool2str
)

def choices_actions():
    return [
        'add','remove'
    ]

def choices_binding_type():
    return [
        'AuthenticationKeyBinding',
        'OcspKeyBinding',
    ]
    
def choices_cipher_suites():
    return [
        'TLSv1.2;TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLSv1.2;TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLSv1.2;TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLSv1.2;TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    ]
    
def choices_commands():
    return [
        'create',
        'delete',
        'exportcert',
        'gencsr',
        'import',
        'modify',
        'list',
        'setstatus'
    ]
    
def choices_properties():
    return [
        ('protocolAndCipherSuite','protocol'),
        ('nonexistingisgood','non_good'),
        ('nonexistingisrevoked','non_revoked'),
        ('nonexistingisunauthorized','non_unauthorized'),
        ('includecertchain','include_chain'),
        ('includesigncert','include_cert'),
        ('requireTrustedSignature','require_trusted_signer'),
        ('responderidtype','responder_id'),
        ('maxAge','max_age'),
        ('enableNonce','enable_nonce'),
        ('omitreasoncodewhenrevocationreasonunspecified','omit_reason'),
    ]

def choices_responder_id():
    return [
        'KEYHASH',
        'NAME'
    ]
    
def choices_settings():
    return [
        ('Archive Cutoff','archive-cutoff'),
        ('Ocsp Extensions','ocsp-extensions'),
        ('Property','property'),
        ('sign_on_behalf','signonbehalf'),
        ('trust','trust'),
    ]

def spec_main():
    return dict(
        active=dict(
            default=True,
            type='bool'
        ),
        cert=dict(
            default='null',
            type='str'
        ),
        cmd=dict(
            required=True, 
            type='str',
            choices=[k for k in choices_commands()]
        ),
        key=dict(type='str'),
        bind=dict(type='str'),
        file=dict(type='path'),
        path=dict(
            required=True,
            type='str'
        ),
        properties=dict(
            type='dict',
            options=dict(
                non_good=dict(type='bool'),
                non_revoked=dict(type='bool'),
                non_unauthorized=dict(type='bool'),
                include_chain=dict(type='bool'),
                include_cert=dict(type='bool'),
                require_trusted_signer=dict(type='bool'),
                responder_id=dict(
                    type='str',
                    choices=[k for k in choices_responder_id()]
                ),
                next_update=dict(type='int'),
                max_age=dict(type='int'),
                enable_nonce=dict(type='bool'),
                omit_reason=dict(type='bool'),
                protocol=dict(
                    type='str',
                    choices=[k for k in choices_cipher_suites()]
                )
            ),
            mutually_exclusive=[
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
        return_output=dict(
            default=True,
            type='bool'
        ),
        setting=dict(
            type='str',
            choices=[k for k,v in choices_settings()]
        ),
        sigalg=dict(
            default='SHA256WithRSA',
            type='str',
            choices=[k for k in sign_algorithms()]
        ),
        sign_on_behalf=dict(
            type='dict',
            options=dict(
                action=dict(
                    required=True,
                    type='str',
                    choices=[k for k in choices_actions()]
                ),
                ca=dict(
                    required=True,
                    type='str'
                ),
            ),
        ),
        token=dict(type='str'),
        trust=dict(
            type='dict',
            options=dict(
                action=dict(
                    required=True,
                    type='str',
                    choices=[k for k in choices_actions()]
                ),
                ca=dict(
                    required=True,
                    type='str'
                ),
                serial=dict(
                    required=True,
                    type='str'
                )
            ),
        ),
        type=dict(
            type='str',
            choices=[k for k in choices_binding_type()]
        ),
    )
        
class EjbcaKeyBind(EjbcaCli):
    
    def __init__(self, module):
        self.module=module
        self.category='keybind'
        super().__init__(module)
        
        if self.cmd in ['create','modify'] and self.properties != None:
            self.property_params=''
            for p,v in self.properties.items():
                for property,alias in choices_properties():   
                    self.property_params+=f' -{property}="{bool2str(v)}"' if v != None and alias == p else ''
                        
            self.args+=self.property_params

            # update type
            self.modify_setting =''.join([v for k,v in choices_settings() if self.setting == k])
            
    def _parser_list(self,bindings):
        # create type match for extracting dict value from line
        sign_algo_search_list=[k for k in sign_algorithms()]
        status_search_list=['ACTIVE','DISABLED']
        properties_search=('properties={','}')
        protocol_search=('protocolAndCipherSuite=',' ')
        sign_on_behalf_search=('signOnBehalfOfCas={','}')
        ocsp_ext_search=('ocspExtensions={','}')
        archive_cutoff_search=('archiveCutoff={','}')
        trust_search=('trust={','}')
        
        # create attribute parser class
        self.parser = AttributeParser()
        
        for b in bindings:
            
            bind_type=b['type']
            line=b['line']

            # split strings into multiple sections
            properties=StringParser(line).tuple(properties_search)
            first_string=line.split(',')[0].strip()
            second_string=line.split(first_string+', ')[1].split('properties={')[0].strip()
            #properties=line.split(second_string)[1].split('trust={')[0].splitlines()
            
            # build dictionary values
            name=StringParser(first_string).quotes()
            id=self.parser.id(first_string)
            status=StringParser(second_string).list(status_search_list)
            issuer_dn=self.parser.distinguished_name(second_string.split(status)[1])
            cert=StringParser(second_string.split(issuer_dn,1)[1]).comma()
            token=StringParser(second_string.split(cert,1)[1]).quotes()
            token_id=self.parser.id(second_string)
            alias=StringParser(second_string.split(token_id,1)[1]).comma()
            alias_next=StringParser(second_string.split(alias,1)[1]).comma()
            sign_algorithm=StringParser(second_string).list(sign_algo_search_list)
            
            # store in dictionary
            bind=dict(
                type=bind_type,
                name=name,
                id=int(id),
                status=status,
                issuer=None if issuer_dn == 'n/a' else issuer_dn,
                cert=None if cert == 'n/a' else cert,
                token=token,
                token_id=int(token_id),
                alias=alias,
                alias_next=None if alias_next == 'null' else alias_next,
                sign_algorithm=sign_algorithm, 
            )

            trusted_cas=[]
            # authentication key binding only
            if bind_type == 'AuthenticationKeyBinding':
                trusted=str(StringParser(line).tuple(trust_search)).splitlines()
                # if a CN is not included in the line, add ANY to the ca key
                # if the CA key is ANY, add ANY to serial else add the serial number
                # if the returned serial number is 'ANY certificate', update serial value to be 'ANY'
                for t in trusted:
                    ca='ANY known CA' if 'known CA' in StringParser(t).quotes() else StringParser(t).quotes()
                    serial='ANY certificate'
                    if 'ANY' not in ca:
                        serial=t.split(ca)[1].split(',')[1].strip()
                    trusted_cas.append(dict(
                        ca=ca,
                        serial=serial
                    ))
                properties_list=dict(protocol=StringParser(properties).tuple(protocol_search))
                
            else:
                properties_lines=properties.splitlines()
                properties_list={}
                for p in properties_lines:
                    k=StringParser(p).equal_sign(before=True)
                    v=StringParser(p).equal_sign()
                    properties_list[k]=v
                
                # sign on behalf ca list
                sign_on_behalf_lines=StringParser(line).tuple(sign_on_behalf_search).splitlines()
                bind.update(sign_on_behalf=[StringParser(s).quotes() for s in sign_on_behalf_lines])
                
                # ocsp extensions
                ocsp_ext_lines=StringParser(line).tuple(ocsp_ext_search).splitlines()
                bind.update(ocsp_extensions=[StringParser(s).colon() for s in ocsp_ext_lines])
                
                # archive cutoff
                # only include if line in ocsp binding dump
                # ocsp bindings without the extension enabled will not include the line in the dump
                # remove period at end of sentence
                if 'archiveCutoff' in line:
                    archive_cutoff_lines=StringParser(line).tuple(archive_cutoff_search)
                    bind.update(archive_cutoff=''.join(archive_cutoff_lines.rsplit('.')))

            bind.update(
                properties=[properties_list],
                trusted_cas=trusted_cas
            )
            
            # add binding to list and finish loop
            self.bind_list.append(bind)

            # add line to stdout if set to true
            if self.return_output:
                self.stdout_lines.append(b)

    def execute(self):
        try:
            # dictionary building from parsing output
            # cannot use the main key and token parsers
            if self.cmd in ['list']:
                self.bind_list=[]
                output,rc=self._shell(self.args)
                bindings=[]

                # sepereate ocsp and auth bindings if ocsp exists
                # create binding lines and append to single list for single parsing function
                if 'OcspKeyBinding' in output:
                    ocsp_lines=output.split('OcspKeyBinding')[1:]
                    
                    # only add if type not defined or type is defined and defined as OcspKeyBinding
                    if self.type is None or (self.type and self.type == 'OcspKeyBinding'):
                        for a in ocsp_lines:
                            bindings.append(
                                dict(
                                    type='OcspKeyBinding',
                                    line=''.join(a)
                                )
                            )

                    if 'AuthenticationKeyBinding' in output:
                        # remove ocsp key bindings and convert to string for second parsing
                        authkey_bindings=''.join(output.split('OcspKeyBinding')[:1])
                        authkey_lines=authkey_bindings.split('AuthenticationKeyBinding')[1:]
                
                # split stdout not using OcspKeyBinding if it is not in output  
                else:
                    authkey_lines=output.split('AuthenticationKeyBinding')[1:]
                    
                # add AuthenticationKeyBinding to dict if exists in output and the defined type is null or AuthenticationKeyBinding
                if 'AuthenticationKeyBinding' in output and \
                    self.type is None or (self.type and self.type == 'AuthenticationKeyBinding'):
                    for a in authkey_lines:
                        bindings.append(
                            dict(
                                type='AuthenticationKeyBinding',
                                line=''.join(a)
                            )
                        )
                    
                self._parser_list(bindings)

                # update bindings list in results
                self.result.update(bindings=self.bind_list) 
                
            else:
                # set baseline args used by all the following commands
                self.args+=f' \
                    --name "{self.bind}"'
                status='ACTIVE' if self.active else 'DISABLED'
                
                if self.cmd in ['modify']:
                    self.condition_ok=['No changes were made']
                    if self.trust:
                        self.args+=f' \
                            --{self.trust["action"]}trust "{self.trust["ca"]};{self.trust["serial"]}"'
                            
                    elif self.sign_on_behalf:
                        self.args+=f' \
                            --{self.sign_on_behalf["action"]}signonbehalf "{self.sign_on_behalf["ca"]}"'
                        
                elif self.cmd in ['create']:
                    self.args+=f" \
                        --alias {self.key} \
                        --cert {self.cert} \
                        --sigalg {self.sigalg} \
                        --status {status} \
                        --token {self.token} \
                        --type {self.type}"

                elif self.cmd in ['exportcert','gencsr','import']:
                    self.args+=f" \
                        -f {self.file}"
                        
                    if self.cmd in ['gencsr']: # change successful message for matching 'gencsr'
                        self.condition_changed=['Stored PEM encoded PKCS#10']
                    
                elif self.cmd in ['setstatus']:
                    self.condition_changed=['updated']
                    self.args+=f" \
                        -v {status}"
                    
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
            ('cmd', 'create', ['bind','key','token','type']), 
            ('cmd', 'delete', ['bind']), 
            ('cmd', 'export', ['bind','file']), 
            ('cmd', 'gencsr', ['bind','file']), 
            ('cmd', 'import', ['bind','file']), 
            ('cmd', 'import', ['bind','active']), 
            ('cmd', 'modify', ['trust','sign_on_behalf','properties'], True),
        ],
        mutually_exclusive=[
            ('trust','sign_on_behalf','properties')
        ],
    )
    
    if module.check_mode:
        module.exit_json(**result)

    # validate output/input file path
    if module.params['file'] != None:
        if os.path.isdir(module.params['file']):
            module.fail_json(msg=f"profile file paramater {module.params['file']} is a directory. A file path is required.")
            
        elif module.params['cmd'] in 'import' and not os.path.exists(module.params['file']):
            module.fail_json(msg=f"provided certificate file {module.params['file']} not found.")
            
    # check for empty list of ocsp configs if list is defined and key binding type is set to 'ocsp'
    if module.params['properties'] and module.params['properties'] is None:
        module.fail_json(msg=F"properties is defined but does not include any parameters")

    command=EjbcaKeyBind(module)
    result=command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()