#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: peer
version_added: "1.0.0"
description: This module emulates the peer categoryof the EJBCA Shell.
options:
    action:
        description: Friendly names that map to a valid Shell command
        required: true
        type: str
        choices:
            - create
            - edit-global
            - edit-peer
            - list
            - remove
            
    akb:
        description: Check for existing keybinding by Name before creating
        type: str
        
    check_existing:
        description: List existing peers to verify a Name doesnt already exist. EJBCA will create peers with the same name so use this boolean to prevent the creation of multiple peers with the same name. Only use this if not list the peers prior to a creation task.
        default: False
        type: bool
        
    enable_in:
        description: Allow incoming peer connections. One of 'true' or 'false'.
        type: bool
        
    enable_out:
        description: Allow outgoing peer connections. One of 'true' or 'false'.
        type: bool
        
    id:
        description: ID of the peer connector to edit. Required instead of name because names are not unique.
        type: int
        
    max:
        description: The maximum number of threads used to process incoming requests.
        type: int
        
    min:
        description: The minimum number of threads used to process incoming requests.
        choices:
            - 1
            - 2
            - 3
            - 4
        type: int
    
    name:
        description: Name of the peer connection.
        type: str
        
    path:
        description: Absolute path of EJBCA home directory.
        default: /opt/ejbca
        required: false
        type: path
        
    process_incoming:
        description: Allow or deny processing of incoming requests
        type: bool
        
    return_output:
        description: Returns stdout and stderr lines in output. Set to 'false' to limit console output.
        default: true
        type: bool
        
    state:
        description: State of the created peer connection. One of 'enabled' or 'disabled'.
        choices:
            - Enabled
            - Disabled
        type: str
        
    type:
        description: Filter returned peers by Incoming or Outgoing connections.
        choices:
            - incoming
            - outgoing
        type: str
        
    url:
        description: URL to the peer.
        type: str
'''

EXAMPLES = r'''
- name: List all peer connections
  ejbca.shell.peer:
    action: list
    
- name: List only outgoing peer connections
  ejbca.shell.peer:
    action: list
    type: outgoing

'''

RETURN = r'''
peers:
    description: Dictionary containing Peer attributes.
    returned: success
    type: dict
    contains:
        id:
            description: ID of the peer connector.
            type: int
        name:
            description: Name of the peer connection
            type: str
        state:
            description:  State of the created peer connection.
            type: int
        sync_status: 
            description: LDAP attributes
            type: str
        url:
            description: When the End Entity was created.
            type: str
        
    sample:
            
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
    argument_spec_common
)

SHELL_COMMANDS = dict(
    # Dictionary mapping for CLI commands
    config = 'config',
    create = 'create',
    edit = 'edit',
    list = 'list',
    remove = 'remove',
)

SHELL_ARGUMENTS = dict(
    # Dictionary mapping for available CLI arguments
    # each key maps to a module parameter
    # the value is the parameter value defined by EJBCA CLI
    # to add additional items, use "module_parameter = cli_parameter"
    id='--id',
    akb='--akb',
    enable_in='--enable-in',
    enable_out='--enable-out',
    max='--max-parallel-requests',
    min='--min-parallel-requests',
    name='--name',
    process_incoming='--process-incoming-requests',
    state='--state',
    url='--url',
)

MODULE_ACTIONS = dict(
    create = dict(
        category = 'peer',
        cmd = SHELL_COMMANDS['create'],
        action = 'create',
        allowed_params = [
            'akb',
            'name',
            'state',
            'url',
        ],
        condition_failed = [
            'Parameter --akb must be specified as one of'
        ],
        condition_failed_msg = 'Specified keybinding doesnt exist. Provide a valid keybinding.'
    ),
    edit_global = dict(
        category = 'peer',
        cmd = SHELL_COMMANDS['config'],
        action = 'edit-global',
        allowed_params = [
            'enable_in',
            'enable_out',
        ],
        condition_ok = [
            'already exists'
        ],
        condition_changed = [
            'Disabled',
            'Enabled'
        ],
    ),
    edit_peer = dict(
        category = 'peer',
        cmd = SHELL_COMMANDS['edit'],
        action = 'edit-peer',
        allowed_params = [
            'akb',
            'id',
            'max',
            'min',
            'name',
            'process_incoming',
            'state',
            'url',
        ],
        condition_changed = [
            'was updated'
        ],
        condition_failed = [
            'does not exist'
        ],
    ),
    list = dict(
        category = 'peer',
        cmd = SHELL_COMMANDS['list'],
        action = 'list',
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
    remove = dict(
        category = 'peer',
        cmd = SHELL_COMMANDS['remove'],
        action = 'remove',
        allowed_params = [
            'id',
        ],
        condition_ok = [
            'No Peer with ID'
        ],
    ),
)

# Available choices to select from
CHOICES = dict(
    state = [
        'ENABLED',
        'DISBALED'
    ],
    connection = [
        'incoming',
        'outgoing'
    ]
)

class EjbcaPeer(Shell):
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
        
    def _parser_incoming_outgoing(self, output:str):
        """ Parse list of peers into Incoming and Outgoing. """
        
        # include all peering connections if no type was defined or
        # include only outgoing or incoming connections
        if self.type is None:
            connections = output.split('Outgoing Connections:')[1].split('Incoming Connections:')
        else:
            if self.type in ['outgoing']:
                connections = output.split('Outgoing Connections:')[1].split('Incoming Connections:')[0]
            elif self.type in ['incoming']:
                connections = output.split('Incoming Connections:')[1]
                
        # remove empty lines creating from splitting output and return splitlines
        lines = '\n'.join([line.rstrip() for line in ''.join(connections).splitlines() if line.strip()]).splitlines()
        return lines

    def _parser_list(self, output:str):
        """ Create list of peers.
        
        Description:
            - Set 'changed' state to True to indicate a successful list operation
            - Iterates over list of dicationaries created from parsed stdout
            
        Return: 
            - List consisting of key dictionaries. Will be empty if no peers exist.
        """
    
        peers_list = []
        for line in output:
            if ('No' and 'connections') in line:
                pass
            else:
                if ('Name' and 'ID' and 'URL' and 'State') not in line:
                    id = StringParser(line).id()
                    name = StringParser(line).split_strip(id)
                    state = StringParser(line).list(CHOICES['state']) # search ilne for values in list
                    url = StringParser(line).tuple((id, state)) # use parsed id and state values as tuple to grab url between each
                    sync_status = StringParser(line).split_strip(state, before = False) # get value after parsed state value
                    peer = dict(
                        id = int(id),
                        name = name,
                        state = state,
                        sync_status = sync_status,
                        url = url,
                    )
                    peers_list.append(peer)
                    self.stdout_lines.append(line.strip())
                    
        return peers_list
            
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
            if self.action in ['list']:
                results['peers'] = self._parser_list(
                    self._parser_incoming_outgoing(output)
                )
                
            # Create
            elif self.action in ['create']:
                if results['changed']:
                    results['peers'] = dict(
                        name = self.name,
                        id = int(self.id)           
                    )
                            
            # pass results through class to modify returned values before returning
            return self.return_results(results)          
            
        except ValueError as e:
            self.module.fail_json(msg = e)
            
def argument_spec_peer():
    return dict(
        akb = dict(
            type = 'str'
        ),
        check_existing = dict(
            defuault = False,
            type = 'bool'
        ),
        enable_in = dict(
            type = 'bool'
        ),
        enable_out = dict(
            type = 'bool'
        ),
        id = dict(
            type = 'int'
        ),
        max = dict(
            type = 'int',
            #choices = [n for n in range(2,50)]
        ),
        min = dict(
            type = 'int',
            #choices = [n for n in range(1,5)]
        ),
        name = dict(
            type = 'str'
        ),
        process_incoming = dict(
            type = 'bool'
        ),
        return_output = dict(
            default = True,
            type = 'bool'
        ),
        state = dict(
            type = 'str',
            choices = [k for k in CHOICES['state']]
        ),
        type = dict(
            type = 'str',
            choices = [k for k in CHOICES['connection']]
        ),
        url = dict(
            type = 'str'
        )
    )
            
def run_module():
    
   # Load main argument spec into module argument spec
    module_args = argument_spec_common()
    
    # Update with sub class module argument spec
    module_args.update(argument_spec_peer())
    
    # Update action choices
    # Replace underscore with hyphen for use to provide hyphen in the module action value
    module_args['action'].update(choices  =  [k.replace('_','-') for k in MODULE_ACTIONS])
    
    # Build module opbject
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('cmd','create',[
                'akb',
                'name',
                'state',
                'url'
            ]),
            ('cmd','edit-global',[
                'enable_in',
                'enable_out'
            ], True),
            ('cmd','edit-peer',[
                'id'
            ]),
            ('cmd','remove',[
                'id'
            ])
        ],
        required_together=[
            {'min','max'}
        ]
    )
    
    if module.check_mode:
        module.exit_json(**result)
        
    # check edit-peer params to valid values
    if module.params['action'] in ['edit-peer']:
        
        if module.params['min'] or module.params['max']:
            # fail if provided min value is 0 or a negative integer
            
            if not module.params["min"] >= 1:
                module.fail_json('min must be a value of 1 or greater')
                
            elif module.params["min"] > module.params["max"]: # fail if provided min value is higher than provided max value
                module.fail_json(f'min ({module.params["min"]}) cannot be greater than max ({module.params["max"]})')

    # debug option parameters
    if module.params['debug']:
        
        if module.params['debug_option'] == 'params': # debug module parameters
            module.fail_json(module.params)
        
        if module.params['debug_option'] == 'spec': # debug module argument spec
            module.fail_json(module.argument_spec)
    
    # return 
    command = EjbcaPeer(module)
    result = command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()