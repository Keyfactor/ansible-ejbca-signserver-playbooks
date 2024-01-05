#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Keyfactor
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ejbca_peer
description: This module emulates the peer category of the EJBCA CLI.
author:
    - Jamie Garner (@jtgarner-keyfactor)
'''

import re
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ejbca import (
    EjbcaCli,
    AttributeParser,
    StringParser,
    bool2str
)

def choices_commands():
    return [
        'config','create','edit',
        'list','remove'
        # need to be added
        #'sync'
    ]
    
def choices_connection():
    return [
        'incoming','outgoing'
    ]
    
def choices_state():
    return [
        'ENABLED','DISABLED'
    ]

def spec_main():
    return dict(
        akb=dict(type='str'),
        cmd=dict(
            required=True,
            type='str',
            choices=[k for k in choices_commands()]
        ),
        enable_in=dict(type='bool'),
        enable_out=dict(type='bool'),
        id=dict(type='int'),
        max=dict(
            type='int',
            #choices=[n for n in range(2,50)]
        ),
        min=dict(
            type='int',
            choices=[n for n in range(1,5)]
        ),
        name=dict(type='str'),
        path=dict(
            required=True,
            type='str',
        ),
        process_incoming=dict(type='bool'),
        return_output=dict(
            default=True,
            type='bool'
        ),
        state=dict(
            type='str',
            choices=[k for k in choices_state()]
        ),
        type=dict(
            type='str',
            choices=[k for k in choices_connection()]
        ),
        url=dict(type='str')
    )
    
class EjbcaPeer(EjbcaCli):
    
    def __init__(self,module):
        self.module=module
        self.category='peer'
        super().__init__(module)
        
        self.command=f"{self.path} {self.category} {self.cmd}"
        
        # build dictionary mapping module params to cli parameters
        # each key maps to a module parameter
        # the value is the parameter value defined by EJBCA CLI
        # to add additional items, use "module_parameter=cli_parameter"
        self.args=dict(
            id='id',
            akb='akb',
            enable_in='enable-in',
            enable_out='enable-out',
            max='max-parallel-requests',
            min='min-parallel-requests',
            name='name',
            process_incoming='process-incoming-requests',
            state='state',
            url='url',
        )
        
        # initialize allowed parameters for conditional check when building cli string
        # if the parameter is not in the list, but is provided as a module parameter, it will be exluded in the CLI
        self.allowed_params=list()
        if self.cmd in ['config']:
            self.allowed_params=['enable_in','enable_out']
        elif self.cmd in ['create']:
            self.allowed_params=['akb','name','state','url']
        elif self.cmd in ['edit']:
            self.allowed_params=['id','akb','max','min','name','process_incoming','state','url']
        elif self.cmd in ['remove']:
            self.allowed_params=['id']
        
    def _parser_list(self,output):
        peers_list=[]
        self.parser=AttributeParser()
        for line in output:
            if ('No' and 'connections') in line:
                self.stdout_lines.append(line.strip())
            else:
                if ('Name' and 'ID' and 'URL' and 'State') not in line:
                    id=StringParser(line).id()
                    state=StringParser(line).list(choices_state())
                    name=StringParser(line).split_strip(id)
                    url=StringParser(line).tuple((id,state))
                    sync_status=StringParser(line).split_strip(state,before=False)
                    peer=dict(
                        name=name,
                        id=int(id),
                        url=url,
                        state=state,
                        sync_status=sync_status
                    )
                    peers_list.append(peer)
                    self.stdout_lines.append(line.strip())
        return peers_list
    
    def _parser_edit(self,output):
        # initialize list with property values that can be modified
        edit_list={k:False for k,v in self.args.items() if k != 'id'}
        self.parser=AttributeParser()
        for line in output:
            if f'Changing AuthenticationKeyBinding to {self.akb}' in line:
                edit_list.update(akb=StringParser(line).quotes())
            elif f'Setting max number of parallel requests to {self.max}' in line:
                edit_list.update(max=StringParser(line).int())
            elif f'Setting min number of parallel requests to {self.min}' in line:
                edit_list.update(min=StringParser(line).int())
            elif f'Changing name to {self.name}' in line:
                edit_list.update(min=re.search(self.name,line).group(0))
            elif f'Enabling processing of incoming requests' in line:
                edit_list.update(process_incoming=True)
            elif f'Changing state to {self.state}' in line:
                edit_list.update(state=StringParser(line).list(choices_state()))
            elif f'Changing URL to {self.url}' in line:
                edit_list.update(url=StringParser(line).split_strip('Changing URL to',before=False))
                
        return edit_list
        
    def _list(self,output):
        # include all peering connections if no type was defined or
        # include only outgoing or incoming connections
        if self.type is None:
            connections=output.split('Outgoing Connections:')[1].split('Incoming Connections:')
        else:
            if self.type in ['outgoing']:
                connections=output.split('Outgoing Connections:')[1].split('Incoming Connections:')[0]
            elif self.type in ['incoming']:
                connections=output.split('Incoming Connections:')[1]
                
        # remove empty lines creating from splitting output and return splitlines
        lines='\n'.join([line.rstrip() for line in ''.join(connections).splitlines() if line.strip()]).splitlines()
        return lines
        
    def execute(self):
        # create argument string based on provided parameters
        # loop through class attributes created during initialization
        # add each cli_parameter and the value of the module_parameter if the module_parameter is not null
        args=str()
        for k,v in self.args.items():
            if getattr(self,k) != None and k in self.allowed_params:
                args+=f' --{v} "{bool2str(getattr(self,k))}"'
        try:
            if self.cmd in ['list']:
                # no additional arguments are required because 'list' is already included during _init
                output,rc=self._shell()
                # split cli output to remove unnecessary lines and seperate incoming/outgoing peers if specified
                # parse split cli output to build peer list containing dictionaries for each peer 
                self.result['peers']=self._parser_list(self._list(output))
                
            elif self.cmd in ['edit']:
                self.condition_changed=['Peer with ID','was updated']
                output,rc=self._shell(options=args)
                self.result['edit']=self._check_result(output.splitlines(),rc)
                # parse cli output to build update list containing properties update results
                # only parse property results if overall result was successful
                if self.result['edit']['success']:
                    self.result['updated']=self._parser_edit(output.splitlines())
                    
            elif self.cmd in ['create']:
                self.condition_failed=['Parameter --akb must be specified as one of:']
                self.condition_failed_msg=f'Provided Authentication Key Binding {self.akb} does not exist or is not active.'
                output,rc=self._shell(options=args)
                self.result['create']=self._check_result(output.splitlines(),rc)
                if self.result['create']['success']:
                    self.result['create'].update(
                        name=self.name
                    )

            else:
                    
                if self.cmd in ['config']:
                    self.condition_changed=['Disabled','Enabled']
                    
                elif self.cmd in ['remove']:
                    self.condition_failed=['No Peer with ID']
                
                # use single _shell and _check_results for commands included in the 'else' portion of the try/catch
                # only reason for single _check_results is fewer lines of code. provides no specific function
                output,rc=self._shell(options=args)
                self.result[self.cmd]=self._check_result(output.splitlines(),rc)

            # update results dictionary for return to Ansible console
            return self._return_results()
            
        except ValueError as e:
            self.module.fail_json(msg=e)
            
def run_module():

    module_args = spec_main()
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('cmd','create',['akb','name','state','url']),
            ('cmd','config',['enable_in','enable_out'],True),
            ('cmd','edit',['id']),
            ('cmd','remove',['id']),
        ],
        required_together=[
            ('max','min')
        ],
    )
    
    if module.check_mode:
        module.exit_json(**result)

    if module.params['cmd'] in ['edit']:
        # include addition validation only if min/max were provided
        if module.params['min'] or module.params['max']:
            # fail if provided min value is 0 or a negative integer
            if module.params["min"] < 1 :
                module.fail_json(msg=f'min ({module.params["min"]}) must be a value of 1 or greater')
            # fail if provided min value is higher than provided max value
            elif module.params["min"] > module.params["max"]:
                module.fail_json(msg=f'min ({module.params["min"]}) cannot be greater than max ({module.params["max"]})')
            
    command=EjbcaPeer(module)
    result=command.execute()
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()