#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import yaml
from ansible.module_utils.basic import AnsibleModule

class ManageVars(object):
    
    def __init__(self, module:AnsibleModule):
        """ Use to import Ansible variables file and output a file containing the results. """
        
        self.module = module
        self.current_imported_dict = str()
        self.incoming_imported_dict = str()
        self.added_vars_dict = dict()
        self.removed_vars_dict = dict()
        self.current_imported_list = list()
        self.incoming_imported_list = list()
        self.dir_files = dict(
            current = list(),
            incoming = list()
        )
        
        # create class attributes for all module params
        for key in self.module.params:
            setattr(self, key, self.module.params[key])
            
        if self.diff_file:
            with open(self.diff_dest, 'a') as file:
                file.write("##--- Variables Difference --- ##\n")
                file.close()

    def _import_file(self, current:str, incoming:str):
        """ Import variables file and creates temporary dictionary """
        
        current_vars_dict = dict()
        incoming_vars_dict = dict()
        
        with open(current, 'r') as file:
            current_imported_file = yaml.safe_load(file)
            for key,value in current_imported_file.items() if current_imported_file != None else {}:
                current_vars_dict[key] = value
                
            file.close()
            
        with open(incoming, 'r') as file:
            incoming_imported_file = yaml.safe_load(file)
            for key,value in incoming_imported_file.items() if incoming_imported_file != None else {}:
                incoming_vars_dict[key] = value
                
            file.close()
                
        return current_vars_dict, incoming_vars_dict
            
    def _differences(self, current:dict, incoming:dict):
        """ Find differences between two files """
        
        added_vars_dict = dict()
        removed_vars_dict = dict()
        
        # check for new variables
        if current != incoming:
            
            # create dict of new vars if they exist in the new file but not the old
            for key, value in incoming.items():
                if key not in current:
                    added_vars_dict[key] = value
            
            # create dict of removed vars if they exist in the old file but not the new
            for key,value in current.items():
                if key not in incoming:
                    removed_vars_dict[key] = value
                    
        return added_vars_dict, removed_vars_dict
    
    def _output_diff(self, added:dict, removed:dict, vars_file:str = None):
        """ Build output files with differences and comments """
        
        #self.module.fail_json(added)
        if self.mode == 'file':
            vars_file = self.current
        
        with open(self.diff_dest, 'a') as file:
            
            # add file header
            file.write(f"\n## {os.path.relpath(vars_file)}\n")
            
            # add variables that exist in the new file, but not old
            if len(added):
                file.write(f"# The following variables have been added:\n")
                yaml.dump(added, file) 
            else:
                file.write(f"# No variables have been added.\n")
            
            # add variables that exist in the old file, but not new
            if len(removed):
                file.write(f"\n# The following variables have been removed:\n")
                yaml.dump(removed, file)  
            else:
                file.write(f"# No variables have been removed.\n")
                
    def exec(self):
        """ Execute class attributes and functions """
        
        if self.mode == 'file':
            # import file
            current_dict, incoming_dict = self._import_file(self.current, self.incoming)
            added_dict, removed_dict = self._differences(current_dict, incoming_dict)
            
            if self.diff_file:  
                self._output_diff(added_dict, removed_dict)
            
        else:

            for root, dirs, files in os.walk(self.current, topdown = True): 
                for f in files:
                    self.current_imported_root = root
                    self.current_imported_list.append(f)
            
            for root, dirs, files in os.walk(self.incoming, topdown = True): 
                for f in files:
                    self.incoming_imported_root = root
                    self.incoming_imported_list.append(f)
                    
            for c in self.current_imported_list:
                for i in self.incoming_imported_list:
                    if c == i:
                        current = f"{self.current_imported_root}/{c}"
                        incoming = f"{self.incoming_imported_root}/{i}"
                        
                        # import each file if they match
                        current_dict, incoming_dict = self._import_file(current, incoming)


                        added_dict, removed_dict = self._differences(current_dict, incoming_dict)

                        # output file if different file was requested
                        if self.diff_file:  

                            self._output_diff(added_dict, removed_dict, c)
        
        # return dicts to console if difference file not requested
        return dict(
            added = self.added_vars_dict,
            removed = self.removed_vars_dict
        )
                
        
def argument_spec():
    return dict(
        current = dict(
            required = True,
            type = 'path'
        ),
        incoming = dict(
            required = True,
            type = 'path'
        ),
        mode = dict(
            default = 'directory',
            type = 'str',
            choices = [
                'file',
                'directory'
            ]
        ),
        diff_file = dict(
            default = True,
            type = 'bool',
        ),
        diff_dest = dict(
            default = f"{os.getcwd()}/diff_vars.yml",
            type = 'path',
        ),
        ansible_path = dict(
            default = os.getcwd(),
            type = 'path'
        ),
        recursive = dict(
            default = False,
            type = 'bool'
        )
    )

def run_module():

    # Load main argument spec into module argument spec
    module_args = argument_spec() 

    # Build module opbject
    module = AnsibleModule(
        argument_spec = module_args,
        supports_check_mode = True,
    )
    
    result = dict(
        changed = False,
        ansible_path = module.params['ansible_path'],
        diff_file = module.params['diff_file'] if module.params['diff_file'] else '',
        diff_dest = module.params['diff_dest'] if module.params['diff_file'] else '',
        added = dict(),
        removed = dict()
    )
    
    if module.check_mode:
        module.exit_json(**result)
        
    # validate current and incoming parameters are not the same
    if module.params['current'] == module.params['incoming']:
        module.fail_json(f"current and incoming cannot be the same path.")
        
    # validate current and incoming paths
    failed_param = str()
    if module.params['mode'] == 'directory':

        # check if either parameters are directory
        if not os.path.isdir(module.params['current']):
            failed_param = 'current'
        elif not os.path.isdir(module.params['incoming']):
            failed_param = 'incoming'
            
    else:   
        
        # check if either parameters are files
        if not os.path.isfile(module.params['current']):
            failed_param = 'current'
        elif not os.path.isfile(module.params['incoming']):
            failed_param = 'incoming'
                
    # fail if failed_params was updated after the previous validation checks 'failed'
    if failed_param:
        module.fail_json(f"{failed_param} must be a path to a variables {module.params['mode']} when running the task in {module.params['mode']} mode.")
        
    # validate difference file for check outputs
    if module.params['diff_file']:
        diff_dest_dirname = os.path.dirname(module.params['diff_dest'])
        if not os.path.isdir(diff_dest_dirname):
            module.fail_json('provided diff_dest is not a valid directory.')
            
    # validate recursive path
    if module.params['recursive']:
        if not os.path.isdir(module.params['ansible_path']):
            module.fail_json('provided ansible path is not a valid directory.')
            
            
    # # return 
    manage = ManageVars(module)
    result.update(manage.exec())
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()