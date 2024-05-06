#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
import os
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ejbca.shell.plugins.module_utils.common import (
    StderrParser, StringParser, Converter,
    slugify, bool2str,
    COMMON_DEFAULTS
)

class Shell(object):
    def __init__(self, module:AnsibleModule, actions_dict:dict, args_dict:dict): 
        """ 
        Description:
            - CLI class containing common functions used by subclasses to execute and parse CLI output
        
        Arguments:
            - module: 
                - AnsibleModule containing parsed parameters passed from Ansible task.
                - Should not change after subclass instantiation.
            - actions_dict: 
                - Contains avaiable subclass actions and the values required to execute each action with the CLI.
                - Should not change after subclass instantiation.
            - args_dict: 
                - Mapping of subclass Ansible Module parameters to CLI switch values and adds them to the command string passed to the CLI.
                - Filters out empty parameters and parameters provided in the Ansible task that are not accepted by the provided action.
                - Should not change after subclass instantiation.
        """
        self.module = module
        self.argument_spec = module.argument_spec
        self.args_dict = args_dict
        self.actions_dict = actions_dict
        
        # initialize empty strings to be built by each sub class
        self.category = str()
        self.command = str() 
        self.allowed_params = list()
        
        # initialize result dictinary and changed variable for each method to update
        self.stdout_lines = list()
        self.stderr_lines = list()
        self.result = dict()
        self.changed = False
        self.exists = False
        self.failed = False
        self.rc = 0
        
        # default condition evalution matches
        # can be overridden or appended in each subclass command operations based on the output string from the cli
        # list is joined with a | for a regex search during the _check_result function
        self.condition_ok = ['already']
        self.condition_exists = ['already exists']
        self.condition_non_exists = ['Unknown']
        self.condition_changed = ['successfully']
        #self.condition_failed = ['ERROR','failed','Failure']
        self.condition_failed = ['failed','Failure']
        self.condition_exception = str()
        self.condition_failed_msg = str()

        # create class attributes for all module params
        for key in self.module.params:
            setattr(self, key, self.module.params[key])
            
        if self.debug:
            if self.debug_option == 'params':
                self.module.fail_json(self.module.params)
                
            elif self.debug_option == 'action':
                self.module.fail_json(self.action)
            
        # slugify action parameter
        self.action = slugify(self.action)
            
        # ejbca home path validation
        if os.path.exists(self.path):
            self.path += '/bin/ejbca.sh'
        else:
            self.module.fail_json(
                f"The provided EJBCA home path {self.path} does not exist. If no path parameter was provided, override the default path value by providing the correct path parameter."
            )
        
    def build_action_items(self, action:str, cmd:str = None):
        """ Loop actions list to update class attributes
        
        Description:
            - Used in sub class to build cli command and parse output results
        
        Arguments:
            - action: sub class self.action attribute
            - cmd: Override the cmd value in the provided action dictionary item
     
        Conditionals:
            - self.action == k:
                - Selects dictionary items that matches the action attribute
                - Uses a None default in case the key doesnt exists
            
        Returns: 
            - action_items: Dictionary of action items for the provided action arguement
        """
        
        action_items = dict()  
        #self.module.fail_json(format_name)         
        for k,v in self.actions_dict.items():
            if action == k:
                action_items['cmd'] = cmd if cmd else v.get('cmd')
                action_items['category'] = v.get('category', '')
                action_items['allowed_params'] = v.get('allowed_params', [])
                action_items['condition_ok'] = v.get('condition_ok', [])
                action_items['condition_changed'] = v.get(('condition_changed'), [])
                action_items['condition_failed'] = v.get('condition_failed', [])
                action_items['condition_failed_msg'] = v.get('condition_failed_msg','')

        if self.debug and self.debug_option == 'action_items':
            self.module.fail_json(action_items)
              
        #self.module.fail_json(action_items['cmd'])  
        if not action_items.get('cmd'):
            raise KeyError(f"cmd is missing from the '{action}' dictionary item or the cmd parameter was not passed to the build_actions function")
                
        #self.module.fail_json(action_items)        
        return action_items 

    def build_args(self, parameters:list):
        """ Loops through the subclass arg_list and adds matching attributes from allowed_params list
        
        Description:
            - Compares static list of arguments in sub class against parameters with values provided in Ansible Module
            - Includes the ability to check second-level options to add parameters, meeting conditionals in the loop, to the argument list. 
            
        Arguments:
            - parameters: list of allowed parameters for a specific action
            
        Conditionals:
            - k in self.allowed_params and p == k:
                - If parameter is provided in Ansible module and exists in the argument list, it is added to the argument string.
            - t['type'] == 'list':
                - After the parameter is matched, check the parameter type in the argument spec to determine how the parameter value(s) should be added to the argument string.
            - t.get('options')
                - If second-level options exist for the parameter in the argument_spec, loop the options and check for the same condition as the previous condition.

        Return: 
            - args: EJBCA CLI parameters and Ansible module parameter values
        """        
        args = str()
        for cli_arg,cli_value in self.args_dict.items():
            for spec_arg,spec_type in self.argument_spec.items():
                if getattr(self, cli_arg, None) != None and cli_arg in parameters and spec_arg == cli_arg: 
                    if spec_type['type'] == 'list': # get ag
                        args += f' {cli_value} "{",".join(getattr(self, cli_arg))}"'
                    else:
                        args += f' {cli_value} "{bool2str(getattr(self, cli_arg))}"'
                elif spec_type.get('options'):
                    for option in spec_type['options']:
                        if getattr(self, cli_arg, None) != None and cli_arg in parameters and option == cli_arg:
                            # option type is boolean, set the string to 'parameter=value'
                            # initially created for "properties" when creating key bindings.
                            if bool(spec_type['type']):
                                args += f' {cli_value}={bool2str(getattr(self, cli_arg))}'   
                            else:
                                args += f' {cli_value} "{bool2str(getattr(self, cli_arg))}"'    
        return args    
    
    def build_command(self, action:str = None, cmd:str = None):
        """ Builds action items dict and command
        
        Description:
            - Needs to be included whenever exectuing a CLI command
            - Useful when executing multiple cli operations in a single Ansible task.
            
        Arguments:
            - action: The action value to parse and build the command. 
            - cmd: Override the cmd value in the provided action dictionary item
            
        Return:
            - command: string for cli to execute
        """
        
        # get dictionary items for actions
        # throw exception if empty dicationary is returned
        try:
            if not action:
                action = self.action
            self.action_items = self.build_action_items(action, cmd)
            if not self.action_items:
                raise ValueError
            else:
                command=(
                    # dont include space at the beginning of self.path f-string
                    # add space to all other f-strings
                    f" {self.path}" 
                    f" {self.action_items['category']}"
                    f" {self.action_items['cmd']}"
                    f" {self.build_args(self.action_items['allowed_params'])}"
                )
        except ValueError:
            self.module.fail_json(f"self.action_items dictionary was returned empty for {action}")
    
        return command
    
    def converter(self, line:str, field_name:str = None, field_list:list = None):
        """ Converts value from database into a human-readable value.
         
        Description:
            - Uses database schema provided in tuple to determine how to convert value
        
        Arguments:
            - line:
                - String from output containing value needing to be parsed

        Return: Converted value
        """
        
        # load class attributes if arguments not passed
        if field_name is None:
            field_name = getattr(self, 'field')
        if field_list is None:
            field_list = getattr(self, 'field_list')
            
        # get type from tuple for provided field name
        field_type = ''.join(schema for field, schema in field_list if field == field_name)
        value = StringParser(line).quotes(single = True) # get value between single quotes

        # long
        if field_type in ['long']:
            return Converter.from_milliseconds(int(value))

        # int
        elif field_type in ['int']:
            
            # status
            if field_name in ['status']:
                if int(value) == 1: # active
                    return 'active'
                elif int(value) == 5: # off-line
                    return 'off-line'
                elif int(value) == 6: # external
                    return 'external'
                return value 
        
            # return value if none of conditions met
            return int(value)
        
        # boolean
        elif field_type in ['boolean']:
            return Converter.str_to_bool(value)
                
        # list
        elif field_type in ['list']:
            
            # check for empty list as string
            if value == '[]': # convert to empty list
                value_list = [] 
                return 'undefined'
            
            else: # convert string to list
                value_list = list(value) 
                return value_list

        # string
        elif field_type in ['string']:
            if not len(value):
                return 'undefined'
            return value
            
        # all other types
        else:
            return value
    
    def shell(self, command, extra_args: str = None, check_results: bool = True):
        """ EJBCA CLI execution
        
        Description:
            - Uses the Ansible module utilities to execute the argument string.
            - A tuple containing a return code, stdout, and stderr are returned by the run_command. 
            - Some dictionary values not specific to Ansible can be included to allow additional parsing
              based on results returned by this function.
              
        Arguments:
            - extra_args 
                - extra arguments not already added to the argument string.
            - command 
                - used to pass a command base that overrides the command attributes defined during initialization.
                - the initialized command base is used by default if no command parameter is passed to the function.
              
        Conditionals:
            - stderr:
                - If the stderr tuple index is not empty, it is parsed for a Java exception.
            
        Return:
            - Standard error (stderr):
                - A java exception is returned to console as an immediate module failure.
                - A non-java exception is returned.
            - Standard output (stdout)
            - Results:
                - Parsed results of command from parse_cli_output function
            - Return code (rc)
        """
        
        if extra_args: # append extra args if argument is provided
            command += f' {extra_args}'
        
        if self.debug and self.debug_option == 'command':
            self.module.fail_json(command)
        rc, stdout, stderr = self.module.run_command(
            args = command
        )
        
        #self.module.fail_json(stderr)
        #self.module.fail_json(rc)
        if self.debug and self.debug_option == 'output':
            if len(stdout) :
                self.module.fail_json(stdout)
            elif len(stderr) and self.debug:
                self.module.fail_json(stderr)
        
        # exit module with invalid command
        # this is only intended to throw an error when an invalid command is passed from inside the module
        if 'And the following commands are available' in stdout:
            self.module.fail_json(f'Invalid command: {command}')
            
        elif stderr: # initialize parser to clean up the java exception.
            # if exception exists, it is trimmed and possible mutuated to provided better 
            exception = StderrParser.java_exception(stderr.splitlines()) 
            
            # load error into cli_output for parsing
            if exception:
                cli_output = exception
            else:
                cli_output = stderr
        
        else: # load output into cli_output for parsing 
            cli_output=stdout
            
        if check_results: # check_result function included in shell command
            results = self.parse_cli_output(
                output = cli_output,
                action_items = self.action_items,
                return_code = rc
            )
            return stdout, results
        
        else: # only command function requested and not check_result
            return stdout, rc
         
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

            # pass results through class to modify returned values before returning
            return self.return_results(results)          
            
        except ValueError as e:
            self.module.fail_json(msg = e)       
            
    def parse_cli_output(self,output:str,return_code=0,action_items:dict={}):
        """ Loop command output lines
        
        Description:
            - Determines if Ansible task returns status: ok, changed, or failed.
            - 'Ok' is the default status and only changes if 'changed' or 'failed' conditions are met. 
            - Some dictionary values not specific to Ansible can be included to allow additional parsing 
              based on results returned by this function.
            - Result dictionary does not update Ansible results returned to console. This dictionary is only 
              used for additional parsing in the subclass.
              
        Conditionals:
            - condition_exists
                - update return dictionary 'exists' value to true for additional parsing in the sub class.
            
        Return:
            - result: Dictionary containing results
        """
        
        if action_items is None: # use the class attribute if parameter not provided
            action_items = self.action_items
            
        # create matching conditions from lists
        # combine action_items with class attributes defined in __init__
        condition_ok = '|'.join(self.condition_ok + action_items['condition_ok'])
        condition_changed = '|'.join(self.condition_changed + action_items['condition_changed'])
        condition_failed = '|'.join(self.condition_failed + action_items['condition_failed'])
        condition_exists = '|'.join(self.condition_exists)
        condition_non_exists = '|'.join(self.condition_non_exists)
        condition_failed_msg = action_items['condition_failed_msg']
        
        # initialize result dict
        result = dict(
            changed = False,
            failed = False,
            rc = return_code,
        )
        output = output.splitlines() # split string into lines
        for line in output: # loop results
            
            #self.module.fail_json(condition_ok)
            
            # Result 'OK'
            # no changes were made or overriding a stderr so task doesnt fail
            # useful when ejbca cli tries to create an object and it already exists.
            # creating an object that already exists would return a stderr even though Ansible wants it as OK.
            if re.findall(condition_ok,line): 
                
                #self.stdout_lines.append(line.strip())
                if re.findall(condition_exists,line): # update exists boolean if exists condition is met
                    result.update(exists = True)          
                
                # included as an option to return ok so sub class can return an 'ok'
                if re.findall(condition_non_exists,line): # update does not exist boolean if condition is met
                    result.update(exists = False)   
                
                # result needs to be updated if previous set to failed and stderr_lines emptied
                # this is necessary if return code is other than 0 and failed/stderr_lines were already updated
                result.update(failed = False)
                self.stderr_lines.clear() # remove any lines added to 
                
                # loop lines again to add all lines to stdout
                for l in output:
                    self.stdout_lines.append(l.strip())
                    
                return result

            # override return code successful result 
            elif re.findall(condition_changed,line):  
                #self.changed = True
                result.update(changed = True)
                self.stdout_lines.append(line.strip())
                
                # add id attribute if detected in line
                # useful during creation operation when ID is generate during command execution
                # populated with None if ID does not exist
                self.id = StringParser(line).id()
                
                if re.findall(condition_exists,line): # update exists boolean if exists condition is met
                    result.update(exists = True)          
                
                # included as an option to return ok so sub class can return an 'ok'
                if re.findall(condition_non_exists,line): # update does not exist boolean if condition is met
                    result.update(exists = False)   
                
            # override return code failed result 
            elif re.findall(condition_failed,line):  
                if condition_failed_msg: # immedately return failure on error
                     self.module.fail_json(condition_failed_msg.strip())
                elif 'ERROR:' in line: # immedately return failure on error
                     self.module.fail_json(line.split('ERROR:')[1].strip())
                else:
                    self.module.fail_json(line.strip())
                    rc = 1 if return_code == 0 else return_code # update rc to 1 if 0 or if value is already greate than one, use current rc
                    self.stderr_lines.append(line.strip())
                    result.update(
                        failed = True,
                        rc = rc,
                    )

            # catch all lines that dont meet the above conditions
            elif len(line): # length of line evaluated to filter out empty lines
                if return_code == 0: # assume a return code of 0 is stdout
                    self.stdout_lines.append(line.strip())
                else: # assume any return code greater than 0 is a stderr
                    result.update(failed = True)
                    self.stderr_lines.append(line.strip())

        return result # return updated dictionary

    def return_results(self,results:dict):
        """ Adds all return values updated during the execute of each operation 
        
        Arguments:
            - results:
                - Contains results from check_results which may vary from the value defined in the class attributes
        """
        if self.return_output: # update default class attributes if return output parameter provided and value is True
            results.update(
                stdout_lines = self.stdout_lines,
                stderr_lines = self.stderr_lines,
            )
        
        return results