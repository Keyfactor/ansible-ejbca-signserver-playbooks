#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ejbca.manage.plugins.module_utils.common import (
    import_yaml, output_yaml
)


class ManageInventory(object):
    
    def __init__(self, module:AnsibleModule):
        """ Use to import and update Ansible inventory file and output a file containing the results. """
        
        self.module = module
        
        # create class attributes for all module params
        for key in self.module.params:
            setattr(self, key, self.module.params[key])
        
    def exec(self, **kwargs):
        """ Execute class attributes and functions """

        inventory_dict = import_yaml(self.path)
        
        child = self.child
        parents = self.parents
        
        try:
            res = ({
                child: None
            })
            
            #self.module.fail_json(inventory_dict)
            # for p in parents:
            #     res = ({
            #         child: None
            #     })
                
            #self.module.fail_json(res)
            #self.module.fail_json(type(inventory_dict['all']['children']))
            for c in inventory_dict['all']['children']:
                if c in parents:
                    if inventory_dict['all']['children'][c]['children'] != None:
                        existing_children = inventory_dict['all']['children'][c]['children']
                        existing_children.update(res)
                    else:
                        inventory_dict['all']['children'][c].update({'children':{res}})
                        #inventory_dict['all']['children'][c]['children'] = res
                    
                    
                    #self.module.fail_json(c)
                    #self.module.fail_json(inventory_dict['all']['children'][c])
                    #inventory_dict['all']['children'][c]['children'] = existing_children
                    #c['children'].update(res)
                    #k.update(res)
            #inventory_dict['all']['children'].update(res)
            #self.module.fail_json(inventory_dict)
            output_yaml(self.path, inventory_dict)
            
        except TypeError:
            self.module.fail_json('type error') 
            
        # except Exception as e:
        #     self.module.fail_json(e) 
        
        return dict(
            changed = True
        )
        
def argument_spec():
    return dict(
        path = dict(
            required = True,
            type = 'path'
        ),
        mode = dict(
            required = True,
            type = 'str',
            choices = [
                'build',
                'update',
            ]
        ),
        child = dict(
            type = 'str'
        ),
        children = dict(
            type = 'list'
        ),
        parents = dict(
            type = 'list'
        ),
        host = dict(
            type = 'dict',
            options = dict(
                name = dict(
                    required = True,
                    type = 'str'
                ),
                ansible_host = dict(
                    required = True,
                    type = 'str'
                ),
            ),
        ),
    )

def run_module():

    # Load main argument spec into module argument spec
    module_args = argument_spec() 

    # Build module opbject
    module = AnsibleModule(
        argument_spec = module_args,
        supports_check_mode = True,
        required_if = [
            ('mode', 'build', [
                'child',
                'parents'
            ]),
            ('mode', 'update', [
                'child',
                'host'
            ]),
        ]
    )
    
    result = dict(
        changed = False,
        msg = 'passed validation'
    )

    if module.check_mode:
        module.exit_json(**result)
        
    # validate difference file for check outputs
    if not os.path.isfile(module.params['path']):
        module.fail_json('provided inventory path is not valid.')
        
    #module.fail_json(module.params)
        
    # return 
    manage = ManageInventory(module)
    result.update(manage.exec())
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()