
import yaml
import os


file_current = "/Users/jtgarner/git/ansible-ejbca-signserver-playbooks/ansible_ejbca_signsrv/group_vars/all.yml"
file_new = "/Users/jtgarner/git/ansible-ejbca-signserver-playbooks/ansible_ejbca_signsrv/group_vars_2/all.yml"
file_out = "/Users/jtgarner/git/ansible-ejbca-signserver-playbooks/ansible_ejbca_signsrv/difference_outfile.yml"

#vars_file_current = yaml.safe_load(file_current)

file_1 = open(file_current, 'r')
file_2 = open(file_new, 'r')

file_1_lines = file_1.readlines()
file_2_line = file_2.readline()

with open(file_current, 'r') as c_file:
    vars_file_current = yaml.safe_load(c_file)
    
with open(file_new, 'r') as n_file:
    vars_file_new = yaml.safe_load(n_file)
    

current_dict = dict()
for key,value in vars_file_current.items():
    current_dict[key] = value
    
new_dict = dict()
for key,value in vars_file_new.items():
    new_dict[key] = value

# check for new variables
if current_dict != new_dict:
    
    # create dict of new vars if they exist in the new file but not the old
    added_vars_dict = dict()
    for key,value in new_dict.items():
        if key not in current_dict:
            added_vars_dict[key] = value
    
    # create dict of removed vars if they exist in the old file but not the new
    removed_vars_dict = dict()
    for key,value in current_dict.items():
        if key not in new_dict:
            removed_vars_dict[key] = value

# with open(file_out, 'w') as file:
#     file.write(f"\n# The following variables have been aded to {os.path.relpath(file_current)}\n")
#     file.close()


with open(file_out, 'w') as file:
    file.write(f"\n# The following variables have been aded to {os.path.relpath(file_current)}\n")
    
    if len(added_vars_dict):
        yaml.dump(added_vars_dict, file) 
    else:
        file.write(f"# No variables have been added.")
        
    
    file.write(f"\n# The following variables have been removed {os.path.relpath(file_current)}\n")
    if len(removed_vars_dict):
        yaml.dump(removed_vars_dict, file)  
    else:
        file.write(f"# No variables have been removed.")
    
    # res = all((current_dict.get(k) == v for k, v in new_dict.items()))
    # print(res)
    
# with open(file_current, 'r') as c_file:
#     #vars_file_current = yaml.safe_load(c_file)
#     with open(file_new, 'r') as n_file:
#         #vars_file_new = yaml.safe_load(n_file)
#         same = set(file_current).intersection(file_new)
    
# print(same)

# for line in same:
#     print(line, end='')

# with open(file_current, 'w') as file:
#     yaml.safe_dump(vars_file_current, file)

#print(open(file_path).read())
#json_str = json.dumps(variables_file, indent=2)
    
#print(yaml_dump)