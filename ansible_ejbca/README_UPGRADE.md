ansible_ejbca_upgrade
=========

Upgrades EJBCA instances to a newer version and completes the upgrade after all nodes have deployed the new ear file.

This playbook downloads the EJBCA files from a webserver configured in the customer_vars.yml file.

Example Playbook
----------------

This example is taken from `upgradeEjbca.yml` 
```yaml
---

- hosts: ejbcaCaServers
  become: yes
  become_method: sudo
  gather_facts: true
  pre_tasks:
    - include_vars: customer_info/customer_vars.yml
  vars:
    ejbca_src_dir: "{{ ejbca_src_dir_name }}"
    ejbca_software_url: "{{ ejbca_software_ee_url }}"
    ejbca_group: ejbca
    ejbca_user: ejbca
  roles:
    #- ansible-ejbca-upgrade

- hosts: ejbcaCaServers[0]
  become: yes
  become_method: sudo
  gather_facts: false
  pre_tasks:
    - include_vars: customer_info/customer_vars.yml
  vars:
    ejbca_src_dir: "{{ ejbca_src_dir_name }}"
    ejbca_software_url: "{{ ejbca_software_ee_url }}"
    ejbca_group: ejbca
    ejbca_user: ejbca
  roles:
    #- ansible-ejbca-complete-upgrade

- hosts: ejbcaRaServers
  become: yes
  become_method: sudo
  gather_facts: true
  pre_tasks:
    - include_vars: customer_info/customer_vars.yml
  vars:
    ejbca_src_dir: "{{ ejbca_src_dir_name }}_RA"
    ejbca_software_url: "{{ ejbca_software_ra_url }}"
    ejbca_group: ejbcara
    ejbca_user: ejbcara
  roles:
    - ansible-ejbca-upgrade

- hosts: ejbcaRaServers[0]
  become: yes
  become_method: sudo
  gather_facts: false
  pre_tasks:
    - include_vars: customer_info/customer_vars.yml
  vars:
    ejbca_src_dir: "{{ ejbca_src_dir_name }}_RA"
    ejbca_software_url: "{{ ejbca_software_ra_url }}"
    ejbca_group: ejbcara
    ejbca_user: ejbcara
  roles:
    - ansible-ejbca-complete-upgrade

- hosts: ejbcaVaServers
  become: yes
  become_method: sudo
  gather_facts: true
  pre_tasks:
    - include_vars: customer_info/customer_vars.yml
  vars:
    ejbca_src_dir: "{{ ejbca_src_dir_name }}_VA"
    ejbca_software_url: "{{ ejbca_software_va_url }}"
    ejbca_group: ejbcava
    ejbca_user: ejbcava
  roles:
    - ansible-ejbca-upgrade

- hosts: ejbcaVaServers[0]
  become: yes
  become_method: sudo
  gather_facts: false
  pre_tasks:
    - include_vars: customer_info/customer_vars.yml
  vars:
    ejbca_src_dir: "{{ ejbca_src_dir_name }}_VA"
    ejbca_software_url: "{{ ejbca_software_va_url }}"
    ejbca_group: ejbcava
    ejbca_user: ejbcava
  roles:
    - ansible-ejbca-complete-upgrade
```


Update the vars to assert the correct owner of the ejbca files.

The inventory file should contain the following: `inventory`:
```yaml
[ejbcaCaServers]
ejbca01.solitude.skyrim ansible_host=172.16.170.129

[ejbcaVaServers]
ejbcava01.solitude.skyrim ansible_host=172.16.170.128

[ejbcaRaServers]
ejbcara01.solitude.skyrim ansible_host=172.16.170.142
```

Role Variables
--------------

Role variables are set per customer in a yaml file under customer_info.  Create a yaml file with the customer name.  The following variables are needed:
```yaml
---
# Version to upgrade EJBCA
ejbca_version: 7.4.0

# URL for the EJBCA EE build
ejbca_software_ee_url: http://172.16.170.132/ejbca/ejbca_ee_7_4_0.zip

# URL for the EJBCA RA build
ejbca_software_ra_url: http://172.16.170.132/ejbca/ejbca_ee_7_4_0_RA.zip

# URL for the EJBCA VA build
ejbca_software_va_url: http://172.16.170.132/ejbca/ejbca_ee_7_4_0_VA.zip

# EJBCA source directory name when unzipping the archive
ejbca_src_dir_name: ejbca_ee_7_4_0

```

Requirements
------------

- EJBCA archive must be uploaded to a webserver accessible by the EJBCA node to download the file
- SSH access to EJBCA node using public key
- Root permissions on the EJBCA to elevate and access account that owns EJBCA files
- A recent version of Ansible. (Tests run on the current, previous and next release of Ansible.)

Dependencies
------------

None - This is a self contained playbook.



Compatibility
-------------

This role has been tested on these:

|container|tags|
|---------|----|
|el|7, 8|


The minimum version of Ansible required is 2.9 but tests have been done to:

- The previous version, on version lower.
- The current version.
- The development version.

Exceptions
----------

Some variarations of the build matrix do not work. These are the variations and reasons why the build won't work:

| variation                 | reason                 |
|---------------------------|------------------------|
| TBD | TBD |




License
-------

LGPL v2.1 or later

Author Information
------------------

[PrimeKey](https://primekey.com)
