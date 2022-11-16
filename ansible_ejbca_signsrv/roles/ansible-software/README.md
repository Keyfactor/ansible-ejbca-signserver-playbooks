Role Name
=========

This role provides version controls to currently installed applications and packages on the remote hosts. Use the eeSoftware group variables file to manage the names, version, and management options list below.

This role can be used in conjunction with EJBCA and SignServer deployments.

Requirements
------------

None

Role Variables
--------------

Main

Remove

User_Groups


Dependencies
------------
Roles:
Ansible-changelog
Ansible-software-applications
Ansible-software-packages

Modules:
Amazon.aws - Requred for download packages and applications for an organizational S3 bucket
Azure.azcollection - Requred for download packages and applications for an organizational Azure blob storage container

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: eeSoftware
      roles:
         - { role: username.rolename, x: 42 }

License
-------

BSD

Author Information
------------------

Jamie Garner, Repository Maintainer, Keyfactor
