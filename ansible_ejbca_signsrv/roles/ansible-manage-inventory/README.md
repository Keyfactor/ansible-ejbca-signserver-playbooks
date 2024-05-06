Manage Inventory
================
Creates an inventory file with components required to manage an Ansible deployment. The template includes defaults based on the structure of the Ansible repository role and variable structure.

Requirements
------------
None

Role Variables
--------------
deployment_edition_enterprise: true
deployment_edition_community: false
deployment_container: false


Dependencies
------------
None


Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: localhost
      include_role:
        name: ansible-manage-inventory
        tasks_from: build.yml
      loop: "{{ ee_ejbca_children }}"
      loop_control:
        label: "{{ item.name }}
          

License
-------

BSD

Author Information
------------------

An optional section for the role authors to include contact information, or a website (HTML is not allowed).
