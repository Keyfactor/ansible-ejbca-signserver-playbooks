ansible_ejbca_vault_subca
=========

Installs and configures Docker and a Hashicorp Vault container, enables Vault PKI, creates CSR, EJBCA signs the CSR, Vault PKI imports signed certificate, and then issues certificates from Vault PKI.



Example Playbook
----------------

This example is taken from `deployVaultEjbcaDemo.yml` and is tested on CentOS 8 EJBCA and Docker virtual machines.
```yaml
---
- hosts: docker_hosts
  become: yes
  become_method: sudo
  vars:
    docker_users:
      - srajala
  roles:
    - ansible-role-docker

- hosts: docker_hosts
  gather_facts: false
  pre_tasks:
    - setup:
        filter: ansible_env
  vars:
    vault_int_pki_name: pki_int
    vault_int_ca_dn: 'common_name="Vault Intermediate Authority GX2"  organization="Skyrim"'
    vault_int_ca_keysize: 2048
    vault_cli_url: https://releases.hashicorp.com/vault/1.3.4/vault_1.3.4_linux_amd64.zip
  roles:
    - ansible-ejbca-vault-container
    - ansible-ejbca-vault-ca-setup

- hosts: primekeyServers
  gather_facts: false
  become: yes
  become_method: sudo
  vars:
    vault_int_pki_name: pki_int
    vault_int_pki_passwd: "{{ encrypted_vault_int_pki_passwd | default('foo123') }}"
    vault_int_root_ca_cert_url: https://enrollprimekey.solitude.skyrim/ejbca/publicweb/webdist/certdist?cmd=cacert&issuer=CN%3DSolitude+Root+CA+G1%2COU%3DCertification+Authorities%2COU%3DSolitude%2CO%3DSkyrim&level=0
    vault_int_ca_ejbca_dn: 'CN=Vault Intermediate Authority GX2,OU=Certification Authorities,OU=Solitude,O=Skyrim'
    vault_int_ca_ejbca_rootca_sign: Solitude-Root-CA 
    vault_int_ca_ejbca_certprofile: HashiCorp-SubCA-G1
    vault_int_ca_ejbca_endentityprofile: Hashicorp-SubCA 
    ejbcawsracli_url: https://enrollprimekey.solitude.skyrim/ejbca/ejbcaws/ejbcaws
    ejbcawsracli_keystore_path: /opt/ejbca/p12/SkryimSuperAdministrator.p12
    ejbcawsracli_keystore_password: foo123
    ejbcawsracli_truststore_path: "{{ ejbca_toolbox }}/truststore"
    ejbcawsracli_truststore_url: https://enrollprimekey.solitude.skyrim/ejbca/publicweb/webdist/certdist?cmd=cachain&caid=1595111880&format=jks
  roles:
    - ansible-ejbca-certreq-websvc

- hosts: docker_hosts
  gather_facts: false
  pre_tasks:
    - setup:
        filter: ansible_env
  vars:
    vault_int_pki_domain: 
      - instance: solitude-skyrim
        allowed_domains: solitude.skyrim
        allow_subdomains: true
        max_ttl: 160h
        key_usage: 'DigitalSignature, KeyEncipherment'
    vault_int_pki_ee_domain: 
      - instance: solitude-skyrim
        common_name: test1.solitude.skyrim
        ttl: 24h
      - instance: solitude-skyrim
        common_name: test2.solitude.skyrim
        ttl: 48h
  roles:
    - ansible-ejbca-vault-ca-signed-cert
    - ansible-ejbca-vault-ca-issue-cert

```

The inventory file should contain the following: `inventory`:
```yaml
[docker_hosts]
docker01.solitude.skyrim ansible_host=172.16.170.133

[primekeyServers]
ejbca01.solitude.skyrim ansible_host=172.16.170.129
```



Also see a [full documentation of EJBCA](https://doc.primekey.com/doc) on how to further configure/manage EJBCA.

Role Variables
--------------

There are numerous variables for this playbook, but the most important ones are listed below.  The rest can be left as default. These variables are set in `defaults/main.yml` for the roles this playbook depends on:
```yaml
---
# User account to add to docker group
     docker_users:
      - srajala
# Vault PKI instance name of subordinate CA
    vault_int_pki_name: pki_int
# Vault Sub CA DN requested in the CSR.  Only the CN is used from the CSR when submitting the PKCS10 over the Web Service.  The CA DN is configured in EJBCA when adding the account to the CA
    vault_int_ca_dn: 'common_name="Vault Intermediate Authority GX2"  organization="Skyrim"'
# Vault Sub CA key size.  Can be 2048 or 4096.  3072 will not work
    vault_int_ca_keysize: 2048
# Verion of the Vault CLI to use
    vault_cli_url: https://releases.hashicorp.com/vault/1.3.4/vault_1.3.4_linux_amd64.zip
# Vault Sub CA user account password created in EJBCA
    vault_int_pki_passwd: "{{ encrypted_vault_int_pki_passwd | default('foo123') }}"
# URL to download the Root CA PEM file from EJBCA. This file is added to the signed certificate from EJBCA that is imported into Vault
    vault_int_root_ca_cert_url: https://enrollprimekey.solitude.skyrim/ejbca/publicweb/webdist/certdist?cmd=cacert&issuer=CN%3DSolitude+Root+CA+G1%2COU%3DCertification+Authorities%2COU%3DSolitude%2CO%3DSkyrim&level=0
# CA DN that will be used to issue Vault a Sub CA
    vault_int_ca_ejbca_dn: 'CN=Vault Intermediate Authority GX2,OU=Certification Authorities,OU=Solitude,O=Skyrim'
# EJBCA CA Name of the Root CA that will sign the Vault Sub CA CSR
    vault_int_ca_ejbca_rootca_sign: Solitude-Root-CA
# EJBCA Certificate Profile to use for Vault Sub CA 
    vault_int_ca_ejbca_certprofile: HashiCorp-SubCA-G1
# EJBCA End Entity Profile to use for Vault Sub CA
    vault_int_ca_ejbca_endentityprofile: Hashicorp-SubCA 
# URL of EJBCA web service
    ejbcawsracli_url: https://enrollprimekey.solitude.skyrim/ejbca/ejbcaws/ejbcaws
# Full path of the location of p12 file that is used to authenticate to EJBCA web service.  PKCS11 could be used, but would require updates to this Ansible role ansible-ejbca-certreq-websvc.
    ejbcawsracli_keystore_path: /opt/ejbca/p12/SkryimSuperAdministrator.p12
# Password for the p12 file
    ejbcawsracli_keystore_password: "{{ encrypted_ejbcawsracli_keystore_password | default('foo123') }}"
# Path to where the truststore that contains the CA chain of the endpoint that hosts the EJBCA web service
    ejbcawsracli_truststore_path: "{{ ejbca_toolbox }}/truststore"
# URL of the CA chain in JKS format to download from EJBCA. This file is stored at the ejbcawsracli_truststore_path variable
    ejbcawsracli_truststore_url: https://enrollprimekey.solitude.skyrim/ejbca/publicweb/webdist/certdist?cmd=cachain&caid=1595111880&format=jks
# Domain to create in Vault Sub CA PKI for issuing certificates to a domain.  Can create multiple domains by specifying multiple domains by using the format below.
    vault_int_pki_domain: 
      - instance: solitude-skyrim
        allowed_domains: solitude.skyrim
        allow_subdomains: true
        max_ttl: 160h
        key_usage: 'DigitalSignature, KeyEncipherment'
# Certificates issued from Vault Sub CA.  Can create multiple certficates by specifying servers like the examples below.
    vault_int_pki_ee_domain: 
      - instance: solitude-skyrim
        common_name: test1.solitude.skyrim
        ttl: 24h
      - instance: solitude-skyrim
        common_name: test2.solitude.skyrim
        ttl: 48h

```

Requirements
------------

- Internet Access
- Access to a repository containing packages, likely on the internet.
- A recent version of Ansible. (Tests run on the current, previous and next release of Ansible.)
- EJBCA must have a Root CA available to sign the Vault Sub CA CSR
- An EJBCA adminstrator credential in p12 format to authenticate to web service
- A certificate profile, and end entity profile defined in EJBCA



Dependencies
------------

This is a self contained playbook.  All the roles in this playbook are needed to get sucessfully use this playbook



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


Author Information
------------------

[PrimeKey](https://primekey.com)
