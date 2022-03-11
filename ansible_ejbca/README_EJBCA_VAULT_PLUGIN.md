# ansible_ejbca_vault_plugin

Install and configures Docker, Hashicorp Vault container, EJBCA Vault plugin to issue certificates from EJBCA requested through Vault.



# Example Playbook

This example is taken from `deployVaultEjbcaPlugin.yml` and is tested on CentOS 8 EJBCA and Docker virtual machines.
```yaml
---

- hosts: ejbcaCaServers
  gather_facts: false
  become: yes
  become_method: sudo
  pre_tasks:
    - include_vars: deployment_vars/deploy_vars.yml
  roles:
    - ansible-ejbca-certreq-cli
    - ansible-ejbca-ca-add-sn-to-admin-role

- hosts: docker_hosts
  become: yes
  become_method: sudo
  pre_tasks:
    - include_vars: deployment_vars/deploy_vars.yml
  roles:
    - ansible-role-docker

- hosts: docker_hosts
  become: no
  become_method: sudo
  pre_tasks:
    - include_vars: deployment_vars/deploy_vars.yml
    - setup:
        filter: ansible_env.HOME
  roles:
    - ansible-ejbca-vault-container

```

The inventory file should contain the following: `inventory`:
```yaml
[docker_hosts]
docker01.solitude.skyrim ansible_host=172.16.170.133

[primekeyServers]
ejbca01.solitude.skyrim ansible_host=172.16.170.129
```

Also see a [full documentation of EJBCA](https://doc.primekey.com/doc) on how to further configure/manage EJBCA.

# Role Variables

There are numerous variables for this playbook, and are specified in the deployment_vars/deploy_vars.yml. Details of these variables are described below.
```yaml
---

# Organization name, used for templating variables based off EJBCA deployed with the ansible_ejbca_ca_ee playbook
organizationName: Solitude

# Organization short name when the name is long or has spacing, used for templating variables based off EJBCA deployed with the ansible_ejbca_ca_ee playbook 
organizationNameShort: "{{ organizationName }}"

# FQDN used for EJBCA name or RA Peer, used for templating variables based off EJBCA deployed with the ansible_ejbca_ca_ee playbook 
organizationDomainName: solitude.skyrim

# Country name used for templating, used for templating variables based off EJBCA deployed with the ansible_ejbca_ca_ee playbook 
countryName: US

# Directory where certificates are copied down from EJBCA to the Ansible control host
ejbca_csr_dir_output: "{{ playbook_dir }}/ejbcaCSR"

# Staging location for certificates to be configured for Vault
vault_crt_stage_dir: /var/tmp

# The directory where Vault configuration files are configured for the Vault container. This variable is configured to use the user who executes this playbook.
vault_cfg_dir: "{{ ansible_env.HOME }}/vault"

# CA ID for the Sub CA DN. This variable can be found viewing a CA in EJBCA adminweb in the CA ID field.
sub_ca_1_id: -127947408

# CA ID for the Root CA DN. This variable can be found viewing a CA in EJBCA adminweb in the CA ID field.
root_ca_1_id: -1905764898

# The CA chains to download and configure for Vault and EJBCA plugin.
# caname: The name of the CA in EJBCA.  Reference the Certification Authorities link in EJBCA Admin for the name of the CA.  This is not the CA DN
# cert_download_url: URL to download the CA cert/chain file from.  This variable has been templated to allow for easy modifcation using supporting variables
# cert_file_location: Location to store the file when it is downloaded to the host downloading the certificates

tls_certifate_chain:
  - caname: "{{ organizationNameShort }}-Sub-CA"
    cert_download_url: "https://{{ ejbca_enrollment_fqdn }}/ejbca/publicweb/webdist/certdist?cmd=cachain&caid={{ sub_ca_1_id }}&format=pem&level=0"
    cert_file_location: "/var/tmp/{{ organizationNameShort }}-Sub-CA.crt"
  - caname: "{{ organizationNameShort }}-Root-CA"
    cert_download_url: "https://{{ ejbca_enrollment_fqdn }}/ejbca/publicweb/webdist/certdist?cmd=cachain&caid={{ root_ca_1_id }}&format=pem"
    cert_file_location: "{{ vault_cfg_dir }}/build/certs/{{ organizationNameShort }}-Root-CA.crt"
  - caname: "{{ organizationNameShort }}-Sub-CA"
    cert_download_url: "https://{{ ejbca_enrollment_fqdn }}/ejbca/publicweb/webdist/certdist?cmd=cacert&caid={{ sub_ca_1_id }}&format=pem&level=0"
    cert_file_location: "{{ vault_cfg_dir }}/build/certs/{{ organizationNameShort }}-Sub-CA.crt"


# A list of certificates to create in EJBCA used for deploying Vault.  A minimum of credentials required are the RA and TLS certificate for Vault 
# name: Friendly name of the credential, used for loop label
# full_dn:  Full DN for the certificate requested with ejbca.sh, e.g. "cn=ejbca-vault-connector-ra02,ou=Devices,O={{ organizationName }},C={{ countryName }}"
# username: End entity username created in EJBCA
# password: Password for the end entity created in EJBCA
# altname: Subject Alt names to include in the certificate, this must match what the end entity profile allows
# certprofile: Certificate profile to create the credential with, and must be allowed in the end entity profile
# eeprofile: End entity profile configured in EJBCA to create the credential with
# caname: The name of the CA in EJBCA.  Reference the Certification Authorities link in EJBCA Admin for the name of the CA.  This is not the CA DN
# token: Form factor for the credential; PEM, P12, or JKS
# useType: This is required to proper ID where a certificate is used. Value are: raAdmin, tls

identity_info:
  - name: ejbca-vault-connector-ra02
    full_dn: "cn=ejbca-vault-connector-ra02,ou=Devices,O={{ organizationName }},C={{ countryName }}"
    username: vault_connector_ra02
    password: "{{ encrypted_ejbca_vault_ra_identity_password | default('foo123') }}"
    altname: "dNSName=ejbca-vault-connector-ra02"
    certprofile: tlsClientAuth
    eeprofile: "tlsServer{{ organizationNameShort }}"
    caname: "{{ organizationNameShort }}-Sub-CA"
    token: PEM
    useType: raAdmin
  - name: "vault02.{{ organizationDomainName }}"
    full_dn: "cn=vault02.{{ organizationDomainName }},ou=Devices,O={{ organizationName }},C={{ countryName }}"
    username: vault02_tls
    password: "{{ encrypted_vaultTls_identity_password | default('foo123') }}"
    altname: "dNSName=vault02.{{ organizationDomainName }}"
    certprofile: tlsServerAuth
    eeprofile: "tlsServer{{ organizationName }}"
    caname: "{{ organizationName }}-Sub-CA"
    token: PEM
    useType: tls

# A list of the certificate files that are copied to the docker server used for configuring Vault and the EJBCA plugin. The variable is populated from the identity_info variable. 

id_cert_files:
  - src: "{{ ejbca_csr_dir_output }}/{{ identity_info[0].name }}.crt"
    dest: "{{ vault_crt_stage_dir }}/id/{{ identity_info[0].name }}.crt"
  - src: "{{ ejbca_csr_dir_output }}/{{ identity_info[0].name }}.key"
    dest: "{{ vault_crt_stage_dir }}/id/{{ identity_info[0].name }}.key"
  - src: "{{ ejbca_csr_dir_output }}/{{ identity_info[1].name }}.crt"
    dest: "{{ vault_cfg_dir }}/config/tmp/0.crt"
  - src: "{{ ejbca_csr_dir_output }}/{{ identity_info[01].name }}.key"
    dest: "{{ vault_cfg_dir }}/config/vault.key"
  - src: "{{ ejbca_csr_dir_output }}/{{ organizationNameShort }}-Sub-CA.crt"
    dest: "{{ vault_cfg_dir }}/config/tmp/{{ organizationNameShort }}-Sub-CA.crt"

# Variable uses the values in the identity_info variable, and it is used to merge files together. Do not change this variable unless you know what you are doing.

merge_id_cert_files:
  - name: "{{ identity_info[0].name }}"
    dir: "{{ vault_crt_stage_dir }}/id/"
    file: "{{ vault_crt_stage_dir }}/{{ identity_info[0].name }}.crt"
  - name: "{{ identity_info[1].name }}"
    dir: "{{ vault_cfg_dir }}/config/tmp/"
    file: "{{ vault_cfg_dir }}/config/vault.crt"

# Docker Compose file settings

# The hostname that the container will use, this MUST match the common name of the certificate Vault will use for TLS
vault_container_name: "{{ identity_info[1].name }}"

# Container image to use. A new container is built of the Hashicorp Vault container to add the EJBCA TLS trust chain into the new container
vault_container_image: ejbca/vault

# Vault TCP non TLS port
vault_host_tcp_port: 8200



# Vault json config settings
# Log level for Vault: Trace, Debug, Info, Error
vault_log_level: Info

# Vault API Address, this is the container name, and must match the name in the certificate Vault uses to terminate TLS on the container
vault_api_addr: "https://{{ identity_info[1].name }}:8210"

# Vault TCP non TLS port
vault_tcp_port: 8200

# Enable TCP TLS Vault listener, MUST be enabled to use the EJBCA plugin
vault_tls_listener: true

# TCP TLS port for Vault, this port is used by the API Address for the EJBCA plugin to function
vault_tls_tcp_port: 8210

# Role in EJBCA that the credential Vault will use to connect to the EJBCA REST API will be added to
ejbca_ra_admin_role_name: RA-Vault

# FQDN of EJBCA or RA peer that Vault is used for Vault to access the EJBCA REST API
ejbca_enrollment_fqdn: "enroll.{{ organizationDomainName }}"

# OS usernames to be added to the Docker group when Docker is installed.  This is a list variable to support multiple users
docker_users:
  - srajala

# The URL for downloading the Vault CLI 
vault_cli_url: https://releases.hashicorp.com/vault/1.5.3/vault_1.5.3_linux_amd64.zip

# Specifies the details to download the compiled EJBCA vault plugin.  This is a list variable to support deploying additional secret plugins
# url: URL where the compiled plugin available for download
# name: Name of the plugin. The plugin when unarchived has the name ejbca-vault-plugin-v1, and that vaule is what must be asserted
# path: the Vault sys/mount path created when enabling the EJBCA Vault plugin.  This should align with the plugin name/version, e.g. ejbcav1
# checksum: The checksum of the plugin after is unarchived. Use the sha256sum command to get the checksum

vault_plugin_download_urls:
  - url: http://172.16.170.133:8080/ejbca/ejbca-vault-plugin-v1-alpine.tar.gz
    name: ejbca-vault-plugin-v1
    path: ejbcav1
    checksum: cb6a0d4c7e959b55088acc851e01f55cc02091c7a1c3d36166cadee7297f2ff3

# Policies to configure in Vault when deploying/configuring Hashicorp Vault. This is a list variable to support adding multiple policies
# name: A friendly name for the policy
# src: The name of the policy as set in the templates directory for the ansible-ejbca-vault-container role
# dest: The destination where the policy is copied to.

vault_role_policies:
  - name: admin
    src: admin-policy.hcl.j2
    dest: "{{ vault_cli_dir }}/admin-policy.hcl"
  - name: provisioner
    src: provisioner-policy.hcl.j2
    dest: "{{ vault_cli_dir }}/provisioner-policy.hcl"

# Variables to configure Vault to issue certificates using EJBCA Vault plugin.  This is a list variable to support multiple certificate types to issue from one or more CA's
# name: The name of the EJBCA Vault instance, this can be the name of the EE or CP profile to distinguish between the differnt profiles, or add the CA name if needed. 
# caname: The name of the CA in EJBCA.  Reference the Certification Authorities link in EJBCA Admin for the name of the CA.  This is not the CA DN
# certprofile: The certificate profile defined in EJBCA that is configured in the end entity profile that will be issued
# eeprofile: The end entity profile defined in EJBCA that is used for issuing a certificate
# pem_bundle: A certificate and private key in PEM format that has administrative permission in EJBCA. The RA Administrators role is a good starting point to use. 
# tls_certifate_chain: The certificate chain that terminate TLS for EJBCA when accessing EJBCA over port 8443 or port 443 when Apache/Nginx are in front of Wildfly
# url: The URL for the EJBCA Vault plugin to access the EJBCA REST API, e.g. https://enroll.primekey.com/ejbca/ejbca-rest-api/v1
# vault_path: The sys/mount point that is created in Vault when enabling the EJBCA Vault plugin, e.g. ejbcav1

vault_ejbca_instances:
  - name: tlsServerAuth
    caname: "{{ organizationNameShort }}-Sub-CA"
    certprofile: tlsServerAuth
    eeprofile: "tlsServer{{ organizationNameShort }}"
    pem_bundle: "{{ vault_crt_stage_dir }}/{{ identity_info[0].name }}.crt"
    tls_certifate_chain: "{{ tls_certifate_chain[0].cert_file_location }}"
    url: "https://{{ ejbca_enrollment_fqdn }}/ejbca/ejbca-rest-api/v1"
    vault_path: "{{ vault_plugin_download_urls[0].path }}"


```

# Requirements

* Internet Access
* Access to a repository containing packages, likely on the internet or internally.
* A recent version of Ansible. (Tests run on the current, previous and next release of Ansible.)
* EJBCA: 
  * SSH access to EJBCA
  * EJBCA must have a CA available to issue certificates
  * EJBCA REST API enabled
  * A certificate profile, and end entity profile defined for TLS certificate, Vault RA credential, and certificate type that Vault will issue
* EJBCA Vault plugin
  * An Alpine Linux host to compile the plugin on
* A webserver to host files, this can be physical, virtual, or container.  Otherwise update the playbook accordingly to obtain the compiled plugin for installation


# Dependencies

The following dependencies are required:
* A host to install Docker on, physical or virtual
* EJBCA Enterprise
* Host that has Ansible installed
* Host that provides files over the web like a file repository, used to host the EJBCA Vault plugin after it is compiled


# Compatibility

This role has been tested on these:

|container|tags|
|---------|----|
|el|7, 8|


The minimum version of Ansible required is 2.9 but tests have been done to:

- The previous version, on version lower.
- The current version.
- The development version.

# Exceptions

Some variarations of the build matrix do not work. These are the variations and reasons why the build won't work:

| variation                 | reason                 |
|---------------------------|------------------------|
| TBD | TBD |


# License

LGPL v2.1 or later

# Author Information

[PrimeKey](https://primekey.com)
