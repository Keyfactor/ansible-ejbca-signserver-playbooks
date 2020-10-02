ansible_ejbca_ra_ee
=========

Installs and configures EJBCA External RA using the management CA certificate from the EJBCA CA server, configures Sub CA for RA.  The stack includes Java 8, Apache HTTPD, Maraia DB, SoftHSM, & Wildfly.



Example Playbook
----------------

This example is taken from `deployVA.yml` and is tested on CentOS 8 with FIPS mode enabled.  The playbook requires the peer_cert_serial_numbers.yml for the Peer Connector certificate that is configured as a keybinding on the CA be accessible in `~/ansible/ansibleCacheDir`.

```yaml
---

- hosts: ejbcaRaServers
  become: yes
  become_method: sudo
  gather_facts: true
  pre_tasks:
    - include_vars: customer_info/customer_vars.yml
  roles:
    - ansible-role-hostname
    - ansible-role-mariadb
    - ansible-ejbca-wildfly
    - ansible-ejbca-ra-prep
    - ansible-ejbca-ra-ee

- hosts: ejbcaCaServers
  become: yes
  become_method: sudo
  gather_facts: false
  pre_tasks:
    - include_vars: customer_info/customer_vars.yml
  roles:
    - ansible-ejbca-certreq-cli

- hosts: ejbcaRaServers
  become: yes
  become_method: sudo
  gather_facts: false
  pre_tasks:
    - include_vars: customer_info/customer_vars.yml      
  roles:
    - ansible-ejbca-ra-httpd
    - ansible-ejbca-ra-peer

- hosts: ejbcaCaServers
  become: yes
  become_method: sudo
  gather_facts: false
  pre_tasks:
    - include_vars: customer_info/customer_vars.yml
  roles:
    - ansible-ejbca-ca-peer-ra
```

The inventory file should contain the following: `inventory`:
```yaml
[allLinux]
ejbca01.solitude.skyrim ansible_host=172.16.170.129
webrepo.solitude.skyrim ansible_host=72.16.170.132
ejbcara01.solitude.skyrim ansible_host=172.16.170.142

[ejbcaCaServers]
ejbca01.solitude.skyrim ansible_host=172.16.170.129

[ejbcaVaServers]
ejbcava01.solitude.skyrim ansible_host=172.16.170.128

[ejbcaRaServers]
ejbcara01.solitude.skyrim ansible_host=172.16.170.142
```



Also see a [full documentation of EJBCA](https://doc.primekey.com/doc) on how to further configure/manage EJBCA.

Role Variables
--------------

There are numerous variables for this playbook, but the most important ones are listed below.  The rest can be left as default. These variables are set in `customer_info/customer_vars.yml` for the roles this playbook depends on:
```yaml
---

organizationName: Solitude
organizationDomainName: solitude.skyrim
countryName: US
superAdminCn: "04Jun2020 Skyrim Super Administrator"

# The CA ID for the CA's.  This number is obtained from ejbca.sh ca listcas or using client toolbox
management_ca_id: 966011820
root_ca_1_id: -1905764898
sub_ca_1_id: -127947408

peer_ca_cert_serial_numbers: "{{ lookup('file', '~/ansible/ansibleCacheDir/peer_cert_serial_numbers.yml' ) | from_yaml }}"

mariadb_root_password:  "{{ encrypted_database_rootuser_password | default('PrimeKeyPkI4all') }}"
mariadb_binlog_formatt: ROW
mariadb_databases:
  - name: ejbca
    collation: "utf8_general_ci"
    encoding: "utf8"
mariadb_users:
  - name: ejbca-usr
    password: "{{ encrypted_database_ejbcauser_password | default('ejbca') }}"
    priv: "ejbca.*:ALL"
    host: "%"
  - name: ejbca-usr
    password: ejbca
    priv: "ejbca.*:ALL"
    host: "localhost"

ejbca_version: 7.4.0
ejbca_software_url: http://172.16.170.132/ejbca/ejbca_ee_7_4_0_RA.zip
ejbca_src_dir_name: ejbca_ee_7_4_0_RA
ejbca_jdbc_driver: https://downloads.mariadb.com/Connectors/java/connector-java-2.5.4/mariadb-java-client-2.5.4.jar

appsrv_datasources:
  - jndi_name: "java:/EjbcaDS"
    pool_name: ejbcads
    host: 127.0.0.1
    port: 3306
    database: ejbca
    user: ejbca-usr
    password: "{{ encrypted_database_ejbcauser_password | default('ejbca') }}"
ejbca_cli_defaultpassword: "{{ encrypted_ejbca_cli_password | default('ejbca') }}"
ejbca_ca_cmskeystorepass: "{{ encrypted_ejbca_ca_cmskeystorepass | default('ejbca') }}"

management_import_certification_authorities:
  - caname: "ManagementCA"
    cert_download_url: "https://ca01.{{ organizationDomainName }}/ejbca/publicweb/webdist/certdist?cmd=cachain&caid={{ management_ca_id }}&format=pem"
    cert_file_location: /var/tmp/managementca.crt
    superadmincn: "{{ superAdminCn }}"
  - caname: "{{ organizationName }}-Root-CA"
    cert_download_url: "https://ca01.{{ organizationDomainName }}/ejbca/publicweb/webdist/certdist?cmd=cachain&caid={{ root_ca_1_id }}&format=pem"
    cert_file_location: "/var/tmp/{{ organizationName }}-Root-CA.crt"
    superadmincn: ""
  - caname: "{{ organizationName }}-Sub-CA"
    cert_download_url: "https://ca01.{{ organizationDomainName }}/ejbca/publicweb/webdist/certdist?cmd=cacert&caid={{ sub_ca_1_id }}&format=pem&level=0"
    cert_file_location: "/var/tmp/{{ organizationName }}-Sub-CA.crt"
    superadmincn: ""

identity_info:
  - dn: "ou=Devices,O={{ organizationName }},C={{ countryName }}"
    name: "ra01.{{ organizationDomainName }}"
    full_dn: "cn=ra01.{{ organizationDomainName }},ou=Devices,O={{ organizationName }},C={{ countryName }}"
    username: ra_httpd_tls
    password: "{{ encrypted_httpd_identity_password | default('foo123') }}"
    altname: "dNSName=ra01.{{ organizationDomainName }}, dNSName=enroll.{{ organizationDomainName }}"
    certprofile: tlsServerClientAuth
    eeprofile: "tlsServer{{ organizationName }}"
    caname: "{{ organizationName }}-Sub-CA"
    token: PEM
    useType: ra

# Add the management CA to HTTP trust chain file. 
add_mgmt_ca: true

httpd_identity_info:
  id_name: "{{ identity_info[0].name }}"
  id_ca_cert_file: "{{ identity_info[0].caname }}.crt"

```

Requirements
------------

- Internet Access
- Access to a repository containing packages, likely on the internet.
- A recent version of Ansible. (Tests run on the current, previous and next release of Ansible.)
- A web respository that has the enterprise version of EJBCA to download
- Fully configured EJBCA CA server accessible over SSH



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




License
-------

TBD


Author Information
------------------

[PrimeKey](https://primekey.com)
