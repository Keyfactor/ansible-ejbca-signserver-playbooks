ansible_ejbca_ca_ee
=========

Installs and configures EJBCA with a management, root, & issuing CA.  The stack includes Java 8, Apache HTTPD, Maraia DB, SoftHSM, & Wildfly. The playbook have abilities to set up other HSMs and create [Peer Connections](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/peer-systems) to [RA](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ra-concept-guide), [VA](https://doc.primekey.com/ejbca/ejbca-introduction/ejbca-architecture/external-ocsp-responders) and [SignServer](https://doc.primekey.com/signserver/signserver-reference/peer-systems).

Requirements
------------

- Internet Access
- Access to a repository containing packages, likely on the internet.
- A recent version of [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html).
- A web respository that has the enterprise version of EJBCA to download
- A host from where to run the Ansible playbook
- A host where to install EJBCA on, reachable from the Ansible host using SSH with configured SSH keys for SSH agent based login, and the user with ability to become root using sudo.
- the target host need the configured hostname in DNS or hostsfile for Apache to startup properly, i.e.
>/etc/hosts: 192.168.122.92 ca01.solitude.skyrim

Dependencies
------------

This is a self contained playbook.  All the roles in this playbook are needed to get sucessfully use this playbook.

Security
------------

Some software is downloaded when running this playbook. It is your responsibility to ensure that the files downloaded are the correct ones, and that integrity is protected. It is recommended to use an internal repository, with approved files, in your organization if security is of a concern.

Quick Start
-----------
Edit _customer_info/customer_vars.yml_ and run:

>ansible-playbook -i inventory deployEJBCA.yml --ask-become-pass

Example Playbook
----------------

This example is taken from `deployEJBCA.yml` and is tested on CentOS 8 with FIPS mode enabled.  The playbook saves the serial number for the Peer Connector certificate that is configured as a keybinding on the CA.  Use the serial numbers in this file called peer_cert_serial_numbers.yml to use in the VA and RA ansible playbooks for configuring the Peering Roles.  The playbook creates a file called peer_cert_serial_numbers.yml for the Peer Connector certificates.  This file is saved to  `~/ansible/ansibleCacheDir` and must be accessible for the VA and RA roles.

```yaml
---

- hosts: primekeyServers
  become: yes
  become_method: sudo
  roles:
    - ansible-role-hostname
    - ansible-role-mariadb
    - ansible-ejbca-wildfly
    - ansible-ejbca-prep
    - ansible-ejbca-ca-ee
    - ansible-ejbca-httpd
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
superAdminCn: "27May2020 Skyrim Super Administrator"
sharedVarsLocation: ~/ansible/ansibleCacheDir

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
ejbca_software_url: http://172.16.170.132/ejbca/ejbca_ee_7_4_0.zip
ejbca_src_dir_name: ejbca_ee_7_4_0
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
management_add_end_entities:
  - username: "SkryimSuperAdministrator"
    dn: "C={{ countryName }},O={{ organizationName }},OU=Administrators,CN={{ superAdminCn }}"
    caname: "ManagementCA"
    token: "P12"
    password: "{{ encrypted_superadmin_enrollment_code | default('foo123') }}"
    certprofile: adminMgmtCA
    eeprofile: AdminInternal  
management_add_administrators:
  - role: "Super Administrator Role"
    caname: "ManagementCA"
    match_with: "WITH_COMMONNAME"
    match_value: "{{ superAdminCn }}"

ejbca_peer_crypto_token:
  - name: peeringCryptoToken
    slot_label: KeyBinding_SLOT
    slot_identifier_type: "SLOT_LABEL"
    type: PKCS11CryptoToken
    slot_index: 0
    slot_pin: "{{ encrypted_peerKeyBinding_token_pin | default('foo123') }}"
    slot_identifier: "SLOT_LABEL:KeyBinding_SLOT"
    ocsp_key_size: "3072"
    ocsp_key_label: peerKeyBindingOcsp00001
    ra_key_size: "3072"
    ra_key_label: peerKeyBindingRa00001

ejbca_keybinding:
  - name: ejbca01PeerClient-ocsp
    crypto_token_name: peeringCryptoToken
    key_label: "{{ ejbca_peer_crypto_token[0].ocsp_key_label }}"
    signature_algorithm: SHA256WithRSA
    dn: "CN=ejbca01PeerClient-ocsp,OU=Peering,O={{ organizationName }},C={{ countryName }}"
    caname: "ManagementCA"
    token: "USERGENERATED"
    password: "{{ encrypted_keybind_enrollment_code | default('foo123') }}"
    certprofile: tlsPeerConnector
    eeprofile: tlsPeerConnMgmt
    useType: ocsp
  - name: ejbca01PeerClient-ra
    crypto_token_name: peeringCryptoToken
    key_label: "{{ ejbca_peer_crypto_token[0].ra_key_label }}"
    signature_algorithm: SHA256WithRSA
    dn: "CN=ejbca01PeerClient-ra,OU=Peering,O={{ organizationName }},C={{ countryName }}"
    caname: "ManagementCA"
    token: "USERGENERATED"
    password: "{{ encrypted_keybind_enrollment_code | default('foo123') }}"
    certprofile: tlsPeerConnector
    eeprofile: tlsPeerConnMgmt
    useType: ra


httpd_identity_info:
  id_dn: "ou=Devices,O={{ organizationName }},C={{ countryName }}"
  id_name: "ca01.{{ organizationDomainName }}"
  id_full_dn: "cn=ca01.{{ organizationDomainName }},ou=Devices,O={{ organizationName }},C={{ countryName }}"
  id_username: ca_httpd_tls
  id_password: "{{ encrypted_httpd_identity_password | default('foo123') }}"
  id_altname: "dNSName=ca01.{{ organizationDomainName }}, dNSName=ca.{{ organizationDomainName }}"
  id_certprofile: tlsServerClientAuth
  id_eeprofile: "tlsServer{{ organizationName }}"
  id_caname: "{{ organizationName }}-Sub-CA"

# Add the management CA to HTTP trust chain file. 
add_mgmt_ca: true


ejbca_peerConnector:
  - name: OCSP-01
    url: "https://ocsp01.{{ organizationDomainName }}/ejbca/peer/v1"
    keybinding: "{{ ejbca_keybinding[0].name }}"
    type: ocsp
  - name: RA-01
    url: "https://ra01.{{ organizationDomainName }}/ejbca/peer/v1"
    keybinding: "{{ ejbca_keybinding[1].name }}"
    type: ra  

# List of certification authorities that should be added using CLI
# caname: CA name
# certprofile: Certificate profile
# dn: CA distinguished name
# subjectaltname: CA subject alt name
# validity: Validity time or end date
# policy: "null" or policy oid
# keytype: RSA, DSA or ECDSA
# keyspec: Size of RSA keys, size of DSA keys or name of curve for ECDSA keys
# signalg: Signature algorithm
# tokentype: "soft" or "org.cesecore.keys.token.PKCS11CryptoToken"
# tokenpass: Password for the CA token
# pkcs11_token: Dict of parameters needed for PKCS11 token
# slot_identifier_type: "SLOT_LABEL", "SLOT_INDEX" or "SLOT_NUMBER"
# slot_identifier_value: Slot identifier
# signkey_label: Signing key label
# defaultkey_label: Default (encryption) key label
# testkey_label: Test key label
# The order must be Management CA and then Root CA
management_add_certification_authorities:
  - caname: "ManagementCA"
    certprofile: "managementCA"
    dn: "CN=ManagementCA,OU=Certification Authorities,O={{ organizationName }},C={{ countryName }}"
    subjectaltname: ""
    validity: "3650"
    validity_yml: "10y"
    policy: "null"
    keytype: "RSA"
    keyspec: "3072"
    signalg: "SHA384WithRSA"
    tokentype: "org.cesecore.keys.token.PKCS11CryptoToken"
    tokenpass: "{{ encrypted_mgmtca_token_pin | default('foo123') }}"
    defaultCRLDP: "http://crl.{{ organizationDomainName }}/CRLs/{{ organizationName | lower }}-mgmtca.crl"
    defaultOCSPServiceLocator: "http://ocsp.{{ organizationDomainName }}/ocsp"
    authorityInformationAccess: "http://aia.{{ organizationDomainName }}/CertsIssuedTo{{ organizationName}}Mgmtca.p7b"
    certificateAiaDefaultCaIssuerUri: "http://aia.{{ organizationDomainName }}/CertsIssuedTo{{ organizationName}}-mgmtca.p7b"
    crlPeriod: 259200000
    crlIssueInterval: 86400000
    useLdapDnOrder: false
    pkcs11_token:
      slot_identifier_type: "SLOT_LABEL"
      slot_identifier_value: "Management_CA_SLOT"
      signkey_label: "signKey00001"
      defaultkey_label: "defaultKey00001"
      testkey_label: "testKey"
  - caname: "{{ organizationName }}-Root-CA"
    certprofile: "RootCA-{{ organizationName }}-G1"
    dn: "CN={{ organizationName }} Root CA G1,OU=Certification Authorities,O={{ organizationName }},C={{ countryName }}"
    subjectaltname: ""
    validity: "9125"
    validity_yml: "25y"
    policy: "null"
    keytype: "RSA"
    keyspec: "4096"
    signalg: "SHA512WithRSA"
    tokentype: "org.cesecore.keys.token.PKCS11CryptoToken"
    tokenpass: "{{ encrypted_rootca_token_pin | default('foo123') }}"
    defaultCRLDP: "http://crl.{{ organizationDomainName }}CRLs/{{ organizationName | lower }}-rootca-g1.crl"
    defaultOCSPServiceLocator: "http://ocsp.{{ organizationDomainName }}/ocsp"
    authorityInformationAccess: "http://aia.{{ organizationDomainName }}/AIA/CertsIssuedTo{{ organizationName }}RootCAG1.p7b"
    certificateAiaDefaultCaIssuerUri: "http://aia.{{ organizationDomainName }}/AIA/CertsIssuedTo{{ organizationName }}RootCAG1.p7b"
    crlPeriod: 15552000000
    crlIssueInterval: 0
    useLdapDnOrder: false
    pkcs11_token:
      slot_identifier_type: "SLOT_LABEL"
      slot_identifier_value: "Root_CA_SLOT"
      signkey_label: "signKey00001"
      defaultkey_label: "defaultKey00001"
      testkey_label: "testKey"

# List of certification authorities that should be added using CLI
# caname: CA name
# certprofile: Certificate profile
# dn: CA distinguished name
# subjectaltname: CA subject alt name
# validity: Validity time or end date
# policy: "null" or policy oid
# keytype: RSA, DSA or ECDSA
# keyspec: Size of RSA keys, size of DSA keys or name of curve for ECDSA keys
# signalg: Signature algorithm
# tokentype: "soft" or "org.cesecore.keys.token.PKCS11CryptoToken"
# tokenpass: Password for the CA token
# pkcs11_token: Dict of parameters needed for PKCS11 token
# slot_identifier_type: "SLOT_LABEL", "SLOT_INDEX" or "SLOT_NUMBER"
# slot_identifier_value: Slot identifier
# signkey_label: Signing key label
# defaultkey_label: Default (encryption) key label
# testkey_label: Test key label
sub_add_certification_authorities:
  - caname: "{{ organizationName }}-Sub-CA"
    certprofile: "SubCA-{{ organizationName }}-G1"
    dn: "CN={{ organizationName }} Issuing CA G1,OU=Certification Authorities,O={{ organizationName }},C={{ countryName }}"
    rootDn: "CN={{ organizationName }} Root CA G1,OU=Certification Authorities,O={{ organizationName }},C={{ countryName }}"
    subjectaltname: ""
    validity: "3650"
    validity_yml: "10y"
    policy: "null"
    keytype: "RSA"
    keyspec: "3072"
    signalg: "SHA384WithRSA"
    tokentype: "org.cesecore.keys.token.PKCS11CryptoToken"
    tokenpass: "{{ encrypted_subca_token_pin | default('foo123') }}"
    defaultCRLDP: "http://crl.{{ organizationDomainName }}/CRLs/{{ organizationName | lower }}-subca-g1.crl"
    defaultOCSPServiceLocator: "http://ocsp.{{ organizationDomainName }}/ocsp"
    authorityInformationAccess: "http://aia.{{ organizationDomainName }}/AIA/CertsIssuedTo{{ organizationName}}SubCAG1.p7b"
    certificateAiaDefaultCaIssuerUri: "http://aia.{{ organizationDomainName }}/AIA/CertsIssuedTo{{ organizationName}}SubCAG1.p7b"
    crlPeriod: 259200000
    crlIssueInterval: 86400000
    useLdapDnOrder: false
    doEnforceUniqueDistinguishedName: false
    pkcs11_token:
      slot_identifier_type: "SLOT_LABEL"
      slot_identifier_value: "Sub_CA_SLOT"
      signkey_label: "signKey00001"
      defaultkey_label: "defaultKey00001"
      testkey_label: "testKey"

certification_authorities_crl_files:
  - crlfilename: "{{ organizationName | lower }}-mgmtca.crl"
    cadn: "CN%3dManagementCA%2cOU%3dCertification+Authorities%2cO%3d{{ organizationName}}%2cC%3d{{ countryName }}"
  - crlfilename: "{{ organizationName | lower }}-rootca-g1.crl"
    cadn: "CN%3d{{ organizationName}}+Root+CA+G1%2cOU%3dCertification+Authorities%2cO%3d{{ organizationName}}%2cC%3d{{ countryName }}"
  - crlfilename: "{{ organizationName | lower }}-subca-g1.crl"
    cadn: "CN%3d{{ organizationName}}+Issuing+CA+G1%2cOU%3dCertification+Authorities%2cO%3d{{ organizationName }}%2cC%3d{{ countryName }}"

```

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

Installation Notes
------------------
1. Using a CentOS8 VM to install onto, installing python3 from yum makes /usr/bin/python3 available, while ANsble by default looks for /usr/bin/python.
Add  
```
vars:
    ansible_python_interpreter: /usr/bin/python3
```
to deployEJBCA.yml

2. Also seen on CentOS8 is that Apache enables TLSv1.3 bby default, and FireFox does not work with client certificate authentication using that. This results in EJBCA Admin UI being unreachable. The TLS config in Apache in available on the target, after the installation, in /etc/httpd/conf.d/ssl.conf
The setting in question is _SSLProtocol -all +TLSv1.2_ and You can enable this setting in the playbook in the file ./roles/ansible-ejbca-httpd/templates/ssl2.conf.j2.

3. The superadmin keystore, SkyrimSuperAdministrator.p12 file ends up in ~/Desktop in the host where you run the ansible-playbook command.


License
-------

LGPL v2.1 or later

Author Information
------------------

[PrimeKey](https://primekey.com)
