# ansible_ejbca
[![Discuss](https://img.shields.io/badge/discuss-ejbca-ce?style=flat)](https://github.com/Keyfactor/ejbca-ce/discussions) 

An Ansible playbook that installs EJBCA & SignServer Community or Enterprise. The community EJBCA playbook deploys an EJBCA node and configures the management CA and Super Admin to begin using EJBCA to build out your PKI. It is easy to use for deploying a simple PKI with the community edition. The Enterprise playbooks are available to deploy a CA, external RA, & external VA. The enterprise version can also be configured as a standalone CA without deploying external RA/VA.

## Requirements

- Internet Access (required for downloading Wildfly, JDBC driver, HSM client, etc.)
- Access to a repository containing packages, likely on the internet.
- A recent version of [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html).
- A web respository that has the Community EJBCA or SignServer, or the enterprise version of EJBCA (Full, RA & VA builds) version to download. Community can be downloaded from GitHub if you would like to keep the zip release local
- A host with Ansible, AWX, or Ansible Tower installed from where to run the Ansible playbook
- A Linux host that EJBCA shall be installed on, reachable from the Ansible host using SSH with configured SSH keys for SSH agent based login (preferred method) or password, and the user with ability to become root using sudo
- The target host needs the configured hostname in DNS or hostsfile for Apache to startup properly, i.e.

```bash
/etc/hosts: 192.168.122.92 ejbca01.solitude.skyrim
```
- If Sudo requires a password use the `--ask-become-pass` flag when running `ansible-playbook`. Otherwise this flag is not required if passwordless Sudo is enabled. Examples below assert the flag

## For information - Before getting started

### Dependencies
This is a self contained playbook.  All the roles in this playbook are needed to sucessfully use this playbook.

### Security
Some software is downloaded when running this playbook (JDBC driver, Ant, Wildfly). It is your responsibility to ensure that the files downloaded are the correct ones, and that integrity is protected. It is recommended to use an internal repository, with approved files, in your organization if security is of a concern. 

### Role Variables
There are numerous variables for this playbook. These variables are set in `group_vars` and the `host_vars`. Reference the vars files for the settings used to deploy.

## Quick Start
Below you will find the steps to run some common tasks. 

### Deploy Community EJBCA version
1. Edit _group_vars/ceServers.yml_, _host_vars/ce01.yml_, and _inventory_.
2. Run:

```bash
ansible-playbook -i inventory -l ce01 deployCeNode.yml --ask-become-pass
```

### Deploy Community SignServer version
1. Edit _group_vars/ceSignServers.yml_, _host_vars/cess01.yml_, and _inventory_.
2. Run:

```bash
ansible-playbook -i inventory -l cess01,ssTlsCerts,ssCsrCerts deployCeSS.yml --ask-become-pass
```

### Deploy Enterprise SignServer version
1. Edit _group_vars/eeSignServers.yml_, _host_vars/ss01.yml_, and _inventory_.
2. Run:

```bash
ansible-playbook -i inventory -l ss01,ssTlsCerts,ssCsrCerts deploySS.yml --ask-become-pass
```

### Deploy an Enterprise CA
1. Edit _group_vars/eeCaServers.yml_, _host_vars/ca01.yml_, and _inventory_.
2. Run:

```bash
ansible-playbook -i inventory -l ca01 deployCa.yml --ask-become-pass
```

### Deploy an Enterprise external RA
1. Edit _group_vars/eeRaServers.yml_, _group_vars/pkiTlsCerts.yml_, _host_vars/ra01.yml_, and _inventory_.
2. Run:

```bash
ansible-playbook -i inventory -l ra01,pkiTlsCerts deployRa.yml --ask-become-pass
```
### Deploy an Enterprise external VA
1. Edit _group_vars/eeVaServers.yml_, _group_vars/pkiTlsCerts.yml_, _group_vars/pkiCsrCerts.yml_, _host_vars/va01.yml_, and _inventory_.
2. Run:

```bash
ansible-playbook -i inventory -l eeVaServers,va01,pkiTlsCerts,pkiCsrCerts deployVa.yml --ask-become-pass
```

### Upgrade EJBCA Community or Enterprise
1. Edit _group_vars/ceServers.yml_ or _group_vars/eeCaServers.yml_, _group_vars/eeRaServers.yml_, _group_vars/eeVaServers.yml_ and _inventory_.
2. Run to upgrade Community:

```bash
ansible-playbook -i inventory -l upgradeCeServers
```
3. Run to upgrade Enterprise:
```bash
ansible-playbook -i inventory -l upgradeEeServers
```

### Switch the Datasource
To use the Database source failover/failback use the following commands:

#### Failover 
```bash
ansible-playbook -i inventory -l ca01,ca02 -e failover_wildfly_db=true configureDB.yml
```

#### Failback
```bash
ansible-playbook -i inventory -l ca01,ca02 -e failback_wildfly_db=true configureDB.yml 
```

### Use Ansible Vault

Create a password file protected with Ansible Vault:

```bash
touch passwords/custom_enc_ca_vars.yml
ansible-vault create passwords/custom_enc_ca_vars.yml
```

Edit the password file to add/remove variables:

```bash
ansible-vault edit passwords/custom_enc_ca_vars.yml
```

Use the Ansible Vault password file:

```bash
ansible-playbook --ask-vault-pass -i inventory -e @passwords/custom_enc_ca_vars.yml deployCa.yml
```

## Current Ansible plays

### configureDB.yml (Community or Enterprise)
Use this play to update wildfly to point to a different datasource for failing over the EJBCA database. This play can also failback. Reference the steps in the Quickstart section for using this play.

### deployCa.yml (Enterprise)
Installs and configures EJBCA with a management, root, & issuing CA.  The stack includes Java 11, Apache HTTPD, Maraia DB, SoftHSM, & Wildfly. The playbook has the ability to set up other HSMs and create [Peer Connections](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/peer-systems) to [RA](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ra-concept-guide), [VA](https://doc.primekey.com/ejbca/ejbca-introduction/ejbca-architecture/external-ocsp-responders) and [SignServer](https://doc.primekey.com/signserver/signserver-reference/peer-systems).

### deployCeNode.yml (Community)
Installs and configures EJBCA community with a management CA and creates the SuperAdmin credential. The stack includes Java 11, Apache HTTPD, Maraia DB, & Wildfly.

### deployCeSS.yml (Community)
Installs and configures SignServer community. The stack includes Java 11, Apache HTTPD, Maraia DB, SoftHSM, & Wildfly. Configure the host_vars to define which workers you want. The default is to configure PDF, TSA, PGP, DNS, Plain, and XML.

### deployRa.yml (Enterprise)
Installs and configures EJBCA as an External RA. The play can configure the protocols when not using the RA variant which does not have protocol configuration using the CLI yet. The stack includes Java 11, Apache HTTPD, Maraia DB, SoftHSM, & Wildfly.

### deployVa.yml (Enterprise)
Installs and configures EJBCA as an External Validation Authority. The play configures OCSP signing certificates for the management, Root and Sub CA's.  The stack includes Java 11, Apache HTTPD, Maraia DB, SoftHSM, & Wildfly.

### deployCaAndPostConfig.yml (Enterprise)
This play is handy for populating an EJBCA instance that is freshly built with no configuration such as EJBCA Cloud. EJBCA must already be built and running for this play. CA hierarchies such as root and sub can be built with the play. Configdump is used to bootstrap EJBCA with certificate profiles, end entity profiles, protocl aliases, key bindings, publishers, services, and the protocol configuration.

### deployCaExtDb.yml (Enterprise)
This play is the same as deployCA.yml except it doesn't install or configure a database. The database must be setup and ready for EJBCA to connect before using this play.

### deployExtRootCaForSubPart1.yml (Enterprise)
Installs and configures EJBCA with a management CA. A TLS certificate is created for the Root CA Node and downloaded the Ansible controller.  The stack includes Java 11, Apache HTTPD, Maraia DB, SoftHSM, & Wildfly. The playbook has the ability to set up other HSMs.

### deployExtRootCaForSubPart2.yml (Enterprise)
Installs and configures EJBCA with a Root CA, imports the ManagementCA, adds Super Admin to the Super Admin role. The stack includes Java 11, Apache HTTPD, Maraia DB, SoftHSM, & Wildfly. The playbook has the ability to set up other HSMs.

### deployExtRootCaForSubPart3.yml (Enterprise)
Creates a sub CA in EJBCA issuing CA node, downloads the CSR to the Ansible controller.

### deployExtRootCaForSubPart4.yml (Enterprise)
Uploads a sub CA CSR from the Ansible controller to the EJBCA Root CA node to sign, then downloads the signed certificate to the Ansible controller.

### deployExtRootCaForSubPart5.yml (Enterprise)
Uploads the signed sub CA certificate to the issuing EJBCA node, imports the certificate, and then does post configuration tasks (Key bindings, peering, publishers, etc).

### deployExtSignCA.yml (Enterprise)
Creates a sub CA on the Issuing EJBCA node, downloads the CSR to the Ansible controller, Uploads the CSR to the EJBCA Root CA node, signs the CSR, downloads the certificate to the Ansible controller, uploads the certificate to the Issuing EJBCA node, and finally imports the certificate to complete the subordination.

### deployExtSignMgmtCa.yml (Enterprise)
Installs and configures EJBCA with a ManagementCA that will be subordinated to an external CA. The stack includes Java 11, Apache HTTPD, Maraia DB, SoftHSM, & Wildfly. The playbook has the ability to set up other HSMs.

### deployExtSignMgmtCaPost.yml (Enterprise)
Imports the signed certificate for the ManagementCA signed by an external CA. Adds administrators to the Super Admin role and creates P12 files on the the EJBCA node. EJBCA protocols are configured to enable/disable which protocols are served by the EJBCA node.

### deployExtSignPolCa.yml (Enterprise)
Creates a Policy CA in EJBCA issuing CA node, downloads the CSR to the Ansible controller.

### deployExtSignPolCaPost.yml (Enterprise)
Imports the signed Policy CA certificate for the ManagementCA signed by an external CA.

### deployIssuingCa.yml (Enterprise)
Creates an issuing CA signed by a Policy CA on the EJBCA node.

### deployPostCaConfig.yml (Enterprise)
Handles post configuration tasks (Key bindings, peering, publishers, etc).

### deploySS.yml (Enterprise)
Install and configure SignServer Enterprise with peering and workers to begin signing your artifacts. The stack includes Java 11, Apache HTTPD, Maraia DB, SoftHSM, & Wildfly. Configure the host_vars to define which workers you want.

### upgradeEjbca.yml (Community & Enterprise)
Upgrade EJBCA community and enterprise versions to a new version. EJBCA is downloaded from an internal web repo or can be downloaded from GitHub. The zip release is unarchived, compiled, and deployed.

### Documentation 
Also see a [full documentation of EJBCA](https://doc.primekey.com/ejbca) on how to further configure/manage EJBCA.


## Compatibility

This role has been tested on these:

|container|tags|
|---------|----|
|el| 8|


The minimum version of Ansible required is 2.9 but tests have been done to:

- The previous version, on version lower.
- The current version.
- The development version.

## Exceptions

Some variarations of the build matrix do not work. These are the variations and reasons why the build won't work:

| variation                 | reason                 |
|---------------------------|------------------------|
| TBD | TBD |

## Installation Notes

1. Using a Alma or Rocky 8 VM to install onto, installing python3 from yum makes /usr/bin/python3 available, while Ansible by default looks for /usr/bin/python.

The following can been set in the `group_vars/all.yml` that will be used for running plays, e.g. deployCa.yml or deployRa.yml, deployCeSS.yml

```yaml
    ansible_python_interpreter: /usr/bin/python3
```

2. Also seen on RedHat derivitive (CentOS, Alma, Rocky) is that Apache enables TLSv1.3 by default, and FireFox does not work with client certificate authentication using TLSv1.3. This results in EJBCA Admin UI being unreachable. The TLS config in Apache in available on the target, after the installation, in /etc/httpd/conf.d/ssl.conf
The setting in question is _SSLProtocol -all +TLSv1.2_ and You can enable this setting in the playbook in the file ./roles/ansible-ejbca-httpd/templates/ssl2.conf.j2.

3. The superadmin keystore, SkyrimSuperAdministrator.p12 file ends up in ~/Desktop in the host where you run the ansible-playbook command.

## License

LGPL v2.1 or later. See [LICENSE](./LICENSE).

## Author Information
- Keyfactor Community Team

