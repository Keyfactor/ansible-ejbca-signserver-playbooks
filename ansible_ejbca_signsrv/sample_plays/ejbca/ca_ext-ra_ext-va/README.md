# Use Case

This sample deploys an EJBCA PKI with a CA/RA/VA in an AWS environment using version control.

# Instances

- 1 CA Cluster Node
- 1 External RA Node
- 1 External VA Node

# PKI

- 1 Root CA
- 1 Management CA
- 1 Issuing CA

# Database

- Local MariaDB Database

# PKCS#11

- Software HSM
- Remote OCSP Key Bindings on VA Node

# Version Control

- Set all application variables specific to the version and installation directory in versionControl group_var
