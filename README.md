# Ansible Playbooks for EJBCA and SignServer 
[![Discuss](https://img.shields.io/badge/discuss-ejbca-ce?style=flat)](https://github.com/Keyfactor/ejbca-ce/discussions) 

This is a collection of Ansible playbooks to use with EJBCA, SignServer, and integrations. Both Community and Enterprise versions of EJBCA are supported. By using these Ansible playbooks you can easily get EJBCA or SignServer up and running, including a complete technology stack with Java 11, Apache HTTPD, Maria DB, SoftHSM, and Wildfly.

## Available playbooks 

These playbooks are available:  
* **[ansible_ejbca_signsrv](./ansible_ejbca_signsrv)** – For use with EJBCA & SignServer Community or Enterprise version to install and configure EJBCA CA, external RA, & external VA, or only standalone CA without deploying external RA/VA, and SignServer.
* **[ejbca_certificate_request_role](./ejbca_certificate_request_role)** – For use with EJBCA Enterprise version to issue certificates from an EJBCA server using the REST API 

## Get started 

Example: 
To run the EJBCA or SignServer ansible playbook with EJBCA or SignServer Community, do the following: 
1. Make sure to follow the prerequisites. 
2. Set any required variables. 
3. Run the ansible playbook. 
For details, see README in the respective playbook. 

## Support  

We welcome contributions. These Ansible playbooks are open source and community supported, meaning that no SLA is applicable. 

* To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. 
* If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.
* Ask the community for ideas: **[EJBCA Discussions](https://github.com/Keyfactor/ejbca-ce/discussions)**  
* Read more in our documentation: **[Deploying PKI and signature services in DevOps environments](https://doc.primekey.com/ejbca/solution-areas/deploying-pki-and-signature-services-in-devops-environments)**

## License 

EJBCA is licensed under the LGPL license, please see **[LICENSE](LICENSE)**. 

## Related projects 

* [Keyfactor/ejbca-ce](https://github.com/Keyfactor/ejbca-ce) 
* [Keyfactor/ejbca-tools](https://github.com/Keyfactor/ejbca-tools) 
* [Keyfactor/ejbca-vault-plugin](https://github.com/Keyfactor/ejbca-vault-plugin) 
* [Keyfactor/ejbca-vault-monitor](https://github.com/Keyfactor/ejbca-vault-monitor) 
* [Keyfactor/ejbca-cert-cvc](https://github.com/Keyfactor/ejbca-cert-cvc) 
* [Keyfactor/ejbca-containers](https://github.com/Keyfactor/ejbca-containers) 
* [Keyfactor/signserver-tools](https://github.com/Keyfactor/signserver-tools) 
