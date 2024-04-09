<!--EJBCA Community logo -->
<a href="https://ejbca.org">
    <img src=".github/images/community-ejbca.png?raw=true)" alt="EJBCA logo" title="EJBCA" height="50" />
</a>
<!--EJBCA Enterprise logo -->
<a href="https://www.keyfactor.com/products/ejbca-enterprise/">
    <img src=".github/images/keyfactor-ejbca-enterprise.png?raw=true)" alt="EJBCA logo" title="EJBCA" height="50" />
</a>
<!-- SignServer Community logo -->
<a href="https://signserver.org">
    <img src=".github/images/community-signserver.png?raw=true)" alt="SignServer logo" title="SignServer" height="50" />
</a>
<!-- SignServer Enterprise logo -->
<a href="https://www.keyfactor.com/products/signserver-enterprise/">
    <img src=".github/images/keyfactor-signserver-enterprise.png?raw=true)" alt="SignServer logo" title="SignServer" height="50" />
</a>

# Ansible Playbooks for EJBCA and SignServer 
[![Discuss](https://img.shields.io/badge/discuss-ejbca-ce?style=flat)](https://github.com/Keyfactor/ansible-ejbca-signserver-playbooks/discussions) 

This is a collection of Ansible playbooks to use with EJBCA, SignServer, and integrations. Both Community and Enterprise versions of EJBCA are supported. By using these Ansible playbooks you can easily get EJBCA or SignServer up and running, including a complete technology stack with Java 11, Apache HTTPD, Maria DB, SoftHSM, and Wildfly.

## Available playbooks 

These playbooks are available:  
* **[ansible_ejbca_signsrv](./ansible_ejbca_signsrv)** – For use with EJBCA & SignServer Community or Enterprise version to install and configure EJBCA CA, external RA, & external VA, or only standalone CA without deploying external RA/VA, and SignServer.
* **[ejbca_certificate_request_role](./ejbca_certificate_request_role)** – For use with EJBCA Enterprise version to issue certificates from an EJBCA server using the REST API 

## Get started 
For details on how to set up and run the Ansible playbooks, see README in the respective playbook:
* [Ansible EJBCA SignServer README](https://github.com/Keyfactor/ansible-ejbca-signserver-playbooks/blob/main/ansible_ejbca_signsrv/README.md)
* [EJBCA Certificate Request Role README](https://github.com/Keyfactor/ansible-ejbca-signserver-playbooks/blob/main/ejbca_certificate_request_role/README.md)

### System Requirements
For more information, see 
* [Ansible EJBCA SignServer Requirements](https://github.com/Keyfactor/ansible-ejbca-signserver-playbooks/blob/main/ansible_ejbca_signsrv/README.md#requirements)
* [EJBCA Certificate Request Role Requirements](https://github.com/Keyfactor/ansible-ejbca-signserver-playbooks/blob/main/ejbca_certificate_request_role/README.md#requirements)

## Community Support
In the [Keyfactor Community](https://www.keyfactor.com/community/), we welcome contributions. 

The Community software is open-source and community-supported, meaning that **no SLA** is applicable.

* Read more in our documentation: [Deploying PKI and signature services in DevOps environments](https://doc.primekey.com/ejbca/solution-areas/deploying-pki-and-signature-services-in-devops-environments)
* Ask the community for ideas: [EJBCA Ansible Playbook Discussions](../../discussions)  
* To report a problem or suggest a new feature, go to [Issues](../../issues).
* If you want to contribute actual bug fixes or proposed enhancements, see the [Contributing Guidelines](CONTRIBUTING.md) and go to [Pull requests](../../pulls).

## Commercial Support

Commercial support is available for [EJBCA Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/) and [SignServer Enterprise](https://www.keyfactor.com/products/signserver-enterprise/).

## License
For license information, see [LICENSE](LICENSE). 

## Related Projects
See all [Keyfactor EJBCA GitHub projects](https://github.com/orgs/Keyfactor/repositories?q=ejbca) or [Keyfactor SignServer GitHub projects](https://github.com/orgs/Keyfactor/repositories?q=signserver). 

