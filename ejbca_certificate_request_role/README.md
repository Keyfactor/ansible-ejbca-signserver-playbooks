ejbca_certificate_request_role
=====================

Purpose of role
---------------
This role issues a certificate from en EJBCA server using the EJBCA REST API.

 - Create a private key.
 - Create a certificate signing request (CSR).
 - Issue your certificates using the EJBCA REST API.
    - Note: You must have REST API credentials (TLS client key and certificate).

Requirements
------------
 - Ansible version 2.10
 - PyYAML version 3.11 or higher
 - cryptography version 1.6 or higher

Role Variables
--------------

See variables in defaults/main.yml


Dependencies
------------

None

Ansible 2.10
------------
With python3 you can easily install the latest version of Ansible in a python virt env using pip

>python3.8 -m venv ~/ansible-env
>source ~/ansible-env/bin/activate
>pip install ansible

Using the module
----------------
The Ansible module located in ejbca_certificate_request/modules/ejbca_certificate.py must be placed in a location where Ansible finds modules, before running the sample playbook.
On a typical Linux system this can be done with the following command:
> cp ejbca_certificate_request/modules/ejbca_certificate.py ~/.ansible/plugins/modules/.

You must have EJBCA REST API client key and certificate configured in the path noted in ejbca_certificate_request/defaults/main.yml

You can create them from a p12 file for example like this.
NOTE: the private key is stored unprotected here, which is not recommended. Use Ansible Vault or similar module to protect secrets.
>openssl pkcs12 -in superadmin.p12 -nodes

Copy the client cert and key respectively...
>cat > apiClientCert.pem
>cat > apiClientKey.pem

You must configure Ansible to trust the CA certificate that issued the EJBCA servers TLS server certificate.
Copy the CA certificate to a file and set the environment variable for Ansible:
>export SSL_CERT_FILE=/path/to/sslca/ca.pem

Example Playbook
----------------

The command below is an example of how to use the role.

Before running the example you will need to to update the below in defaults/main.yml:

Mandatory Parameters:
	working_path # Path that the key pair, certificate signing request, and certificate will be stored in, unless otherwise specified (see optional parameters)
	cert_common_name
	cert_organization_name:
	cert_organizational_unit_name:
	cert_country_name:
	cert_state_or_province_name:
	cert_type

Mandatory authentication parameters
    ejbca_api_url # The URL to EJBCA REST API end point
	ejbca_api_client_cert_path # The TLS client certificate used to authenticate to the EJBCA REST API
	ejbca_api_client_cert_key_path # The TLS private key used to authenticate to the EJBCA REST API

Optional parameters:
	cert_path # Full path to the location that will be used to save the generated certificate.
	csr_path: # Full path to the location that will be used to save the certificate signing request
	privatekey_path: # Full path to the location that will be used to save the private key.
	request_type
	days_remaining

Run command "ansible-playbook sample_playbook.yml"

Additional references
---------------------
https://github.com/EntrustCorporation/ecs_certificate_request_role

- Leveraging Deployment Automation Ansible Role to Set Up and Refresh Your Web Infrastructure (article)
https://blog.entrust.com/2019/08/leveraging-deployment-automation-tools/
- Entrust SSL certificates information/purchase pages
https://www.entrust.com/digital-security/certificate-solutions/products/digital-certificates/tls-ssl-certificates

License
-------

MIT

Author Information
------------------
This role extends code Copyright (c), Entrust Corporation, 2021
