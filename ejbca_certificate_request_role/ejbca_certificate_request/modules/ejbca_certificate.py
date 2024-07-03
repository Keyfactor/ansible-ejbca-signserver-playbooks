#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c), PrimeKey Solutions AB, 2021
# Based on code Copyright (c), Entrust Datacard Corporation, 2019

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: ejbca_certificate
extends_documentation_fragment:
- community.crypto.ejbca_credential

'''

EXAMPLES = r'''
- name: Request a new certificate from EJBCA.
'''

RETURN = '''
filename:
    description: The destination path for the generated certificate.
    returned: changed or success
    type: str
    sample: /etc/ssl/crt/www.ansible.com.crt
'''

#from ansible_collections.community.crypto.plugins.module_utils.ejbca.api import (
#    ejbca_client_argument_spec,
#    EJBCAClient,
#    RestOperationException,
#    SessionConfigurationException,
#)

import json
import datetime
import os
import re
import time
import traceback
import base64
import ssl

from distutils.version import LooseVersion

from ansible.module_utils._text import to_text, to_native
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils._text import to_native, to_bytes
from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.error import HTTPError

from ansible_collections.community.crypto.plugins.module_utils.io import (
    write_file,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    load_certificate,
)

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True

MINIMAL_CRYPTOGRAPHY_VERSION = '1.6'


def validate_cert_expiry(cert_expiry):
    search_string_partial = re.compile(r'^([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])\Z')
    search_string_full = re.compile(r'^([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):'
                                    r'([0-5][0-9]|60)(.[0-9]+)?(([Zz])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))\Z')
    if search_string_partial.match(cert_expiry) or search_string_full.match(cert_expiry):
        return True
    return False


def calculate_cert_days(expires_after):
    cert_days = 0
    if expires_after:
        expires_after_datetime = datetime.datetime.strptime(expires_after, '%Y-%m-%dT%H:%M:%SZ')
        cert_days = (expires_after_datetime - datetime.datetime.now()).days
    return cert_days


# Populate the value of body[dict_param_name] with the JSON equivalent of
# module parameter of param_name if that parameter is present, otherwise leave field
# out of resulting dict
def convert_module_param_to_json_bool(module, dict_param_name, param_name):
    body = {}
    if module.params[param_name] is not None:
        if module.params[param_name]:
            body[dict_param_name] = 'true'
        else:
            body[dict_param_name] = 'false'
    return body


class EjbcaCertificate(object):
    '''
    EJBCA Certificate Services certificate class.
    '''

    def __init__(self, module):
        self.path = module.params['path']
        self.full_chain_path = module.params['full_chain_path']
        self.force = module.params['force']
        self.backup = module.params['backup']
        self.request_type = module.params['request_type']
        self.csr = module.params['csr']
        self.certificate_profile = module.params['certificate_profile_name']
        self.end_entity_profile = module.params['end_entity_profile_name']
        self.certificate_authority = module.params['certificate_authority_name']
        self.username = module.params['end_entity_username']
        self.password = module.params['end_entity_password']

        # All return values
        self.changed = False
        self.filename = None
        self.tracking_id = None
        self.cert_status = None
        self.serial_number = None
        self.cert_days = None
        self.cert_details = None
        self.backup_file = None
        self.backup_full_chain_file = None

        self.cert = None
        self.ejbca_client = None
        if self.path and os.path.exists(self.path):
            try:
                self.cert = load_certificate(self.path, backend='cryptography')
            except Exception as dummy:
                self.cert = None
        # Instantiate the EJBCA client and then try a no-op connection to verify credentials are valid
        try:
            self.ejbca_client = EJBCAClient(
                ejbca_api_url=module.params['ejbca_api_url'],
                ejbca_api_cert=module.params['ejbca_api_client_cert_path'],
                ejbca_api_cert_key=module.params['ejbca_api_client_cert_key_path'],
            )
        except SessionConfigurationException as e:
            module.fail_json(msg='Failed to initialize EJBCA Provider: {0}'.format(to_native(e)))
        try:
            self.api_status = self.ejbca_client.GetStatus()
            self.status = self.api_status.get('status')
            self.api_ver = self.api_status.get('version')
            # This is the first REST API call to check connectivity, status and get version
            # Do a: https://localhost:8443/ejbca/ejbca-rest-api/v1/certificate/status
            #{
            #  "status": "OK",
            #  "version": "1.0",
            #  "revision": "EJBCA 7.5.0-Snapshot Enterprise (working copy)"
            #}
            # DEBUG
            #print ("STATUS: " + self.status)
            #print ("API VERSION: " + self.api_ver)
            if self.status != 'OK':
                raise RestOperationException({"status": self.status, "errors": [{"message": "API status is not OK: '" + self.status + ", " + self.api_ver + "'"}]})
        except RestOperationException as e:
            module.fail_json(msg='Please verify credential information. Received exception when testing connection: {0}'.format(to_native(e.message)))

    def request_cert(self, module):
        if self.force:
            body = {}

            # Read the CSR contents
            if self.csr and os.path.exists(self.csr):
                with open(self.csr, 'r') as csr_file:
                    body['certificate_request'] = csr_file.read()

            # Check if the path is already a cert
            # set details by get_cert_details if an ejbca cert is in 'path'.
            if self.request_type != 'new':
                module.warn('No existing certificate found in path={0}, setting request_type to "new" for this task'
                            'run. Future playbook runs that point to the pathination file in {1} will use request_type={2}'
                            .format(self.path, self.path, self.request_type))
                self.request_type = 'new'
            elif self.request_type == 'new':
                module.warn('Existing certificate being acted upon, but request_type is "new", so will be a new certificate issuance rather than a '
                            'reissue or renew')
            # Use cases where request type is new and no existing certificate, or where request type is reissue/renew and a valid
            # existing certificate is found, do not need warnings.

            #body['certificate_profile_name'] = 'Client';
            body['certificate_profile_name'] = self.certificate_profile;
            #body['end_entity_profile_name'] = 'User';
            body['end_entity_profile_name'] = self.end_entity_profile;
            #body['certificate_authority_name'] = 'ManagementCA';
            body['certificate_authority_name'] = self.certificate_authority;
            body['include_chain'] = 'true';

            body['username'] = self.username;
            body['password'] = self.password;

            if not module.check_mode:
                try:
                    if self.request_type == 'validate_only':
                        body['validateOnly'] = 'true'
                        result = self.ejbca_client.NewCertRequest(Body=body) #TODO
                    if self.request_type == 'new':
                        result = self.ejbca_client.Pkcs10Enroll(Body=body)
                    elif self.request_type == 'renew':
                        result = self.ejbca_client.RenewCertRequest(trackingId=self.tracking_id, Body=body)#TODO
                    elif self.request_type == 'reissue':
                        result = self.ejbca_client.ReissueCertRequest(trackingId=self.tracking_id, Body=body)#TODO
                    self.serial_number = result.get('serial_number')
                except RestOperationException as e:
                    module.fail_json(msg='Failed to request new certificate from EJBCA {0}'.format(e.message))

                if self.request_type != 'validate_only':
                    if self.backup:
                        self.backup_file = module.backup_local(self.path)
                    # We get certbytes just base64 encoded, but without PEM headers
                    certbytes = base64.b64decode(result.get('certificate'))
                    cert_PEM = ssl.DER_cert_to_PEM_cert(certbytes);
                    write_file(module, to_bytes(cert_PEM))
                    if self.full_chain_path and result.get('certificate_chain'):
                        if self.backup:
                            self.backup_full_chain_file = module.backup_local(self.full_chain_path)
                        chain_string = '\n'.join(result.get('certificate_chain')) + '\n'
                        write_file(module, to_bytes(chain_string), path=self.full_chain_path)
                    self.changed = True

    def dump(self):
        result = {
            'changed': self.changed,
            'filename': self.path,
            'cert_status': self.cert_status,
            'serial_number': self.serial_number,
            'cert_days': self.cert_days,
            'cert_details': self.cert_details,
        }
        if self.backup_file:
            result['backup_file'] = self.backup_file
            result['backup_full_chain_file'] = self.backup_full_chain_file
        return result


def custom_fields_spec():
    return dict(
        text1=dict(type='str'),
        text2=dict(type='str'),
        text3=dict(type='str'),
        text4=dict(type='str'),
        text5=dict(type='str'),
        text6=dict(type='str'),
        text7=dict(type='str'),
        text8=dict(type='str'),
        text9=dict(type='str'),
        text10=dict(type='str'),
        text11=dict(type='str'),
        text12=dict(type='str'),
        text13=dict(type='str'),
        text14=dict(type='str'),
        text15=dict(type='str'),
        number1=dict(type='float'),
        number2=dict(type='float'),
        number3=dict(type='float'),
        number4=dict(type='float'),
        number5=dict(type='float'),
        date1=dict(type='str'),
        date2=dict(type='str'),
        date3=dict(type='str'),
        date4=dict(type='str'),
        date5=dict(type='str'),
        email1=dict(type='str'),
        email2=dict(type='str'),
        email3=dict(type='str'),
        email4=dict(type='str'),
        email5=dict(type='str'),
        dropdown1=dict(type='str'),
        dropdown2=dict(type='str'),
        dropdown3=dict(type='str'),
        dropdown4=dict(type='str'),
        dropdown5=dict(type='str'),
    )


def ejbca_certificate_argument_spec():
    return dict(
        backup=dict(type='bool', default=False),
        force=dict(type='bool', default=True),
        path=dict(type='path', required=True),
        full_chain_path=dict(type='path'),
        remaining_days=dict(type='int', default=30),
        request_type=dict(type='str', default='new', choices=['new', 'renew', 'reissue', 'validate_only']),
        certificate_profile_name=dict(type='str', required=True),
        end_entity_profile_name=dict(type='str', required=True),
        certificate_authority_name=dict(type='str', required=True),
        ejbca_api_url=dict(type='str', required=True),
        csr=dict(type='str'),
        subject_alt_name=dict(type='list', elements='str'),
        eku=dict(type='str', choices=['SERVER_AUTH', 'CLIENT_AUTH', 'SERVER_AND_CLIENT_AUTH']),
        ct_log=dict(type='bool'),
        client_id=dict(type='int', default=1),
        org=dict(type='str'),
        ou=dict(type='list', elements='str'),
        end_user_key_storage_agreement=dict(type='bool'),
        additional_emails=dict(type='list', elements='str'),
        custom_fields=dict(type='dict', default=None, options=custom_fields_spec()),
        cert_expiry=dict(type='str'),
        cert_lifetime=dict(type='str', choices=['P1Y', 'P2Y', 'P3Y']),
        end_entity_username=dict(type='str', required=True),
        end_entity_password=dict(type='str', required=True),
    )

#
# From api.py BEGIN
#

def ejbca_client_argument_spec():
    return dict(
        ejbca_api_client_cert_path=dict(type='path', required=True),
        ejbca_api_client_cert_key_path=dict(type='path', required=True, no_log=True),
    )


class SessionConfigurationException(Exception):
    """ Raised if we cannot configure a session with the API """

    pass


class RestOperationException(Exception):
    """ Encapsulate a REST API error """

    def __init__(self, error):
        self.status = to_native(error.get("status", None))
        self.errors = [to_native(err.get("message")) for err in error.get("errors", {})]
        self.message = to_native(" ".join(self.errors))

def bind(instance, method, operation_name):
    def binding_scope_fn(*args, **kwargs):
        return method(instance, *args, **kwargs)

    # Make sure we don't confuse users; add the proper name and documentation to the function.
    # Users can use !help(<function>) to get help on the function from interactive python or pdb
    binding_scope_fn.__name__ = str(operation_name)
    binding_scope_fn.__doc__ = operation_name

    return binding_scope_fn

class RestOperation(object):
    def __init__(self, session, uri, method, parameters=None):
        self.session = session
        self.method = method
        if parameters is None:
            self.parameters = {}
        else:
            self.parameters = parameters
        self.url = "{api_url}{uri}".format(api_url=self.session.get_config('ejbca_api_url'), uri=uri)
        #self.url = "{scheme}://{host}{base_path}{uri}".format(scheme="https", host=session._spec.get("host"), base_path=session._spec.get("basePath"), uri=uri)

    def restmethod(self, *args, **kwargs):
        """Do the hard work of making the request here"""

        # gather named path parameters and do substitution on the URL
        if self.parameters:
            path_parameters = {}
            body_parameters = {}
            query_parameters = {}
            for x in self.parameters:
                expected_location = x.get("in")
                #print ("in:'" + expected_location+"'")
                key_name = x.get("name", None)
                #print ("key_name:'" + key_name+"'")
                key_value = kwargs.get(key_name, None)
                #print ("key_value:'")
                #print (key_value)
                #print (kwargs)
                if expected_location == "path" and key_name and key_value:
                    path_parameters.update({key_name: key_value})
                elif expected_location == "body" and key_name and key_value:
                    body_parameters.update({key_name: key_value})
                elif expected_location == "query" and key_name and key_value:
                    query_parameters.update({key_name: key_value})

            if len(body_parameters.keys()) >= 1:
                body_parameters = body_parameters.get(list(body_parameters.keys())[0])
            else:
                body_parameters = None
        else:
            path_parameters = {}
            query_parameters = {}
            body_parameters = None

        # This will fail if we have not set path parameters with a KeyError
        url = self.url.format(**path_parameters)
        if query_parameters:
            # modify the URL to add path parameters
            url = url + "?" + urlencode(query_parameters)

        try:
            if body_parameters:
                body_parameters_json = json.dumps(body_parameters)
                response = self.session.request.open(method=self.method, url=url, data=body_parameters_json)
            else:
                response = self.session.request.open(method=self.method, url=url)
            request_error = False
        except HTTPError as e:
            # An HTTPError has the same methods available as a valid response from request.open
            response = e
            request_error = True

        # Return the result if JSON and success ({} for empty responses)
        # Raise an exception if there was a failure.
        try:
            result_code = response.getcode()
            result = json.loads(response.read())
            # DEBUG
            #print (result)
        except ValueError:
            result = {}

        if result or result == {}:
            if result_code and result_code < 400:
                return result
            else:
                raise RestOperationException(result)

        # Raise a generic RestOperationException if this fails
        raise RestOperationException({"status": result_code, "errors": [{"message": "REST Operation Failed"}]})

class Resource(object):
    """ Implement basic CRUD operations against a path. """

    def __init__(self, session):
        self.session = session
        self.parameters = {}

        operation_name = "GetStatus"
        # HTTP GET without parameters
        parameters = None
        op = RestOperation(session, "/certificate/status", "GET", parameters)
        setattr(self, operation_name, bind(self, op.restmethod, operation_name))

        operation_name = "Pkcs10Enroll"
        parameters={}
        # The body parameters themselves are defined when calling the method
        parameters = [{'in':'body','name':'Body'}]

        #print (parameters)
        op = RestOperation(session, "/certificate/pkcs10enroll", "POST", parameters)
        setattr(self, operation_name, bind(self, op.restmethod, operation_name))


# Session to encapsulate the connection parameters of the module_utils Request object, the api spec, etc
class EJBCASession(object):
    def __init__(self, name, **kwargs):
        """
        Initialize our session
        """

        self._set_config(name, **kwargs)

    def client(self):
        resource = Resource(self)
        return resource

    def _set_config(self, name, **kwargs):
        headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
        }
        self.request = Request(headers=headers, timeout=60)

        configurators = [self._read_config_vars]
        for configurator in configurators:
            self._config = configurator(name, **kwargs)
            if self._config:
                break
        if self._config is None:
            raise SessionConfigurationException(to_native("No Configuration Found."))

        # set up client certificate if passed (support all-in one or cert + key)
        ejbca_api_url = self.get_config("ejbca_api_url")
        ejbca_api_cert = self.get_config("ejbca_api_cert")
        ejbca_api_cert_key = self.get_config("ejbca_api_cert_key")
        if ejbca_api_cert:
            self.request.client_cert = ejbca_api_cert
            if ejbca_api_cert_key:
                self.request.client_key = ejbca_api_cert_key
                if ejbca_api_url:
                    self.request.url = ejbca_api_url
        else:
            raise SessionConfigurationException(to_native("Client certificate for authentication to the API must be provided."))

# TODO: how to configure verify CA certificates in Request?
#        self.verify = '/home/user/Documents/PrimeKey/Solutions/RedHat/Ansible-Module/test/files/ca.pem'
#In Request(?):verify='/home/user/Documents/PrimeKey/Solutions/RedHat/Ansible-Module/test/files/ca.pem'
#works: export SSL_CERT_FILE=/home/user/Documents/PrimeKey/Solutions/RedHat/Ansible-Module/test/files/ca.pem

    def get_config(self, item):
        return self._config.get(item, None)

    def _read_config_vars(self, name, **kwargs):
        """ Read configuration from variables passed to the module. """
        config = {}

        for required_file in ["ejbca_api_cert", "ejbca_api_cert_key"]:
            file_path = kwargs.get(required_file)
            if not file_path or not os.path.isfile(file_path):
                raise SessionConfigurationException(
                    to_native("Parameter provided for {0} of value '{1}' was not a valid file path.".format(required_file, file_path))
                )

        config["ejbca_api_url"] = kwargs.get("ejbca_api_url")
        config["ejbca_api_cert"] = kwargs.get("ejbca_api_cert")
        config["ejbca_api_cert_key"] = kwargs.get("ejbca_api_cert_key")

        return config


def EJBCAClient(ejbca_api_url=None, ejbca_api_cert=None, ejbca_api_cert_key=None):
    """Create an EJBCA client"""


    # Not functionally necessary with current uses of this module_util, but better to be explicit for future use cases
    ejbca_api_url = to_text(ejbca_api_url)
    ejbca_api_cert = to_text(ejbca_api_cert)
    ejbca_api_cert_key = to_text(ejbca_api_cert_key)

    return EJBCASession(
        "ejbca",
        ejbca_api_url=ejbca_api_url,
        ejbca_api_cert=ejbca_api_cert,
        ejbca_api_cert_key=ejbca_api_cert_key,
    ).client()

#
# From api.py END
#

def main():
    ejbca_argument_spec = ejbca_client_argument_spec()
    ejbca_argument_spec.update(ejbca_certificate_argument_spec())
    module = AnsibleModule(
        argument_spec=ejbca_argument_spec,
        mutually_exclusive=(
            ['cert_expiry', 'cert_lifetime'],
        ),
        supports_check_mode=True,
    )

    if not CRYPTOGRAPHY_FOUND or CRYPTOGRAPHY_VERSION < LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION):
        module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                         exception=CRYPTOGRAPHY_IMP_ERR)

    # A reissued request can not specify an expiration date or lifetime
    if module.params['request_type'] == 'reissue':
        if module.params['cert_expiry']:
            module.fail_json(msg='The cert_expiry field is invalid when request_type="reissue".')
        elif module.params['cert_lifetime']:
            module.fail_json(msg='The cert_lifetime field is invalid when request_type="reissue".')
    # Only a reissued request can omit the CSR
    else:
        module_params_csr = module.params['csr']
        if module_params_csr is None:
            module.fail_json(msg='The csr field is required when request_type={0}'.format(module.params['request_type']))
        elif not os.path.exists(module_params_csr):
            module.fail_json(msg='The csr field of {0} was not a valid path. csr is required when request_type={1}'.format(
                module_params_csr, module.params['request_type']))

    if module.params['ou'] and len(module.params['ou']) > 1:
        module.fail_json(msg='Multiple "ou" values are not currently supported.')

    if module.params['org'] and module.params['client_id'] != 1:
        module.fail_json(msg='The "org" parameter is not supported when client_id parameter is set to a value other than 1".')

    if module.params['cert_expiry']:
        if not validate_cert_expiry(module.params['cert_expiry']):
            module.fail_json(msg='The "cert_expiry" parameter of "{0}" is not a valid date or date-time'.format(module.params['cert_expiry']))

    certificate = EjbcaCertificate(module)
    certificate.request_cert(module)
    result = certificate.dump()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
