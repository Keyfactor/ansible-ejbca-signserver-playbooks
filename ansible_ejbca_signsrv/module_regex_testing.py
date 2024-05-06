from lib.ansible.module_utils.ejbca import (
    StringParser,
    sign_algorithms
)
import re

output='''"Type	"Name" (id), Status, "IssuerDN", SerialNumber, "CryptoTokenName" (id), KeyPairAlias, NextKeyPairAlias, SignatureAlgorithm, properties={Implementations specific properties}, trust={list of trusted CAs and certificates}, signOcspResponsesOnBehalf={list of other CAs for which responses are signed}
 AuthenticationKeyBinding	"peerClient-ocsp" (-2126235996), ACTIVE, "CN=ManagementCA,OU=Certification Authorities,O=Solitude,C=US", 7C09F2C8570937AFE2D3E384057BD3383BF2A67D, "(CryptoToken does not exist)" (1981522710), peerKeyBindingOcsp0001, null, SHA256WithRSA, properties={
	protocolAndCipherSuite=TLSv1.2;TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 [String, default=TLSv1.2;TLS_DHE_RSA_WITH_AES_128_GCM_SHA256]
 }, 	trust={
		ANY certificate issued by a known CA
 }
 AuthenticationKeyBinding	"peerClient-ra" (743238425), ACTIVE, "CN=ManagementCA,OU=Certification Authorities,O=Solitude,C=US", 406136A9922F7E8271717663B05F134BCE3F814C, "(CryptoToken does not exist)" (1981522710), peerKeyBindingRa0001, null, SHA256WithRSA, properties={
	protocolAndCipherSuite=TLSv1.2;TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 [String, default=TLSv1.2;TLS_DHE_RSA_WITH_AES_128_GCM_SHA256]
 }, 	trust={
		ANY certificate issued by a known CA
 }
'''

bind_list=list()
output=output.splitlines()
for line in output:
    while True:
        if 'AuthenticationKeyBinding' in line:
            print(line)
        #bind_list.append(line)
        
        # while not 'AuthenticationKeyBinding' in line:
        #     bind_list.append(line)
    #print(bind_list)