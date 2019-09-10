#!/usr/bin/env python

import os
import sys
import re
import random
import boto3
from OpenSSL import crypto
from OpenSSL import SSL
from datetime import datetime
from base64 import b64decode


class ACM_PCA:
    def __init__(self, *args, **kwargs):
        self.verbose = bool(int(os.getenv('VERBOSE', 0)))
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )


    def get_private_key_pem(self, param):
        ssm = boto3.client('ssm')
        return ssm.get_parameter(
            Name=param,
            WithDecryption=True
        )['Parameter']['Value']


    def load_private_key(self, key_pem):
        return crypto.load_privatekey(
            crypto.FILETYPE_PEM,
            key_pem.encode()
        )


    def dump_private_key(self, private_key):
        return crypto.dump_privatekey(
            crypto.FILETYPE_PEM,
            private_key
        )


    def check_cert(self, private_key, cert):
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.use_privatekey(private_key)
        ctx.use_certificate(cert)
        try:
          ctx.check_privatekey()
          return True
        except SSL.Error:
          return False


    def issue_certificate(self, *args, **kwargs):
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )
        client = boto3.client('acm-pca')
        return client.issue_certificate(
            CertificateAuthorityArn=kwargs['CertificateAuthorityArn'],
            Csr=kwargs['Csr'].encode(),
            SigningAlgorithm=kwargs['SigningAlgorithm'],
            TemplateArn=kwargs['TemplateArn'],
            Validity={
                'Value': kwargs['Validity']['Value'],
                'Type': kwargs['Validity']['Type']
            }
        )


    def create_self_signed_cert(self, *args, **kwargs):
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )
        private_key = self.load_private_key(
            self.get_private_key_pem(kwargs['PrivateKey'])
        )
        ca_cert = crypto.X509()
        ca_cert.set_version(2)
        ca_cert.get_subject().C = kwargs['Country']
        ca_cert.get_subject().O = kwargs['Org']
        ca_cert.get_subject().OU = kwargs['OrgUnit']
        ca_cert.get_subject().CN = kwargs['CanonicalName']
        ca_cert.set_serial_number(int(kwargs['Serial']))
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(int(kwargs['ValidityInSeconds']))
        ca_cert.set_issuer(ca_cert.get_subject())

        ca_cert.add_extensions([
            crypto.X509Extension(
                b'basicConstraints',
                True,
                b'CA:TRUE'
            ),
            crypto.X509Extension(
                b'subjectKeyIdentifier',
                False,
                b'hash',
                subject=ca_cert
            ),
            crypto.X509Extension(
                b'keyUsage',
                True,
                b'digitalSignature, cRLSign, keyCertSign'
            )
        ])

##        ca_cert.add_extensions([
##            crypto.X509Extension(
##                b'authorityKeyIdentifier',
##                False,
##                b'keyid:always,issuer',
##                issuer=ca_cert
##            )
##        ])

        ca_cert.set_pubkey(private_key)
        ca_cert.sign(private_key, kwargs['Digest'])
        return {
            'Certificate': crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode()
        }
        

    def sign_csr(self, *args, **kwargs):
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )
        private_key = self.load_private_key(
            self.get_private_key_pem(kwargs['PrivateKey'])
        )

        try:
            csr_pem = b64decode(kwargs['Csr']).decode()
        except:
            csr_pem = kwargs['Csr']
        try:
            csr_payload = re.search(
                '-----BEGIN CERTIFICATE REQUEST-----(.*)-----END CERTIFICATE REQUEST-----',
                csr_pem,
                re.IGNORECASE
            )
            assert csr_payload
            csr_formatted = '{}{}{}'.format(
                '-----BEGIN CERTIFICATE REQUEST-----',
                csr_payload.group(1).replace(' ', '\n').replace('\\n', '\n'),
                '-----END CERTIFICATE REQUEST-----'
            )
            csr_pem = csr_formatted
        except:
            pass

        csr = crypto.load_certificate_request(
            crypto.FILETYPE_PEM,
            csr_pem
        )

        ca_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM,
            kwargs['CACert'].replace('\\n', '\n')
        )

        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(random.randint(50000000,100000000))
        cert.set_issuer(ca_cert.get_subject())
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())

        cert.add_extensions([
            crypto.X509Extension(
                b'basicConstraints',
                True,
                b'CA:TRUE'
            ),
            crypto.X509Extension(
                b'subjectKeyIdentifier',
                False,
                b'hash',
                subject=cert
            ),
            crypto.X509Extension(
                b'keyUsage',
                True,
                b'digitalSignature, cRLSign, keyCertSign'
            )
        ])

##        cert.add_extensions([
##            crypto.X509Extension(
##                b'authorityKeyIdentifier',
##                False,
##                b'keyid:always,issuer',
##                issuer=ca_cert
##            )
##        ])

        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(int(kwargs['ValidityInSeconds']))
        cert.sign(private_key, kwargs['Digest'])
        return {
            'Certificate': crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
        }


    def import_certificate_authority_certificate(self, *args, **kwargs):
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )
        client = boto3.client('acm-pca')
        params = {
            'CertificateAuthorityArn': kwargs['CertificateAuthorityArn'],
            'Certificate': kwargs['Certificate'].replace('\\n', '\n').encode()
        }
        try:
            assert 'CertificateChain' in kwargs
            params['CertificateChain'] = kwargs['CertificateChain'].replace('\\n', '\n').encode()
        except:
            pass
        return client.import_certificate_authority_certificate(**params)
