#!/usr/bin/env python

import os
import sys
import re
import random
import boto3
from OpenSSL import crypto
from OpenSSL import SSL
from datetime import datetime


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


    def sign_csr(self, *args, **kwargs):
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )
        private_key = self.load_private_key(
            self.get_private_key_pem(kwargs['PrivateKey'])
        )

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
                csr_payload.group(1).replace(' ', '\n'),
                '-----END CERTIFICATE REQUEST-----'
            )
            csr_pem = csr_formatted
        except:
            csr = crypto.load_certificate_request(
                crypto.FILETYPE_PEM,
                csr_pem
            )

        cert = crypto.X509()
        cert.set_version(3)
        cert.set_serial_number(random.randint(50000000,100000000))
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.add_extensions([
            crypto.X509Extension(
                'basicConstraints'.encode(),
                False,
                'critical,CA:TRUE'.encode(),
            )
        ])
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(kwargs['ValidityInSeconds'])
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
            'Certificate': kwargs['Certificate'].encode()
        }
        try:
            assert 'CertificateChain' in kwargs
            params['CertificateChain'] = kwargs['CertificateChain'].encode()
        except:
            pass
        return client.import_certificate_authority_certificate(params)
