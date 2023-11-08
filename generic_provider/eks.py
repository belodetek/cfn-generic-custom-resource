#!/usr/bin/env python

import base64
import boto3
import os, sys
import re
import tempfile
import yaml
from botocore.signers import RequestSigner
from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException
from uuid import uuid4


class EKS:
    url_expires_in = 60 # seconds

    def __init__(self, *args, **kwargs):
        self.verbose = bool(int(os.getenv('VERBOSE', 0)))
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )
        self.session = boto3.session.Session(**kwargs)
        self.region_name = kwargs['region_name']

    # https://github.com/kubernetes-sigs/aws-iam-authenticator/blob/master/README.md#api-authorization-from-outside-a-cluster
    def get_bearer_token(self, region_name, cluster_name):
        client = self.session.client('sts')
        service_id = client.meta.service_model.service_id

        signer = RequestSigner(
            service_id,
            region_name,
            'sts',
            'v4',
            self.session.get_credentials(),
            self.session.events
        )

        print(self.session.get_credentials().__dict__)
        if self.verbose: print('signer: {}'.format(signer.__dict__), file=sys.stderr)

        params = {
            'method': 'GET',
            'url': 'https://sts.{}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15'.format(region_name),
            'body': {},
            'headers': {
                'x-k8s-aws-id': cluster_name
            },
            'context': {}
        }

        signed_url = signer.generate_presigned_url(
            params,
            region_name=region_name,
            expires_in=self.url_expires_in,
            operation_name=''
        )
        base64_url = base64.urlsafe_b64encode(signed_url.encode('utf-8')).decode('utf-8')
        return 'k8s-aws-v1.' + re.sub(r'=*', '', base64_url)

    # https://www.analogous.dev/blog/using-the-kubernetes-python-client-with-aws/
    def write_cafile(self, data: str) -> tempfile.NamedTemporaryFile:
        cafile = tempfile.NamedTemporaryFile(delete=False)
        cadata_b64 = data
        cadata = base64.b64decode(cadata_b64)
        cafile.write(cadata)
        cafile.flush()
        return cafile

    def authenticate_eks(self, region_name, cluster_name):
        client = self.session.client('eks')

        cluster_info = client.describe_cluster(name=cluster_name)['cluster']
        if self.verbose: print('cluster_info: {}'.format(cluster_info), file=sys.stderr)

        certificate = self.write_cafile(cluster_info['certificateAuthority']['data'])

        token = self.get_bearer_token(region_name, cluster_name)
        if self.verbose: print('token: {}'.format(token), file=sys.stderr)

        configuration = k8s_client.Configuration()
        configuration.host = cluster_info['endpoint']
        configuration.ssl_ca_cert = certificate.name
        configuration.api_key['authorization'] = f'Bearer {token}'

        if self.verbose: print(
            'configuration: {}'.format(configuration.__dict__),
            file=sys.stderr
        )
        return k8s_client.CoreV1Api(k8s_client.ApiClient(configuration))

    def get_aws_auth_configmap(self, region_name, cluster_name):
        v1 = self.authenticate_eks(region_name, cluster_name)
        try:
            return v1.read_namespaced_config_map('aws-auth', 'kube-system')
        except ApiException as e:
            print(f'Exception when calling CoreV1Api->read_namespaced_config_map: {e}\n')
            return

    def patch_aws_auth_configmap(self, region_name, cluster_name, aws_auth_configmap):
        v1 = self.authenticate_eks(region_name, cluster_name)
        try:
            response = v1.replace_namespaced_config_map('aws-auth', 'kube-system', aws_auth_configmap)
        except ApiException as e:
            print(f'Exception when calling CoreV1Api->replace_namespaced_config_map: {e}\n')

        if self.verbose: print(
            'response: {}'.format(response),
            file=sys.stderr
        )
        return response

    def update_aws_auth_configmap(self, *args, **kwargs):
        cluster_name = kwargs['ClusterName']
        region_name = self.region_name
        role_arn = kwargs['RoleArn']
        username = kwargs['Username']
        groups = kwargs['Groups']

        aws_auth_configmap = self.get_aws_auth_configmap(region_name, cluster_name)
        map_roles = yaml.safe_load(aws_auth_configmap.data['mapRoles'])

        for idx in [i for i, x in enumerate(map_roles) if x['rolearn'] == role_arn]:
            del map_roles[idx]

        map_roles.append({
            'rolearn': role_arn,
            'username': username,
            'groups': groups
        })
        aws_auth_configmap.data['mapRoles'] = yaml.dump(map_roles)
        response = self.patch_aws_auth_configmap(region_name, cluster_name, aws_auth_configmap)
        return {'uid': response.metadata.uid}

    def delete_aws_auth_configmap(self, *args, **kwargs):
        cluster_name = kwargs['ClusterName']
        region_name = self.region_name
        role_arn = kwargs['RoleArn']

        response_data = {'uid': str(uuid4())}
        try:
            aws_auth_configmap = self.get_aws_auth_configmap(region_name, cluster_name)
            map_roles = yaml.safe_load(aws_auth_configmap.data['mapRoles'])

            for idx in [i for i, x in enumerate(map_roles) if x['rolearn'] == role_arn]:
                del map_roles[idx]
            aws_auth_configmap.data['mapRoles'] = yaml.dump(map_roles)
            response = self.patch_aws_auth_configmap(region_name, cluster_name, aws_auth_configmap)
            response_data = {'uid': response.metadata.uid}
        except Exception as e:
            print(f'Exception when calling patch_aws_auth_configmap: {e}\n')
        return response_data

    def get_service_account(self, region_name, cluster_name, service_account, namespace):
        v1 = self.authenticate_eks(region_name, cluster_name)
        try:
            return v1.read_namespaced_service_account(service_account, namespace)
        except ApiException as e:
            print(f'Exception when calling CoreV1Api->read_namespaced_service_account: {e}\n')
            return

    def patch_service_account(self, region_name, cluster_name, service_account, namespace, body):
        v1 = self.authenticate_eks(region_name, cluster_name)
        try:
            response = v1.patch_namespaced_service_account(service_account, namespace, body)
        except ApiException as e:
            print(f'Exception when calling CoreV1Api->patch_namespaced_service_account: {e}\n')
            return

        if self.verbose: print(
            'response: {}'.format(response),
            file=sys.stderr
        )
        return response

    def update_service_account_iam_role(self, *args, **kwargs):
        cluster_name = kwargs['ClusterName']
        region_name = self.region_name
        service_account = kwargs['ServiceAccount']
        namespace = kwargs['Namespace']
        role_arn = kwargs['RoleArn']

        body = self.get_service_account(
            region_name,
            cluster_name,
            service_account,
            namespace
        )

        try:
            body.metadata.annotations['eks.amazonaws.com/role-arn'] = role_arn
        except TypeError:
            body.metadata.annotations = {'eks.amazonaws.com/role-arn': role_arn}

        response = self.patch_service_account(region_name, cluster_name, service_account, namespace, body)
        return {'uid': response.metadata.uid}
