#!/usr/bin/env python

import boto3
import json
import os, sys
from uuid import uuid4


class IAM:

    def __init__(self, *args, **kwargs):
        self.verbose = bool(int(os.getenv('VERBOSE', 0)))
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )
        self.session = boto3.session.Session(**kwargs)
        self.region_name = kwargs['region_name']

    def delete_iam_role_trust_policy(self, *args, **kwargs):
        client = self.session.client('iam')
        role_name = kwargs['RoleName']
        statement = kwargs['Statement']
        response = client.get_role(RoleName=role_name)
        if self.verbose: print(
            'response: {}'.format(response),
            file=sys.stderr
        )

        response_data = {'RequestId': str(uuid4())}
        try:
            trust_policy = response['Role']['AssumeRolePolicyDocument']
            for idx in [i for i, x in enumerate(trust_policy['Statement']) if x == statement]:
                del trust_policy['Statement'][idx]

            response = client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(trust_policy)
            )

            if self.verbose: print(
                'response: {}'.format(response),
                file=sys.stderr
            )
            response_data = {'RequestId': response['ResponseMetadata']['RequestId']}
        except Exception as e:
            print(f'Exception when calling update_assume_role_policy: {e}\n')
        return response_data

    def append_iam_role_trust_policy(self, *args, **kwargs):
        client = self.session.client('iam')
        role_name = kwargs['RoleName']
        statement = kwargs['Statement']
        response = client.get_role(RoleName=role_name)
        if self.verbose: print(
            'response: {}'.format(response),
            file=sys.stderr
        )

        trust_policy = response['Role']['AssumeRolePolicyDocument']
        for idx in [i for i, x in enumerate(trust_policy['Statement']) if x == statement]:
            return {'RequestId': response['ResponseMetadata']['RequestId']}

        trust_policy['Statement'].append(statement)
        response = client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(trust_policy)
        )

        if self.verbose: print(
            'response: {}'.format(response),
            file=sys.stderr
        )
        return {'RequestId': response['ResponseMetadata']['RequestId']}
