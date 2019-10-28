#!/usr/bin/env python

import os
import unittest.mock
from boto3 import client
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4
from random import randint
from generic_provider import Provider


region = os.getenv('AWS_REGION', 'us-east-1')
try:
    account_id = client('sts').get_caller_identity()['Account']
except:
    account_id = randint(123456789000, 123456789099)


class TestEvent:
    def __init__(self, typ, request, response):
        self.typ = typ
        self.request = request
        self.response = response


class TestProvider(TestCase):
    response_url = 'https://cloudformation-custom-resource-response-{}.s3.amazonaws.com/'.format(region)

    stack_id = 'arn:aws:cloudformation:{}:{}:stack/MockStack/{}'.format(
        region,
        account_id,
        str(uuid4())
    )

    test_events = [
        # boto3.client('ssm').put_parameter
        TestEvent(
            'client',
            {
                'RequestType': 'Create',
                'ResponseURL': response_url,
                'StackId': stack_id,
                'RequestId': str(uuid4()),
                'ResourceType': 'Custom::MockResource',
                'LogicalResourceId': 'MockResource',
                'ResourceProperties': {
                    'AgentType': 'client',
                    'AgentService': 'ssm',
                    'AgentCreateMethod': 'put_parameter',
                    'AgentResourceId': 'Name',
                    'AgentCreateArgs': {
                        'Name': '/foo/bar',
                        'Value': 'foo-bar',
                        'Type': 'SecureString',
                        'Overwrite': False
                    }
                }
            },
            {
                'Version': 1,
                'ResponseMetadata': {}
            }
        ),
        # boto3.client('ssm').delete_parameter
        TestEvent(
            'client',
            {
                'RequestType': 'Delete',
                'ResponseURL': response_url,
                'StackId': stack_id,
                'RequestId': str(uuid4()),
                'ResourceType': 'Custom::MockResource',
                'LogicalResourceId': 'MockResource',
                'PhysicalResourceId': '/foo/bar',
                'ResourceProperties': {
                    'AgentType': 'client',
                    'AgentService': 'ssm',
                    'AgentDeleteMethod': 'delete_parameter',
                    'AgentResourceId': 'Name',
                    'AgentDeleteArgs': {
                        'Name': '/foo/bar'
                    }
                }
            },
            {
                'ResponseMetadata': {}
            }
        ),
        # boto3.resource('ec2').Instance('i-abcedf1234567890')
        TestEvent(
            'resource',
            {
                'RequestType': 'Create',
                'ResponseURL': response_url,
                'StackId': stack_id,
                'RequestId': str(uuid4()),
                'ResourceType': 'Custom::MockResource',
                'LogicalResourceId': 'MockResource',
                'ResourceProperties': {
                    'AgentService': 'ec2',
                    'AgentType': 'resource',
                    'AgentWaitQueryExpr': '$..Ipv6Address',
                    'AgentResourceId': 'Ipv6Address',
                    'AgentCreateMethod': 'network_interfaces_attribute',
                    'AgentCreateArgs': {
                        'ResourceName': 'Instance',
                        'ResourceId': 'i-abcedf1234567890'
                    }
                }
            },
            [{
                'Ipv6Addresses': [{
                    'Ipv6Address': 'fdd7:874:8e55:4500:ffff:ffff:ffff:ffff'
                }]
            }]
        )
    ]


    def test_provider(self):
        provider = Provider()
        for test_event in self.test_events:
            if test_event.typ == 'client':
                with patch.object(Provider, 'get_response', wraps=provider.get_response) as mock:
                    provider.get_response.return_value = test_event.response
                    self.assertTrue(provider.handle_event(event=test_event.request))

            if test_event.typ == 'resource':
                with patch.object(Provider, 'get_resource', wraps=provider.get_resource) as mock:
                    provider.get_resource.return_value = test_event.response
                    self.assertTrue(provider.handle_event(event=test_event.request))
