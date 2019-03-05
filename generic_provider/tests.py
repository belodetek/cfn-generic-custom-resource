#!/usr/bin/env python

import os
import unittest.mock
from boto3 import client
from unittest import TestCase
from mock import patch
from uuid import uuid4
from generic_provider import Provider


region = os.getenv('AWS_REGION', 'us-east-1')
account_id = client('sts').get_caller_identity()['Account']


class TestEvent:
    def __init__(self, request, response):
        self.request = request
        self.response = response


class TestProvider(TestCase):

    test_events = [
        # boto3.client('ssm').put_parameter
        TestEvent(
            {
                'RequestType': 'Create',
                'ResponseURL': 'https://cloudformation-custom-resource-response-{}.s3.amazonaws.com/'.format(region),
                'StackId': 'arn:aws:cloudformation:{}:{}:stack/MockStack/{}'.format(
                    region,
                    account_id,
                    str(uuid4())
                ),
                'RequestId': str(uuid4()),
                'ResourceType': 'Custom::MockResource',
                  'LogicalResourceId': 'MockResource',
                  'ResourceProperties': {
                      'AgentType': 'client',
                      'AgentService': 'ssm',
                      'AgentCreateMethod': 'put_parameter',
                      'AgentUpdateMethod': 'put_parameter',
                      'AgentDeleteMethod': 'delete_parameter',
                      'AgentResourceId': 'Name',
                      'AgentCreateArgs': {
                          'Name': '/foo/bar',
                          'Value': 'foo-bar',
                          'Type': 'SecureString',
                          'Overwrite': False
                      },
                      'AgentUpdateArgs': {
                          'Name': '/foo/bar',
                          'Value': 'foo-bar',
                          'Type': 'SecureString',
                          'Overwrite': True
                      },
                      'AgentDeleteArgs': {
                          'Name': '/foo/bar'
                      }
                  }
            },
            {
                'Version': 1,
                'ResponseMetadata': {
                    'RequestId': str(uuid4()),
                    'HTTPStatusCode': 200,
                    'HTTPHeaders': {
                        'x-amzn-requestid': str(uuid4()),
                        'content-type': 'application/x-amz-json-1.1',
                        'content-length': '13',
                        'date': 'Tue, 05 Mar 2019 15:47:45 GMT'
                    },
                    'RetryAttempts': 0
                }
            }
        ),
        # boto3.client('ssm').delete_parameter
        TestEvent(
            {
                'RequestType': 'Delete',
                'ResponseURL': 'https://cloudformation-custom-resource-response-{}.s3.amazonaws.com/'.format(region),
                'StackId': 'arn:aws:cloudformation:{}:{}:stack/MockStack/{}'.format(
                    region,
                    account_id,
                    str(uuid4())
                ),
                'RequestId': str(uuid4()),
                'ResourceType': 'Custom::MockResource',
                  'LogicalResourceId': 'MockResource',
                  'PhysicalResourceId': '/foo/bar',
                  'ResourceProperties': {
                      'AgentType': 'client',
                      'AgentService': 'ssm',
                      'AgentCreateMethod': 'put_parameter',
                      'AgentUpdateMethod': 'put_parameter',
                      'AgentDeleteMethod': 'delete_parameter',
                      'AgentResourceId': 'Name',
                      'AgentCreateArgs': {
                          'Name': '/foo/bar',
                          'Value': 'foo-bar',
                          'Type': 'SecureString',
                          'Overwrite': False
                      },
                      'AgentUpdateArgs': {
                          'Name': '/foo/bar',
                          'Value': 'foo-bar',
                          'Type': 'SecureString',
                          'Overwrite': True
                      },
                      'AgentDeleteArgs': {
                          'Name': '/foo/bar'
                      }
                  }
            },
            {
                'ResponseMetadata': {
                    'RequestId': str(uuid4()),
                    'HTTPStatusCode': 200,
                    'HTTPHeaders': {
                        'x-amzn-requestid': str(uuid4()),
                        'content-type': 'application/x-amz-json-1.1',
                        'content-length': '2', 'date': 'Tue, 05 Mar 2019 17:34:25 GMT'
                    },
                    'RetryAttempts': 0
                }
            }
        )
    ]


    def test_provider(self):
        provider = Provider()
        for test_event in self.test_events:
            with patch.object(Provider, 'get_response', wraps=provider.get_response) as mock:
                provider.get_response.return_value = test_event.response
                self.assertTrue(provider.handle_event(event=test_event.request))
