#!/usr/bin/env python

import cfnresponse
import botocore
import boto3
import json
import os
import sys

from ast import literal_eval
from uuid import uuid4
from jsonpath import jsonpath
from time import sleep
from traceback import print_exc
from retrying import retry


class Provider:
    def __init__(self):
        self.default_wait_secs = 5
        self.verbose = bool(int(os.getenv('VERBOSE', 0)))
        self.profile = os.getenv('AWS_PROFILE')

        try:
            self.region = os.getenv('AWS_DEFAULT_REGION')
            assert self.region
        except:
            try:
                self.region = os.getenv('AWS_REGION')
                assert self.region
            except:
                self.region = 'us-east-1'

        self.session = boto3.session.Session()
        boto3.setup_default_session()
        if self.profile:
            print(
                'profile={} region={}'.format(
                    self.profile,
                    self.region
                ),
                file=sys.stderr
            )
            self.session = boto3.session.Session(profile_name=self.profile)
            boto3.setup_default_session(profile_name=self.profile)


    def get_response(self, agent_attr, **agent_kwargs):
        # TBC: better way to differentiate between resources and clients
        if 'ResourceName' in agent_kwargs and 'ResourceId' in agent_kwargs:
            return agent_attr(agent_kwargs['ResourceId'])
        else:
            return agent_attr(**agent_kwargs)


    def get_resource(self, resource, expr):
        return eval(expr)


    def wait_event(self, agent, event, resource=None, create=False, update=False, delete=False):
        resource_key = 'ResourceProperties'
        try:
            no_echo = event[resource_key]['NoEcho'].lower()
        except:
            no_echo = 'false'
        if update:
            try:
                agent_query_value = event[resource_key]['AgentWaitUpdateQueryValues']
            except:
                agent_query_value = None
            try:
                agent_exceptions = []
                for ex in event[resource_key]['AgentWaitUpdateExceptions']:
                    agent_exceptions.append(eval(ex))
            except:
                agent_exceptions = None
        if create:
            try:
                agent_query_value = event[resource_key]['AgentWaitCreateQueryValues']
            except:
                agent_query_value = None
            try:
                agent_exceptions = []
                for ex in event[resource_key]['AgentWaitCreateExceptions']:
                    agent_exceptions.append(eval(ex))
            except:
                agent_exceptions = None
        if delete:
            try:
                agent_query_value = event[resource_key]['AgentWaitDeleteQueryValues']
            except:
                agent_query_value = None
            try:
                agent_exceptions = []
                for ex in event[resource_key]['AgentWaitDeleteExceptions']:
                    agent_exceptions.append(eval(ex))
            except:
                agent_exceptions = None
        try:
            agent_kwargs = json.loads(event[resource_key]['AgentWaitArgs'])
        except:
            try:
                agent_kwargs = event[resource_key]['AgentWaitArgs']
            except:
                agent_kwargs = {}
        try:
            agent_resource_id = event[resource_key]['AgentWaitResourceId']
        except:
            agent_resource_id = None
        if agent_resource_id:
            try:
                agent_kwargs[agent_resource_id] = resource[agent_resource_id]
            except:
                try:
                    if type(agent_resource_id) == list:
                        agent_kwargs[agent_resource_id[0]] = [event['PhysicalResourceId']]
                        assert agent_kwargs[agent_resource_id[0]]
                    else:
                        agent_kwargs[agent_resource_id] = event['PhysicalResourceId']
                        assert agent_kwargs[agent_resource_id]
                except:
                    try:
                        agent_kwargs[agent_resource_id] = event[resource_key]['AgentWaitArgs'][agent_resource_id]
                    except:
                        pass
        try:
            agent_method = event[resource_key]['AgentWaitMethod']
        except:
            agent_method = None
        try:
            agent_wait_delay = int(event[resource_key]['AgentWaitDelay'])
        except:
            agent_wait_delay = 0
        try:
            agent_query_expr = event[resource_key]['AgentWaitQueryExpr']
        except:
            agent_query_expr = None
        try:
            assert agent_method in getattr(agent, 'waiter_names')
            waiter = getattr(agent, 'get_waiter')(agent_method)
            agent_attr = None
        except:
            if self.verbose: print_exc()
            waiter = None
            try:
                agent_attr = getattr(agent, agent_method)
            except:
                if self.verbose: print_exc()
                agent_attr = None

        if no_echo == 'false':
            print(
                'agent_method={}, agent_kwargs={}, agent_attr={} agent_resource_id={} agent_exceptions={} agent_wait_delay={}'.format(
                    agent_method,
                    agent_kwargs,
                    agent_attr,
                    agent_resource_id,
                    agent_exceptions,
                    agent_wait_delay
                ),
                file=sys.stderr
            )

        if waiter:
            if agent_exceptions:
                try:
                    waiter.wait(**agent_kwargs)
                except tuple(agent_exceptions) as e:
                    print(
                        'passing exception={}'.format(
                            repr(e)
                        ),
                        file=sys.stderr
                    )
                    if self.verbose: print_exc()
            else:
                waiter.wait(**agent_kwargs)
                return

        if agent_attr and agent_query_expr and agent_query_value is not None:
            response = {}
            match = None
            sleep(agent_wait_delay)
            while True:
                if agent_exceptions:
                    try:
                        response = self.get_response(agent_attr, **agent_kwargs)
                    except tuple(agent_exceptions) as e:
                        print(
                            'passing exception={}'.format(
                                repr(e)
                            ),
                            file=sys.stderr
                        )
                        if self.verbose: print_exc()
                else:
                    response = self.get_response(agent_attr, **agent_kwargs)

                match = jsonpath(response, agent_query_expr)
                if no_echo == 'false':
                    print(
                        'agent_query_expr={} agent_query_value={} match={} create={} update={} delete={}'.format(
                            agent_query_expr,
                            agent_query_value,
                            match,
                            create,
                            update,
                            delete
                        ),
                        file=sys.stderr
                    )
                if match is not None and response and (match == agent_query_value or not match): break
                sleep(self.default_wait_secs)


    @retry(wait_exponential_multiplier=1000, wait_exponential_max=10000, stop_max_delay=30000)
    def handle_client_event(self, agent, event, create=False, update=False, delete=False):
        resource_key = 'ResourceProperties'
        args_key = 'AgentCreateArgs'
        method_key = 'AgentCreateMethod'
        exceptions_key = 'AgentCreateExceptions'
        if update:
            args_key = 'AgentUpdateArgs'
            method_key = 'AgentUpdateMethod'
            exceptions_key = 'AgentUpdateExceptions'
        if delete:
            args_key = 'AgentDeleteArgs'
            method_key = 'AgentDeleteMethod'
            exceptions_key = 'AgentDeleteExceptions'
        try:
            no_echo = event[resource_key]['NoEcho'].lower()
        except:
            no_echo = 'false'
        try:
            agent_kwargs = json.loads(event[resource_key][args_key])
        except:
            try:
                agent_kwargs = literal_eval(event[resource_key][args_key])
                assert type(agent_kwargs) == type(dict())
            except:
                try:
                    agent_kwargs = event[resource_key][args_key]
                except:
                    agent_kwargs = {}
        try:
            agent_response_node = event[resource_key]['AgentResponseNode']
        except:
            agent_response_node = None
        try:
            agent_resource_id = event[resource_key]['AgentResourceId']
        except:
            agent_resource_id = None
        if agent_resource_id and not create:
            try:
                agent_kwargs[agent_resource_id] = event['PhysicalResourceId']
            except:
                try:
                    agent_kwargs[agent_resource_id] = event[resource_key][args_key][agent_resource_id]
                except:
                    pass
        try:
            agent_query_expr = event[resource_key]['AgentWaitQueryExpr']
        except:
            agent_query_expr = None
        try:
            agent_exceptions = []
            for ex in event[resource_key][exceptions_key]:
                agent_exceptions.append(eval(ex))
        except:
            if self.verbose: print_exc()
            agent_exceptions = None
        try:
            agent_method = event[resource_key][method_key]
        except:
            agent_method = None
        try:
            agent_attr = getattr(agent, agent_method)
        except:
            if self.verbose: print_exc()
            agent_attr = None
        if agent_attr:
            response = {}
            if no_echo == 'false':
                print(
                    'agent_method={}, agent_kwargs={}, agent_attr={} agent_resource_id={} agent_exceptions={} agent_response_node={}'.format(
                        agent_method,
                        agent_kwargs,
                        agent_attr,
                        agent_resource_id,
                        agent_exceptions,
                        agent_response_node
                    ),
                    file=sys.stderr
                )
            if agent_exceptions:
                try:
                    response = self.get_response(agent_attr, **agent_kwargs)
                except tuple(agent_exceptions) as e:
                    print(
                        'passing exception={}'.format(
                            repr(e)
                        ),
                        file=sys.stderr
                    )
                    if self.verbose: print_exc()
            else:
                response = self.get_response(agent_attr, **agent_kwargs)
            if no_echo == 'false':
                print(
                    'response={} create={} update={} delete={}'.format(
                        response,
                        create,
                        update,
                        delete
                    ),
                    file=sys.stderr
                )

            # wait
            self.wait_event(
                agent,
                event,
                resource=response,
                create=create,
                update=update,
                delete=delete
            )

            try:
                responseData = jsonpath(response, agent_response_node)[0]
                assert responseData, 'responseData from jsonpath(response, agent_response_node)'
            except:
                if self.verbose: print_exc()
                try:
                    responseData = response
                    assert responseData
                except:
                    if self.verbose: print_exc()
                    responseData = {}
            try:
                PhysicalResourceId = responseData[agent_resource_id]
                assert PhysicalResourceId, 'PhysicalResourceId from responseData[agent_resource_id]'
            except:
                if self.verbose: print_exc()
                try:
                    PhysicalResourceId = jsonpath(responseData, agent_query_expr)[0]
                    assert PhysicalResourceId, 'PhysicalResourceId from jsonpath(response, agent_query_expr)'
                except:
                    if self.verbose: print_exc()
                    try:
                        PhysicalResourceId = jsonpath(responseData, agent_resource_id)[0]
                        assert PhysicalResourceId, 'PhysicalResourceId from jsonpath(response, agent_resource_id)'
                    except:
                        if self.verbose: print_exc()
                        try:
                            PhysicalResourceId = agent_kwargs[agent_resource_id]
                            assert PhysicalResourceId, 'PhysicalResourceId from event[resource_key][args_key][agent_resource_id]'
                        except:
                            if self.verbose: print_exc()
                            PhysicalResourceId = str(uuid4())
            if create:
                if no_echo == 'false':
                    print(
                        'PhysicalResourceId={} responseData={}'.format(
                            PhysicalResourceId,
                            responseData
                        ),
                        file=sys.stderr
                    )
                return (PhysicalResourceId, responseData)
            else:
                print(
                    'PhysicalResourceId={} responseData={}'.format(
                        event['PhysicalResourceId'],
                        responseData
                    ),
                    file=sys.stderr
                )
                return responseData
        return {}


    @retry(wait_exponential_multiplier=1000, wait_exponential_max=10000, stop_max_delay=30000)
    def handle_resource_event(self, agent, event):
        PhysicalResourceId = str(uuid4())
        responseData = {}
        resource_key = 'ResourceProperties'
        try:
            no_echo = event[resource_key]['NoEcho'].lower()
        except:
            no_echo = 'false'
        try:
            agent_property = event[resource_key]['AgentCreateMethod']
        except:
            agent_property = None
        try:
            agent_resource_id = event[resource_key]['AgentResourceId']
        except:
            agent_resource_id = None
        try:
            agent_kwargs = json.loads(event[resource_key]['AgentCreateArgs'])
        except:
            try:
                agent_kwargs = literal_eval(event[resource_key]['AgentCreateArgs'])
                assert type(agent_kwargs) == type(dict())
            except:
                try:
                    agent_kwargs = event[resource_key]['AgentCreateArgs']
                except:
                    agent_kwargs = {}
        try:
            agent_query_expr = event[resource_key]['AgentWaitQueryExpr']
        except:
            agent_query_expr = None
        try:
            agent_attr = getattr(agent, agent_kwargs['ResourceName'])
        except:
            if self.verbose: print_exc()
            agent_attr = None

        if no_echo == 'false':
            print(
                'agent_kwargs={}, agent_query_expr={}, agent_attr={} agent_resource_id={} agent_property={}'.format(
                    agent_kwargs,
                    agent_query_expr,
                    agent_attr,
                    agent_resource_id,
                    agent_property
                ),
                file=sys.stderr
            )
        assert agent_attr and agent_resource_id and agent_query_expr and agent_property
        resource = self.get_response(agent_attr, **agent_kwargs)
        if agent_property in dir(resource):
            response = self.get_resource(
                resource,
                'resource.{}'.format(agent_property)
            )
        match = jsonpath(response, agent_query_expr)
        if no_echo == 'false': print(
            'response={} match={}'.format(
                response,
                match
            ),
            file=sys.stderr
        )
        try:
            assert match
            responseData[agent_resource_id] = ','.join(match)
        except:
            pass
        return (PhysicalResourceId, responseData)


    def handle_event(self, event=None, context=None):
        try:
            no_echo = event['ResourceProperties']['NoEcho'].lower()
        except:
            no_echo = 'false'
        if no_echo == 'true':
            no_echo = True
        elif no_echo == 'false':
            no_echo = False
        else:
            no_echo = False
        try:
            if not no_echo: print(
                'event: {}, context: {}'.format(
                    json.dumps(event),
                    context
                ),
                file=sys.stderr
            )
        except:
            pass

        kwargs = {}
        try:
            kwargs['region_name'] = event['ResourceProperties']['AgentRegion']
        except:
            kwargs['region_name'] = self.region

        try:
            RoleArn = event['ResourceProperties']['RoleArn']
            client = boto3.client('sts', region_name=self.region)
            response = client.assume_role(
                RoleArn=RoleArn,
                RoleSessionName=str(uuid4())
            )
            if not no_echo: print(
                'response={}'.format(response),
                file=sys.stderr
            )
            kwargs['aws_access_key_id'] = response['Credentials']['AccessKeyId']
            kwargs['aws_secret_access_key'] = response['Credentials']['SecretAccessKey']
            kwargs['aws_session_token'] = response['Credentials']['SessionToken']
            if not no_echo: print(
                'get_caller_identity={}'.format(
                    client.get_caller_identity()
                ),
                file=sys.stderr
            )
        except Exception as e:
            if self.verbose: print_exc()
            if not self.profile:
                kwargs['aws_access_key_id'] = os.getenv('AWS_ACCESS_KEY_ID')
                kwargs['aws_secret_access_key'] = os.getenv('AWS_SECRET_ACCESS_KEY')
                kwargs['aws_session_token'] = os.getenv('AWS_SESSION_TOKEN')

        if not no_echo: print('kwargs={}'.format(kwargs), file=sys.stderr)

        responseData = {}

        try:
            agent_service = event['ResourceProperties']['AgentService']
            try:
                agent_type = event['ResourceProperties']['AgentType']
            except:
                agent_type = 'client'
            StackId = event['StackId']
            ResponseURL = event['ResponseURL']
            RequestType = event['RequestType']
            ResourceType = event['ResourceType']
            RequestId = event['RequestId']
            LogicalResourceId = event['LogicalResourceId']
            CreateFailedResourceId = '{}-CREATE_FAILED'.format(LogicalResourceId)
            if agent_type == 'client':
                agent = self.session.client(agent_service, **kwargs)
            if agent_type == 'resource':
                try:
                    agent = self.session.resource(agent_service, **kwargs)
                    (physicalResourceId, responseData) = self.handle_resource_event(
                        agent,
                        event
                    )
                    assert physicalResourceId and responseData
                    cfnresponse.send(
                        event,
                        context,
                        cfnresponse.SUCCESS,
                        responseData=responseData[0] if type(responseData) == list else responseData,
                        physicalResourceId=physicalResourceId,
                        noEcho=no_echo
                    )
                    return True
                except Exception as e:
                    if self.verbose: print_exc()
                    cfnresponse.send(
                        event,
                        context,
                        cfnresponse.FAILED,
                        noEcho=no_echo,
                        reason=str(e)
                    )
                return False
            if agent_type == 'custom':
                from importlib import import_module
                agent_module = import_module(agent_service)
                agent = getattr(agent_module, agent_service.upper())(**kwargs)
        except Exception as e:
            if self.verbose: print_exc()
            cfnresponse.send(
                event,
                context,
                cfnresponse.FAILED,
                noEcho=no_echo,
                reason=str(e)
            )
            return False


        ''' Update: runs only if AgentUpdateMethod is present otherwise the old
            resource is deleted and a new one is created. No backups are taken,
            possible loss of data.'''
        if RequestType == 'Update':
            try:
                responseData = self.handle_client_event(
                    agent,
                    event,
                    update=True
                )
                if responseData:
                    cfnresponse.send(
                        event,
                        context,
                        cfnresponse.SUCCESS,
                        responseData=responseData[0] if type(responseData) == list else responseData,
                        physicalResourceId=event['PhysicalResourceId'],
                        noEcho=no_echo
                    )
                    return True
            except Exception as e:
                if self.verbose: print_exc()
                cfnresponse.send(
                    event,
                    context,
                    cfnresponse.FAILED,
                    noEcho=no_echo,
                    reason=str(e)
                )
                return False


        ''' Delete: runs if AgentDeleteMethod is present. Returns immediatly after
            completion if RequestType == 'Delete' or continues to (re)reate the
            resource.'''
        if RequestType in ['Update', 'Delete']:
            try:
                if event['PhysicalResourceId'] != CreateFailedResourceId:
                    responseData = self.handle_client_event(
                        agent,
                        event,
                        delete=True
                    )
                else:
                    responseData = {}
                if RequestType == 'Delete':
                    cfnresponse.send(
                        event,
                        context,
                        cfnresponse.SUCCESS,
                        responseData=responseData[0] if type(responseData) == list else responseData,
                        physicalResourceId=event['PhysicalResourceId'],
                        noEcho=no_echo
                    )
                    return True
                event['ResourceProperties'].pop('AgentResourceId', None)
            except Exception as e:
                if self.verbose: print_exc()
                cfnresponse.send(
                    event,
                    context,
                    cfnresponse.FAILED,
                    noEcho=no_echo,
                    reason=str(e)
                )
                return False


        ''' Create: (re)creates a resource and returns PhysicalResourceId based on
            the specified AgentResourceId.'''
        try:
            (PhysicalResourceId, responseData) = self.handle_client_event(
                agent,
                event,
                create=True
            )
            cfnresponse.send(
                event,
                context,
                cfnresponse.SUCCESS,
                responseData=responseData[0] if type(responseData) == list else responseData,
                physicalResourceId=PhysicalResourceId,
                noEcho=no_echo
            )
            return True
        except Exception as e:
            if self.verbose: print_exc()
            cfnresponse.send(
                event,
                context,
                cfnresponse.FAILED,
                noEcho=no_echo,
                physicalResourceId=CreateFailedResourceId,
                reason=str(e)
            )
            return False


def lambda_handler(event=None, context=None):
    provider = Provider()
    return provider.handle_event(event=event, context=context)


if __name__ == '__main__':
    try:
        event = json.loads(sys.argv[1])
    except:
        try:
            event = json.loads(sys.stdin.read())
        except:
            sys.exit(1)
    lambda_handler(event=event)
