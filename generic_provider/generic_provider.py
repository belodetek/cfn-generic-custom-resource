#!/usr/bin/env python

import cfnresponse
import botocore
import boto3
import json
import os
import sys

from uuid import uuid4
from jsonpath import jsonpath
from time import sleep
from traceback import print_exc
from retrying import retry


default_wait = 5    # seconds
region = os.getenv('AWS_REGION')
profile = os.getenv('AWS_PROFILE')

session = boto3.session.Session()
boto3.setup_default_session()
if profile:
    print('profile={} region={}'.format(profile, region))
    session = boto3.session.Session(profile_name=profile)
    boto3.setup_default_session(profile_name=profile)


def wait_event(agent, event, create=False, update=False, delete=False):
    resource_key = 'ResourceProperties'
    try:
        no_echo = event[resource_key]['NoEcho'].lower()
    except:
        no_echo = 'false'
    if update:
        resource_key = 'OldResourceProperties'
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
        agent_query_expr = event[resource_key]['AgentWaitQueryExpr']
    except:
        agent_query_expr = None
    try:
        assert agent_method in getattr(agent, 'waiter_names')
        waiter = getattr(agent, 'get_waiter')(agent_method)
        agent_attr = None
    except:
        print_exc()
        waiter = None
        try:
            agent_attr = getattr(agent, agent_method)
        except:
            print_exc()
            agent_attr = None

    if no_echo == 'false':
        print('agent_method={}, agent_kwargs={}, agent_attr={} agent_resource_id={} agent_exceptions={}'.format(
            agent_method, agent_kwargs, agent_attr, agent_resource_id, agent_exceptions
        ))

    if waiter:
        if agent_exceptions:
            try:
                waiter.wait(**agent_kwargs)
            except tuple(agent_exceptions) as e:
                print('passing exception={}'.format(repr(e)))
                print_exc()
        else:
            waiter.wait(**agent_kwargs)
            return

    if agent_attr and agent_query_expr and agent_query_value is not None:
        response = {}
        match = None
        while True:
            if agent_exceptions:
                try:
                    response = agent_attr(**agent_kwargs)
                except tuple(agent_exceptions) as e:
                    print('passing exception={}'.format(repr(e)))
                    print_exc()
            else:
                response = agent_attr(**agent_kwargs)
            
            match = jsonpath(response, agent_query_expr)
            if no_echo == 'false':
                print('agent_query_expr={} agent_query_value={} match={} create={} update={} delete={}'.format(
                    agent_query_expr,
                    agent_query_value,
                    match,
                    create,
                    update,
                    delete
                ))
            if match is not None and response and (match == agent_query_value or not match): break
            sleep(default_wait)


@retry(wait_exponential_multiplier=1000, wait_exponential_max=10000, stop_max_delay=30000)
def handle_client_event(agent, event, create=False, update=False, delete=False):
    resource_key = 'ResourceProperties'
    args_key = 'AgentCreateArgs'
    method_key = 'AgentCreateMethod'
    exceptions_key = 'AgentCreateExceptions'
    if update:
        resource_key = 'OldResourceProperties'
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
            agent_kwargs = event[resource_key][args_key]
        except:
            agent_kwargs = {}
    try:
        agent_resource_id = event[resource_key]['AgentResourceId']
    except:
        agent_resource_id = None
    if agent_resource_id:
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
        print_exc()
        agent_exceptions = None
    try:
        agent_method = event[resource_key][method_key]
    except:
        agent_method = None
    try:
        agent_attr = getattr(agent, agent_method)
    except:
        print_exc()
        agent_attr = None
    if agent_attr:
        response = {}
        if no_echo == 'false':
            print('agent_method={}, agent_kwargs={}, agent_attr={} agent_resource_id={} agent_exceptions={}'.format(
                agent_method, agent_kwargs, agent_attr, agent_resource_id, agent_exceptions
            ))
        if agent_exceptions:
            try:
                response = agent_attr(**agent_kwargs)
            except tuple(agent_exceptions) as e:
                print('passing exception={}'.format(repr(e)))
                print_exc()
        else:
            response = agent_attr(**agent_kwargs)
        if no_echo == 'false':
            print('response={} create={} update={} delete={}'.format(
                response,
                create,
                update,
                delete
            ))
        wait_event(agent, event, create=create, update=update, delete=delete)
        try:
            responseData = response
        except:
            responseData = {}
        try:
            PhysicalResourceId = response[agent_resource_id]
        except:
            try:
                PhysicalResourceId = jsonpath(response, agent_query_expr)
                assert PhysicalResourceId
                PhysicalResourceId = ','.join(PhysicalResourceId)
            except:
                try:
                    PhysicalResourceId = event[resource_key][args_key][agent_resource_id]
                    assert PhysicalResourceId
                except:
                    PhysicalResourceId = str(uuid4())
        if create:
            if no_echo == 'false':
                print('PhysicalResourceId={} responseData={}'.format(
                    PhysicalResourceId,
                    responseData
                ))
            return (PhysicalResourceId, responseData)
        else:
            print('PhysicalResourceId={} responseData={}'.format(
                event['PhysicalResourceId'],
                responseData
            ))
            return responseData
    return {}


@retry(wait_exponential_multiplier=1000, wait_exponential_max=10000, stop_max_delay=30000)
def handle_resource_event(agent, event):
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
        print_exc()
        agent_attr = None

    if no_echo == 'false':
        print('agent_kwargs={}, agent_query_expr={}, agent_attr={} agent_resource_id={} agent_property={}'.format(
            agent_kwargs, agent_query_expr, agent_attr, agent_resource_id, agent_property
        ))
    assert agent_attr and agent_resource_id and agent_query_expr and agent_property
    resource = agent_attr(agent_kwargs['ResourceId'])
    if agent_property in dir(resource):
        response = eval('resource.{}'.format(agent_property))
    match = jsonpath(response, agent_query_expr)
    if no_echo == 'false': print('response={} match={}'.format(response, match))
    try:
        assert match
        responseData[agent_resource_id] = ','.join(match)
    except:
        pass
    return (PhysicalResourceId, responseData)


def lambda_handler(event=None, context=None):
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
        if not no_echo: print('event: {}, context: {}'.format(json.dumps(event), context))
    except:
        pass

    kwargs = {}
    try:
        kwargs['region_name'] = event['ResourceProperties']['AgentRegion']
    except:
        kwargs['region_name'] = region

    try:
        RoleArn = event['ResourceProperties']['RoleArn']
        client = boto3.client('sts', region_name=region)
        response = client.assume_role(
            RoleArn=RoleArn,
            RoleSessionName=str(uuid4())
        )
        if not no_echo: print('response={}'.format(response))
        kwargs['aws_access_key_id'] = response['Credentials']['AccessKeyId']
        kwargs['aws_secret_access_key'] = response['Credentials']['SecretAccessKey']
        kwargs['aws_session_token'] = response['Credentials']['SessionToken']
        if not no_echo: print('get_caller_identity={}'.format(client.get_caller_identity()))
    except:
        if not profile:
            kwargs['aws_access_key_id'] = os.getenv('AWS_ACCESS_KEY_ID')
            kwargs['aws_secret_access_key'] = os.getenv('AWS_SECRET_ACCESS_KEY')
            kwargs['aws_session_token'] = os.getenv('AWS_SESSION_TOKEN')

    if not no_echo: print('kwargs={}'.format(kwargs))

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
        if agent_type == 'client':
            agent = session.client(agent_service, **kwargs)
        if agent_type == 'resource':
            try:
                agent = session.resource(agent_service, **kwargs)
                (physicalResourceId, responseData) = handle_resource_event(agent, event)
                assert physicalResourceId and responseData
                cfnresponse.send(
                    event,
                    context,
                    cfnresponse.SUCCESS,
                    responseData=responseData,
                    physicalResourceId=physicalResourceId,
                    noEcho=no_echo
                )
            except:
                print_exc()
                cfnresponse.send(event, context, cfnresponse.FAILED, noEcho=no_echo)
            return
    except:
        print_exc()
        cfnresponse.send(event, context,cfnresponse.FAILED, noEcho=no_echo)
        return


    ''' Update: runs only if AgentUpdateMethod is present otherwise the old resource is
        deleted and a new one is created. No backups are taken, possible loss of data.'''
    if RequestType == 'Update':
        try:
            responseData = handle_client_event(agent, event, update=True)
            if responseData:
                cfnresponse.send(
                    event,
                    context,
                    cfnresponse.SUCCESS,
                    responseData=responseData,
                    physicalResourceId=event['PhysicalResourceId'],
                    noEcho=no_echo
                )
                return
        except:
            print_exc()
            cfnresponse.send(event, context, cfnresponse.FAILED, noEcho=no_echo)
            return


    ''' Delete: runs if AgentDeleteMethod is present. Returns immediatly after completion
        if RequestType == 'Delete' or continues to (re)reate resource.'''
    if RequestType in ['Update', 'Delete']:
        try:
            responseData = handle_client_event(agent, event, delete=True)
            if RequestType == 'Delete':
                cfnresponse.send(
                    event,
                    context,
                    cfnresponse.SUCCESS,
                    responseData=responseData,
                    physicalResourceId=event['PhysicalResourceId'],
                    noEcho=no_echo
                )
                return
            event['ResourceProperties'].pop('AgentResourceId', None)
        except:
            print_exc()
            cfnresponse.send(event, context, cfnresponse.FAILED, noEcho=no_echo)
            return


    ''' Create: (re)creates a resource and returns PhysicalResourceId based on
        the specified AgentResourceId.'''
    try:
        (PhysicalResourceId, responseData) = handle_client_event(agent, event, create=True)
        cfnresponse.send(
            event,
            context,
            cfnresponse.SUCCESS,
            responseData=responseData,
            physicalResourceId=PhysicalResourceId,
            noEcho=no_echo
        )
        return
    except:
        print_exc()
        cfnresponse.send(event, context, cfnresponse.FAILED, noEcho=no_echo)
        return


if __name__ == '__main__':
    try:
        event = json.loads(sys.argv[1])
    except:
        try:
            event = json.loads(sys.stdin.read())
        except:
            sys.exit(1)
    lambda_handler(event=event)
