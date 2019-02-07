#!/usr/bin/env python

import cfnresponse
import boto3
import json
import os
import sys
from uuid import uuid4
from jsonpath import jsonpath
from time import sleep
from traceback import print_exc


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
    if update:
        resource_key = 'OldResourceProperties'
        try:
            agent_query_value = event[resource_key]['AgentWaitUpdateQueryValues']
        except:
            agent_query_value = None
    if create:
        try:
            agent_query_value = event[resource_key]['AgentWaitCreateQueryValues']
        except:
            agent_query_value = None
    if delete:
        try:
            agent_query_value = event[resource_key]['AgentWaitDeleteQueryValues']
        except:
            agent_query_value = None
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
        waiter = None
        try:
            agent_attr = getattr(agent, agent_method)
        except:
            agent_attr = None

    print('agent_method={}, agent_kwargs={}, agent_attr={} agent_resource_id={}'.format(
        agent_method, agent_kwargs, agent_attr, agent_resource_id
    ))

    if waiter:
        waiter.wait(**agent_kwargs)

    if agent_attr and agent_query_expr and agent_query_value is not None:
        response = {}
        match = None
        while True:
            response = agent_attr(**agent_kwargs)
            match = jsonpath(response, agent_query_expr)
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


def handle_event(agent, event, create=False, update=False, delete=False):
    resource_key = 'ResourceProperties'
    args_key = 'AgentCreateArgs'
    method_key = 'AgentCreateMethod'
    if update:
        resource_key = 'OldResourceProperties'
        args_key = 'AgentUpdateArgs'
        method_key = 'AgentUpdateMethod'
    if delete:
        args_key = 'AgentDeleteArgs'
        method_key = 'AgentDeleteMethod'
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
        agent_method = event[resource_key][method_key]
    except:
        agent_method = None
    try:
        agent_attr = getattr(agent, agent_method)
    except:
        print_exc()
        agent_attr = None
    if agent_attr:
        print('agent_method={}, agent_kwargs={}, agent_attr={} agent_resource_id={}'.format(
            agent_method, agent_kwargs, agent_attr, agent_resource_id
        ))
        response = agent_attr(**agent_kwargs)
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
                PhysicalResourceId = jsonpath(response, '$..{}'.format(agent_resource_id))
                assert PhysicalResourceId
                PhysicalResourceId = ''.join(PhysicalResourceId)
            except:
                try:
                    PhysicalResourceId = event[resource_key][args_key][agent_resource_id]
                    assert PhysicalResourceId
                except:
                    PhysicalResourceId = str(uuid4())
        if create:
            print(
                'PhysicalResourceId={} responseData={}'.format(
                    PhysicalResourceId,
                    responseData
                )
            )
            return (PhysicalResourceId, responseData)
        else:
            print(
                'PhysicalResourceId={} responseData={}'.format(
                    event['PhysicalResourceId'],
                    responseData
                )
            )
            return responseData


def lambda_handler(event=None, context=None):
    try:
        print('event: {}, context: {}'.format(json.dumps(event), context))
    except:
        pass

    kwargs = {}
    kwargs['region_name'] = region

    try:
        RoleArn = event['ResourceProperties']['RoleArn']
        client = boto3.client('sts', region_name=region)
        response = client.assume_role(
            RoleArn=RoleArn,
            RoleSessionName=str(uuid4())
        )
        kwargs['aws_access_key_id'] = response['Credentials']['AccessKeyId'],
        kwargs['aws_secret_access_key'] = response['Credentials']['SecretAccessKey'],
        kwargs['aws_session_token'] = response['Credentials']['SessionToken']
        print(client.get_caller_identity())
    except:
        if not profile:
            kwargs['aws_access_key_id'] = os.getenv('AWS_ACCESS_KEY_ID')
            kwargs['aws_secret_access_key'] = os.getenv('AWS_SECRET_ACCESS_KEY')
            kwargs['aws_session_token'] = os.getenv('AWS_SESSION_TOKEN')

    responseData = {}

    try:
        agent_service = event['ResourceProperties']['AgentService']
        agent_type = event['ResourceProperties']['AgentType']
        StackId = event['StackId']
        ResponseURL = event['ResponseURL']
        RequestType = event['RequestType']
        ResourceType = event['ResourceType']
        RequestId = event['RequestId']
        LogicalResourceId = event['LogicalResourceId']
        if agent_type == 'client': agent = session.client(agent_service, **kwargs)
        if agent_type == 'resource': agent = session.resource(agent_service, **kwargs)
    except:
        print_exc()
        cfnresponse.send(
            event,
            context,
            cfnresponse.FAILED
        )
        return


    ''' Update: runs only if AgentUpdateMethod is present otherwise the old resource is
        deleted and a new one is created. No backups are taken, possible loss of data.'''
    if RequestType == 'Update':
        try:
            responseData = handle_event(agent, event, update=True)
            if responseData:
                cfnresponse.send(
                    event,
                    context,
                    cfnresponse.SUCCESS,
                    responseData=responseData,
                    physicalResourceId=event['PhysicalResourceId']
                )
                return
        except:
            print_exc()
            cfnresponse.send(
                event,
                context,
                cfnresponse.FAILED
            )
            return


    ''' Delete: runs if AgentDeleteMethod is present. Returns immediatly after completion
        if RequestType == 'Delete' or continues to (re)reate resource.'''
    if RequestType in ['Update', 'Delete']:
        try:
            responseData = handle_event(agent, event, delete=True)
            if RequestType == 'Delete':
                cfnresponse.send(
                    event,
                    context,
                    cfnresponse.SUCCESS,
                    responseData=responseData,
                    physicalResourceId=event['PhysicalResourceId']
                )
                return
        except:
            print_exc()
            cfnresponse.send(
                event,
                context,
                cfnresponse.FAILED
            )
            return


    ''' Create: (re)creates a resource and returns PhysicalResourceId based on
        the specified AgentResourceId.'''
    try:
        (PhysicalResourceId, responseData) = handle_event(agent, event, create=True)
        cfnresponse.send(
            event,
            context,
            cfnresponse.SUCCESS,
            responseData=responseData,
            physicalResourceId=PhysicalResourceId
        )
        return
    except:
        print_exc()
        cfnresponse.send(
            event,
            context,
            cfnresponse.FAILED
        )
        return


if __name__ == '__main__':
    event = json.loads(sys.argv[1])
    lambda_handler(event=event)
