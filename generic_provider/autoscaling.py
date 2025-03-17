#!/usr/bin/env python

import os
import sys
import boto3

from traceback import print_exc


class AUTOSCALING:

    def __init__(self, *args, **kwargs):
        self.verbose = bool(int(os.getenv('VERBOSE', 0)))
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )
        self.session = boto3.session.Session(**kwargs)
        self.region_name = kwargs['region_name']

    def filter_launch_configuration(self, *args, **kwargs):
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )

        allowed_keys = [
            'KernelId',
            'EbsOptimized',
            'IamInstanceProfile',
            'BlockDeviceMappings',
            'NetworkInterfaces',
            'ImageId',
            'InstanceType',
            'KeyName',
            'Monitoring',
            'Placement',
            'RamDiskId',
            'DisableApiTermination',
            'InstanceInitiatedShutdownBehavior',
            'UserData',
            'TagSpecifications',
            'ElasticGpuSpecifications',
            'ElasticInferenceAccelerators',
            'SecurityGroupIds',
            'SecurityGroups',
            'InstanceMarketOptions',
            'CreditSpecification',
            'CpuOptions',
            'CapacityReservationSpecification',
            'LicenseSpecifications',
            'HibernationOptions'
        ]

        pop_keys = [
            key for key in kwargs['launch_template_data'].keys()
            if key not in allowed_keys
            or kwargs['launch_template_data'][key] == ''
            or kwargs['launch_template_data'][key] == []
            or kwargs['launch_template_data'][key] == {}
        ]
        for key in pop_keys: kwargs['launch_template_data'].pop(key, None)

        if self.verbose: print(
            'pop_keys: {} launch_template_data: {}'.format(
                pop_keys,
                kwargs['launch_template_data']
            ),
            file=sys.stderr
        )

        instance_profile = kwargs['launch_template_data']['IamInstanceProfile'].split('/')[-1:][0]
        kwargs['launch_template_data'].pop('IamInstanceProfile', None)
        kwargs['launch_template_data']['IamInstanceProfile'] = {}
        client = self.session.client('iam')
        response = client.get_instance_profile(
            InstanceProfileName=instance_profile
        )

        if self.verbose: print(
            'response: {}'.format(response),
            file=sys.stderr
        )

        kwargs['launch_template_data']['IamInstanceProfile']['Arn'] = response['InstanceProfile']['Arn']

        # fix wrong key: SecurityGroups instead of SecurityGroupIds (VPC)
        try:
            assert True in [
                True for group in kwargs['launch_template_data']['SecurityGroups']
                if group.split('-')[:1][0] == 'sg'
            ]
            kwargs['launch_template_data']['SecurityGroupIds'] = kwargs['launch_template_data']['SecurityGroups']
            kwargs['launch_template_data'].pop('SecurityGroups', None)
        except:
            # default VPC
            pass

        if self.verbose: print(
            'launch_template_data: {}'.format(kwargs['launch_template_data']),
            file=sys.stderr
        )

        return kwargs['launch_template_data']


    def describe_launch_configuration(self, *args, **kwargs):
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )

        client = self.session.client('autoscaling')
        response = client.describe_launch_configurations(
            LaunchConfigurationNames=[kwargs['launch_configuration_name']]
        )

        if self.verbose: print(
            'response: {}'.format(response),
            file=sys.stderr
        )

        return response['LaunchConfigurations'][:1][0]


    def create_launch_template_from_configuration(self, *args, **kwargs):
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )

        launch_template_data = self.describe_launch_configuration(
            launch_configuration_name=kwargs['LaunchConfigurationName']
        )

        tag_specifications = kwargs['TagSpecifications']
        launch_template_name = kwargs['LaunchTemplateName']
        description = kwargs['Description']

        client = self.session.client('ec2')
        response = client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription=description,
            LaunchTemplateData=self.filter_launch_configuration(
                launch_template_data=launch_template_data
            ),
            TagSpecifications=tag_specifications
        )

        if self.verbose: print(
            'response: {}'.format(response),
            file=sys.stderr
        )

        return response['LaunchTemplate']


    def delete_launch_template(self, *args, **kwargs):
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )

        client = self.session.client('ec2')
        response = client.delete_launch_template(**kwargs)

        if self.verbose: print(
            'response: {}'.format(response),
            file=sys.stderr
        )

        return response['LaunchTemplate']


    def update_auto_scaling_group(self, *args, **kwargs):
        if self.verbose: print(
            'args: {}, kwargs: {}'.format(args, kwargs),
            file=sys.stderr
        )

        auto_scaling_group_name = kwargs['AutoScalingGroupName']
        mixed_instances_policy = kwargs['MixedInstancesPolicy']

        if self.verbose: print(
            'kwargs: {} auto_scaling_group_name: {} mixed_instances_policy: {}'.format(
                kwargs,
                auto_scaling_group_name,
                mixed_instances_policy
            ),
            file=sys.stderr
        )

        client = self.session.client('autoscaling')
        response = client.update_auto_scaling_group(
            AutoScalingGroupName=auto_scaling_group_name,
            MixedInstancesPolicy=mixed_instances_policy
        )

        if self.verbose: print(
            'response: {}'.format(response),
            file=sys.stderr
        )

        return response
