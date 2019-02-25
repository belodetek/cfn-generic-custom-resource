# cfn-custom-resource-provider

> **TL;DR** One *Custom Resource provider* to Rule Them All 🤓


## CloudFormation
> Generic CloudFormation [Custom Resources](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html) provider. All shell-fu is Bash; `git`, `pip`, `awscli` and `jq` required.

### init

    git clone https://github.com/ab77/cfn-generic-custom-resource\
      && cd cfn-generic-custom-resource\
      && git pull --recurse-submodules\
      && git submodule update --remote --recursive


### create bucket
> 📝 creates a new bucket with a random GUID; ensure `~/.aws/credentials` and `~/.aws/config` are configured (run `aws configure ...`) and export `AWS_PROFILE` and `AWS_REGION` environment variables

    bucket=$(uuid)
    aws s3 mb s3://${bucket}


#### install requirements
> 📝 AWS Lambda provided boto3 library doesn't support Client VPN resources at the time of writing, so we need to package it with the code

    pushd generic_provider\
      && pip install --upgrade -r requirements.txt -t .\
      && popd


### Client VPN demo
> ☢️ beware of the currently eye-watering Client VPN [pricing](https://aws.amazon.com/vpn/pricing/)

#### certificates
> 📜 [issue](https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/authentication-authrization.html) certificates with [easy-rsa](https://github.com/OpenVPN/easy-rsa) and upload to ACM, using fictional domain `foo.bar`

    domain_name='foo.bar'


    pushd easy-rsa/easyrsa3

    ./easyrsa init-pki

    ./easyrsa build-ca nopass

    ./easyrsa build-server-full server.${domain_name} nopass\
      && ./easyrsa build-client-full client1.${domain_name} nopass

    popd

    server_certificate=$(aws acm import-certificate\
      --certificate file://easy-rsa/easyrsa3/pki/issued/server.${domain_name}.crt\
      --private-key file://easy-rsa/easyrsa3/pki/private/server.${domain_name}.key\
      --certificate-chain file://easy-rsa/easyrsa3/pki/ca.crt | jq -r '.CertificateArn')

    client_certificate=$(aws acm import-certificate\
      --certificate file://easy-rsa/easyrsa3/pki/issued/client1.${domain_name}.crt\
      --private-key file://easy-rsa/easyrsa3/pki/private/client1.${domain_name}.key\
      --certificate-chain file://easy-rsa/easyrsa3/pki/ca.crt | jq -r '.CertificateArn')


#### package assets
> 📦 package CloudFormation templates and Lambda function(s) and upload to S3

    for template in lambda client-vpn client-vpn-main; do
        aws cloudformation package\
          --template-file ${template}-template.yaml\
          --s3-bucket ${bucket}\
          --output-template-file ${template}.yaml
    done


#### deploy stack
> 📝  creates Client VPN endpoint with `certificate-authentication`; for `directory-service-authentication` or both, specify additional `DirectoryId` parameter

    stack_name='client-vpn-demo'
    vpc_id=vpc-abcdef1234567890
    subnets=(subnet-abcdef1234567890 subnet-1234567890abcdef)
    subnet_count=${#subnets[@]}
    cidr=172.16.0.0/22


    aws cloudformation deploy\
      --template-file client-vpn-main.yaml\
      --stack-name ${stack_name}\
      --capabilities CAPABILITY_IAM\
      --parameter-overrides\
      VpcId=${vpc_id}\
      CidrBlock=${cidr}\
      SubnetIds=$(echo ${subnets[*]} | tr ' ' ',')\
      SubnetCount=${subnet_count}\
      ServerCertificateArn=${server_certificate}\
      ClientRootCertificateChainArn=${client_certificate}\
      --tags\
      Name=${stack_name}\
      Region=${AWS_REGION}\
      Profile=${AWS_PROFILE}\
      AccountId=$(aws sts get-caller-identity | jq -r '.Account')


#### download profile

    vpn_stack=$(aws cloudformation list-exports\
      | jq -r ".Exports[] | select(.Name==\"VPNStackName-${stack_name}\").Value")

    client_vpn_endpoint=$(aws cloudformation list-exports\
      | jq -r ".Exports[] | select(.Name | startswith(\"ClientVpnEndpointId-${vpn_stack}\")).Value")

    aws ec2 export-client-vpn-client-configuration\
      --client-vpn-endpoint-id ${client_vpn_endpoint} | jq -r '.ClientConfiguration' > client.ovpn


#### connect
* [macOS](https://tunnelblick.net/downloads.html)
* [Windows/Linux](https://openvpn.net/community-downloads/)



### Cognito demo
> 📝 make sure to [create bucket](#create-bucket) and [install requirements](#install-requirements) first

#### update bucket policy
> ⚠️ public read access required for access to `MetadataURL`, adjust as necessary

```
tmpfile=$(mktemp)
cat << EOF > ${tmpfile}
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "$(date +%s)",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::${bucket}/*"
      ]
    }
  ]
}
EOF

aws s3api put-bucket-policy\
  --bucket ${bucket}\
  --policy file://${tmpfile}\
  && rm ${tmpfile}
```


#### download metadata
* login to [Google Apps Admin](https://admin.google.com)
* navigate to `Apps -> SAML Apps --> + --> SETUP MY OWN CUSTOM APP`
* select `(Option 2) IDP metadata`, download and save


#### copy metadata

    domain_name='foo.bar'

    aws s3 cp GoogleIDPMetadata-${domain_name}.xml s3://${bucket}/


#### package assets

    for template in lambda cognito cognito-main; do
        aws cloudformation package\
          --template-file ${template}-template.yaml\
          --s3-bucket ${bucket}\
          --output-template-file ${template}.yaml
    done


#### deploy stack

    stack_name='c0gn1t0-demo'
    metadata_url=https://${bucket}.s3.amazonaws.com/GoogleIDPMetadata-${domain_name}.xml

    aws cloudformation deploy\
      --template-file cognito-main.yaml\
      --stack-name ${stack_name}\
      --capabilities CAPABILITY_IAM\
      --parameter-overrides\
      DomainName=${domain_name}\
      MetadataURL=${metadata_url}\
      --tags\
      Name=${stack_name}\
      Region=${AWS_REGION}\
      Profile=${AWS_PROFILE}\
      AccountId=$(aws sts get-caller-identity | jq -r '.Account')


    cognito_stack=$(aws cloudformation list-exports\
      | jq -r ".Exports[] | select(.Name==\"CognitoStackName-${stack_name}\").Value")

    user_pool_id=$(aws cloudformation list-exports\
      | jq -r ".Exports[] | select(.Name | startswith(\"UserPoolId-${cognito_stack}\")).Value")


    echo "ACS URL: https://${stack_name}.auth.${AWS_REGION}.amazoncognito.com/saml2/idpresponse"
    echo "Entity ID: urn:amazon:cognito:sp:${user_pool_id}"


#### configure G Suite
> [Cognito IdP](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-configuring-federation-with-saml-2-0-idp.html) with [Google SAML](https://support.google.com/a/answer/6087519?hl=en)

* login to [Google Apps Admin](https://admin.google.com)
* navigate to `Apps -> SAML Apps --> + --> SETUP MY OWN CUSTOM APP`
* set `ACS URL` as per above
* set `Entity ID` as per above
* continue with [ALB configuration](https://aws.amazon.com/blogs/aws/built-in-authentication-in-alb/)



## mock client requests
> 🐞 useful to debug resource creation locally

### Directory Services
> [Directory Services](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ds.html) API reference

#### AD Connector
> mock CloudFormation request to create [AD Connector](https://docs.aws.amazon.com/directoryservice/latest/admin-guide/directory_ad_connector.html)

    mock_lambda_event=$(echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"ResourceProperties\": {
        \"AgentService\": \"ds\",
        \"AgentType\": \"client\",
        \"AgentCreateMethod\": \"connect_directory\",
        \"AgentDeleteMethod\": \"delete_directory\",
        \"AgentWaitMethod\": \"describe_directories\",
        \"AgentWaitQueryExpr\": \"$.DirectoryDescriptions[].Stage\",
        \"AgentWaitCreateQueryValues\": [
            \"Active\"
        ],
        \"AgentWaitUpdateQueryValues\": [],
        \"AgentWaitDeleteQueryValues\": [],
        \"AgentResourceId\": \"DirectoryId\",
        \"AgentWaitResourceId\": [
          \"DirectoryIds\"
        ],
        \"AgentCreateArgs\": {
          \"Size\": \"Small\",
          \"Description\": \"Active Directory connection.\",
          \"Name\": \"foo-bar.local\",
          \"ShortName\": \"foo-bar\",
          \"Password\": \"bar\",
          \"ConnectSettings\": {
            \"VpcId\": \"vpc-abcdef1234567890\",
            \"SubnetIds\": [
              \"subnet-1234567890abcdef\",
              \"subnet-abcdef1234567890\"
            ],
            \"CustomerDnsIps\": [
              \"1.2.3.4\",
              \"4.5.6.7\"
            ],
            \"CustomerUserName\": \"foo\"
          }
        }
      }
    }" | jq -c)\
    && pushd generic_provider\
    && ./generic_provider.py "${mock_lambda_event}"\
    && popd


### IAM
> [IAM](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html) API reference

#### SSH public key
> mock CloudFormation request to [upload](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.upload_ssh_public_key) SSH public key

    pushd generic_provider
    echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"ResourceProperties\": {
          \"AgentType\": \"client\",
          \"AgentService\": \"iam\",
          \"AgentResourceId\": \"SSHPublicKeyId\",
          \"AgentWaitQueryExpr\": \"$.SSHPublicKey.SSHPublicKeyId\",
          \"AgentCreateMethod\": \"upload_ssh_public_key\",
          \"AgentCreateArgs\": {
              \"UserName\": \"foo-bar\",
              \"SSHPublicKeyBody\": \"$(cat ~/.ssh/id_rsa.pub | head -n 1)\"
          },
          \"AgentDeleteMethod\": \"delete_ssh_public_key\",
          \"AgentDeleteArgs\": {
            \"UserName\": \"foo-bar\"
          }
      }
    }" | jq -c | ./generic_provider.py
    popd


### KMS
> [KMS](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html) API reference

#### encrypt
> mock CloudFormation request to [encrypt](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html#KMS.Client.encrypt) with KMS

    pushd generic_provider
    echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"ResourceProperties\": {
          \"AgentCreateArgs\": {
              \"KeyId\": \"arn:aws:kms:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):key/$(uuid)\",
              \"Plaintext\": \"foo-bar\"
          },
          \"AgentType\": \"client\",
          \"AgentService\": \"kms\",
          \"AgentCreateMethod\": \"encrypt\"
      }
    }" | jq -c | ./generic_provider.py
    popd


### Relational Database Service
> [RDS](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html) API reference

#### modify-db-cluster
> mock CloudFormation request to [modify](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.modify_db_cluster) DB cluster

    pushd generic_provider
    echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"PhysicalResourceId\": \"$(uuid)\",
      \"ResourceProperties\": {
        \"AgentService\": \"rds\",
        \"AgentType\": \"client\",
        \"AgentCreateMethod\": \"modify_db_cluster\",
        \"AgentCreateArgs\": {
          \"DBClusterIdentifier\": \"foo-bar\",
          \"CloudwatchLogsExportConfiguration\": {
            \"EnableLogTypes\": [
              \"error\",
              \"slowquery\"
            ],
            \"DisableLogTypes\": []
          }
        },
        \"AgentDeleteMethod\": \"modify_db_cluster\",
        \"AgentDeleteArgs\": {
          \"DBClusterIdentifier\": \"foo-bar\",
          \"CloudwatchLogsExportConfiguration\": {
            \"DisableLogTypes\": [
              \"error\",
              \"slowquery\"
            ],
            \"EnableLogTypes\": []
          }
        },
        \"AgentWaitMethod\": \"describe_db_instances\",
        \"AgentWaitDelay\": \"60\",
        \"AgentWaitArgs\": {
          \"Filters\": [
            {
              \"Name\": \"db-cluster-id\",
              \"Values\": [
                \"foo-bar\"
              ]
            },
            {
              \"Name\": \"db-instance-id\",
              \"Values\": [
                \"foo-bar\"
              ]
            }
          ]
        },
        \"AgentWaitQueryExpr\": \"$.DBInstances[*].DBInstanceStatus\",
        \"AgentWaitCreateQueryValues\": [
            \"available\"
        ],
        \"AgentWaitDeleteQueryValues\": [
            \"available\"
        ]
      }
    }" | jq -c | ./generic_provider.py
    popd


### Database Migration Service
> [DMS](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dms.html) API reference

#### describe-replication-tasks
> mock CloudFormation request to [describe](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dms.html#DatabaseMigrationService.Client.describe_replication_tasks) running replication tasks

    pushd generic_provider
    echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"PhysicalResourceId\": \"$(uuid)\",
      \"ResourceProperties\": {
        \"AgentService\": \"dms\",
        \"AgentType\": \"client\",
        \"AgentCreateMethod\": \"describe_replication_tasks\",
        \"AgentCreateArgs\": {
          \"Filters\": [
            {
              \"Name\": \"replication-instance-arn\",
              \"Values\": [
                \"arn:aws:dms:us-west-2:313347522657:rep:ABCDEFGHIJKLMNOPQRSTUVWXYZ\"
              ]
            }
          ]
        },
        \"AgentWaitQueryExpr\": \"$.ReplicationTasks[?(@.Status=='running')].ReplicationTaskArn\"
      }
    }" | jq -c | ./generic_provider.py
    popd


#### stop-replication-task
> mock CloudFormation request to [stop](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dms.html#DatabaseMigrationService.Client.stop_replication_task) replication task

    pushd generic_provider
    echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"PhysicalResourceId\": \"MockResource\",
      \"ResourceProperties\": {
        \"AgentService\": \"dms\",
        \"AgentType\": \"client\",
        \"AgentWaitMethod\": \"replication_task_stopped\",
        \"AgentWaitArgs\": {
          \"Filters\": [
            {
              \"Name\": \"replication-task-arn\",
              \"Values\": [
                \"arn:aws:dms:${AWS_REGION}:1234567890:task:ABCDEFGHIJKLMNOPQRSTUVWXYZ\"
              ]
            }
          ]
        },
        \"AgentCreateMethod\": \"stop_replication_task\",
        \"AgentCreateExceptions\": [
          \"agent.exceptions.InvalidResourceStateFault\"
        ],
        \"AgentCreateArgs\": {
          \"ReplicationTaskArn\": \"arn:aws:dms:${AWS_REGION}:1234567890:task:ABCDEFGHIJKLMNOPQRSTUVWXYZ\"
        }
      }
    }" | jq -c | ./generic_provider.py
    popd


### EC2
> [EC2](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html) API reference

#### create-tags
> mock CloudFormation request to [tag](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.ServiceResource.create_tags) resources

    pushd generic_provider
    echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"ResourceProperties\": {
          \"AgentType\": \"client\",
          \"AgentService\": \"ec2\",
          \"AgentCreateMethod\": \"create_tags\",
          \"AgentCreateArgs\": {
              \"Resources\": [
                  \"eipalloc-12345677890\"
              ],
              \"Tags\": [
                  {
                      \"Key\": \"foo\",
                      \"Value\": \"bar\"
                  }
              ]
          },
          \"AgentDeleteMethod\": \"delete_tags\",
          \"AgentDeleteArgs\": {
              \"Resources\": [
                  \"eipalloc-12345677890\"
              ],
              \"Tags\": [
                  {
                      \"Key\": \"foo\",
                      \"Value\": \"bar\"
                  }
              ]
          }
      }
    }" | jq -c | ./generic_provider.py
    popd



#### authorize-security-group-ingress
> mock CloudFormation request to [authorize_security_group_ingress](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress) in another account

    pushd generic_provider
    echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"ResourceProperties\": {
          \"AgentType\": \"client\",
          \"AgentService\": \"ec2\",
          \"RoleArn\": \"arn:aws:iam::1234567890:role/CrossAccountRole\",
          \"AgentRegion\": \"us-east-1\",
          \"AgentCreateMethod\": \"authorize_security_group_ingress\",
          \"AgentCreateArgs\": {
              \"GroupId\": \"sg-1234567890abcdef\",
              \"IpPermissions\": [
                  {
                      \"FromPort\": 22,
                      \"IpProtocol\": \"tcp\",
                      \"IpRanges\": [
                          {
                              \"CidrIp\": \"172.16.0.0/16\",
                              \"Description\": \"foo-bar\"
                          }

                      ],
                      \"ToPort\": 22
                  }
              ]
          },
          \"AgentDeleteMethod\": \"revoke_security_group_ingress\",
          \"AgentDeleteArgs\": {
              \"GroupId\": \"sg-1234567890abcdef\",
              \"IpPermissions\": [
                  {
                      \"FromPort\": 22,
                      \"IpProtocol\": \"tcp\",
                      \"IpRanges\": [
                          {
                              \"CidrIp\": \"172.16.0.0/16\",
                              \"Description\": \"foo-bar\"
                          }

                      ],
                      \"ToPort\": 22
                  }
              ]
          }
      }
    }" | jq -c | ./generic_provider.py
    popd


#### modify-subnet-attribute
> mock CloudFormation request to [modify](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.modify_subnet_attribute) subnet attribute(s)

    pushd generic_provider
    echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"ResourceProperties\": {
          \"AgentType\": \"client\",
          \"AgentService\": \"ec2\",
          \"AgentCreateMethod\": \"modify_subnet_attribute\",
          \"AgentCreateArgs\": {
              \"MapPublicIpOnLaunch\": {
                  \"Value\": true
              },
              \"SubnetId\": \"subnet-abcdef1234567890\"
          }
      }
    }" | jq -c | ./generic_provider.py
    popd


#### get-parameter
> mock CloudFormation request to [get](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ssm.html#SSM.Client.get_parameter) SSM parameter

    pushd generic_provider
    echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"ResourceProperties\": {
          \"AgentType\": \"client\",
          \"AgentService\": \"ssm\",
          \"AgentCreateMethod\": \"get_parameter\",
          \"AgentWaitQueryExpr\": \"$.Parameter.Value\",
          \"AgentCreateArgs\": {
              \"Name\": \"/foo/bar\",
              \"WithDecryption\": true
          }
      }
    }" | jq -c | ./generic_provider.py
    popd



## mock resources requests

> [EC2](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html) API reference

#### network-interfaces-attribute
> mock CloudFormation request to [obtain](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Instance.network_interfaces_attribute) instance public IPv6 address

     pushd generic_provider
     echo "{
      \"RequestType\": \"Create\",
      \"ResponseURL\": \"https://cloudformation-custom-resource-response-${AWS_REGION}.s3.amazonaws.com/\",
      \"StackId\": \"arn:aws:cloudformation:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):stack/MockStack/$(uuid)\",
      \"RequestId\": \"$(uuid)\",
      \"ResourceType\": \"Custom::MockResource\",
      \"LogicalResourceId\": \"MockResource\",
      \"ResourceProperties\": {
        \"AgentService\": \"ec2\",
        \"AgentType\": \"resource\",
        \"AgentWaitQueryExpr\": \"$..Ipv6Address\",
        \"AgentResourceId\": \"Ipv6Address\",
        \"AgentCreateMethod\": \"network_interfaces_attribute\",
        \"AgentCreateArgs\": {
          \"ResourceName\": \"Instance\",
          \"ResourceId\": \"i-abcdef1234567890\"
        }
      }
    }" | jq -c | ./generic_provider.py
    popd



>--belodetek 😬
