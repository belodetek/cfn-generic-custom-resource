# cfn-custom-resource-provider [![Build Status](https://travis-ci.org/ab77/cfn-generic-custom-resource.svg?branch=master)](https://travis-ci.org/ab77/cfn-generic-custom-resource)

> **TL;DR** One *Custom Resource provider* to Rule Them All, inspect the [code](https://github.com/ab77/cfn-generic-custom-resource/blob/master/generic_provider/generic_provider.py), read the [blog](https://anton.belodedenko.me/generic-custom-resource-provider/), try some [examples](http://cloudformation.belodetek.io/#mock-client-requests) and consider [contributing](CONTRIBUTING.md) 🤓



## TOC

### CloudFormation demo stacks
* [Client VPN](#client-vpn-demo)
* [Cognito IdP](#cognito-demo)
* [VPC peering](#vpc-peering-demo)
* [AWS Backup (EFS)](#aws-backup-efs)
* [ACM Private CA](#acm-private-ca)


### mock requests

#### client
* [ACM](#acm)
* [S3](#s3)
* [AWS Backup](#backup)
* [Directory Services](#directory-services)
* [IAM](#iam)
* [KMS](#kms)
* [Relational Database Service](#relational-database-service)
* [Database Migration Service](#database-migration-service)
* [EC2](#ec2)
* [KMS](#kms)

#### resources
* [resources requests](#mock-resources-requests)



## about
The idea behind this project was to make available a flexible and simple tool to enable creation of any AWS resource supported by the API. We implement this functionality via a generic CloudFormation [Custom Resources](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html) provider in Python (3), using [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html). The word "generic" is used here in a sense of having just one Lambda function, which can be used to create different custom resources by varying the input parameters.

For more information, please read this blog [post](https://anton.belodedenko.me/generic-custom-resource-provider/).



## CloudFormation
> All shell-fu is Bash; `git`, `pip`, `awscli` and `jq` required.

### init

    git clone --recurse-submodules --remote-submodules\
      https://github.com/ab77/cfn-generic-custom-resource\
      && cd cfn-generic-custom-resource


### create bucket
> 📝 creates a new bucket with a random GUID; ensure `~/.aws/credentials` and `~/.aws/config` are configured (run `aws configure ...`) and export `AWS_PROFILE` and `AWS_REGION` environment variables

    bucket=$(uuid)
    aws s3 mb s3://${bucket}


#### install requirements (venv)
> 📝 AWS Lambda provided boto3 library doesn't support Client VPN resources at the time of writing, so we need to package it with the code

    sudo pip install venv --user || sudo pip install virtualenv --user\
      && pushd generic_provider\
      && python -m venv venv || python -m virtualenv venv\
      && . venv/bin/activate\
      && pip install --upgrade pip\
      && pip install --upgrade -r requirements.txt -t .\
      && popd


#### compile dependencies

    docker ps && pushd generic_provider && make && popd


### Client VPN demo
> ☢️ beware of the currently eye-watering Client VPN [pricing](https://aws.amazon.com/vpn/pricing/)

#### certificates
> 📜 [issue](https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/authentication-authrization.html) certificates with [easy-rsa](https://github.com/OpenVPN/easy-rsa) and upload to ACM, using fictional domain `foo.bar`

    domain_name='foo.bar'

    git clone https://github.com/OpenVPN/easy-rsa

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

    pushd client-vpn; for template in lambda main client-vpn; do
        aws cloudformation package\
          --template-file ${template}-template.yaml\
          --s3-bucket ${bucket}\
          --output-template-file ${template}.yaml
    done; popd


#### deploy stack
> 📝  creates Client VPN endpoint with `certificate-authentication`; for `directory-service-authentication` or both, specify additional `DirectoryId` parameter

    stack_name='client-vpn-demo'
    vpc_id=$(aws ec2 describe-vpcs | jq -r .Vpcs[0].VpcId)
    subnets=(
        $(aws ec2 describe-subnets | jq -r ".Subnets[0] | select(.VpcId==\"${vpc_id}\").SubnetId")
        $(aws ec2 describe-subnets | jq -r ".Subnets[1] | select(.VpcId==\"${vpc_id}\").SubnetId")
    )
    subnet_count=${#subnets[@]}
    cidr=172.16.0.0/22


    pushd client-vpn; aws cloudformation deploy\
      --template-file main.yaml\
      --stack-name ${stack_name}\
      --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM\
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
      AccountId=$(aws sts get-caller-identity | jq -r '.Account'); popd


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

    pushd cognito-idp; for template in lambda main cognito; do
        aws cloudformation package\
          --template-file ${template}-template.yaml\
          --s3-bucket ${bucket}\
          --output-template-file ${template}.yaml
    done; popd


#### deploy stack

    stack_name='c0gn1t0-demo'
    metadata_url=https://${bucket}.s3.amazonaws.com/GoogleIDPMetadata-${domain_name}.xml

    pushd cognito-idp; aws cloudformation deploy\
      --template-file main.yaml\
      --stack-name ${stack_name}\
      --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM\
      --parameter-overrides\
      DomainName=${domain_name}\
      MetadataURL=${metadata_url}\
      --tags\
      Name=${stack_name}\
      Region=${AWS_REGION}\
      Profile=${AWS_PROFILE}\
      AccountId=$(aws sts get-caller-identity | jq -r '.Account'); popd


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



### VPC peering demo
> creates a peering connection between source and destination VPCs, including tags and routes in both directions

#### package assets

    pushd vpc-peering; for template in lambda main; do
        aws cloudformation package\
          --template-file ${template}-template.yaml\
          --s3-bucket ${bucket}\
          --output-template-file ${template}.yaml
    done; popd


#### create IAM role
> ☢ ensure appropriate [VPCPeeringRole](lambda-template.yaml#L12) exists in the VPC accepter AWS account and review IAM role permissions

      VPCPeeringRole:
        Type: 'AWS::IAM::Role'
        Properties:
          RoleName: 'VPCPeeringRole'
          AssumeRolePolicyDocument:
            Version: '2012-10-17'
            Statement:
            - Effect: Allow
              Principal:
                AWS:
                # list your VPC peering requester (source) AWS accounts here
                - '123456789000'
                ...
              Action: sts:AssumeRole
          Path: '/'
          ...


#### update IAM role
> ☢ add VPC requester AWS accounts to [CustomResourceLambdaRole](lambda-template.yaml#L94) under the `AmazonSTSPolicy` policy and review IAM role permissions

      - PolicyName: AmazonSTSPolicy
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - 'sts:AssumeRole'
            - 'sts:PassRole'
            Resource:
            # list your VPC peering accepter (target) AWS accounts here
            - !Sub 'arn:${AWS::Partition}:iam::123456789001:role/VPCPeeringRole'
            ...


#### deploy stack
> 📝 optionally enable EC2 nested stack and supply `SecurityGroup` in the accepter VPC as well as `TargetPort`

    # peering between VPCs in this mock account 123456789000 (requester) and 123456789001 (accepter)
    stack_name='vpc-peering-demo'

    # create IPv6 routes (both VPCs must be IPv6)
    ipv6='false'

    # requester VPC
    source_vpc='vpc-abcdef1234567890'

    # comma separated list of one or more route table id(s) in the requester VPC'
    source_route_table_ids='rtb-abcdef1234567890'

    # accepter VPC
    source_vpc='vpc-1234567890abcdef'

    # VPC accepter AWS account
    target_account_id=123456789001

    # VPC accepter AWS region
    target_region=${AWS_REGION}

    # comma separated list of one or more route table id(s) in the accepter VPC'
    target_route_table_ids='rtb-1234567890abcdef'


    source_route_table_ids=($(echo ${source_route_table_ids} | sed 's/,/ /g' | tr ' ' '\n'))\
      && source_route_tables=${#source_route_table_ids[@]}\
      && source_route_table_ids="$(echo ${source_route_table_ids[*]} | tr ' ' ',')"

    target_route_table_ids=($(echo ${target_route_table_ids} | sed 's/,/ /g' | tr ' ' '\n'))\
      && target_route_tables=${#target_route_table_ids[@]}\
      && target_route_table_ids="$(echo ${target_route_table_ids[*]} | tr ' ' ',')"

    pushd vpc-peering; aws cloudformation deploy\
      --template-file main.yaml\
      --stack-name ${stack_name}\
      --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM\
      --parameter-overrides\
      SourceVpcId=${source_vpc}\
      SourceRouteTableIds=${source_route_table_ids}\
      SourceRouteTables=${source_route_tables}\
      TargetRegion=${target_region}\
      TargetAccountId=${target_account_id}\
      TargetVpcId=${target_vpc}\
      TargetRouteTableIds=${target_route_table_ids}\
      TargetRouteTables=${target_route_tables}\
      EC2Template=false\
      --tags\
      Name=${stack_name}\
      Region=${AWS_REGION}\
      Profile=${AWS_PROFILE}\
      AccountId=$(aws sts get-caller-identity | jq -r '.Account'); popd



### AWS Backup (EFS)
> also see mock [examples](#backup) below

#### package assets

    pushd aws-backup; for template in lambda; do
        aws cloudformation package\
          --template-file ${template}-template.yaml\
          --s3-bucket ${bucket}\
          --output-template-file ${template}.yaml
    done; popd


#### deploy stack
> see [resource ARNs and namespaces](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) for `ResourceId` parameter

    stack_name='aws-backup-demo'

    # specify resource ARN and name
    resource_id="arn:aws:elasticfilesystem:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):file-system/fs-abcde1234"
    resource_name='efs-resource-name'


    pushd aws-backup; aws cloudformation deploy\
      --template-file backup.yaml\
      --stack-name ${stack_name}\
      --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM\
      --parameter-overrides\
      NameTag=${stack_name}\
      ResourceId=${resource_id}\
      ResourceName=${resource_name}\
      --tags\
      Name=${stack_name}\
      Region=${AWS_REGION}\
      Profile=${AWS_PROFILE}\
      AccountId=$(aws sts get-caller-identity | jq -r '.Account'); popd



### ACM Private CA
> also see mock [examples](#acm-pca) below

#### package assets

    pushd acm-pca; for template in lambda main; do
        aws cloudformation package\
          --template-file ${template}-template.yaml\
          --s3-bucket ${bucket}\
          --output-template-file ${template}.yaml
    done; popd


#### deploy stack
> ⚠️ ensure to clean-up the CA resources to avoid $400/month surprise on your next AWS bill

    stack_name='acm-pca'

    # change to a domain you own with postmaster and hostmaster email addresses forwarded for ACM SSL certificate validation
    domain_name='belodetek.io'


    pushd acm-pca; aws cloudformation deploy\
      --template-file main.yaml\
      --stack-name ${stack_name}\
      --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM\
      --parameter-overrides\
      NameTag=${stack_name}\
      DomainWithoutDot=${domain_name}\
      S3Template=true\
      IAMTemplate=true\
      R53Template=true\
      ACMTemplate=true\
      CFTemplate=true\
      IAMTemplate=true\
      PCATemplate=true\
      --tags\
      Name=${stack_name}\
      Region=${AWS_REGION}\
      Profile=${AWS_PROFILE}\
      AccountId=$(aws sts get-caller-identity | jq -r '.Account'); popd



## mock client requests
> 🐞 useful to debug resource creation of AWS resources from a local workstation


### ACM
> [ACM](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html) API reference

#### request_certificate
> mock CloudFormation request to [request_certificate](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.request_certificate) in a different account and/or region (e.g. for CloudFront)

    # https://forums.aws.amazon.com/thread.jspa?messageID=912980
    aws_region='us-east-1'

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
          \"AgentType\": \"client\",
          \"AgentService\": \"acm\",
          \"AgentRegion\": \"${aws_region}\",
          \"AgentCreateMethod\": \"request_certificate\",
          \"AgentUpdateMethod\": \"update_certificate_options\",
          \"AgentDeleteMethod\": \"delete_certificate\",
          \"AgentWaitMethod\": \"certificate_validated\",
          \"AgentWaitQueryExpr\": \"$.CertificateArn\",
          \"AgentWaitResourceId\": \"CertificateArn\",
          \"AgentResourceId\": \"CertificateArn\",
          \"AgentCreateArgs\": {
              \"DomainName\": \"foo.baz.com\",
              \"ValidationMethod\": \"EMAIL\",
              \"SubjectAlternativeNames\": [
                  \"bar.baz.com\"
              ],
              \"DomainValidationOptions\": [
                  {
                      \"DomainName\": \"foo.baz.com\",
                      \"ValidationDomain\": \"baz.com\"
                  },
                  {
                      \"DomainName\": \"bar.baz.com\",
                      \"ValidationDomain\": \"baz.com\"
                  }
              ]
          },
          \"AgentUpdateArgs\": {
              \"Options\": {
                  \"CertificateTransparencyLoggingPreference\": \"DISABLED\"
              }
          }
      }
    }" | jq -c | VERBOSE=1 ./generic_provider.py
    popd


### ACM-PCA
> [ACM-PCA](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm-pca.html) API reference

#### create_certificate_authority
> mock CloudFormation request to [create_certificate_authority](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm-pca.html#ACMPCA.Client.create_certificate_authority)

(⚠️ ensure to clean-up the CA resources to avoid $400/month surprise on your next AWS bill)

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
          \"AgentType\": \"client\",
          \"AgentService\": \"acm-pca\",
          \"AgentCreateMethod\": \"create_certificate_authority\",
          \"AgentUpdateMethod\": \"update_certificate_authority\",
          \"AgentDeleteMethod\": \"delete_certificate_authority\",
          \"AgentWaitQueryExpr\": \"$.CertificateAuthorityArn\",
          \"AgentWaitResourceId\": \"CertificateAuthorityArn\",
          \"AgentWaitDeleteExceptions\": [
            \"botocore.exceptions.WaiterError\"
          ],
          \"AgentResourceId\": \"CertificateAuthorityArn\",
          \"AgentCreateArgs\": {
              \"CertificateAuthorityConfiguration\": {
                  \"KeyAlgorithm\": \"RSA_2048\",
                  \"SigningAlgorithm\": \"SHA256WITHRSA\",
                  \"Subject\": {
                      \"Country\": \"FB\",
                      \"Organization\": \"foo-bar\",
                      \"OrganizationalUnit\": \"foo-bar\",
                      \"CommonName\": \"foo@bar.com\"
                  }
              },
              \"RevocationConfiguration\": {
                  \"CrlConfiguration\": {
                      \"Enabled\": true,
                      \"ExpirationInDays\": 7,
                      \"CustomCname\": \"foo.bar.com\",
                      \"S3BucketName\": \"foo-bar\"
                  }
              },
              \"CertificateAuthorityType\": \"SUBORDINATE\",
              \"Tags\": [
                  {
                      \"Key\": \"Name\",
                      \"Value\": \"foo-bar\"

                  }
              ]
          },
          \"AgentUpdateArgs\": {
              \"RevocationConfiguration\": {
                  \"CrlConfiguration\": {
                      \"Enabled\": true,
                      \"ExpirationInDays\": 7,
                      \"CustomCname\": \"foo.bar.com\"
                  }
              },
              \"Status\": \"ACTIVE\"
          },
          \"AgentDeleteArgs\": {
              \"PermanentDeletionTimeInDays\": 7
          }
      }
    }" | jq -c | VERBOSE=1 ./generic_provider.py
    popd


#### create_self_signed_cert
> mock CloudFormation request to [create_self_signed_cert](https://github.com/ab77/cfn-generic-custom-resource/blob/master/generic_provider/acm_pca.py)

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
          \"AgentType\": \"custom\",
          \"AgentService\": \"acm_pca\",
          \"AgentCreateMethod\": \"create_self_signed_cert\",
          \"AgentCreateArgs\": {
              \"PrivateKey\": \"/rsa-private-keys/acm-pca/key_pair\",
              \"Country\": \"US\",
              \"Org\": \"foo\",
              \"OrgUnit\": \"bar\",
              \"CommonName\": \"foo-bar\",
              \"Serial\": 1,
              \"ValidityInSeconds\": 315360000,
              \"Digest\": \"sha256\"
          }
      }
    }" | jq -c | VERBOSE=1 ./generic_provider.py | jq -r .Data.Certificate > ca.crt\
    && openssl x509 -in ca.crt -text -noout
    popd


#### get_certificate_authority_csr
> mock CloudFormation request to [get_certificate_authority_csr](https://github.com/ab77/cfn-generic-custom-resource/blob/master/generic_provider/acm_pca.py)

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
          \"AgentType\": \"client\",
          \"AgentService\": \"acm-pca\",
          \"AgentCreateMethod\": \"get_certificate_authority_csr\",
          \"AgentCreateArgs\": {
              \"CertificateAuthorityArn\": \"arn:aws:acm-pca:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):certificate-authority/$(uuid)\",
          }
        }
      }" | jq -c | VERBOSE=1 ./generic_provider.py | jq -r .Data.Csr > csr.pem && openssl req -in csr.pem -text -noout
      popd


#### sign_csr
> mock CloudFormation request to [sign_csr](https://github.com/ab77/cfn-generic-custom-resource/blob/master/generic_provider/acm_pca.py) request

    # upload RSA private (signing) key to the SSM Parameter Store
    openssl genrsa -out signing.key 4096 && signing_key=$(cat signing.key)

    aws ssm put-parameter --type SecureString\
      --name '/rsa-private-keys/acm-pca/key_pair'\
      --value ${signing_key}


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
          \"AgentType\": \"custom\",
          \"AgentService\": \"acm_pca\",
          \"AgentCreateMethod\": \"sign_csr\",
          \"AgentCreateArgs\": {
              \"PrivateKey\": \"/rsa-private-keys/acm-pca/key_pair",
              \"Csr\": \"$(cat csr.pem | base64)\",
              \"ValidityInSeconds\": 315360000,
              \"Digest\": \"sha256\"
          }
      }
    }" | jq -c | VERBOSE=1 ./generic_provider.py > test.crt && openssl x509 -in test.crt -text -noout
    popd


#### import_certificate_authority_certificate
> mock CloudFormation request to [import_certificate_authority_certificate](https://github.com/ab77/cfn-generic-custom-resource/blob/master/generic_provider/acm_pca.py)

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
          \"AgentType\": \"custom\",
          \"AgentService\": \"acm_pca\",
          \"AgentCreateMethod\": \"import_certificate_authority_certificate\",
          \"AgentCreateArgs\": {
              \"CertificateAuthorityArn\": \"arn:aws:acm-pca:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):certificate-authority/$(uuid)\",
              \"Certificate\": \"$(cat test.crt | base64)\"
              \"CACertificate\": \"$(cat csr.pem | base64)\"
          }
      }
    }" | jq -c | VERBOSE=1 ./generic_provider.py
    popd


### S3
> [S3](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html) API reference

#### put-bucket-notification-configuration
> mock CloudFormation request to [add](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.put_bucket_notification_configuration) a bucket Lambda notification configuration

    bucket='foo'

    lambda_function='bar'


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
          \"AgentType\": \"client\",
          \"AgentService\": \"s3\",
          \"AgentCreateMethod\": \"put_bucket_notification_configuration\",
          \"AgentUpdateMethod\": \"put_bucket_notification_configuration\",
          \"AgentDeleteMethod\": \"put_bucket_notification_configuration\",
          \"AgentCreateArgs\": {
              \"Bucket\": \"${bucket}\",
              \"NotificationConfiguration\": {
                  \"LambdaFunctionConfigurations\": [{
                      \"LambdaFunctionArn\": \"arn:aws:lambda:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):function:${lambda_function}\",
                      \"Events\": [
                          \"s3:ObjectRemoved:*\"
                      ],
                      \"Filter\": {
                          \"Key\": {
                              \"FilterRules\": [
                                  {
                                      \"Name\": \"prefix\",
                                      \"Value\": \"foo/\"
                                  },
                                  {
                                      \"Name\": \"suffix\",
                                      \"Value\": \".bar\"
                                  }
                              ]
                          }
                      }
                  }]
              }
          },
          \"AgentUpdateArgs\": {
              \"Bucket\": \"${bucket}\",
              \"NotificationConfiguration\": {
                  \"LambdaFunctionConfigurations\": [{
                      \"LambdaFunctionArn\": \"arn:aws:lambda:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):function:${lambda_function}\",
                      \"Events\": [
                          \"s3:ObjectRemoved:*\"
                      ],
                      \"Filter\": {
                          \"Key\": {
                              \"FilterRules\": [
                                  {
                                      \"Name\": \"prefix\",
                                      \"Value\": \"foo/\"
                                  },
                                  {
                                      \"Name\": \"suffix\",
                                      \"Value\": \".bar\"
                                  }
                              ]
                          }
                      }
                  }]
              }
          },
          \"AgentDeleteArgs\": {
              \"Bucket\": \"${bucket}\",
              \"NotificationConfiguration\": {}
          }
      }
    }" | jq -c | VERBOSE=1 ./generic_provider.py
    popd


### Backup
> [Backup](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/backup.html) API reference

#### create-backup-vault
> mock CloudFormation request to [create](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/backup.html#Backup.Client.create_backup_vault) a backup vault

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
          \"AgentType\": \"client\",
          \"AgentService\": \"backup\",
          \"AgentCreateMethod\": \"create_backup_vault\",
          \"AgentDeleteMethod\": \"delete_backup_vault\",
          \"AgentCreateArgs\": {
              \"BackupVaultName\": \"foo-bar\",
              \"EncryptionKeyArn\": \"arn:aws:kms:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):key/$(uuid)\",
              \"BackupVaultTags\": {
                \"Name\": \"foo-bar\"
              }
          },
          \"AgentDeleteArgs\": {
              \"BackupVaultName\": \"foo-bar\"
          }
      }
    }" | jq -c | VERBOSE=1 ./generic_provider.py
    popd


#### create-backup-plan
> mock CloudFormation request to [create](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/backup.html#Backup.Client.create_backup_plan) a backup plan

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
          \"AgentService\": \"backup\",
          \"AgentCreateMethod\": \"create_backup_plan\",
          \"AgentUpdateMethod\": \"update_backup_plan\",
          \"AgentDeleteMethod\": \"delete_backup_plan\",
          \"AgentResourceId\": \"BackupPlanId\",
          \"AgentWaitQueryExpr\": \"$.BackupPlanId\",
          \"AgentCreateArgs\": {
            \"BackupPlan\": {
              \"BackupPlanName\": \"foo-bar\",
              \"Rules\": [
                {
                  \"RuleName\": \"foo-bar\",
                  \"TargetBackupVaultName\": \"Default\",
                  \"ScheduleExpression\": \"cron(0 2 * * ? *)\",
                  \"StartWindowMinutes\": 60,
                  \"CompletionWindowMinutes\": 180,
                  \"Lifecycle\": {
                    \"MoveToColdStorageAfterDays\": 30,
                    \"DeleteAfterDays\": 365
                  }
                }
              ]
            },
            \"BackupPlanTags\": {
              \"Name\": \"foo-bar\"
            }
          },
          \"AgentUpdateArgs\": {
            \"BackupPlan\": {
              \"BackupPlanName\": \"foo-bar\",
              \"Rules\": [
                {
                  \"RuleName\": \"foo-bar\",
                  \"TargetBackupVaultName\": \"Default\",
                  \"ScheduleExpression\": \"cron(0 2 * * ? *)\",
                  \"StartWindowMinutes\": 60,
                  \"CompletionWindowMinutes\": 180,
                  \"Lifecycle\": {
                    \"MoveToColdStorageAfterDays\": 30,
                    \"DeleteAfterDays\": 365
                  }
                }
              ]
            }
          }
        }
      }
    }" | jq -c | VERBOSE=1 ./generic_provider.py
    popd


#### create-backup-selection
> mock CloudFormation request to [create](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/backup.html#Backup.Client.create_backup_selection) a backup slection

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
          \"AgentService\": \"backup\",
          \"AgentCreateMethod\": \"create_backup_selection\",
          \"AgentDeleteMethod\": \"delete_backup_selection\",
          \"AgentResourceId\": \"SelectionId\",
          \"AgentWaitQueryExpr\": \"$.SelectionId\",
          \"AgentCreateArgs\": {
            \"BackupPlanId\": \"$(uuid)\",
            \"BackupSelection\": {
              \"SelectionName\": \"foo-bar\",
              \"IamRoleArn\": \"arn:aws:iam::$(aws sts get-caller-identity | jq -r '.Account'):role/service-role/AWSBackupDefaultServiceRole\",
              \"Resources\": [
                \"arn:aws:elasticfilesystem:${AWS_REGION}:$(aws sts get-caller-identity | jq -r '.Account'):file-system/fs-abcde1234\"
              ],
              \"ListOfTags\": [
                {
                  \"ConditionType\": \"STRINGEQUALS\",
                  \"ConditionKey\": \"AccountId\",
                  \"ConditionValue\": \"$(aws sts get-caller-identity | jq -r '.Account')\"
                }
              ]
            }
          },
          \"AgentDeleteArgs\": {
            \"BackupPlanId\": \"$(uuid)\"
          }
        }
      }
    }" | jq -c | VERBOSE=1 ./generic_provider.py
    popd



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
> mock CloudFormation request to [enable](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.modify_db_cluster) RDS CloudWatch metrics

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


#### modify-db-instance
> mock CloudFormation request to [enable](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.modify_db_cluster) RDS Performance Insights

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
        \"AgentCreateMethod\": \"modify_db_instance\",
        \"AgentCreateArgs\": {
          \"DBInstanceIdentifier\": \"abcdefghij1234\",
          \"EnablePerformanceInsights\": true,
          \"PerformanceInsightsKMSKeyId\": \"arn:aws:kms:${AWS_REGION}:1234567890:key/$(uuid)\",
          \"PerformanceInsightsRetentionPeriod\": 7,
          \"ApplyImmediately\": true
        },
        \"AgentDeleteMethod\": \"modify_db_instance\",
        \"AgentDeleteArgs\": {
          \"DBInstanceIdentifier\": \"1234abcdefghij\",
          \"EnablePerformanceInsights\": false,
          \"ApplyImmediately\": true
        },
        \"AgentWaitMethod\": \"describe_db_instances\",
        \"AgentWaitDelay\": \"60\",
        \"AgentWaitArgs\": {
          \"Filters\": [
            {
              \"Name\": \"db-cluster-id\",
              \"Values\": [
                \"1234abcdefghij\"
              ]
            },
            {
              \"Name\": \"db-instance-id\",
              \"Values\": [
                \"abcdefghij1234\"
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
          \"agent.exceptions.InvalidResourceStateFault\",
          \"agent.exceptions.ClientError\"
        ],
        \"AgentWaitCreateExceptions\": [
          \"botocore.exceptions.WaiterError\"

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
> mock CloudFormation request to [get](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ssm.html#SSM.Client.get_parameter) existing SSM parameter (stored outside of stack)

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


#### put-parameter
> mock CloudFormation request to [put](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ssm.html#SSM.Client.put_parameter) SSM parameter

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
          \"AgentCreateMethod\": \"put_parameter\",
          \"AgentUpdateMethod\": \"put_parameter\",
          \"AgentDeleteMethod\": \"delete_parameter\",
          \"AgentResourceId\": \"Name\",
          \"AgentCreateArgs\": {
              \"Name\": \"/foo/bar\",
              \"Value\": \"foo-bar\",
              \"Type\": \"SecureString\",
              \"Overwrite\": false
          },
          \"AgentUpdateArgs\": {
              \"Name\": \"/foo/bar\",
              \"Value\": \"foo-bar\",
              \"Type\": \"SecureString\",
              \"Overwrite\": true
          },
          \"AgentDeleteArgs\": {
              \"Name\": \"/foo/bar\"
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
