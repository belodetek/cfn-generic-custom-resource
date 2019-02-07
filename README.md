# cfn-custom-resource-provider

> **TL;DR** because a new Lambda function for each custom resource is not DevOps 🤓


## CloudFormation
> Generic CloudFormation [Custom Resources](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html) provider.

### Client VPN demo

#### init

    git clone https://github.com/ab77/cfn-generic-custom-resource

    git pull --recurse-submodules

    git submodule update --remote --recursive


#### certificates
> [issue](https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/authentication-authrization.html) certificates with [easy-rsa](https://github.com/OpenVPN/easy-rsa)

    domain_name='foo.bar'


    pushd easy-rsa/easyrsa3

    ./easyrsa init-pki

    ./easyrsa build-ca nopass

    ./easyrsa build-server-full server.${domain_name} nopass

    ./easyrsa build-client-full client1.${domain_name} nopass

    popd

    server_certificate=$(aws acm import-certificate\
      --certificate file://easy-rsa/easyrsa3/pki/issued/server.${domain_name}.crt\
      --private-key file://easy-rsa/easyrsa3/pki/private/server.${domain_name}.key\
      --certificate-chain file://easy-rsa/easyrsa3/pki/ca.crt | jq -r '.CertificateArn')

    client_certificate=$(aws acm import-certificate\
      --certificate file://easy-rsa/easyrsa3/pki/issued/client1.${domain_name}.crt\
      --private-key file://easy-rsa/easyrsa3/pki/private/client1.${domain_name}.key\
      --certificate-chain file://easy-rsa/easyrsa3/pki/ca.crt | jq -r '.CertificateArn')


#### install requirements
> Lambda provided boto3 doesn't support Client VPN resources at the time of writing

    pushd generic_provider\
      && pip install --upgrade -r requirements.txt -t .\
      && popd


#### package assets
> ⚠️ creates a new bucket with a random GUID

    bucket=$(uuid)
    aws s3 mb s3://${bucket}


    for template in lambda client-vpn client-vpn-main; do
        aws cloudformation package\
          --template-file ${template}-template.yaml\
          --s3-bucket ${bucket}\
          --output-template-file ${template}.yaml
    done


#### deploy stack

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


#### configure G Suite
> [TBC](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-configuring-federation-with-saml-2-0-idp.html)

* login to [Google Apps Admin](https://admin.google.com)
* navigate to `Apps -> SAML Apps --> + --> SETUP MY OWN CUSTOM APP`
* set `ACS URL` to `https://${stack_name}.auth.${AWS_REGION}.amazoncognito.com/saml2/idpresponse`
* set `Entity ID` to `urn:amazon:cognito:sp:${user_pool_id}`
* [continue with ALB configuration](https://aws.amazon.com/blogs/aws/built-in-authentication-in-alb/) (out-of-scope)



## mock requests

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
    }" | jq -c) && ./generic_provider.py "${mock_lambda_event}"



>--belodetek 😬
