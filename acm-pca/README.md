# thrive-yum-repository

## TOC

* [configure](#configure-account)
* [package](#package)
* [create/update stack](#create-stack)



## package

    stack_name='acm-pca'

    mkdir -p __dist__/templates/${stack_name}

    aws cloudformation package\
      --template-file templates/${stack_name}/main-template.yml\
      --s3-bucket cfn-${AWS_MASTER_ACCOUNT_ALIAS}-${AWS_REGION}\
      --s3-prefix templates/${stack_name}\
      --output-template-file __dist__/templates/${stack_name}/main.yml\
      --profile ${AWS_MASTER_ACCOUNT_ALIAS}\
      --region ${AWS_REGION}


## create stack


    aws cloudformation deploy\
      --stack-name ${stack_name}\
      --template-file __dist__/templates/${stack_name}/main.yml\
      --s3-bucket cfn-${AWS_MASTER_ACCOUNT_ALIAS}-${AWS_REGION}\
      --s3-prefix templates/${stack_name}\
      --profile ${AWS_MASTER_ACCOUNT_ALIAS}\
      --region ${AWS_REGION}\
      --notification-arns ${notification_topic_master}\
      --capabilities CAPABILITY_NAMED_IAM\
      --parameter-overrides\
      LogsRetentionInDays=7\
      S3Template=true\
      IAMTemplate=true\
      R53Template=true\
      ACMTemplate=true\
      CFTemplate=true\
      PCATemplate=false\
      IAMTemplate=true\
      --tags\
      MasterAccountId=${AWS_MASTER_ACCOUNT_ID}\
      MasterAccountAlias=${AWS_MASTER_ACCOUNT_ALIAS}\
      AccountEmail=${org_email}\
      OrgId=${org_id}\
      OrgArn=${org_arn}
