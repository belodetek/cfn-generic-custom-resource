# https://docs.aws.amazon.com/lambda/latest/dg/python-image.html#python-image-instructions
FROM public.ecr.aws/lambda/python:3.11 AS build

WORKDIR ${LAMBDA_TASK_ROOT}/build

# FIXME: https://github.com/aws/aws-lambda-base-images/issues/245#issuecomment-2725656680
RUN yum update -y \
    && yum groupinstall "Development Tools" -y \
    && yum install -y ibffi openssl-devel-1.0.2k-24.amzn2.0.14

COPY requirements.txt .

RUN pip install -r requirements.txt -t .

COPY generic_provider.py cfnresponse.py acm_pca.py autoscaling.py eks.py iam.py .


# --- runtime
FROM public.ecr.aws/lambda/python:3.11

COPY --from=build ${LAMBDA_TASK_ROOT}/build .

CMD [ "generic_provider.lambda_handler" ]
