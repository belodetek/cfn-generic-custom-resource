#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.

from botocore.vendored import requests
import json

SUCCESS = "SUCCESS"
FAILED = "FAILED"

def send(event, context, responseStatus, responseData=None, physicalResourceId=None, noEcho=False):
    try:
        log_stream_name = context.log_stream_name
    except:
        log_stream_name = '__mock__'

    if responseData:
        response_size = 0
        try:
            response_size = len(json.dumps(responseData))
            assert response_size <= 4096
        except:
            if not noEcho: print('Response object is too long, length={}'.format(
                response_size
            ))
            responseData = None

    responseUrl = event['ResponseURL']
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + log_stream_name
    responseBody['PhysicalResourceId'] = physicalResourceId or log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['Data'] = responseData
    responseBody['NoEcho'] = noEcho

    json_responseBody = json.dumps(responseBody, sort_keys=True, default=str)

    if not noEcho: print("Response body:\n" + json_responseBody)

    if not log_stream_name == '__mock__':
        headers = {
            'content-type' : '',
            'content-length' : str(len(json_responseBody))
        }

        try:
            response = requests.put(
                responseUrl,
                data=json_responseBody,
                headers=headers
            )
            print("Status code: " + response.reason)
        except Exception as e:
            print("send(..) failed executing requests.put(..): " + str(e))
    else:
        print('Done!')
