import io
import os
import json
import traceback
import urllib.parse
import boto3
import copy
import botocore.response as br
import urllib3
from datetime import datetime

from boto3.dynamodb.conditions import Key
from boto3.dynamodb.conditions import Attr

# clients
s3 = boto3.resource('s3')
smclient = boto3.client('secretsmanager')
ddb = boto3.resource('dynamodb')
sapauth = {}

# constants
DEFECT_SERVICE = '/sap/opu/odata/sap/API_DEFECT_SRV'
DEFECT_SERVICE_PATH = '/sap/opu/odata/sap/ZAPI_QUAL_NOTIFICATION_SRV'
ATTACHMENT_SERVICE = '/sap/opu/odata/sap/API_CV_ATTACHMENT_SRV'
NOTIF_SERVICE = 'https://s4h.saponaws.online/sap/opu/odata/sap/API_MAINTNOTIFICATION/'

def handler(event, context):
    try:
        # Incoming json file
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
        # Read the json file   
        print(bucket)
        print(key)

        S3client = boto3.client("s3")

        fileobj = S3client.get_object(
            Bucket=bucket,
            Key=key
        )

        filetext = fileobj['Body'].read().decode('utf-8')
        print("File text" + filetext)
        #filesplit = filetext.splitlines()
        #print("File Split" + filesplit)
        # get the latest record
        #filedata = json.load(filesplit[-1])
        filedata = json.loads(filetext)
        print(type(filedata))
        #print("File Data" + filedata)

        if filedata['eventPayload']['assetState']['newState'] == 'NEEDS_MAINTENANCE' and filedata['eventPayload']['assetState']['newState'] != filedata['eventPayload']['assetState']['previousState']:
            notif_data = {}

            ddbConfigTable = ddb.Table(os.environ.get('DDB_CONFIG_TABLE'))

            response = ddbConfigTable.query(KeyConditionExpression=Key('monpath').eq(bucket))
            print(response['Items'])

            configItem = response['Items']
            print(type(configItem))
            print(configItem[0]['sapequi'])

            notif_data['NotificationText'] = 'Monitron Alert'
            notif_data['NotificationType'] = 'M1'
            
            # Generate an English description using Anthropic Claude 3 Sonnet
            prompt = """Given the following JSON data from Amazon Monitron, generate a summary report in markdown format that includes the following sections:

                        1. Header with Timestamp, Event ID, Project, Site, Asset, and Sensor Position 

                        2. Measurements section summarizing the acceleration, temperature, and velocity values
                        
                        3. Model Outputs section listing the persistent/pointwise outputs from Temperature ML, Vibration ISO, and Vibration ML models
                        
                        4. Asset State section showing the new and previous states in the payload under assetState-newState and previousState
                        
                        5. Recommended Actions 
                        
                       Avoid using escape or special characters in the response.
                        
                       Use concise language to summarize the key information from the JSON payload in an easy to read report format."""
            print("Prompt" + prompt)
            result = invoke_claude_3_with_text(prompt+"\n\nJSON data:\n" + json.dumps(filedata))
            english_description = result.get("content", [{}])[0].get("text", "")
            
            notif_data['MaintNotifLongTextForEdit'] = english_description
            notif_data['TechnicalObject'] = configItem[0]['sapequi']
            notif_data['TechObjIsEquipOrFuncnlLoc'] = 'EAMS_EQUI'
            notif_data['MaintenancePlanningPlant'] = '1710'
            notif_data['MaintenancePlannerGroup'] = '920'

            create_request_url = get_odata_url(NOTIF_SERVICE) + "MaintenanceNotification"
            print(create_request_url)
            create_request_payload = notif_data

            try:
                csrf_token, cookie_value = get_csrf_token(create_request_url)
                response = post_odata_request(create_request_url, create_request_payload, csrf_token, cookie_value)
                print('Response Headers:')
                print(response.headers)

                if response.status == 201:
                    sap_message = response.headers.get('location')
                    if sap_message:
                        notification_number = sap_message
                        print('Notification created successfully.')
                        print('Notification Number:', notification_number)
                        #print("response is "+ response.data.decode('utf-8'))
                        
                        # Write the response to an output S3 file
                        current_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
                        output_key = f"output/{configItem[0]['sapequi']}_{current_datetime}.json"
                        output_data = {
                            'inputData': filedata,
                            'notificationNumber': notification_number,
                            'serviceresponse': response.data.decode('utf-8'),
                            'englishDescription': english_description
                        }
                        S3client.put_object(Body=json.dumps(output_data), Bucket=bucket, Key=output_key)
                        print(f"Output file written to S3: {bucket}/{output_key}")
                    else:
                        print('Notification created successfully, but unable to extract notification number from the response headers.')
                else:
                    print(f"Error: {response.status} - {response.reason}")
            except Exception as ex:
                print(ex)

    except Exception as e:
        traceback.print_exc()
        return e

def invoke_claude_3_with_text(prompt):
    """
    Invokes Anthropic Claude 3 Sonnet to run an inference using the input
    provided in the request body.
    :param prompt: The prompt that you want Claude 3 to complete.
    :return: Inference response from the model.
    """
    # Initialize the Amazon Bedrock runtime client
    client = boto3.client(service_name="bedrock-runtime", region_name="us-east-1")

    # Invoke Claude 3 with the text prompt
    model_id = "anthropic.claude-instant-v1"
    try:
        response = client.invoke_model(
            modelId=model_id,
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1024,
                    "messages": [
                        {
                            "role": "user",
                            "content": [{"type": "text", "text": prompt}],
                        }
                    ],
                }
            ),
        )
        # Process and print the response
        #content = response.get("body").read()
        result = json.loads(response.get("body").read())
        input_tokens = result["usage"]["input_tokens"]
        output_tokens = result["usage"]["output_tokens"]
        output_list = result.get("content", [])
        print("Invocation details:")
        print(f"- The input length is {input_tokens} tokens.")
        print(f"- The output length is {output_tokens} tokens.")
        print(f"- The model returned {len(output_list)} response(s):")
        for output in output_list:
            print(output["text"])
        return result
    except Exception as err:
      print(err)

def get_odata_url(service):
    return service

def get_csrf_token(url):
    auth_response = smclient.get_secret_value(
        SecretId=os.environ.get('SAP_AUTH_SECRET')
    )

    sapauth = json.loads(auth_response['SecretString'])
    username = sapauth['Username']
    password = sapauth['Password']

    http = urllib3.PoolManager()

    headers = urllib3.make_headers(basic_auth=f"{username}:{password}")
    headers['x-csrf-token'] = 'fetch'
    headers['Accept'] = '*/*'
    headers['Connection'] = 'keep-alive'
    headers['Accept-Encoding'] = 'gzip, deflate'

    response = http.request('GET', url, headers=headers)
    csrf_token = response.headers.get('x-csrf-token', '')
    cookies = response.headers.get_all('Set-Cookie')

    cookie_value = '; '.join([cookie.split(';')[0] for cookie in cookies])

    return csrf_token, cookie_value

def post_odata_request(url, payload, csrf_token, cookie_value):
    auth_response = smclient.get_secret_value(
        SecretId=os.environ.get('SAP_AUTH_SECRET')
    )

    sapauth = json.loads(auth_response['SecretString'])
    username = sapauth['Username']
    password = sapauth['Password']

    http = urllib3.PoolManager()

    headers = urllib3.make_headers(basic_auth=f"{username}:{password}")
    headers['Content-Type'] = 'application/json'
    headers['Accept'] = 'application/json'
    headers['x-csrf-token'] = csrf_token
    headers['Connection'] = 'keep-alive'
    headers['Accept-Encoding'] = 'gzip, deflate'
    headers['Cookie'] = cookie_value

    encoded_payload = json.dumps(payload).encode('utf-8')
    response = http.request('POST', url, body=encoded_payload, headers=headers, preload_content=False)

    return response

if __name__ == '__main__':
    # Test the functions
    notif_url = get_odata_url(NOTIF_SERVICE) + "MaintenanceNotification"
    test_payload = {
        "NotificationText": "Test Notification",
        "NotificationType": "M1",
        "TechnicalObject": "TestEqui",
        "TechObjIsEquipOrFuncnlLoc": "EAMS_EQUI",
        "MaintNotifLongTextForEdit": "This is a test notification."
    }

    csrf_token, cookie_value = get_csrf_token(notif_url)
    response = post_odata_request(notif_url, test_payload, csrf_token, cookie_value)

    if response.status == 201:
        print('Notification Number: ' + json.loads(response.data.decode('utf-8'))['d']['MaintenanceNotification'])
    else:
        print(f"Error: {response.status} - {response.reason}")