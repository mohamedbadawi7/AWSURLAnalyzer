import json
import boto3
import os
import urllib.request
import time

s3_client = boto3.client('s3')
sns = boto3.client('sns')
api_key = os.environ['API_Key']

def lambda_handler(event, context):

    # Print a simple message to confirm Lambda is executing
    bucket_name = event['detail']['requestParameters']['bucketName']
    file_key = event['detail']['requestParameters']['key']

    topic_arn = 'arn:aws:sns:us-east-1:590183818266:EmailResults'

    # Log the bucket name and file key
    print(f"Bucket Name: {bucket_name}")
    print(f"File Key: {file_key}")

    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
        content = response['Body'].read().decode('utf-8')
        print(f"File Content: {content}")

        urls = extract_urls(content)
        # print(f"Extracted URLs: {urls}")
        for url in urls:
            try:
                uuid = submit_url_for_scan(url, api_key)
                print("Waiting for scan to complete...")
                time.sleep(10)
                result = get_scan_result(uuid)
                verdict = result.get("verdicts", {}).get("overall", {}).get("malicious", False)
                if verdict:
                    print(f"Malicious content detected in {url}")

                    message = {
                        "subject": "{url} Analysis Complete",
                        "body": f"{url} Contains Malicious Content"
                    }

                    response = sns.publish(
                        TopicArn=topic_arn,
                        Message=json.dumps(message),
                        Subject='URL Scan Results'
                    )

                    print("SNS Publish Response:")
                    print(response)
                else:
                    print(f"No malicious content detected in {url}")

                    message = {
                        "subject": "{url} Analysis Complete",
                        "body": f"{url} Contains Not Malicious Content"
                    }

                    response = sns.publish(
                        TopicArn=topic_arn,
                        Message=json.dumps(message),
                        Subject='URL Scan Results'
                    )

                    print("SNS Publish Response:")
                    print(response)

            except Exception as e:
                print(f"Error submitting URL ' + {url} + 'for scan: {str(e)}")
 
        
    except Exception as e:
        print(f"Error accessing file in S3: {str(e)}")
        return {"error": str(e)}

def extract_urls(content):
    import re
    url_pattern = r'https?://[^\s"]+'
    return re.findall(url_pattern, content)

def submit_url_for_scan(url, api_key):

    payload = json.dumps({
        'url': url,
        'visibility': 'public'
    }).encode('utf-8')

    req = urllib.request.Request(
        'https://urlscan.io/api/v1/scan/',
        data=payload,
        headers={
            'API-Key': api_key,
            'Content-Type': 'application/json'
        },
        method='POST'
    )

    with urllib.request.urlopen(req) as response:
        return json.loads(response.read())['uuid']

def get_scan_result(uuid):
    url = f'https://urlscan.io/api/v1/result/{uuid}/'

    request = urllib.request.Request(
        url=url,
        method='GET'
    )

    response = urllib.request.urlopen(request)
    return json.loads(response.read().decode())