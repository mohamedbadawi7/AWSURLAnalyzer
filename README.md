This repo contains the lambda function I used to perform URL scans searching for malicious content.
To do this, I created an S3 bucket where urls would be added.
I created a Lambda function that is triggered by an EventBridge rule when a new url is added to that S3 bucket.
This lambda function reads the uploaded url(s) and then uses the urlscan.io api to check for malicious content in that url.
After the scan is complete, an email is sent via an SNS topic to subscribed emails indicating the result of the scan.
A scan takes 4 seconds to complete.

To make sure this architecture was functional, I needed to attach the following permissions to my Lambda functions execution role:
    - S3 Get Object API Request on that bucket with the url(s)
    - SNS Publish API Request (to the SNS topic I created)

I needed to enable data events in my account to ensure that S3 PUT API Requests were recorded as events.
I also needed to provide EventBridge permissions to listen for S3 PUT Events on that specific bucket.

All this was free to do on AWS and is very maintainable.