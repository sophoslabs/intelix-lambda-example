#  Copyright (c) 2020. Sophos Limited
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import boto3
import hashlib
import os
import requests
import time
import uuid
import json
from urllib.parse import unquote_plus


access_token = "" # Access token provided after login


def login():
    global access_token
    
    # If we already have a token then don't login again
    if not access_token == "":
        return
        
    # Make sure that the login credentials have been supplied in an environment variable
    if 'INTELIX_CREDENTIALS' not in os.environ:
        print("ERROR: Missing credentials, please set environment variable INTELIX_CREDENTIALS")
        exit(1)
    intelix_credentials = os.environ['INTELIX_CREDENTIALS']
    # Setup the authorization header using credentials supplied
    auth_string = "Basic " + intelix_credentials
    headers = {"Authorization": auth_string}
    data = {"grant_type": "client_credentials"}
    response = requests.post("https://api.labs.sophos.com/oauth2/token", data=data, headers=headers)
    # Get the access token from the response, or exit due to login failure
    try:
        access_token = response.json()['access_token']
    except Exception as e:
        print("ERROR: Could not login")
        exit(1)


def get_analysis(filename, url):
    # Setup the request with authorization and the file as the data
    login()
    headers = {"Authorization": access_token}
    files = {"file": open(filename, 'rb')}
    response = requests.post(url, headers=headers, files=files)
    # Response 200 means that the report has been provided in the response
    if response.status_code == 200:
        return response
    # Response 202 means that the job is in progress and we need to wait for the response
    elif response.status_code == 202:
        jobId = response.json()["jobId"]
        report_url = url + "reports/" + jobId
        # Poll every 5 seconds for the job to complete
        # checking status code 200 is complete, 202 is in progress
        for i in range(240):  # 20 minutes, based on breathing space for Dynamic analysis at 15min
            time.sleep(5)
            response = requests.get(report_url, headers=headers)
            if response.status_code == 200:
                return response
            if response.status_code != 202:
                break


def get_hash(filename):
    # Read in the file in blocks. Generate SHA256 hash of the file
    file_hash = hashlib.sha256()
    with open(filename, "rb") as file:
        for block in iter(lambda: file.read(4096), b""):
            file_hash.update(block)

    return file_hash.hexdigest()


def cloud_lookup(file_hash):
    # Based on the SHA256 get the score of the file from Cloud Lookup - File Reputation
    login()
    headers = {"Authorization": access_token}
    url = "https://de.api.labs.sophos.com/lookup/files/v1/" + file_hash
    response = requests.get(url, headers=headers)
    score = response.json()['reputationScore']
    print("Score: " + str(score))
    print("Raw response: \n" + json.dumps(json.loads(response.text), indent=4))
    return score


def static_analysis(filename):
    # Send the file for Static analysis and return the score
    url = "https://de.api.labs.sophos.com/analysis/file/static/v1/"
    response = get_analysis(filename, url)
    print("Score: " + str(response.json()["report"]["score"]))
    print("Raw response: \n" + json.dumps(json.loads(response.text), indent=4))
    return response.json()["report"]["score"]


def dynamic_analysis(filename):
    # Send the file for dynamic analysis and return the score
    url = "https://de.api.labs.sophos.com/analysis/file/dynamic/v1/"
    response = get_analysis(filename, url)
    print("Score: " + str(response.json()["report"]["score"]))
    print("Raw response: \n" + json.dumps(json.loads(response.text), indent=4))
    return response.json()["report"]["score"]


def complete_check_for_malware(filename):
    # Work through the available services to find out if the file is malcious
    # 1. Cloud Lookup
    # 2. Static Analysis
    # 3. Dynamic Analysis

    # If the score is <20 then the file is malicious
    # If the score is >70 then the file is clean
    # Any other score and the next level of analysis is required

    file_hash = get_hash(filename)
    print("Running a cloud lookup...")
    lookup_score = cloud_lookup(file_hash)

    if lookup_score < 20:
        print("File is malicious based on Cloud lookup!!!")
        return True
    elif lookup_score >= 70:
        print("File is clean based on Cloud lookup.")
        return False
    
    print("Proceeding to static analysis...")
    static_score = static_analysis(filename)
    if static_score < 20:
        print("File is malicious based on Static Analysis!!!")
        return True
    elif static_score > 70:
        print("File is clean based on Static Analysis.")
        return False
    
    print("Proceeding to dynamic analysis...")
    dynamic_score = dynamic_analysis(filename)
    if dynamic_score < 20:
        print("File is malicious based on Dynamic Analysis!!!")
        return True
    else:
        print("File is clean based on Dynamic Analysis.")
        return False


def file_check_handler(event, context):
    print("Event is: {}".format(event))
    print("Context is: {}".format(context))

    s3_client = boto3.client("s3")

    bucket = event["Records"][0]["s3"]["bucket"]["name"]
    key = unquote_plus(event["Records"][0]["s3"]["object"]["key"])
    tmpkey = key.replace("/", "")
    download_path = '/tmp/{}{}'.format(uuid.uuid4(), tmpkey)
    s3_client.download_file(bucket, key, download_path)
    if complete_check_for_malware(download_path) == True:
        print("This file CONTAINS MALWARE!! Removing file upload... s3://" + bucket + "/" + key)
        # Delete file that is detected as malware
        s3_client.delete_object(Bucket=bucket, Key=key)
    else:
        output_bucket = os.environ['OUTPUT_BUCKET']
        print("This file is clean, copying to our clean output bucket: " + str(output_bucket))
        copy_source = {
            'Bucket': bucket,
            'Key': key
        }
        # Copy the file to the clean data bucket
        s3_client.copy(copy_source, output_bucket, key)
        # Remove file from input bucket
        s3_client.delete_object(Bucket=bucket, Key=key)


if __name__ == "__main__":
    event = []
    context = []

    # Ask the user for a file to scan
    print("Test a file for malware using SophosLabs Intelix")
    filename = input("Please enter a filename: ")
    print("File being analyzed is {}".format(filename))
    complete_check_for_malware(filename)
