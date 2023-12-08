'''
This script serves to systematically scan URLs containing IP addresses and their associated port numbers. 
It begins by initializing essential variables and parameters, creating application_name and target_name for each component. 
It then initiates the scanning process for each component using the required parameters,  authentication credentials.
During scanning, vulnerabilities are identified and counted for each component. 
Following successful scanning, the script generates comprehensive reports, encompassing vulnerability counts (e.g., critical, high, medium, low) and build information specific to the scanned components. 
Finally, these reports are sent via email to designated recipients, providing them with detailed report...!!!! 
'''

'''
    Positional Arguments: 

    - username (str): The username for authentication.
    - password (str): The password for authentication.
    - application_name (str): The name of the application.
    - target_name (str): The name of the target.
    - component_name (str): The name of the component.
    - secret_description (str): The description of the secret.

    - scan_type (str): The type of scan.
    - sender (str): The sender's email address.
    - Recievers (list): List of recipients' email addresses.
    - ftp_server (str): The FTP server address.
    - ftpdir (str): The directory on the FTP server.
    - ftpuser (str): The FTP server username.
    - ftppassword (str): The FTP server password. 


    The Following properties content should be provided in the properties file:

    - Application_name : Name of the application that you have created in the Solis UI
    - Ftp_server,ftp_username,ftp_password : Ftp details which is to be provided from where you will pick the COP/.iso
    - Secret_description : Required field for the scan configurations in order to get the scan_id and to start the scan.
                           (user can give any description)

                           "Secrets are the encrypted documents which is used for authenticating the scans against your targets
                           which has two fields - Name, Description after giving this it will give the secret_id"
    
    - scan_type : ZAP/SSL  , you can go with either SSL which is  "Crypto Scanning" or ZAP which is "Web Application Scanning"
    - Sender_mail : webexcce-securityscan@cisco.com ,this is the generic email that we are using for sending the mail
    
'''

import requests
import json
import configparser
import smtplib
import time
from urllib.parse import quote_plus
from configparser import ConfigParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from tabulate import tabulate
import os
import re
import ast
import logging
from datetime import datetime
import sys
from email.mime.base import MIMEBase
from email import encoders
import subprocess
from ftplib import FTP,error_perm,all_errors

sys.path.append('C:\\ucce_auto\\TestAutomation\\common\\python')
sys.path.append('C:\\ucce_auto\\TestAutomation\\FunctionalFramework\\scripts')
sys.path.append('C:\\ucce_auto\\TestAutomation\\FunctionalFramework\\Jenkins\\scripts\\python')

# from UpgradeAndCheckVos import getisoversion
# from UpgradeAndCheckICM import connectFTP



config= configparser.ConfigParser()

# Configures the logging system with a specific log message format.
#  Create a logger instance
#  Set the logging level to INFO

logging.basicConfig(format='%(asctime)s %(message)s')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Defines a custom authentication class 'BearerAuth' for adding Bearer tokens to HTTP requests.
# The constructor '__init__' initializes the class with a Bearer token.
# The method '__call__' modifies an HTTP request by adding the Bearer token to its headers.

class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["Authorization"] = f"Bearer {self.token}"
        return r
    
#  This class represents a Solis instance and its attributes.
#  It is designed to hold various parameters related to the Solis application.

class Solis:
    
    def __init__(self,username,password,application_name,target_name,component_name,secret_description,scanning_type,sender,Recievers,binary_file_path):
        self.token=None
        self.username=username
        self.password=password
        self.application_name=application_name
        self.target_name=target_name
        self.component_name=component_name
        self.secret_description=secret_description
        self.scanning_type=scanning_type
        self.sender=sender
        self.Recievers=Recievers
        self.binary_file_path=binary_file_path

    # Perform signup by sending a GET request to the signup URL using the username and password for authentication.
    # Parse the JSON response from the signup request.
    # Extract the token from the JSON response and store it in the instance.     
    
    def signup_and_get_token(self):

        logger.info("--------------------Signup-------------------------")
        sign_url = 'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/login'
        sign_res = requests.get(sign_url, auth=(self.username, self.password))
        sign_json = sign_res.json()
        logger.info("Authentication done........")
        tok_en = sign_json['token']
        self.token=tok_en
 
    # This method retrieves the ID of the specified application using the stored token.
    # It first sends the Get request to the application URL with the stored Bearer token for authentication
    # Parse the JSON response to get the application information
    # Then it iterate through the list of applications to find the matching application name which user will give via the jenkins parameter
    # in return it will give the application id.

    def get_application_id(self):

        app_url = 'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/apps'
        app_res = requests.get(app_url, auth=BearerAuth(self.token))
        app_json = app_res.json()
        app_id = None
        for app in app_json["apps"]:
            if app["name"] == self.application_name:
                app_id = app["_id"]
                break
        if app_id is not None:
            logger.info(f"The Application ID: {app_id}")
        else:
            logger.info(f"{self.application_name} not found.")
        return app_id
    
    # This method retrieves the ID of the specified target using the stored token.
    # It first sends the Get request to the target URL with the stored Bearer token for authentication
    # Parse the JSON response to get the target information
    # Then it iterate through the list of targets to find the matching target name which user will give via the jenkins parameter
    # in return it will give the target id.

    def get_target_id(self):
        targets_url = 'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/targets'
        targets_res = requests.get(targets_url, auth=BearerAuth(self.token))
        targets_json = targets_res.json()
        target_id = None
        for target in targets_json["targets"]:
            if target["name"] == f"{self.target_name}":
                target_id = target["_id"]
                break
        if target_id is not None:
            logger.info(f"The Target ID is: {target_id}")
        return target_id
    
    # This method retrieves the ID of the specified target using the stored token.
    # It first sends the Get request to the target URL with the stored Bearer token for authentication
    # Parse the JSON response to get the chariot information
    # Then it iterate through the list of chariots to find the matching target name which user will give via the jenkins parameter
    # In return it will give the chariot id. 
    # Chariot_id is needed basically for scan configurations which is internally generated...

    def get_chariot_id(self):
        chariots_url = 'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/chariots'
        chariots_res = requests.get(chariots_url, auth=BearerAuth(self.token))
        chariots_json = chariots_res.json()
        chariots_id = chariots_json['chariots'][0]['_id']
        return chariots_id
    
    # This method generates a secret configuration name based on the component name and current datetime.
    # Get the current datetime in the format "YYYY-MM-DD_HH:MM:SS".
    # Construct the secret configuration name using the component name and current datetime.
    # Log the generated secret configuration name.

    def generate_secret_config_name(self):
        current_datetime = time.strftime("%Y-%m-%d_%H:%M:%S")
        secretconfig_name = f"{self.component_name}_{current_datetime}"
        logger.info("scan secret: %s" % secretconfig_name)
        return secretconfig_name
    
    # This method creates a secret configuration for the specified application using the provided information.
    # Two parameters will be passed for the getting the secret_id in return i.e.
    # app_id and secretconfig_name

    def create_secret_configuration(self, app_id, secretconfig_name):
        secret_data = {
            "name": secretconfig_name,
            "description": self.secret_description,
            "config": {"num": "1"}
        }
        secret_json = json.dumps(secret_data)
        secret_url = f'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/apps/{app_id}/config-secrets'
        secret_res = requests.post(secret_url, auth=BearerAuth(self.token), data=secret_json, headers = {
        "Accept": "application/json",
        "Content-type": "application/json",
        "Authorization": f"Bearer {self.token}"
        })
        secret_json = secret_res.json()
        secret_id = secret_json['_id']
        return secret_id

    # This method configures a scan with HAR files for the specified application.
    # Initialize variables for external files and HAR files.
    # Iterate through the provided file names and paths.
    # Define the URL for file upload.
    # It then sends a POST request to upload the file to the specified application.
    # Parse the JSON response to retrieve the URL and fields for S3 upload.
    # Upload the HAR file to S3 using the obtained URL and fields.
    # Generate a unique scan configuration name using the component name and current datetime.

    def scan_config_har(self,app_id,chariots_id,file_names,paths):

        external_files_str = ""
        har_files_list = []

        for path, file_name in zip(paths,file_names):

            fileupload_data = {
                "filename": f"{file_name}",
                "description": f"{file_name} har file "
            }

            fileupload_data = json.dumps(fileupload_data)
            fileupload_url = f'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/apps/{app_id}/files'
            fileupload_res = requests.post(fileupload_url, auth=BearerAuth(self.token), data=fileupload_data,headers = {
            "Accept": "application/json",
            "Content-type": "application/json",
            "Authorization": f"Bearer {self.token}"
            })
            fileupload_json = fileupload_res.json()
            # print(fileupload_json)

            url = fileupload_json['url']
            fields = fileupload_json['fields']

            # Upload HAR file to S3
            with requests.Session() as request_session:
                with open(path, "rb") as input_file:
                    response = request_session.post(
                        url,
                        data=fields,
                        files={"file": input_file},
                    )

                if response.status_code == 200 or response.status_code == 204:
                    logger.info("File uploaded successfully.")
                else:
                    logger.info(f"File upload failed with status code: {response.status_code}")

            if external_files_str:
                external_files_str += ","
            external_files_str += f"{file_name}:/solis/external_files/{file_name}"

            har_files_list.append(f"/solis/external_files/{file_name}")
       
        # Generate unique scan configuration name
        current_datetime = time.strftime("%Y-%m-%d_%H:%M:%S")
        scan_config_name = f"{self.component_name}_{current_datetime}"

        # Create scan configuration
        data_json_scanconfig = {
            "name": scan_config_name,
            "chariot_id": chariots_id,
            "config": {
                "external_files":external_files_str, 
                "har_files": har_files_list,
                "active_scanners":["6","20012","20016","20019","40009","40012","40014","40016","40017","40018","40019","40020","40021","40022","40024","40026","40027","80001","80002","80004","80005","80006","80008","80009","90019","90020","90021","90023"],
                "auth_method": "bearer",
                "auth_access_token": self.token,
                "using_jwt": True,
                "passive_scanners": "all"
            },
            "scope": [
                {
                    "app_id": app_id,
                    "role": "admin"
                }
            ]
        }
        # logger.info(json.dumps(data_json_scanconfig, indent=4))
        return data_json_scanconfig
    
    # This method configures a scan with a list of URLs for the specified application.
    # Generate a unique scan configuration name using the component name and current datetime.

    def scan_config_url(self,app_id,chariots_id,url_list1):
            current_datetime = time.strftime("%Y-%m-%d_%H:%M:%S")
            scan_config_name = f"{self.component_name}_{current_datetime}"
           
            data_json_scanconfig = {
                "name": scan_config_name,
                "chariot_id": chariots_id,
                "config": {
                    "url_list": url_list1.split(","),
                    "auth_method": "bearer",
                    "auth_access_token": self.token
                },
                "scope": [
                    {
                        "app_id": app_id,
                        "role": "admin"
                    }
                ]
            }
            return data_json_scanconfig
    
    # This method creates a scan configuration and retrieves its ID.
    # Send a POST request to create the scan configuration with the provided data.
    # Parse the JSON response to get the scan configuration information.
    # Log the start of the scan configuration creation process.
    # Log the scan configuration JSON response.
    # Retrieve and log the scan configuration ID.

    def get_scan_config_id(self, data_json_scanconfig):
        Scanconfig_url = 'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/scan-configs'
        Scanconfig_res_post = requests.post(Scanconfig_url, auth=BearerAuth(self.token), data=data_json_scanconfig)
        scanconfig_json = Scanconfig_res_post.json()
        logger.info("--------------------------------ScanConfig-START---------------------------")
        scanconfig_id = scanconfig_json['_id']
        logger.info("Scan Configurations for component is in progress ..!!!")
        time.sleep(15)
        logger.info("Configurations for the required component is done....!!!")
        time.sleep(5)
        logger.info("Generated scanconfig id is : %s" %scanconfig_id)
        logger.info("--------------------------------ScanConfig-END---------------------------")
        return scanconfig_id

    # This method starts a scan for the specified application, target, and scan configuration.
    # Prepare data for starting the scan including scan type, chariot ID, and scan configuration ID.
    # Send a POST request to start the scan with the provided data.
    # start the scan process.
    # Retrieve and log the scan ID.

    def Start_scan(self,app_id,target_id,chariots_id,scanconfig_id):
        
        start_scan_data = {
            "scan_type": self.scanning_type,
            "chariot_id": chariots_id,
            "config": {},
            "scan_config_ids": [
                scanconfig_id
            ]
        }

        start_scan_data = json.dumps(start_scan_data)
        start_scan_url = f'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/apps/{app_id}/targets/{target_id}/scans'
        start_scan_res = requests.post(start_scan_url, auth=BearerAuth(self.token), data=start_scan_data,headers = {
        "Accept": "application/json",
        "Content-type": "application/json",
        "Authorization": f"Bearer {self.token}"
            
        })
        start_scan_json = start_scan_res.json()
        logger.info("**************************Scan-START****************************************************")
        logger.info(start_scan_json)
        scan_id = start_scan_json['scan']['_id']
        logger.info("Generated scan id is : %s" %scan_id)
        logger.info("***************************Scan-END****************************************************")
        return scan_id

    # This method retrieves scan result values including vulnerability counts and artifact details.
    # Initialize variables for vulnerability counts and artifact details.
    # Continuously check the status of the scan until it is 'SUCCEEDED'.
    # Handle token reauthentication after a certain interval to ensure a fresh token is used.
    # If it's time to reauthenticate, obtain a fresh token.
    # If the scan status is 'SUCCEEDED', retrieve and log vulnerability counts and artifact details.
    # If the scan status is 'ERRORED', log the error and raise an exception.
    # If the scan status is 'RUNNING', log that the scan is still running and wait.
    # Return vulnerability counts and artifact details upon successful completion.

    def get_value(self,scan_id):
        total = ""
        critical = ""
        high = ""
        medium = ""
        low = ""
        informational = ""

        reauth_interval_in_s = 900  # Reauthentication after 30 minutes
        reauth_time = time.time() + reauth_interval_in_s

        logger.info("Scan got Submitted")
        while (True):

            if time.time() > reauth_time:
                sign_url = 'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/login'

                sign_res = requests.get(sign_url, auth=(self.username, self.password))

                sign_json = sign_res.json()  # ----Converting the response into json format---#

                # token = sign_json['token']
                tok_en = sign_json['token']
                reauth_time = time.time() + reauth_interval_in_s
                logger.info("...........Reauthentication..............")
                self.token = tok_en

            url = f'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/scans/{scan_id}'

            
            status_respnse = requests.get(url, auth=BearerAuth(self.token))

            status_json = status_respnse.json()

            if status_json['status'] == "SUCCEEDED":
                
                artifact_key = status_json['artifact_details']['s3_objects']

                total = status_json['failures']['total']
                critical = status_json['failures']['critical']
                high = status_json['failures']['high']
                medium = status_json['failures']['medium']
                low = status_json['failures']['low']
                informational = status_json['failures']['informational']
                logger.info("Scan Succeeded")

                break

            elif status_json['status'] == "ERRORED":

                logger.info(status_json['status'])
                logger.info("Scan encountered an error")
                raise Exception("An errored occured. Stopping the script !!!")
            elif status_json['status'] == "RUNNING":
                logger.info("Scan is running")

            time.sleep(100)

        return total,critical,high,low,medium,informational,artifact_key

    # This method deletes a secret configuration for the specified application.
    # Send a DELETE request to delete the secret configuration.
    # Check the response status code to determine if the deletion was successful.
    # Log an error message if the deletion fails.

    def delete_configs_secrets(self,app_id, secret_id):
        delete_secret_url = f'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/apps/{app_id}/config-secrets/{secret_id}'
        delete_secret_res = requests.delete(delete_secret_url,auth=BearerAuth(self.token),headers = {
        "Accept": "application/json",
        "Content-type": "application/json",
        "Authorization": f"Bearer {self.token}"
        })
        if (delete_secret_res.status_code != 204):
            logger.error("Failed to delete secret.....")
    
    # This method deletes a existing_file for the specified application.
    # Send a DELETE request to delete the existing_file.
    # Check the response status code to determine if the deletion was successful.
    # Log an error message if the deletion fails. 

    def delete_existing_file(self,app_id,file_name):
        delete_file_url = f'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/apps/{app_id}/files/{file_name}'
        delete_file_res = requests.delete(delete_file_url, auth=BearerAuth(self.token),headers = {
        "Accept": "application/json",
        "Content-type": "application/json",
        "Authorization": f"Bearer {self.token}"
        })
        if (delete_file_res.status_code != 204):
            logger.error(f"Failed to delete file '{file_name}'")

    # This method retrieves the HTML scan results from the specified scan's artifacts.
    # Iterate through the artifact keys to find the HTML scan results file.
    # Send a GET request to retrieve the HTML scan results.
    # Return the HTML scan results data.        

    def retrieve_scan_results_html(self,scan_id, artifact_key):
        for each_item in artifact_key:
            if re.search("scan_log.html", each_item):
                final_link = each_item.replace("/", "%2F")
        artifact_url = f'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/scans/{scan_id}/artifacts/' + final_link
        artifact_res = requests.get(artifact_url,auth=BearerAuth(self.token),headers = {
        "Accept": "application/json",
        "Content-type": "application/json",
        "Authorization": f"Bearer {self.token}"
        })
        data = artifact_res.text
        return data
    
    # This method parses HTML scan results data and generates HTML tables with CSS styling.
    # Define a nested function `get_results` to extract relevant data from the HTML.
    # Split the HTML data into lines.
    # Search for the line containing 'window.output["stats"]' to identify the relevant data.
    # Parse the relevant data and return it.
    # Define a nested function `total_results` to calculate the total count of results.
    # Generate table rows in HTML format.
    # Extract and format data for three separate tables.
    # Combine the CSS styles and HTML tables into a complete HTML report.
    # Return the complete HTML report.

    def parse_scan_results(self,data):
        def get_results(self,html):
            res = html.split("\n")
            for each_item in res:
                if 'window.output["stats"]' in each_item:
                    replace_out = each_item.replace('window.output["stats"] = ', '').strip()
                    replace_semi = replace_out.replace(";", "")
                    final_result = ast.literal_eval(replace_semi)
                    return final_result

        def total_results(self,Pass_count, Fail_count):
            return Pass_count + Fail_count

        def generate_table_rows(self,data):
            rows = ""
            for row in data:
                cells = [
                    f"<td style='text-align: left; background-color: #DCDCDC; border: 1px solid black; padding: 8px;'>{cell}</td>"
                    for cell in row]
                rows += "<tr>" + "".join(cells) + "</tr>"
            return rows

        out = get_results(self,data)

        # Formatting data for the first table
        table_data = out[0]
        table_headers = ['Statistics by Tag', 'Pass', 'Fail', 'Total', 'Elapsed']
        table_data_formatted = [
            [row['label'], row['pass'], row['fail'], total_results(self,row['pass'], row['fail']), row['elapsed']] for row in
            table_data]

        # Formatting data for the second table
        table_data1 = out[1]
        table_headers1 = ['Statistics by Tag', 'Pass', 'Fail', 'Total', 'Elapsed']
        table_data_formatted1 = [
            [row['label'], row['pass'], row['fail'], total_results(self,row['pass'], row['fail']), row['elapsed']] for row in
            table_data1]

        # Formatting data for the third table
        table_data2 = out[2]
        table_headers2 = ['Statistics by Tag', 'Pass', 'Fail', 'Total', 'Elapsed']
        table_data_formatted2 = [
            [row['label'], row['pass'], row['fail'], total_results(self,row['pass'], row['fail']), row['elapsed']] for row in
            table_data2]

        # Generating CSS styles
        css_styles = """
        <style>
            .table {
                font-size: 1.0em;
                font-family: Calibri;
                width: 100%;
                border-collapse: collapse;
            }

            .caption {
                background-color: #60A3D9;
                color: #000000;
                height: 10px;
            }

            .header {
                background-color: #DCDCDC;
                color: #ffffff;
                height: 10px;
                font-weight: bold;
            }

            .header th {
                background-color: #BFD7ED;
                color: #000000;
                text-align: center;
                font-weight: bold;
                border: 1px solid black;
                padding: 8px;
            }

            .data td {
                text-align: center;
                background-color: #DCDCDC;
                border: 1px solid black;
                padding: 8px;
            }

            .data td:first-child {
                text-align: left;
                background-color: #DCDCDC;
                color: #000000;
                border: 1px solid black;
                padding: 8px;
            }
        </style>
        """

        # Generating HTML table for the first table with CSS styling
        table_html = f"""
        <table class="table">
            <caption class="caption"></caption>
            <thead>
                <tr class="header">
                    {"".join(f"<th class='header'>{header}</th>" for header in table_headers)}
                </tr>
            </thead>
            <tbody>
                {generate_table_rows(self,table_data_formatted)}
            </tbody>
        </table>
        """

        # Generating HTML table for the second table with CSS styling
        table_html1 = f"""
        <table class="table">
            <caption class="caption"></caption>
            <thead>
                <tr class="header">
                    {"".join(f"<th class='header'>{header}</th>" for header in table_headers1)}
                </tr>
            </thead>
            <tbody>
                {generate_table_rows(self,table_data_formatted1)}
            </tbody>
        </table>
        """

        # Generating HTML table for the third table with CSS styling
        table_html2 = f"""
        <table class="table">
            <caption class="caption"></caption>
            <thead>
                <tr class="header">
                    {"".join(f"<th class='header'>{header}</th>" for header in table_headers2)}
                </tr>
            </thead>
            <tbody>
                {generate_table_rows(self,table_data_formatted2)}
            </tbody>
        </table>
        """

        html = css_styles + "<br>" + table_html + "<br>" + table_html1 + "<br>" + table_html2
        return html

    # This method retrieves the summary of vulnerabilities from the previous scan of a target.
    # Send a GET request to retrieve scan data.
    # Extract the relevant vulnerability summary data from the response.

    def get_previous_vulnerability_summary(self,app_id, target_id):
        scans_url = f'https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production/apps/{app_id}/targets/{target_id}/scans'
        scans_res = requests.get(scans_url,auth=BearerAuth(self.token),headers = {
        "Accept": "application/json",
        "Content-type": "application/json",
        "Authorization": f"Bearer {self.token}"
        })
        scans_json = scans_res.json()

        pre_total = scans_json['scans'][1]['failures']['total']
        pre_critical = scans_json['scans'][1]['failures']['critical']
        pre_high = scans_json['scans'][1]['failures']['high']
        pre_medium = scans_json['scans'][1]['failures']['medium']
        pre_low = scans_json['scans'][1]['failures']['low']
        pre_informational = scans_json['scans'][1]['failures']['informational']
        
        return pre_total, pre_critical, pre_high, pre_medium, pre_low, pre_informational
    
    # This method downloads a zip file artifact associated with a scan, given its scan ID and target ID,
    # and saves it to the specified output path in the Jenkins workspace.

    def zip_file(self,scan_id,target_id,jenkins_path):
        base_url = "https://iqdccg7dpa.execute-api.us-east-1.amazonaws.com/production"

        headers = {
            "Authorization": f"Bearer {self.token}"
        }
        
    # Construct the output path where the downloaded zip file will be saved in the Jenkins workspace.
        output_path = os.path.join(jenkins_path, f"{self.component_name}.zip")
        
        # Encode the artifact name since it will contain forward slashes.
        encoded_artifact = quote_plus(f"{target_id}/{scan_id}/results.zip")

        get_presigned_url_resp = requests.get(
            f"{base_url}/scans/{scan_id}/artifacts/{encoded_artifact}",
            headers=headers,
            allow_redirects=False
        )
        # Download the artifact using the pre-signed URL in the Location response header.
        download_artifact_resp = requests.get(
            get_presigned_url_resp.headers["Location"]
        )
        # Response will be the binary data for the archive.
        # Write that data to a file.
        with open(output_path, "wb") as f_out:
            f_out.write(download_artifact_resp.content)
            
        return output_path  
        
    
    def ImageName(self):
        path = self.binary_file_path
        binary_file_name = ""
        for file in os.listdir(path):
            binary_file_name = file

        return binary_file_name
    

    def send_mail(self,app_id, scan_id,SprintNo,component_name,binary_file_path, total, pre_total, pre_critical,
                critical, pre_high, high, medium, pre_medium, informational, pre_informational, pre_low,low,jenkins_workspace_link,
                  secret_id,html):
        
        msg = MIMEMultipart('alternative')
        link = f"https://solis.cisco.com/v1/apps/{app_id}?selectedScan={scan_id}"
        link2= f"{jenkins_workspace_link}"
        text1 = f"<b>Hello Team,</b><br><br>Your <b> <font style='#4051b5'> {component_name} </font> </b> Scan Report is Ready to View.<br>"
        text2 = f"<br>The Build information for Scanned Component in <b> {SprintNo} </b> is : <b> {binary_file_path} </b> <br>"
        text3 = f"<br> You can access the Report using this <a href = '{link}'> https://solis.cisco.com/v1/apps/{app_id}?selectedScan={scan_id} </a>"
        text4 = f"<b><br><br>Vulnerability Count Summary</b> --<font style='#000000'><b> Total </font> : {total} | <font style='color:#e2231a'> Critical </font> : {critical} | <font style='color:#f66a0a'> High </font> : {high} | <font style='color:#fbab18'> Medium  </font>: {medium} | <font style='color:#eed202'> Low </font>: {low} | <font style='color:#1e4471'> Informational </font> : {informational}</b><br>"
        text5 = f"<b>Previous Vulnerability Count Summary</b> --<font style='#000000'><b> Total </font> : {pre_total} | <font style='color:#e2231a'> Critical </font> : {pre_critical} | <font style='color:#f66a0a'> High </font> : {pre_high} | <font style='color:#fbab18'> Medium  </font>: {pre_medium} | <font style='color:#eed202'> Low </font>: {pre_low} | <font style='color:#1e4471'> Informational </font> : {pre_informational}</b><br>"
        text6 = f"<br>To get comprehensive information regarding vulnerabilities, kindly click on this link : <a href = '{link2}'> {jenkins_workspace_link} </a> <br><br>" 
        msg['Subject'] = f" Your {component_name} target Report is Ready to View "
        msg['From'] = self.sender
        msg['To'] =  ','.join(self.Recievers)

        
        mail_body = MIMEText('<html><body>' + text1 + text2 + text3 + text4 + text5 + text6 + html + '</body></html>', 'html')

        msg.attach(mail_body)
        
        try:
            mail = smtplib.SMTP('outbound.cisco.com')
            mail.sendmail(self.sender, self.Recievers, msg.as_string())
            logger.info("your email has been sent successfully......!!!!!")
            logger.info(f"Your comprehensive reports has been downloaded into your jenkins workspace........")
        except Exception as e:
            logger.info(e)
     


