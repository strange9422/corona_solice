import configparser
import logging
import os
import smtplib  # to send the email
import sys
import time  # for sleep
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
from CoronaScan import *

from solisclass import *

import subprocess
import glob

start_time = time.time()

start_datetime = datetime.fromtimestamp(start_time)

start_time_str = start_datetime.strftime("%d-%m-%Y %H:%M:%S")

# Create and configure logger
logging.basicConfig(format='%(asctime)s %(message)s')

# Creating an object
logger = logging.getLogger()

# Setting the threshold of logger to INFO
logger.setLevel(logging.INFO)

if __name__=="__main__":

        
    config = configparser.ConfigParser()

    ScanType_Name=os.getenv("SCAN_TYPE")
    
    if(ScanType_Name=="CORONA"):

        #Reading the common configuration file 
        # config.read("Scan_Common_Config_File.ini")

        logger.info("----------Signing in------------")

        # reading generic credentials from the Scan_Common_Config_File.ini file

        logger.info("JENKINS CONFIGURATIONS PARAMERTERS ............")
            
        username = os.getenv('username')
        password = os.getenv('password')
        
        product_name = os.getenv("PRODUCT_NAME")
        logger.info("The product name :  %s"%product_name)

        psirt_name =os.getenv('PSIRT_NAME')
    
        logger.info("PSIRT Name : %s"%(psirt_name))

        cvr_product_metadata =os.getenv("CVR_PRODUCT_METADATA")

        
        logger.info("CVR PRODUCT METADATA : %s"%cvr_product_metadata)

        release_version=os.getenv('RELEASE_VERSION')
        logger.info("Release version  : %s"%release_version)

        security_contact= os.getenv("SECURITY_CONTACT")
        logger.info("Security contact Details: %s"%security_contact)

        engineering_contact =os.getenv("ENGINEERING_CONTACT")
        logger.info("Engineering contact details: %s"%engineering_contact)

        sprint_no = os.getenv('SSP_BUILD_SPRINT_NO')
        logger.info("Provided Sprint Number is %s"%sprint_no)


        binary_file_path = os.getenv('FILE_PATH')
        logger.info("Provided path of the image is %s"%binary_file_path)


        reusable_modules=os.getenv("REUSABLE_MODULE_NAME")
        if not reusable_modules:
            logger.info("The %s product not using resuable module  "%product_name)
            
        else:
            reusable_modules=reusable_modules.split(",")
            logger.info("Reusable module name : %s"%reusable_modules)
                    
        import_markup=os.getenv("RESCAN_OR_NEW_IMAGE")
        # sender=config['email']['sender'] # reading sender's mail from jenkins configurations to send the BOM Report
        sender=os.getenv('sender')
        logger.info("The sender mail: %s"%sender)

        receiver=os.getenv('RECEIVERS_MAILS')  #receivers mails
        recepients = receiver.split(",")
        logger.info("The receivers mails : %s"%recepients)



        
        
        corona_scan=CoronaScanAutomation(username,password,product_name,psirt_name,cvr_product_metadata,release_version,sprint_no,engineering_contact,
                                         security_contact,binary_file_path,reusable_modules,sender,recepients)
        
        """ Corona script will start from calling the AccessToken funtion to get authenticate into Corona and 
        
        - CreateProduct() function """
   
        access_token,sign_response=corona_scan.AccessToken()
        if(sign_response.status_code==200):
            logger.info("AUTHENTICATION DONE: Successfully logged-in to Corona .....")
        else:
            logger.info("AUTHENTICATION FAILED:  %s"%sign_response)    
        product_response= corona_scan.CreateProduct(access_token)
        product_response_json=product_response.json()

        """From the CreateProduct() will return the api json  reponsne , below code will check the if product is alreday existed in corona or not
        if conditions true , it for existed product it will fetch the product info , release info if the new release it will create new release and into that release it add binary , initiate scannig
        Else part will meant condition fails , it will release add binary into release and initiate scannning process post that report will send via mail """

        if(product_response.status_code==422 and product_response_json['message']=="Validation failed: Name has already been taken"):
            
            existed_product_id,existed_release_id,existed_release_version=corona_scan.get_release_info(access_token)
        
            
            #checks the version from corona database and user configuratios if it new release it will create new release , if not it will fetch the exsted product info
            #if(release_version!=existed_release_version):
            if(release_version  not in existed_release_version):
                logger.info("existed release%s"%(existed_release_version))
                logger.info("New version is found is %s"%(release_version))
                access_token,sign_response=corona_scan.AccessToken()
                new_release=corona_scan.AddRelease(access_token,existed_product_id)
                logger.info("Successfully created new release to the product ")
                logger.info(new_release)
                new_release_id=new_release['id']
                logger.info("The new release id : %s"%(new_release_id))
                logger.info("Add new Image to the  release")
                image_location_id=corona_scan.ImageLocationId(access_token)
                logger.info("Successfully added image \n  The image location Id: %s"%(image_location_id))
                image_name=corona_scan.ImageName()
                logger.info("The image name : %s"%(image_name))
                image_id=0

                #condition to check weather user needs to add reusable module or not !

                if not reusable_modules:

                    image_response=corona_scan.AddImage(access_token,image_location_id,existed_product_id,new_release_id,image_name)
                    logger.info(" Image Response: %s"%(image_response))
                    image_id=image_response['id']
                    logger.info(" Image Id: %s "%(image_id))

                else:
                    reusable_module_image_id_list=[]

                    for i in range(len(reusable_modules)):
                        logger.info("REUSABLE MODULE NAME: ",reusable_modules[i])
                        reusable_module_image_id_list.append(corona_scan.ReusableModule_Image_Id(access_token,reusable_modules[i]))

                    image_response=corona_scan.Add_Reusable_Module(access_token,existed_product_id,new_release_id,image_location_id,image_name,reusable_module_image_id_list)
                    logger.info("Successfully added reusable module to the product \n  Resuable Module Image Response: %s"%(image_response))
                    image_id=image_response['id']
                    logger.info("Reusable Module Image Id: %s "%(image_id))

                #after adding image to the product , scan will intiate automatically, we were done infinite loop untill the scan status has changed to finished .
                access_token,sign_response=corona_scan.AccessToken()
                corona_scan.ImageScan_Status(access_token,image_id)
                
                end_time = time.time() #scanning end time

                logger.info("Fetching the image risk report data .....")

                vulnerable_list_report, image_risk_report,table_data=corona_scan.ImageRiskReport(access_token,image_id)

                logger.info("creating html table attachment.....")
                
                table_html= corona_scan.create_table(table_data,vulnerable_list_report) 

                image_name=corona_scan.ImageName()
                
                end_datetime = datetime.fromtimestamp(end_time)
                end_time_str = end_datetime.strftime("%d-%m-%Y %H:%M:%S")
                delta = end_time - start_time
                delta_timedelta = timedelta(seconds=delta)

                image_risk_report_first=None
                previous_image_name=None

                # Format timedelta as string (hh:mm:ss)
                delta_str = str(delta_timedelta)
                corona_scan.send_mail(existed_product_id,new_release_id,image_id,image_risk_report_first,image_risk_report,previous_image_name,image_name,table_html,start_time_str,end_time_str,delta_str,sprint_no)

                sys.exit()

            else:

                access_token,sign_response=corona_scan.AccessToken()
                headers={"Content-Type": "application/json","Authorization":'Bearer '+access_token} 
                logger.info(existed_release_id[release_version] )
                url2='https://corona.cisco.com/api/v2/images.json?release_id=%s'%(existed_release_id[release_version])
                res=requests.get(url2,headers=headers)
                image_json=res.json()
                logger.info("imaged info of existed release ")
                
                logger.info(image_json)
                existed_image_id=image_json['data'][0]['id']  # previous image name of the product [predecessor id ]

                logger.info("   Previous image id  : %s"%(existed_image_id))   
                previous_image_name = image_json['data'][0]['name'] 
                logger.info("Previous Image Name before Rescanning is: %s"%(previous_image_name))
 

                vulnerable_list_report, image_risk_report_first,table_data=corona_scan.ImageRiskReport(access_token,existed_image_id)


                image_location_id=corona_scan.ImageLocationId(access_token)
                logger.info("Image successfully added \n , The image location id: %s"%(image_location_id))
                image_name=corona_scan.ImageName()
                logger.info("Binary file used : image name : %s "%(image_name))
                image_id=0

               #checking if reusable module  is already added or not, if added then no need to add again.
                module_already_added = corona_scan.Check_Reusable_Module(access_token, existed_image_id)
                logger.info(module_already_added)
                added_info = module_already_added['data']
                logger.info("Earlier added reusable module information: %s"%(added_info))

                if not reusable_modules or len(added_info) > 0:
                    #if reusable module is already added to image then don't add again and print this message.
                    if(len(added_info) > 0):
                        logger.info("Reusable module is already added to binary.")
                        added_info_data = added_info[0]
                        earlier_rm_id = added_info_data['child']['image_id']
                        logger.info("Image Id of earlier added reusable module is %s"%(earlier_rm_id))


                    image_response=corona_scan.Rescan(access_token,existed_product_id,existed_release_id,existed_image_id,image_location_id,image_name)
                    logger.info("Rescan Image Response: %s"%(image_response))
                    image_id=image_response['id']
                    logger.info(" Image Id: %s "%(image_id))


                else:
                    # if reusable module was not added in the binary earlier and user wants to add now.

                    access_token,sign_response=corona_scan.AccessToken()    
                    reusable_module_image_id_list=[]
                    for i in range(len(reusable_modules)):
                         reusable_module_image_id_list.append(corona_scan.ReusableModule_Image_Id(access_token,reusable_modules[i]))
                    image_response= corona_scan.Add_Reusable_Module_Rescan_Product(access_token,existed_product_id,existed_release_id,existed_image_id,image_location_id,image_name,reusable_module_image_id_list)
                    logger.info("Successfully added Reusable module to %s \n Reusable Module Image Response: %s"%(image_response,product_name))
                    image_id=image_response['id']
                    logger.info("Reusable Module Image Id: %s "%(image_id))



                corona_scan.ImageScan_Status(access_token,image_id)

                end_time = time.time()

                logger.info("Fetching Image risk report data ........ ")
                vulnerable_list_report, image_risk_report,table_data=corona_scan.ImageRiskReport(access_token,image_id)
                
                logger.info("creating html table attachment to the mail . ")
                table_html= corona_scan.create_table(table_data,vulnerable_list_report) 
                
                image_name=corona_scan.ImageName()
             
                end_datetime = datetime.fromtimestamp(end_time)
                end_time_str = end_datetime.strftime("%d-%m-%Y %H:%M:%S")
                delta = end_time - start_time
                delta_timedelta = timedelta(seconds=delta)

                # Format timedelta as string (hh:mm:ss)
                delta_str = str(delta_timedelta)
                corona_scan.send_mail(existed_product_id,existed_release_id,image_id,image_risk_report_first,image_risk_report,previous_image_name,image_name,table_html,start_time_str,end_time_str,delta_str,sprint_no)

                sys.exit()    

        else:
            
        
            logger.info("Successfully Product created . %s \n The product response : %s "%(product_name,product_response_json))
            product_id=product_response_json['id']
            logger.info("Adding release to the product %s : "%product_name)
            access_token,sign_response=corona_scan.AccessToken()
            release_response=corona_scan.AddRelease(access_token,product_id)
            logger.info("Successfully added Release to Product %s"%product_name)
            logger.info("The release response is :  %s"%(release_response))

            release_id=release_response['id']
            logger.info("The release Id : %s"%(release_id))
            logger.info("Adding Image to the release : %s  , product : %s "%(release_version,product_name))
            image_location_id=corona_scan.ImageLocationId(access_token)
            logger.info("The image location id :%s"%(image_location_id))
            image_name=corona_scan.ImageName()
            logger.info("Binary image name : %s"%(image_name))
            image_id=0

            if not reusable_modules:
                access_token,sign_response=corona_scan.AccessToken()
                image_response=corona_scan.AddImage(access_token,image_location_id,product_id,release_id,image_name)
                logger.info(" Image Response: %s"%(image_response))
                image_id=image_response['id']
                logger.info(" Image Id: %s "%(image_id))

            else:
                access_token,sign_response=corona_scan.AccessToken()
                reusable_module_image_id_list=[]
                for i in range(len(reusable_modules)):
                    reusable_module_image_id_list.append(corona_scan.ReusableModule_Image_Id(access_token,reusable_modules[i]))
                    image_response=corona_scan.Add_Reusable_Module(access_token,product_id,release_id,image_location_id,image_name,reusable_module_image_id_list)
                    logger.info("Successfully added reusable module to product \n Resuable Module Image Response: %s"%(image_response))
                    image_id=image_response['id']
                    logger.info("Reusable Module Image Id: %s "%(image_id))
                        
            corona_scan.ImageScan_Status(access_token,image_id)

            end_time = time.time()

            logger.info("Fetching image risk report data ...... ")
            vulnerable_list_report, image_risk_report,table_data=corona_scan.ImageRiskReport(access_token,image_id)
            logger.info("Creating html table attchment to the mail .")    
                
            table_html= corona_scan.create_table(table_data,vulnerable_list_report)  
            
            image_name=corona_scan.ImageName()

            
            end_datetime = datetime.fromtimestamp(end_time)
            end_time_str = end_datetime.strftime("%d-%m-%Y %H:%M:%S")
            delta = end_time - start_time
            delta_timedelta = timedelta(seconds=delta)

            image_risk_report_first=None
            previous_image_name=None

            # Format timedelta as string (hh:mm:ss)
            delta_str = str(delta_timedelta)

            corona_scan.send_mail(product_id,release_id,image_id,image_risk_report_first,image_risk_report,previous_image_name,image_name,table_html,start_time_str,end_time_str,delta_str,sprint_no)


            sys.exit()


    elif(ScanType_Name=="SOLIS"):
        
        config.read("Scan_Common_Config_File.ini")
    
        current_time = datetime.now()
    

        # Extract username and password from the configuration file
        username = os.getenv('GenericUsername')
        password = os.getenv('GenericPassword')
        component_name = os.getenv('component_name')
        logger.info("***********************WELCOME TO SOLIS SCAN FOR % s******************************", component_name)

        sender = os.getenv('sender')

        Recievers = os.getenv("Recievers")
        
        recepients = Recievers.split(",")
        
        SprintNo=os.getenv('SSP_BUILD_SPRINT_NO')
        logger.info("Scanning for %s", SprintNo)

        logger.info("------------------Jenkins Configurations-----------------------")
        
        application_name = os.getenv('application_name')
        logger.info("App_id is generated with having %s as Application Name" , application_name)
        

        target_name = os.getenv("targets_name")
        logger.info("target_id is generated with having %s as Target Name" , target_name)
        
        
        component_name = os.getenv('component_name')
        logger.info("Component name is :  %s " , component_name)
        
        if component_name =='CUIC_SOLIS' or component_name =='FINESSE_SOLIS':
            dir_path = os.getenv('path')


        else:
            url_list = os.getenv('url_list')
            url_list1 = ",".join(line.strip() for line in url_list.splitlines())
            
            
        
        secret_description= os.getenv('secret_description')
        
        scanning_type = os.getenv('scanning_type')
     

        binary_file_name = os.getenv('FILE_PATH')
        logger.info("Provided path of the image is %s"%binary_file_name)
    

        solis_run=Solis(username,password,application_name,target_name,component_name,secret_description,scanning_type,sender,recepients,binary_file_name)


        solis_run.signup_and_get_token()
        
        appid = solis_run.get_application_id()
        
        
        targetid = solis_run.get_target_id()
    
        
        chariotid = solis_run.get_chariot_id()
        
        SecretConfigName = solis_run.generate_secret_config_name()
        
        SecretID = solis_run.create_secret_configuration(appid,SecretConfigName)
        
        
        if component_name =='CUIC_SOLIS' or component_name =='FINESSE_SOLIS':

            logger.info("File uploading in process........")
            
            
            har_files = [file for file in os.listdir(dir_path) if file.endswith('.har')]
            file_names = [os.path.basename(file) for file in har_files]
            paths = [os.path.join(dir_path, file_name) for file_name in har_files]
            paths = [path.replace('\\', '/') for path in paths]

            ScanConfig = solis_run.scan_config_har(appid,chariotid, file_names, paths )
            
            logger.info(json.dumps(ScanConfig, indent=4))

           
        else:
            logger.info("URLs for scanning.........")
            ScanConfig = solis_run.scan_config_url(appid,chariotid,url_list1)
            logger.info(json.dumps(ScanConfig, indent=4))
            
            
        ScanConfigID = solis_run.get_scan_config_id( json.dumps(ScanConfig))
        
        ScanID = solis_run.Start_scan(appid,targetid,chariotid,ScanConfigID)
   

        total,critical,high,low,medium,informational,artifact_key = solis_run.get_value(ScanID)


        Data = solis_run.retrieve_scan_results_html(ScanID,artifact_key)
        HTML = solis_run.parse_scan_results(Data)

        pre_total, pre_critical, pre_high, pre_medium, pre_low, pre_informational = solis_run.get_previous_vulnerability_summary(appid,targetid)

        jenkins_workspace = os.getenv('WORKSPACE', '/var/lib/jenkins/workspace/')
        
        component_job_name = os.getenv('JOB_NAME', 'default_job_name')
        build_number = os.getenv('BUILD_NUMBER', '1')

        jenkins_workspace_link = "http://10.86.130.179:8080/job/" + component_job_name + "/" + build_number

        output_path= solis_run.zip_file(ScanID,targetid,jenkins_workspace)

        build_info =solis_run.ImageName()

        solis_run.send_mail(appid, ScanID, SprintNo,component_name, build_info, total, pre_total, pre_critical, critical, pre_high, high, medium, pre_medium, informational, pre_informational, pre_low, low,jenkins_workspace_link,SecretID,HTML)

        logger.info("SENDER= " + sender)
        
        logger.info("RECIEVERES= " + Recievers)
        
        logger.info(recepients)

        delete_secrets = solis_run.delete_configs_secrets(appid, SecretID)

        if component_name =='CUIC_SOLIS' or component_name =='FINESSE_SOLIS':
            for files in har_files:
                delete_existing_file = solis_run.delete_existing_file(appid,files)

