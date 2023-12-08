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
import subprocess
import json


start_time = time.time()

start_datetime = datetime.fromtimestamp(start_time)

start_time_str = start_datetime.strftime("%d-%m-%Y %H:%M:%S")

# Create and configure logger
logging.basicConfig(format='%(asctime)s %(message)s')

# Creating an object
logger = logging.getLogger()

# Setting the threshold of logger to INFO
logger.setLevel(logging.INFO)



class CoronaScanAutomation:


    def __init__(self,username,password,product_name,psirt_name, cvr_product_metadata,release_version,sprint_no,
                 engineering_contact,security_contact,binary_file_path,reusable_modules,sender,recepients):

        self.username=username
        self.password=password
        self.product_name=product_name
        self.psirt_name=psirt_name
        self.cvr_product_metadata=cvr_product_metadata
        self.release_version=release_version
        self.sprint_no = sprint_no
        self.engineering_contact=engineering_contact
        self.security_contact=security_contact
        self.binary_file_path=binary_file_path
        self.reusable_modules=reusable_modules
        self.sender=sender
        self.recepients=recepients







    #sign in api it will takes generic user name and password and it will authenticate and generate the access_token
    #old API is deprecated -Changes made->URL is changed ,we have to change the variable name that is "token" instead of "Authentication_token"

    def AccessToken(self):
        sign_url="https://corona.cisco.com/api/auth/sign_in"   # old one url https://corona.cisco.com/users/sign_in.json
        sign_response=requests.post(sign_url,json={  
        "user":{  
            "username":self.username,
            "password":self.password
        }} )
        

        sign_json=sign_response.json()
        #logger.info("SIGN IN RESPONSE ....  %s "%sign_json)
        access_token=sign_json['token'] #here we have to change the variable name that is "token" instead of "Authentication_token"
        #logger.info(access_token)
        return access_token,sign_response


            # ------------------ Creating a new product ----------------------

    """ This CreateProduct will create a new prodect as per user jenkins configurations  (product name , psirt_name and cvr_product_metadata) ......
        And it will return the API response , For a successful response, it will give product id w.r.t component 
        or else if bad jenkins parameters configurations is given then it will give error response while creating a new product in corona database .
        Note :  'cvr_product_metadata' is mandatory for products those psirt_name is 'Other' """
        

    def CreateProduct(self,access_token):  #function to create a product

        headers={"Content-Type": "application/json","Authorization":'Bearer '+access_token}


        product_url='https://corona.cisco.com/api/v2/products.json'

        if(self.psirt_name == "Other"):    #if PSIRT Name is defined as "Other", we will use this section, else we'll go in else condition
            product_response = requests.post(product_url, json={
                "product": {
                    "name": self.product_name,
                    "cvr_product_name": self.psirt_name,
                    "cvr_product_name_metadata": self.cvr_product_metadata

                }
            }, headers=headers)

            
            
        else:            # If PSIRT name is not as "Other"
            product_response = requests.post(product_url, json={
                "product": {
                    "name": self.product_name,
                    "cvr_product_name": self.psirt_name,


                }
            }, headers=headers)

        return product_response


  


    """ AddRelease function will create a new release to product that was created from the 'CreateProduct'  function 
        this function will take 
            --product_id : that is returned from the CreateProduct function
            --version    : it is a jenkins param, version of the relase w.r.t product
            --security_contact : security contact , username of security engineer 
            --engineering_contact : engineering contact, username of the engineering support username  """
    
    #API is deprecated - Changes made ->URL is changed ,Passing product_id in payload instead of in URL

    def AddRelease(self,access_token,product_id):         # this function will add the release to the product

        headers={"Content-Type": "application/json","Authorization":'Bearer '+access_token}

        release_url = "https://corona.cisco.com/api/v1/releases.json" #'https://corona.cisco.com/products/%s/releases.json'%(product_id) 
        release_response = requests.post(release_url, json={
            "release": {
                "product_id": product_id,           #here directly we have given product id in json
                "version": self.release_version,
                "security_contact": self.security_contact,
                "engineering_contact":self.engineering_contact    
            }
        }, headers=headers)
        release_json = release_response.json()    

        return release_json
    

    """ get_release_info  funtion will fetch product deatils if the product is alreday created in the corona ,
        it will return the product details:
        
        --product_id, release_id and release version details """
    
    #Both the APIs are deprecated -Changes made-Data paginated so made some changes in code

    def get_release_info(self,access_token):
        headers={"Content-Type": "application/json","Authorization":'Bearer '+access_token} 

        url = "https://corona.cisco.com/api/v2/products.json?name=%s"%(self.product_name) 

        response= requests.get(url,headers=headers)
        response_json= response.json()
        list12=response_json['data'][0]
        existed_product_id=list12['id'] #product id of existed product
        logger.info(existed_product_id)
        

        release_url='https://corona.cisco.com/api/v2/releases.json?product_id=%s'%(existed_product_id)      
        release_response=requests.get(release_url,headers=headers)
        release_json=release_response.json()
        logger.info(release_json)
        
        exi_data=release_json['data']
        release_id_dic={}                    #version as key and id as value
        version_list=[]                      #version list
        for i in range(len(exi_data)) :
            version_list.append(exi_data[i]['version'])
            release_id_dic[exi_data[i]['version']]=exi_data[i]['id']
        
        existed_release_version=version_list
        existed_release_id=release_id_dic
        # existed_release_version=release_json['data'][0]['version'] # release version of the existed product

        logger.info("The Product : {} is already existed in Corona Database ".format(self.product_name))
        logger.info("Product information : ")

        logger.info("Product Id : {0} \n Product Release Id:  {1} \n Product Release Version: {2}  ".format(existed_product_id,existed_release_id,existed_release_version))
        
        #  retrieving the release details of specified product id
        return existed_product_id,existed_release_id,existed_release_version


    """ImageLocationId, function will return the image location id which will used in AddImage function ,
    the parameters 
        binary_file_path : this path will contains the latest Build deleverable , the file was downloaded with help of 'Download latest build jenkin job ' 
        Note : ensure that binary_file_path and 'Download latest build'  job  have same path (DownloadLocalpath) """
    """API deprecated - Changes made -> URL is changed ,this api only give the location where we have to upload the image,so by using another
       post method ,upload the image to the S3 bucket location
    """

    def ImageLocationId(self,access_token):

        url = 'https://corona.cisco.com/api/v3/locations'       #old one "https://corona.cisco.com/location.json"
        path =self.binary_file_path
        binary_file_name=""
        for file in os.listdir(path):
            binary_file_name=file

        imagepath=(path+'/'+binary_file_name)
        # logger.info(binary_file_name)
        # logger.info("The Image Location Path : %s  "%(imagepath))
        logger.info("The Image file : %s"%(binary_file_name))
        file_stats = os.stat(imagepath)
        file_size=file_stats.st_size
        

        
        payload = json.dumps({
            "filename": binary_file_name,
            "file_size": file_size,
            "file_type": "binary",
            "upload_type": "best_fit",
            "expires_in": 3600
                })
        # files = [
        #     ('attachment', (binary_file_name,
        #                     open(imagepath, 'rb'),
        #                     'application/octet-stream'))]

        
        headers = {'Content-Type': 'application/json',"Authorization":'Bearer '+access_token}
        img_location =requests.request("POST", url, headers=headers, data=payload)

        #logger.info("%s"%(img_location.status_code))
        #logger.info("Image Location Response : %s"%img_location.json())
        img_location_json = img_location.json()
        #logger.info(img_location_json)
        payloads={}

        img_location_id = img_location_json['id']
        img_upload_url=img_location_json['upload']['url']
        # headers = {"Authorization":'Bearer '+access_token}
        img_field=img_location_json['upload'][ "fields"]
        img_field['file']=open(imagepath, 'rb')
        # logger.info(img_field)

        # response = requests.post(img_upload_url, file=img_field)
        # file=imagepath
        response=requests.request("POST", img_upload_url, files=img_field)

        if response.status_code == 200:
                logger.info("File uploaded successfully.")
        else:
                logger.info(f"Error uploading file. Status code: {response.status_code}")
        

        return img_location_id      
    

    """ImageName funciton will return the name of the binary 
    We've used this binary file name as a image_name parameter in AddImage funtion ( so that we dont have name conflict issues while adding the image, because it needs unique name )"""

    def ImageName(self):
        path = self.binary_file_path
        binary_file_name = ""
        for file in os.listdir(path):
            binary_file_name = file

        return binary_file_name


    """AddImage function will add the image to the product and intiate the scaning in corona 
    Function will take params...
    --image_location_id   :  image_location id from 'ImagelocationId ' function 
    --product_id, release_id : product_id from the 'CreateProduct' and release id from the 'AddRelease' functions
    --security_contact, engineering_contact
    --inmage_name         : image name param ,from ImageName() function

    this function will return API response,  that contains image_id and other product information 
    """

    def AddImage(self,access_token,image_location_id,product_id,release_id,image_name):

        headers = {"Authorization":'Bearer '+access_token}
        img_add_url='https://corona.cisco.com/api/v2/images.json'
        

        image_response=requests.post(img_add_url,json={
            "image":{
            "product_id": product_id,
            "release_id":release_id,
            "location_attributes":{"uri_type":"upload","image_location_id":image_location_id },
            "name":image_name,
            "security_contact": self.security_contact,
            "engineering_contact":  self.engineering_contact
            }},headers=headers)

        image_response_json=image_response.json()
        return image_response_json




    """ReusableModule_Image_Id function will takes the reuable module name and fetch information( image_id ) and it will the reusable_module_id, this function will add resuable module to the product as per user jenkins configurations 
    
    """
    def ReusableModule_Image_Id(self,access_token,reusable_module_name):

        headers = {"Authorization":'Bearer '+access_token}
        
        url = "https://corona.cisco.com/api/v2/products.json?name=%s"%(reusable_module_name)

        response= requests.get(url,headers=headers)
        
        response_json= response.json()
        logger.info("The reusable module response: ",response_json)
        
        exproduct_id=response_json['data'][0]['id'] #product id of existed product 

        print("Resuable module {0} product id : {1}".format(reusable_module_name,exproduct_id))

        image_url='https://corona.cisco.com/api/v2/images.json?product_id=%s'%(exproduct_id)
        image_response=requests.get(image_url,headers=headers)
        image_json_response=image_response.json()
        Reusable_module_id=image_json_response['data'][0]['id']
        return Reusable_module_id
    
    
    
    """Checking whether the image already contains the reusable module or not.
       If it contains, we don't need to add the reusable module again.
       Parameters are as following.......
       --access_token, predecessor_id.
       """
    
    def Check_Reusable_Module(self, access_token, predecessor_id):
        headers = {"Authorization":'Bearer '+access_token}

        url = 'https://corona.cisco.com/api/v2/reusable_modules/contains.json?image_id=%s'%(predecessor_id)
        response = requests.get(url,headers=headers)
        reusable_response = response.json()
        return reusable_response
    


    """ Add_Reusable_Module funtion will add the reusable modules to the image as per user jenkins configurations 
        Following are the parameters.......

        -- product_id, release_id, security_contact,engineering_contact , image_location_id, image_name, 

        -- resuable_modules : it is list of image_id , image_id from the "Reusable_Module_I" function .
        
        Note :  This will more than one resuable modules to the product """


    def Add_Reusable_Module(self,access_token,product_id,release_id,image_location_id,image_name,reusable_module_image_id_list):

    
        headers = {"Authorization":'Bearer '+access_token}
        
        metadata = "{\"reusable_modules\":[{\"reuse_type\":\"blackbox\",\"corona_image_id\":rsmId}]}"

        new_resue_type="{\"reuse_type\":\"new_type\",\"corona_image_id\":\"new_image_id\"}"

        modified_data=""

        if(len(self.reusable_modules)>1):

            length=len(reusable_module_image_id_list)
            for i in range(0,length-1): 

                metadata=metadata.replace("rsmId",str(reusable_module_image_id_list[0]))
                
                i=i+1
                
                new_resue_type1=new_resue_type.replace("new_image_id",str(reusable_module_image_id_list[i]))
                
                closing_bracket_index = metadata.rindex("]")
                
                # Insert the new reuse_type string before the closing square bracket
                modified_data = metadata[:closing_bracket_index] + "," + new_resue_type1 + metadata[closing_bracket_index:]
                
                metadata=modified_data

        elif(len(self.reusable_modules)==1):
            metadata=metadata.replace("rsmId",str(reusable_module_image_id_list[0]))        



        img_add_url='https://corona.cisco.com/api/v2/images.json'      #adding the image with Reusuable Module

        image_res=requests.post(img_add_url,json={
            "image":{
            "product_id": product_id,
            "release_id":release_id,
            "location_attributes":{"uri_type":"upload","image_location_id":image_location_id },
            "name":image_name,
            "security_contact": self.security_contact,
            "engineering_contact":  self.engineering_contact,
            "additional_metadata": metadata}},headers=headers)

        image_res_json=image_res.json()
        return image_res_json 
    

    """ImageScan_Status funtion will fetch the status of the scan, this funtion is infinate loop for every 10 min it will 
       return scanning status of the binary ..., it will untill it finished or if it is encountered any error ! """


    def ImageScan_Status(self,access_token,image_id):

        while(True):
            
            headers={"Content-Type": "application/json","Authorization":'Bearer '+access_token} 

            url='https://corona.cisco.com/api/v2/images/%s/scan_fsms/current.json'%(image_id)

            status_response=requests.get(url,headers=headers)

            status_json=status_response.json()
        
            if(status_json['state']=="finished"):
                logger.info("Getting Image Scan Status ________________")
                logger.info("image status response :  %s"%(status_json))
                break

            elif(status_json['state']== "error"):
                logger.info("Scanning gets errored ")
                logger.info("status info : %s"%status_json)
                sys.exit(1)


            else:
                logger.info("Getting Image Scan Status ________________")
                logger.info("Image Scanning status Response: %s "%(status_json['state']))
                time.sleep(600)



    """Rescan - This funtion will Rescan the image, and it will take the parameters 
    - username, access token, existed product id, existed release id, predecessor id (id of earlier uploaded image),
      image location id, security and engineering contact
      and this will return the image json response, that contains the information about image and product id, etc."""
    
        #API is deprecated-before running rescan api ,need to update image api so triggered pathch method to update img info

    def Rescan(self,access_token,existed_product_id,existed_release_id,predecessor_id,image_location_id,image_name):
        
        headers = {"Content-Type": "application/json","Authorization":'Bearer '+access_token}
        img_add_url='https://corona.cisco.com/api/v2/images/%s.json'%(predecessor_id)
        

        image_response=requests.patch(img_add_url,json={
            "image":{
            "product_id": existed_product_id,
            "release_id":existed_release_id,
            "location_attributes":{"uri_type":"upload","image_location_id":image_location_id },
            "name":image_name,
            "security_contact": self.security_contact,
            "engineering_contact":  self.engineering_contact
            }},headers=headers)

        image_response_json=image_response.json()
        # logger.info("update info")
        # logger.info(image_response_json)

        self.ImageScan_Status(access_token,predecessor_id)
       

        headers={"Content-Type": "application/json","Authorization":'Bearer '+access_token}        
        img_add_url='https://corona.cisco.com/api/v2/images/%s/rescan.json'%(predecessor_id)


        image_rescan_reponse=requests.put(img_add_url,json={},headers=headers)

        image_resscan_json=image_rescan_reponse.json()
        # logger.info(image_resscan_json)
        image_id=image_resscan_json['id']
        logger.info("The image Id: %s"%(image_id))
        
        return image_resscan_json


    """ Add_Reusable_Module_Rescan_product - This function will be used, when user wants to rescan the image with Reusable module
        and it will take the parameters 
        -- image name, reusable_modules as list of Resuable module names if user wants to add multiple reusable to the product,
        rest of the parameters are same as defined earlier.
        this will return the image json response ."""



    def Add_Reusable_Module_Rescan_Product(self,access_token,product_id,release_id,existed_image_id,image_location_id,image_name,reusable_module_image_id_list):

    
        metadata = "{\"reusable_modules\":[{\"reuse_type\":\"blackbox\",\"corona_image_id\":rsmId}]}"

        new_reusable_module="{\"reuse_type\":\"blackbox\",\"corona_image_id\":\"new_image_id\"}"

        modified_data=""

        if(len(self.reusable_modules)>0):

            length=len(reusable_module_image_id_list)
            for i in range(0,length-1): 

                metadata=metadata.replace("rsmId",str(reusable_module_image_id_list[0]))
                
                i=i+1
                
                new_resue_type1=new_reusable_module.replace("new_image_id",str(reusable_module_image_id_list[i]))
                
                closing_bracket_index = metadata.rindex("]")
                
                # Insert the new reuse_type string before the closing square bracket
                modified_data = metadata[:closing_bracket_index] + "," + new_resue_type1 + metadata[closing_bracket_index:]
                
                metadata=modified_data

        elif(len(self.reusable_modules)==1):
            metadata=metadata.replace("rsmId",str(reusable_module_image_id_list[0]))               



        img_add_url='https://corona.cisco.com/api/v2/images/%s.json'%(existed_image_id)
        headers = {"Authorization":'Bearer '+access_token}
            

        image_response=requests.put(img_add_url,json={
        "image":{
        "product_id": product_id,
        "release_id":release_id,
        "location_attributes":{"uri_type":"upload","image_location_id":image_location_id},
        "name":image_name,
        "security_contact": self.security_contact,
        "engineering_contact":  self.engineering_contact,

        "additional_metadata": modified_data}},headers=headers)

        image_response_json=image_response.json()
        return image_response_json

    

    
      



    def BDHub_config_file(self,access_token,image_id):

        url = f"https://corona.cisco.com/api/v2/images/{image_id}/sbom_records.json"

        payload = {}
        headers = {
        'Content-Type': 'application/json',
        "Authorization":'Bearer '+access_token
        }

        response = requests.request("GET", url, headers=headers, data=payload)

        response_json= response.json()
        image_sha1=response_json['image']['image_sha1']
        logger.info("The image Id: ",image_id)
        logger.info("The image sha1 id : ",image_sha1)
                    
                    
        
    
    """ImageRiskReport - This function is used when we are fetchig the image risk report of the uploaded image,
        and it is taking the parameters username, access_token, image id and table data (in that we're taking the list of sections, we got from image risk report)
        and it will return the API response and vulnerabilty list."""

    def ImageRiskReport(self,access_token,image_id):

        table_data = [["The Category of the Vulnerablity ","Component Name ", "The type of Risk","Risk Scale", "Message "] ]

        headers = {"Authorization":'Bearer '+access_token}
        image_risk_url='https://corona.cisco.com/api/v2/images/%s/risk.json'%(image_id)
        image_risk_response=requests.get(image_risk_url,headers=headers)
        image_risk_json=image_risk_response.json()
       
        #Image risk report api , below script will give the previous Scanned Image risk report 

        risks_report=image_risk_json['risks']

        #empty lists for store the risk report data form the Image riskreport api json response . 
        category=[]
        risk_type=[]
        message=[]
        risk_scale=[]
        component_name=[]


        for data in risks_report:
            category.append(data['category'])
            risk_type.append(data['type'])
            message.append(data['message'])
            risk_scale.append(data['risk'])
            component_name.append(data['obj'])

        
        vulnerable_list=[]
        for i in range(len(category)):
            temp=[]
            for j in range(len(table_data[0])):
                temp.append(category[i])   
                temp.append(component_name[i])
                temp.append(risk_type[i])
                temp.append(risk_scale[i])
                temp.append(message[i])
                    
            vulnerable_list.append(temp) 

        return vulnerable_list,image_risk_json,table_data  


    """ create_table_html  this function , will take table data that we need to replicate into a html attachment in mail 
        parameters :  
                data  - table headers data 
                vulnerable_list  -  it is list of vulnerable data , that was fetch from the Image_risk_report functin .
                it will return the html table with relevent data in it. 
                
                this function we were used for sending the risk report in mail. """


    def create_table(self,data,vulnerable_list):

        num_cols = len(data[0])

        table_html = "<table style='border-collapse: collapse; border: 1px solid black;'>"

        # Create table header
        table_html += "<tr>"
        for header in data[0]:
            table_html += "<th style='border: 1px solid black; padding: 8px;'>{}</th>".format(header)
        table_html += "</tr>"

        # Create table rows
        for row in vulnerable_list:
            table_html += "<tr>"
            for i in range(num_cols):
                    
                
                    table_html += "<td style='border: 1px solid black; padding: 8px;'>{}</td>".format(row[i])
            table_html += "</tr>"

        table_html += "</table>"



        return table_html   


    """ send_mail function will send the scanned product details like , SBOM report , Binary info , Image risk report ,
        an attachment it will contails the risk report of the scanned binary file.
        
        parameters : 
            -- sender , recepients these are the mails , so that the funtion were used the sender param  to forward the report the tagerted people mails ( recepients mails list) 
            -- product_id , product_name , image_name and image_risk_json 
            -- scan start_time ,end_time and the delta 
    """

    def send_mail(self,product_id,release_id,image_id,image_risk_json_first,image_risk_json_second,previous_image_name,image_name,table_html,start_time_str,end_time_str,delta_str,sprint_no):


        message_text="Hi Team,<br> BOM report for your <b>{0}</b> component of <b>{1}</b> is now ready to view.".format(self.product_name,sprint_no)

    
        text3 = "<br><br>Link to access the <b>BOM Report</b> :  <a href = 'https://corona.cisco.com/products/{0}/releases/{1}/bom_report'>https://corona.cisco.com/products/{0}/releases/{1}/bom_report</a>".format(product_id,release_id)

        text4 = "<br>Link to access the <b>Vulnerability Report</b> :  <a href = 'https://ciam.cisco.com/corona/products/{0}/releases/{1}/images/{2}/'>https://ciam.cisco.com/corona/products/{0}/releases/{1}/images/{2}/</a><br><br>Scan Starting Time : {3} <br>Scan Ending Time : {4} <br>  Total Time Taken: {5}".format(product_id,release_id,image_id,start_time_str,end_time_str,delta_str)
        
        text5 = "<br><br>Click on the HTML attachment to have a detailed review about the total component vulnerabilities of image risk report."

        text8 = "<br><b><font style='color:#000000'>Note-</font>Vulnerability Report may take some time to display the data depending upon the artifact size.</b>"


        message = MIMEMultipart()
        logging.info("image risk report for rescan is : ")
        
        print((image_risk_json_first!=None))
        if(image_risk_json_first != None): #means if product is already created

            text1 = "<br><br><b><u><font style='color:#006400'>SUMMARY OF LATEST SCANNED IMAGE:</u></b></font><br><br><b>Latest Scanned Image  is : </b>{0}<br><br><b>Total_risk_count:</b> {1}<br><br><b>Report_status : </b>{2}<br><br><b>Unknown_risk_counts:</b> {3}".format(image_name,image_risk_json_second['summary']['total_risk_count'],image_risk_json_second['summary']['report_status'],image_risk_json_second['summary']['unknown_risk_counts'])

            text2 = "<br><br><br><b><u><font style='color:#006400'>SUMMARY OF PREVIOUS SCANNED IMAGE:</u></b></font><br><br><b>Previous Scanned Image  is : </b>{0}<br><br><b>Total_risk_count:</b> {1}<br><br><b>Report_status : </b>{2}<br><br><b>Unknown_risk_counts:</b> {3}".format(previous_image_name,image_risk_json_first['summary']['total_risk_count'],image_risk_json_first['summary']['report_status'],image_risk_json_first['summary']['unknown_risk_counts'])

            mail_body = MIMEText('<html><body>' + message_text + text1 + text2 + text3 + text4  +  text5 + text8 +'</body></html>', 'html')
        
        else:  #if product is newly created

            text6 = "<br>Scanned Image  is : <b>{0}</b><br>".format(image_name) 

            text7 = "<br><b><u><font style='color:#006400'>SUMMARY OF THE SCANNED IMAGE:</u></b></font><br><br><b>Total_risk_count:</b> {0}<br><br><b>Report_status : </b>{1}<br><br><b>Unknown_risk_counts:</b> {2}".format(image_risk_json_second['summary']['total_risk_count'],image_risk_json_second['summary']['report_status'],image_risk_json_second['summary']['unknown_risk_counts'])

            mail_body = MIMEText('<html><body>' + message_text + text6 + text7 + text3 + text4  +  text5 +text8 +'</body></html>', 'html')
        
        message.attach(mail_body)
        
        message['Subject'] = "Your {0} Product's BOM Report is Ready to View".format(self.product_name)
        message['From'] =self.sender
        message['To'] = ','.join(self.recepients)

        # message.attach(MIMEText(table_html, "html"))

        image_risk_report_html=MIMEText(table_html,"html")
        message.attach(image_risk_report_html)
        attachment_filename="Image_Risk_Report.html"
        image_risk_report_html.add_header('Content-Disposition',f'attachment; filename="{attachment_filename}"')

        try:
            mail = smtplib.SMTP('mail.cisco.com',25)
            mail.sendmail(self.sender, self.recepients, message.as_string())
            logger.info("Email sent successfully... ")
        except Exception as e:
            logger.info("%s"%e)        