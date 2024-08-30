from flask import Flask, request, jsonify, make_response
from waitress import serve
from scraper import WebScraper
import jwt
from cryptography.fernet import Fernet, InvalidToken
from jwt.exceptions import DecodeError, ExpiredSignatureError
from requests.exceptions import SSLError, MissingSchema, ConnectionError
from selenium.common.exceptions import WebDriverException
from selenium import webdriver
from pymongo import MongoClient
from pyodbc import ProgrammingError
from ssl import SSLError
from socket import gaierror
from dateutil import parser
from werkzeug.serving import WSGIRequestHandler
from werkzeug.utils import secure_filename
import shortuuid

try:
    from http.server import BaseHTTPRequestHandler
except: 
    from BaseHTTPServer import BaseHTTPRequestHandler

import pdb
import logging
import os
from datetime import datetime, timedelta, timezone
import time
import json
import secrets
import ssl
import OpenSSL
import socket
import re

from config import StandAloneModule, StandAlonePlatform, StandAlonePlatformClassification, ScrapingStatus
from config import CONNECTION_STRING
from config import ScanRequestStatus
from connections import Connections
from security import Security
from utils import Utility
from custom_logger.logger import CustomLogger, CodeTrigger, LogType


# Create logs folder and initialize logger
if not os.path.exists('logs'):
    os.makedirs('logs')
if not os.path.exists('transferred_logs'):
    os.makedirs('transferred_logs')
logger = CustomLogger(storageName="StorageA", appId="APP1003PY", runTimeArgument=None, appVersion="1.0.0.0", 
                      projectId=1, serverId="Server170", isServerEnvironment=True)


# Create uploads folder
if not os.path.exists('uploads'):
    os.makedirs('uploads')
if not os.path.exists('dump'):
    os.makedirs('dump')
if not os.path.exists('logs/uploader'):
    os.makedirs('logs/uploader')


app = Flask(__name__)
# secret_key = secrets.token_urlsafe(16)
secret_key = 'hRZYpJz0YBxuAwvPQaHfue5Oja'
crypto_key = b'OivegknqMox4wXHHTh2m8DOY7pAru-q8dmnJggG3wsU='
app.config['SECRET_KEY'] = secret_key


@app.route('/login', methods=['POST'])
def login():
    request_data = request.get_json()
    # Check in db if user exists
    if all (key in request_data for key in ("UserName", "SecretKey", "APIKey")):
        validate = Security().validate_utility_user(request_data)
        if len(validate.fetchall()) != 0:
            logger.write(CodeTrigger.Function, LogType.Info, "Credentials Validated!")
            # Encode to get token
            # Add token expiration to encoding
            data = Security().encode_token(request_data, secret_key, crypto_key)
            return data
        else:
            return Utility().dump_error("2002")
    else:
        return Utility().dump_error("2002")

@app.route('/fbid', methods=['POST'])
def fbid():
    if request.headers.get('Authorization'):
        auth = request.headers.get('Authorization')
        token = auth.split()[1]
        # Decode token here
        decoded = Security().decode_token(token, secret_key, crypto_key)
        # Check in db if user exists
        if all (key in decoded for key in ("UserName", "SecretKey", "APIKey")):
            validate = Security().validate_utility_user(decoded)
            if len(validate.fetchall()) != 0:
                logger.write(CodeTrigger.Function, LogType.Info, "Credentials Validated!")
                # Check if token expired
                if int(time.mktime(datetime.utcnow().timetuple())) < decoded['exp']:
                    request_data = request.get_json()
                    if request_data:
                        if 'FacebookURL' in request_data.keys():
                            try:
                                result = {}
                                data = {}
                                html = WebScraper().html_scraper(request_data['FacebookURL'], allow_redirects=True)
                                # pdb.set_trace()
                                if "page_id" in html:
                                    html = html.replace("?", " ")
                                    html = html.replace('"', " ")
                                    html = html.replace("=", " ")
                                    html_list = html.split(" ")
                                    for item in html_list:
                                        idx = html_list.index(item)
                                        if item == "page_id":
                                            # pdb.set_trace()
                                            fbid = html_list[idx + 1]
                                            result['fbid'] = fbid
                                            data['Result'] = result
                                            data['ErrorCode'] = None
                                            data['Message'] = None
                                            data['Success'] = True
                                            return json.dumps(data)
                                        else:
                                            continue
                                    return Utility().dump_error("2010")
                                elif "group_id" in html:
                                    html = html.replace('"', " ")
                                    html = html.replace('"\"', " ")
                                    html = html.replace(":", " ")
                                    html_list = html.split(" ")
                                    for item in html_list:
                                        idx = html_list.index(item)
                                        if item == "group_id":
                                            # pdb.set_trace()
                                            fbid = html_list[idx + 1]
                                            result['fbid'] = fbid
                                            data['Result'] = result
                                            data['ErrorCode'] = None
                                            data['Message'] = None
                                            data['Success'] = True
                                            return json.dumps(data)
                                        else:
                                           continue
                                    return Utility().dump_error("2010")
                                elif "owning_profile_id" in html:
                                    html = html.replace('"', " ")
                                    html = html.replace(":", " ")
                                    html_list = html.split(" ")
                                    for item in html_list:
                                        idx = html_list.index(item)
                                        if item == "owning_profile_id":
                                            # pdb.set_trace()
                                            fbid = html_list[idx + 1]
                                            result['fbid'] = fbid
                                            data['Result'] = result
                                            data['ErrorCode'] = None
                                            data['Message'] = None
                                            data['Success'] = True
                                            return json.dumps(data)
                                        else:
                                           continue
                                    return Utility().dump_error("2010")
                                else:
                                    return Utility().dump_error("2010")
                            except:
                                return Utility().dump_error("2010")
                        else:
                            return Utility().dump_error("2001")
                    else:
                        return Utility().dump_error("2001")
                else:
                    return Utility().dump_error("2004")
            else:
                return Utility().dump_error("2002")
        else:
            return Utility().dump_error("2005")
    else:
        return Utility().dump_error("2006")


@app.route('/v2/central/upload', methods=['POST'])
def upload():
    if request.headers.get('Authorization'):
        auth = request.headers.get('Authorization')
        token = auth.split()[1]
        # Decode token here
        decoded = Security().decode_token(token, secret_key, crypto_key)
        # Check in db if user exists
        if all (key in decoded for key in ("UserName", "SecretKey", "APIKey")):
            validate = Security().validate_utility_user(decoded)
            if len(validate.fetchall()) != 0:
                logger.write(CodeTrigger.Function, LogType.Info, "Credentials Validated!")
                # Check if token expired
                if int(time.mktime(datetime.utcnow().timetuple())) < decoded['exp']:
                    request_data = request.form
                    if request_data:
                        data_complete = 0
                        if 'Username' in request_data.keys():
                            data_complete += 1
                        if 'ModuleId' in request_data.keys():
                            enum_list = [
                                StandAloneModule.Social_Media.value, 
                                StandAloneModule.Mobile_App.value
                            ]
                            if int(request_data["ModuleId"]) in enum_list:
                                data_complete += 1
                            else:
                                return Utility().dump_error("2001")
                        if 'PlatformId' in request_data.keys():
                            enum_list = [
                                StandAlonePlatform.Twitter.value, 
                                StandAlonePlatform.Facebook.value,
                                StandAlonePlatform.Aapks.value,
                                StandAlonePlatform.Apk4k.value,
                                StandAlonePlatform.Apkcombo.value,
                                StandAlonePlatform.Apkdl.value,
                                StandAlonePlatform.Apkfollow.value,
                                StandAlonePlatform.Apkfun.value,
                                StandAlonePlatform.Apkgk.value,
                                StandAlonePlatform.Apkmonk.value,
                                StandAlonePlatform.Apkplus.value,
                                StandAlonePlatform.Apkplz.value,
                                StandAlonePlatform.Apksfull.value,
                                StandAlonePlatform.Apktom.value,
                                StandAlonePlatform.Apktools.value,
                                StandAlonePlatform.Downloadatoz.value,
                                StandAlonePlatform.Choilieng.value,
                                StandAlonePlatform.Mobapks.value,
                                StandAlonePlatform.Nineapps.value,
                                StandAlonePlatform.Apkexite.value,
                                StandAlonePlatform.Apkmirror.value,
                                StandAlonePlatform.Apktoy.value,
                                StandAlonePlatform.Sameapk.value,
                                StandAlonePlatform.Apkily.value,
                                StandAlonePlatform.Apk20.value,
                                StandAlonePlatform.Apksupport.value,
                                StandAlonePlatform.Apknitro.value,
                                StandAlonePlatform.Apkdownload.value,
                                StandAlonePlatform.Apkgold.value,
                                StandAlonePlatform.Apkhere.value,
                                StandAlonePlatform.Apkgit.value,
                                StandAlonePlatform.Apknite.value,
                                StandAlonePlatform.Appszx.value,
                                StandAlonePlatform.Freeapkbaixar.value
                            ]
                            if int(request_data["PlatformId"]) in enum_list:
                                data_complete += 1
                            else:
                                return Utility().dump_error("2001")
                        if 'ClassificationId' in request_data.keys():
                            enum_list = [
                                0,
                                StandAlonePlatformClassification.People.value, 
                                StandAlonePlatformClassification.Pages.value,
                                StandAlonePlatformClassification.Groups.value
                            ]
                            if int(request_data["PlatformId"]) != StandAlonePlatform.Facebook.value and int(request_data["ClassificationId"]) == 0:
                                data_complete += 1
                            elif int(request_data["ClassificationId"]) in enum_list:
                                data_complete += 1
                            else:
                                return Utility().dump_error("2001")
                        if 'Keyword' in request_data.keys():
                            data_complete += 1
                        if 'IPAddress' in request_data.keys():
                            data_complete += 1
                        # Check if data is complete
                        if 5 <= data_complete <= 6:
                            # Insert to database/process the data
                            allowed_extensions = ["txt"]
                            # check if the post request has the file part
                            if 'SourceFile' not in request.files:
                                return Utility().dump_error("2001")
                            file = request.files['SourceFile']
                            # If the user does not select a file, the browser submits an
                            # empty file without a filename
                            if file.filename == '':
                                return Utility().dump_error("2001")
                            if file and file.filename.split(".")[1] in allowed_extensions:
                                try:
                                    ts = datetime.now()
                                    ts = ts.timestamp()
                                    reference_code = shortuuid.uuid()
                                    if int(request_data["PlatformId"]) == StandAlonePlatform.Twitter.value:
                                        filename = "TwitterSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Facebook.value:
                                        filename = "FacebookSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Aapks.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apk4k.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkcombo.value:
                                        filename = "MobileAppSourceCod_{reference_code}e_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkdl.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkfollow.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkfun.value:
                                        filename = "MobileAppSourceCod_{reference_code}e_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkgk.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkmonk.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkplus.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkplz.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apksfull.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apktom.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apktools.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Downloadatoz.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Choilieng.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Mobapks.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Nineapps.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkexite.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkmirror.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apktoy.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Sameapk.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkily.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apk20.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apksupport.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apknitro.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkdownload.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkgold.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkhere.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apkgit.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Apknite.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Appszx.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""), 
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    elif int(request_data["PlatformId"]) == StandAlonePlatform.Freeapkbaixar.value:
                                        filename = "MobileAppSourceCode_{reference_code}_{timestamp}.txt".format(
                                                timestamp=str(ts).replace(".", ""),
                                                reference_code=reference_code
                                            )
                                        file.save("./uploads/{filename}".format(filename=filename))
                                    # Return status or error code
                                    module_id = int(request_data['ModuleId'])
                                    platform_id = int(request_data['PlatformId'])
                                    classification_id = int(request_data['ClassificationId'])
                                    keyword = request_data['Keyword'],
                                    ip_address = request_data['IPAddress'],
                                    user = request_data['Username']
                                    json_status = [
                                        {
                                            "Status": ScrapingStatus.New.value,
                                            "DateTimeStamp": str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                                        }
                                    ]
                                    Connections().insert_scraping_repo(
                                        module_id,
                                        platform_id,
                                        classification_id,
                                        reference_code,
                                        filename,
                                        keyword[0],
                                        ip_address[0],
                                        user,
                                        1,
                                        json.dumps(json_status)
                                    )
                                    result = {
                                        "ReferenceCode": reference_code,
                                        "Filename": filename,
                                        "AddedDate": str(datetime.utcnow())
                                    }
                                    data = {}
                                    data['Result'] = result
                                    data['ErrorCode'] = None
                                    data['Message'] = "File has successfully been uploaded!"
                                    data['Success'] = True
                                    return json.dumps(data)
                                except:
                                    return Utility().dump_error("2013")
                            else:
                                return Utility().dump_error("2013")
                        else:
                            return Utility().dump_error("2001")
                    else:
                        return Utility().dump_error("2001")
                else:
                    return Utility().dump_error("2004")
            else:
                return Utility().dump_error("2002")
        else:
            return Utility().dump_error("2005")
    else:
        return Utility().dump_error("2006")


@app.route('/v2/assetdiscovery/scan', methods=['POST'])
def scan():
    if request.headers.get('Authorization'):
        auth = request.headers.get('Authorization')
        token = auth.split()[1]
        # Decode token here
        decoded = Security().decode_token(token, secret_key, crypto_key)
        # Check in db if user exists
        if all (key in decoded for key in ("UserName", "SecretKey", "APIKey")):
            validate = Security().validate_utility_user(decoded)
            if len(validate.fetchall()) != 0:
                logger.write(CodeTrigger.Function, LogType.Info, "Credentials Validated!")
                # Check if token expired
                if int(time.mktime(datetime.utcnow().timetuple())) < decoded['exp']:
                    request_data = request.get_json()
                    if request_data:
                        if 'Domain' in request_data.keys():
                            # Create scan request
                            try:
                                scan_request_id = shortuuid.uuid()
                                Connections().insert_asset_discovery_scan_request(scan_request_id, request_data['Domain'])
                                result = {
                                    "ScanRequestID": scan_request_id,
                                    "AddedDate": str(datetime.utcnow())
                                }
                                data = {}
                                data['Result'] = result
                                data['ErrorCode'] = None
                                data['Message'] = "Scan Request created!"
                                data['Success'] = True
                                return json.dumps(data)
                            except:
                                return Utility().dump_error("2014")
                        else:
                            return Utility().dump_error("2001")
                    else:
                        return Utility().dump_error("2001")
                else:
                    return Utility().dump_error("2004")
            else:
                return Utility().dump_error("2002")
        else:
            return Utility().dump_error("2005")
    else:
        return Utility().dump_error("2006")


@app.route('/v2/assetdiscovery/status', methods=['POST'])
def status():
    if request.headers.get('Authorization'):
        auth = request.headers.get('Authorization')
        token = auth.split()[1]
        # Decode token here
        decoded = Security().decode_token(token, secret_key, crypto_key)
        # Check in db if user exists
        if all (key in decoded for key in ("UserName", "SecretKey", "APIKey")):
            validate = Security().validate_utility_user(decoded)
            if len(validate.fetchall()) != 0:
                logger.write(CodeTrigger.Function, LogType.Info, "Credentials Validated!")
                # Check if token expired
                if int(time.mktime(datetime.utcnow().timetuple())) < decoded['exp']:
                    request_data = request.get_json()
                    if request_data:
                        if 'ScanRequestID' in request_data.keys():
                            # Retrieve result from MongoDB
                            try:
                                scan_request_id = request_data['ScanRequestID']
                                mongo_client = MongoClient(CONNECTION_STRING)
                                db = mongo_client["asset_discovery"]
                                completed_count = 0
                                scan_request = Connections().get_asset_discovery_scan_request_status(scan_request_id)[0]
                                if scan_request:
                                    if scan_request_id in db.list_collection_names():
                                        result = {}
                                        # if scan_request[0] == ScanRequestStatus.Completed.value:
                                        #     completed_count += 1
                                        if scan_request[1] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[2] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[3] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[4] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if completed_count == 4:
                                            result["Data"] = [ item for item in db[scan_request_id].find({}, {'_id': False}) ]
                                            result["Status"] = "Complete"
                                        else:
                                            result["Data"] = [ item for item in db[scan_request_id].find({}, {'_id': False}) ]
                                            result["Status"] = "Running"
                                        data = {}
                                        data['Result'] = result
                                        data['ErrorCode'] = None
                                        data['Message'] = "Scan Request retrieved!"
                                        data['Success'] = True
                                        return json.dumps(data)
                                    else:
                                        if scan_request[1] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[2] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[3] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[4] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if completed_count == 4:
                                            result = {}
                                            result["Data"] = None
                                            result["Status"] = "Complete"
                                            data = {}
                                            data['Result'] = result
                                            data['ErrorCode'] = None
                                            data['Message'] = "Scan Request retrieved!"
                                            data['Success'] = True
                                            return json.dumps(data)
                                        else:
                                            result = {}
                                            result["Data"] = None
                                            result["Status"] = "Pending"
                                            data = {}
                                            data['Result'] = result
                                            data['ErrorCode'] = None
                                            data['Message'] = "Scan Request retrieved!"
                                            data['Success'] = True
                                            return json.dumps(data)
                                else:
                                    return Utility().dump_error("2015")
                            except Exception as e:
                                logger.write(CodeTrigger.Function, LogType.Info, "Exception occured!", ex=e)
                                return Utility().dump_error("2016")
                        else:
                            return Utility().dump_error("2001")
                    else:
                        return Utility().dump_error("2001")
                else:
                    return Utility().dump_error("2004")
            else:
                return Utility().dump_error("2002")
        else:
            return Utility().dump_error("2005")
    else:
        return Utility().dump_error("2006")


@app.route('/scraper', methods=['POST'])
def scraper():
    if request.headers.get('Authorization'):
        auth = request.headers.get('Authorization')
        token = auth.split()[1]
        # Decode token here
        decoded = Security().decode_token(token, secret_key, crypto_key)
        # Check in db if user exists
        if all (key in decoded for key in ("UserName", "SecretKey", "APIKey")):
            validate = Security().validate_utility_user(decoded)
            if len(validate.fetchall()) != 0:
                logger.write(CodeTrigger.Function, LogType.Info, "Credentials Validated!")
                # Check if token expired
                if int(time.mktime(datetime.utcnow().timetuple())) < decoded['exp']:
                    request_data = request.get_json()
                    if request_data:
                        if 'Url' in request_data.keys():
                            try:
                                if 'IsSourceCodeRequired' not in request_data.keys() or request_data['IsSourceCodeRequired'] == True:
                                    if not 'ScrapingType' in request_data.keys():
                                        scraped_html = WebScraper().html_scraper(request_data['Url'], allow_redirects=True or request_data['IsAutoRedirect'])
                                    elif request_data['ScrapingType'] == 1:
                                        if 'Proxy' in request_data.keys():
                                            if request_data['Proxy'] != None:
                                                scraped_html = WebScraper().html_scraper(request_data['Url'], proxy=request_data['Proxy'], allow_redirects=True or request_data['IsAutoRedirect'])
                                            else:
                                                scraped_html = WebScraper().html_scraper(request_data['Url'], allow_redirects=True or request_data['IsAutoRedirect'])
                                        else:
                                            scraped_html = WebScraper().html_scraper(request_data['Url'], allow_redirects=True or request_data['IsAutoRedirect'])
                                    elif request_data['ScrapingType'] == 2:
                                        if 'Proxy' in request_data.keys():
                                            if request_data['Proxy'] != None:
                                                scraped_html = WebScraper().selenium_scraper(request_data['Url'], proxy=request_data['Proxy'])
                                            else:
                                                scraped_html = WebScraper().selenium_scraper(request_data['Url'])
                                        else:
                                            scraped_html = WebScraper().selenium_scraper(request_data['Url'])
                                    else:
                                        return Utility().dump_error("2012")
                                elif request_data['IsSourceCodeRequired'] == False and 'ScrapingType' in request_data.keys() and request_data['ScrapingType'] > 2:
                                    return Utility().dump_error("2012")
                                else:
                                    scraped_html = None
                            except ConnectionError:
                                url = request_data["Url"]
                                url = url.replace("https://", "")
                                url = url.replace("http://", "")
                                if 'IsSSLVerificationRequired' in request_data.keys():
                                    ssl = request_data['IsSSLVerificationRequired']
                                else:
                                    ssl = True
                                if 'IsSourceCodeRequired' in request_data.keys():
                                    source = request_data['IsSourceCodeRequired']
                                else:
                                    source = True
                                if 'IsAutoRedirect' in request_data.keys():
                                    redirect = request_data['IsAutoRedirect']
                                else:
                                    redirect = True
                                if "https" in request_data["Url"]:
                                    port = 443
                                else:
                                    port = 80
                                return json.dumps({
                                    "Result": {
                                        "Url": request_data['Url'],
                                        "RequestTimeOut": "36000",
                                        "IsAutoRedirect": redirect,
                                        "IsSourceCodeRequired": source,
                                        "IsSSLVerificationRequired": ssl,
                                        "IsSuccess": False,
                                        "RequestFailureMessage": "Failed to establish a connection to the url!",
                                        "IsSourceCodeGrabbed": False,
                                        "SourceCodeGrabbingError": None,
                                        "SourceCode": None,
                                        "StatusCode": 0,
                                        "Errors": None,
                                        "ResponseUrl": request_data['Url'],
                                        "ResponseHost": url,
                                        "ResponsePort": port,
                                        "ResponseHeader": None,
                                        "SslData": None
                                    },
                                    "Success": False,
                                    "Message": "Failed to establish a connection to the url!",
                                    "ErrorCode": "2011"
                                })
                            except WebDriverException:
                                url = request_data["Url"]
                                url = url.replace("https://", "")
                                url = url.replace("http://", "")
                                if "ScrapingType" in request_data.keys():
                                    if request_data['ScrapingType'] == 2:
                                        scraper = 2
                                    else:
                                        scraper = 1
                                else:
                                    scraper = 1
                                if 'IsSSLVerificationRequired' in request_data.keys():
                                    ssl = request_data['IsSSLVerificationRequired']
                                else:
                                    ssl = True
                                if 'IsSourceCodeRequired' in request_data.keys():
                                    source = request_data['IsSourceCodeRequired']
                                else:
                                    source = True
                                if 'IsAutoRedirect' in request_data.keys():
                                    redirect = request_data['IsAutoRedirect']
                                else:
                                    redirect = True
                                if "https" in request_data["Url"]:
                                    port = 443
                                else:
                                    port = 80
                                return json.dumps({
                                    "Result": {
                                        "Url": request_data['Url'],
                                        "ScrapingType": scraper,
                                        "RequestTimeOut": "36000",
                                        "IsAutoRedirect": redirect,
                                        "IsSourceCodeRequired": source,
                                        "IsSSLVerificationRequired": ssl,
                                        "IsSuccess": False,
                                        "RequestFailureMessage": "Failed to establish a connection to the url!",
                                        "IsSourceCodeGrabbed": False,
                                        "SourceCodeGrabbingError": None,
                                        "SourceCode": None,
                                        "StatusCode": 0,
                                        "Errors": None,
                                        "ResponseUrl": request_data['Url'],
                                        "ResponseHost": url,
                                        "ResponsePort": port,
                                        "ResponseHeader": None,
                                        "SslData": None
                                    },
                                    "Success": False,
                                    "Message": "Failed to extract data from the url!",
                                    "ErrorCode": "2009"
                                })
                            if 'Proxy' in request_data.keys():
                                if request_data['Proxy'] != None:
                                    metadata = WebScraper().metadata_extractor(request_data['Url'], proxy=request_data['Proxy'], allow_redirects=True or request_data['IsAutoRedirect'])
                                else:
                                    metadata = WebScraper().metadata_extractor(request_data['Url'], allow_redirects=True or request_data['IsAutoRedirect'])
                            else:
                                metadata = WebScraper().metadata_extractor(request_data['Url'], allow_redirects=True or request_data['IsAutoRedirect'])
                            meta_url = metadata['response_url'].replace("https://", "")
                            meta_url = meta_url.replace("http://", "")
                            meta_host = meta_url.strip("/")
                            metadata_headers = {}
                            headers = metadata['header']
                            for key in headers:
                                metadata_headers["{key}".format(key=key)] = headers["{key}".format(key=key)]
                            port = 0
                            if "https" in metadata['response_url']:
                                port = 443
                            else:
                                port = 80
                            if scraped_html != False:
                                data = {}
                                result = {}
                                result["Url"] = request_data["Url"]
                                # if request_data['IsSourceCodeRequired'] == False:
                                #     pass
                                if scraped_html == None:
                                    pass
                                else:
                                    if 'ScrapingType' in request_data.keys():
                                        result["ScrapingType"] = request_data["ScrapingType"]
                                    else:
                                        result["ScrapingType"] = 1
                                result["RequestTimeOut"] = "36000" or request_data["RequestTimeOut"]
                                if 'IsAutoRedirect' in request_data.keys():
                                    redirect = request_data['IsAutoRedirect']
                                else:
                                    redirect = True
                                result["IsAutoRedirect"] = redirect
                                if 'IsSourceCodeRequired' in request_data.keys():
                                    result["IsSourceCodeRequired"] = request_data["IsSourceCodeRequired"]
                                else:
                                    result["IsSourceCodeRequired"] = True
                                if 'IsSSLVerificationRequired' in request_data.keys():
                                    ssl = request_data['IsSSLVerificationRequired']
                                else:
                                    ssl = True
                                result["IsSSLVerificationRequired"] = ssl
                                if scraped_html:
                                    result["IsSuccess"] = True
                                elif result["IsSourceCodeRequired"] == False:
                                    result["IsSuccess"] = True
                                else:
                                    result["IsSuccess"] = False
                                if result["IsSourceCodeRequired"] == True and result["IsSuccess"] == True:
                                    result["RequestFailureMessage"] = None
                                    if scraped_html == None:
                                        result["IsSourceCodeGrabbed"] = False
                                    else:
                                        result["IsSourceCodeGrabbed"] = True
                                    result["SourceCodeGrabbingError"] = None
                                    result["SourceCode"] = scraped_html
                                    result["StatusCode"] = metadata['status_code']
                                    result["Errors"] = None
                                elif result["IsSourceCodeRequired"] == False and result["IsSuccess"] == True:
                                    result["RequestFailureMessage"] = None
                                    if scraped_html == None:
                                        result["IsSourceCodeGrabbed"] = False
                                    else:
                                        result["IsSourceCodeGrabbed"] = True
                                    result["SourceCodeGrabbingError"] = None
                                    result["SourceCode"] = scraped_html
                                    result["StatusCode"] = metadata['status_code']
                                    result["Errors"] = None
                                else:
                                    result["RequestFailureMessage"] = "Request Failed!"
                                    result["IsSourceCodeGrabbed"] = False
                                    result["SourceCodeGrabbingError"] = "Failed to grab source code!"
                                    result["SourceCode"] = None
                                    result["StatusCode"] = metadata['status_code']
                                    result["Errors"] = None
                                result["ResponseUrl"] = metadata['response_url']
                                result["ResponseHost"] = meta_host
                                result["ResponsePort"] = port
                                result["ResponseHeader"] = metadata_headers
                                if result["IsSSLVerificationRequired"] == True:
                                    url = request_data["Url"]
                                    url = url.replace("https://", "")
                                    url = url.replace("http://", "")
                                    try:
                                        certificate = WebScraper().get_certificate(url, port)
                                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
                                        ssl_data = {}
                                        subject = []
                                        issuer = []
                                        ssl_data["IsValid"] = True
                                        ssl_data["Vulnerabilities"] = None
                                        for t in x509.get_subject().get_components():
                                            key = str(t[0], 'utf-8')
                                            value = str(t[1], 'utf-8')
                                            subject.append(str(key + "=" + value))
                                        ssl_data["Subject"] = str(subject).strip("[]")
                                        ssl_data["Signature"] = None
                                        valid_from = str(x509.get_notBefore(), 'utf-8')
                                        valid_from = valid_from[:4] + "-" + valid_from[4:6] + "-" + valid_from[6:8] + "T" + valid_from[8:10] + ":" + valid_from[10:12] + ":" + valid_from[12:]
                                        ssl_data["ValidFrom"] = valid_from
                                        valid_to = str(x509.get_notAfter(), 'utf-8')
                                        valid_to = valid_to[:4] + "-" + valid_to[4:6] + "-" + valid_to[6:8] + "T" + valid_to[8:10] + ":" + valid_to[10:12] + ":" + valid_to[12:]
                                        ssl_data["ValidTo"] = valid_to
                                        for t in x509.get_issuer().get_components():
                                            key = str(t[0], 'utf-8')
                                            value = str(t[1], 'utf-8')
                                            issuer.append(str(key + "=" + value))
                                        ssl_data["Issuer"] = str(issuer).strip("[]")
                                        result["SslData"] = ssl_data
                                    except SSLError as e:
                                        result["SslData"] = None
                                        data["Result"] = result
                                        data["Success"] = False
                                        data["Message"] = "Failed to verify SSL or webpage does not exist!"
                                        data["ErrorCode"] = "2008"
                                        return json.dumps(data)
                                else:
                                    result["SslData"] = None
                                data["Result"] = result
                                data["Success"] = True
                                data["Message"] = ""
                                data["ErrorCode"] = ""
                                return json.dumps(data)
                        else:
                            return Utility().dump_error("2001")
                    else:
                        return Utility().dump_error("2001")
                else:
                    return Utility().dump_error("2004")
            else:
                return Utility().dump_error("2002")
        else:
            return Utility().dump_error("2005")
    else:
        return Utility().dump_error("2006")


@app.route('/v2/subdirectorytraversal/scan', methods=['POST'])
def discover():
    if request.headers.get('Authorization'):
        auth = request.headers.get('Authorization')
        token = auth.split()[1]
        # Decode token here
        decoded = Security().decode_token(token, secret_key, crypto_key)
        # Check in db if user exists
        if all (key in decoded for key in ("UserName", "SecretKey", "APIKey")):
            validate = Security().validate_utility_user(decoded)
            if len(validate.fetchall()) != 0:
                logger.write(CodeTrigger.Function, LogType.Info, "Credentials Validated!")
                # Check if token expired
                if int(time.mktime(datetime.utcnow().timetuple())) < decoded['exp']:
                    request_data = request.get_json()
                    if request_data:
                        if 'Domain' in request_data.keys():
                            # Create scan request
                            try:
                                scan_request_id = shortuuid.uuid()
                                Connections().insert_subdirectory_traversal_scan_request(scan_request_id, request_data['Domain'])
                                result = {
                                    "ScanRequestID": scan_request_id,
                                    "AddedDate": str(datetime.utcnow())
                                }
                                data = {}
                                data['Result'] = result
                                data['ErrorCode'] = None
                                data['Message'] = "Scan Request created!"
                                data['Success'] = True
                                return json.dumps(data)
                            except:
                                return Utility().dump_error("2014")
                        else:
                            return Utility().dump_error("2001")
                    else:
                        return Utility().dump_error("2001")
                else:
                    return Utility().dump_error("2004")
            else:
                return Utility().dump_error("2002")
        else:
            return Utility().dump_error("2005")
    else:
        return Utility().dump_error("2006")


@app.route('/v2/subdirectorytraversal/status', methods=['POST'])
def list():
    if request.headers.get('Authorization'):
        auth = request.headers.get('Authorization')
        token = auth.split()[1]
        # Decode token here
        decoded = Security().decode_token(token, secret_key, crypto_key)
        # Check in db if user exists
        if all (key in decoded for key in ("UserName", "SecretKey", "APIKey")):
            validate = Security().validate_utility_user(decoded)
            if len(validate.fetchall()) != 0:
                logger.write(CodeTrigger.Function, LogType.Info, "Credentials Validated!")
                # Check if token expired
                if int(time.mktime(datetime.utcnow().timetuple())) < decoded['exp']:
                    request_data = request.get_json()
                    if request_data:
                        if 'ScanRequestID' in request_data.keys():
                            # Retrieve result from MongoDB
                            try:
                                scan_request_id = request_data['ScanRequestID']
                                mongo_client = MongoClient(CONNECTION_STRING)
                                db = mongo_client["subdirectory_traversal"]
                                completed_count = 0
                                scan_request = Connections().get_subdirectory_traversal_scan_request_status(scan_request_id)[0]
                                if scan_request:
                                    if scan_request_id in db.list_collection_names():
                                        result = {}
                                        # if scan_request[0] == ScanRequestStatus.Completed.value:
                                        #     completed_count += 1
                                        if scan_request[1] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[2] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[3] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[4] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if completed_count == 4:
                                            result["Data"] = [ item for item in db[scan_request_id].find({}, {'_id': False}) ]
                                            result["Status"] = "Complete"
                                        else:
                                            result["Data"] = [ item for item in db[scan_request_id].find({}, {'_id': False}) ]
                                            result["Status"] = "Running"
                                        data = {}
                                        data['Result'] = result
                                        data['ErrorCode'] = None
                                        data['Message'] = "Scan Request retrieved!"
                                        data['Success'] = True
                                        return json.dumps(data)
                                    else:
                                        if scan_request[1] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[2] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[3] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if scan_request[4] == ScanRequestStatus.Completed.value:
                                            completed_count += 1
                                        if completed_count == 4:
                                            result = {}
                                            result["Data"] = None
                                            result["Status"] = "Complete"
                                            data = {}
                                            data['Result'] = result
                                            data['ErrorCode'] = None
                                            data['Message'] = "Scan Request retrieved!"
                                            data['Success'] = True
                                            return json.dumps(data)
                                        else:
                                            result = {}
                                            result["Data"] = None
                                            result["Status"] = "Pending"
                                            data = {}
                                            data['Result'] = result
                                            data['ErrorCode'] = None
                                            data['Message'] = "Scan Request retrieved!"
                                            data['Success'] = True
                                            return json.dumps(data)
                                else:
                                    return Utility().dump_error("2015")
                            except Exception as e:
                                logger.write(CodeTrigger.Function, LogType.Info, "Exception occured!", ex=e)
                                return Utility().dump_error("2016")
                        else:
                            return Utility().dump_error("2001")
                    else:
                        return Utility().dump_error("2001")
                else:
                    return Utility().dump_error("2004")
            else:
                return Utility().dump_error("2002")
        else:
            return Utility().dump_error("2005")
    else:
        return Utility().dump_error("2006")


@app.errorhandler(ExpiredSignatureError)
def jwt_expired_signature(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Token expired!")
    return Utility().dump_error("2004")

@app.errorhandler(DecodeError)
@app.errorhandler(InvalidToken)
def jwt_decode_failure(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Failed to decode token!")
    return Utility().dump_error("2007")

@app.errorhandler(SSLError)
def request_ssl_verify_failure(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Failed to verify SSL or webpage does not exists!")
    return Utility().dump_error("2008")
    
@app.errorhandler(TypeError)
def type_failure(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Failed to extract data from the url!")
    return Utility().dump_error("2009")

@app.errorhandler(WebDriverException)
def web_driver_failure(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Failed to extract data from the url!")
    return Utility().dump_error("2009")

@app.errorhandler(MissingSchema)
def schema_failure(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Url is missing a schema!")
    return Utility().dump_error("2010")

@app.errorhandler(ConnectionError)
def connection_failure(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Failed to establish a connection to the url!")
    return Utility().dump_error("2011")

@app.errorhandler(FileNotFoundError)
@app.errorhandler(gaierror)
def cert_ssl_verify_failure(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Failed to verify SSL or webpage does not exists!")
    return Utility().dump_error("2008")

@app.errorhandler(SSLError)
def python_ssl_verify_failure(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Failed to verify SSL or webpage does not exists!")
    return Utility().dump_error("2008")

@app.errorhandler(ProgrammingError)
def login_credentials_failure(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Invalid username/password or missing credentials.")
    return Utility().dump_error("2002")

@app.errorhandler(TypeError)
def empty_request_failure(e):
    logger.write(CodeTrigger.Function, LogType.Info, "Invalid request!")
    return Utility().dump_error("2001")

                                                                                                                                                                                                             


if __name__ == "__main__":
    # app.run(debug=True)
    # BaseHTTPRequestHandler.protocol_version = "HTTP/1.1"
    WSGIRequestHandler.protocol_version = "HTTP/1.1"
    serve(app, host='localhost', port=5000)
    logger.close()