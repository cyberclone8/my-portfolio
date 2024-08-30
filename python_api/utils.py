from flask import Flask, request, jsonify, make_response
from waitress import serve
from scraper import WebScraper
import jwt
from cryptography.fernet import Fernet, InvalidToken
from jwt.exceptions import DecodeError
from requests.exceptions import SSLError, MissingSchema, ConnectionError
from selenium.common.exceptions import WebDriverException
from pyodbc import ProgrammingError
from ssl import SSLError
from socket import gaierror
from dateutil import parser
from werkzeug.serving import WSGIRequestHandler

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

from security import Security


class Utility:
    def dump_error(self, error_code):
        if error_code == "2001":
            return json.dumps({
                "ErrorCode": "2001",
                "Message": "Invalid request!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2002":
            return json.dumps({
                "ErrorCode": "2002",
                "Message": "Invalid username/password or missing credentials.",
                "Result": None,
                "Success": False
            })
        elif error_code == "2004":
            return json.dumps({
                "ErrorCode": "2004",
                "Message": "token has expired.",
                "Result": None,
                "Success": False
            })
        elif error_code == "2005":
            return json.dumps({
                "ErrorCode": "2005",
                "Message": "invalid token!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2006":
            return json.dumps({
                "ErrorCode": "2006",
                "Message": "missing token!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2007":
            return json.dumps({
                "ErrorCode": "2007",
                "Message": "Failed to decode token!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2008":
            return json.dumps({
                "ErrorCode": "2008",
                "Message": "Failed to verify SSL or webpage does not exists!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2009":
            return json.dumps({
                "ErrorCode": "2009",
                "Message": "Failed to extract data from the url!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2010":
            return json.dumps({
                "ErrorCode": "2010",
                "Message": "Invalid or Blocked URL!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2011":
            return json.dumps({
                "ErrorCode": "2011",
                "Message": "Failed to establish a connection to the url!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2012":
            return json.dumps({
                "ErrorCode": "2012",
                "Message": "Invalid scraping method!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2013":
            return json.dumps({
                "ErrorCode": "2013",
                "Message": "File upload failed!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2014":
            return json.dumps({
                "ErrorCode": "2014",
                "Message": "Scan Request creation failed!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2015":
            return json.dumps({
                "ErrorCode": "2015",
                "Message": "Scan Request not found!",
                "Result": None,
                "Success": False
            })
        elif error_code == "2016":
            return json.dumps({
                "ErrorCode": "2016",
                "Message": "Failed to retrieve Scan Request data!",
                "Result": None,
                "Success": False
            })