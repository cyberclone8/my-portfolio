from flask import Flask
from config import SERVER, DATABASE, USERNAME, PASSWORD
import pyodbc

import jwt
from cryptography.fernet import Fernet

from datetime import datetime, timedelta
import pdb


class Security:
    def validate_utility_user(self, request_data):
        cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+SERVER+';DATABASE='+DATABASE+';UID='+USERNAME+';PWD='+ PASSWORD)
        cnxn.autocommit = True
        cursor = cnxn.cursor()
        validate = cursor.execute(
            """
            EXEC ValidateUtilityUser @UserName='{username}', @APIKey='{api_key}', @SecretKey='{secret_key}'
            """.format(username=request_data['UserName'], api_key=request_data['APIKey'], secret_key=request_data['SecretKey'])
        )
        return validate

    def encode_token(self, request_data, secret_key, crypto_key):
        request_data['exp'] = datetime.now() + timedelta(hours=24)
        encoded_token = jwt.encode(request_data, secret_key, algorithm="HS256")
        encrypted_token = Fernet(crypto_key).encrypt(bytes(encoded_token, 'utf-8'))
        data = {
            "Result": {
                "AccessToken": str(encrypted_token, 'utf-8')
            },
            "Success": True,
            "Message": "",
            "ErrorCode": ""
        }
        return data

    def decode_token(self, token, secret_key, crypto_key):
        decrypted_token = Fernet(crypto_key).decrypt(bytes(token, 'utf-8'))
        decoded_data = jwt.decode(decrypted_token, secret_key, algorithms=["HS256"])
        return decoded_data