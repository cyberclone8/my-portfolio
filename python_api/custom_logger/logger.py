import json
from datetime import datetime, timedelta
import socket
import inspect
import os
import glob
from enum import Enum
import traceback
import pkg_resources
import string
import random

import paramiko
from getmac import get_mac_address


class CodeTrigger(Enum):
    Property = 1
    Event = 2
    Function = 3
    Database = 4

class LogType(Enum):
    Info = 1
    Warning = 2
    Error = 3
    FatalError = 4

class Connectivity:
    _selected_storage_name = None
    _is_server_environment = False
    _folder_prefix = None
    _sftp_username = None
    _sftp_password = None
    _sftp_host_name = None
    _ssh_host_key_fingerprint = None

    _encrpyted_storageA_sftp_creds = ""

    _storageA_sftp_username = ""
    _storageA_sftp_password = ""
    _storageA_sftp_host_name = ""
    _storageA_ssh_host_key_fingerprint = ""

    _encrpyted_storage_default_sftp_creds = ""
    
    _storage_default_sftp_username = ""
    _storage_default_sftp_password = ""
    _storage_default_sftp_host_name = ""
    _storage_default_ssh_host_key_fingerprint = ""

    _encrpyted_storage_client_sftp_creds = ""
    
    _storage_client_sftp_username = ""
    _storage_client_sftp_password = ""
    _storage_client_sftp_host_name = ""
    _storage_client_ssh_host_key_fingerprint = ""

    def __init__(self, storageName, isServerEnvironment):
        self._selected_storage_name = storageName
        self._is_server_environment = isServerEnvironment
        if self._is_server_environment == True:
            if self._selected_storage_name == "StorageA":
                credString = self.decrypt(self._encrpyted_storageA_sftp_creds)
                cred = credString.split(",")
                self._sftp_host_name = cred[0]
                self._sftp_username = cred[2]
                self._sftp_password = cred[3]
                self._ssh_host_key_fingerprint = self._storageA_ssh_host_key_fingerprint
            else:
                credString = self.decrypt(self._encrpyted_storage_default_sftp_creds)
                cred = credString.split(",")
                self._sftp_host_name = cred[0]
                self._sftp_username = cred[2]
                self._sftp_password = cred[3]
                self._ssh_host_key_fingerprint = self._storage_default_ssh_host_key_fingerprint
        else:
            self._sftp_host_name = self._storage_client_sftp_host_name
            self._sftp_username = self._storage_client_sftp_username
            self._sftp_password = self._storage_client_sftp_password
            self._ssh_host_key_fingerprint = self._storage_client_ssh_host_key_fingerprint

    def decrypt(self, combinedString):
        import base64
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        keyString = "Tree@Cross@Core@"
        combinedData = base64.b64decode(combinedString)
        aes = AES.new(keyString.encode(), AES.MODE_ECB)
        iv = combinedData[:aes.block_size]
        cipherText = combinedData[aes.block_size:]
        aes.iv = iv
        plainText = aes.decrypt(cipherText)
        plainText = unpad(plainText, AES.block_size).decode()
        return plainText

    def upload_file(self, local_file_path, remote_file_path):
        try:
            transport = paramiko.SSHClient()
            transport.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            transport.connect(
                username=self._sftp_username,
                password=self._sftp_password,
                hostname=self._sftp_host_name,
                port=22
            )
            sftp = transport.open_sftp()
            # Extract the remote directory and remote file name from the remote_file_path
            remote_directory, remote_file_name = os.path.split(remote_file_path)
            # Change directory to the remote directory
            try:
                sftp.chdir(remote_directory)
            except FileNotFoundError:
                # Remote directory doesn't exist, create it
                dirs = remote_directory.split('/')
                for dir in dirs:
                    try:
                        sftp.chdir(dir)
                    except FileNotFoundError:
                        # Subdirectory doesn't exist, create it
                        sftp.mkdir(dir)
                        sftp.chdir(dir)
            # Upload the file to the remote directory with the specified name
            sftp.put(os.path.abspath(local_file_path), remote_file_name)
            sftp.close()
            transport.close()
        except Exception as e:
            print(f"Error uploading log file: {e}")

class CustomFileHandler:
    def __init__(self, file_path):
        self.file_path = file_path

    def emit(self, record):
        log_entry = {
            "LogPart": "Detail",
            "DateTimeStamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            "CodeTrigger": record['codeTrigger'],
            "LogType": record['logType'],
            "Message": record['msg'],
            "MethodName": record['methodName'],
            "ErrorMessages": self.get_error_details(record),
            "Tags": record.get('tags', None)
        }
        with open(self.file_path, 'a') as file:
            file.write(json.dumps(log_entry) + ',\n')

    def get_error_details(self, record):
        exception = record.get('exception', None)
        if exception:
            error_details = []
            error_details.append({"Key": "Message", "Value": str(exception)})
            if isinstance(exception, BaseException):
                # Include stack trace if available
                stack_trace = traceback.format_exc()
                error_details.append({"Key": "StackTrace", "Value": stack_trace})
                # Include base exception details if available
                if exception.__cause__:
                    base_exception = str(exception.__cause__)
                    error_details.append({"Key": "BaseException", "Value": base_exception})
            return error_details
        return None

class CustomLogger:
    def __init__(self, storageName, appId, runTimeArgument, appVersion, projectId, serviceId, serverId, isServerEnvironment, userName=None, logDaysRetention=7, daysToUploadFailedLogs=0):
        self._datetime_started = datetime.utcnow().strftime('%Y%m%d_%H%M%S.%f')
        self._random_suffix = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        self._filename = f"{appId}_{projectId}_{serviceId}_{self._datetime_started}_{self._random_suffix}.json"
        self._filepath_isserver_false = f"{appId}/{projectId}/"
        self._filepath_isserver_true = f"{appId}/{projectId}/{serverId}"
        self._log_file_path = f'logs/{self._filename}'
        self.transferred_logs_path = "transferred_logs"
        self.file_handler = CustomFileHandler(self._log_file_path)
        self.connectivity = Connectivity(storageName, isServerEnvironment)
        self.runtime_argument = runTimeArgument if runTimeArgument else 0
        self.is_server_environment = isServerEnvironment
        self.app_version = appVersion
        self.project_id = projectId
        self.server_id = serverId if serverId else None
        self.storage_name = storageName
        self.filename = self._filename
        self.filepath = os.path.abspath(self._filepath_isserver_true) if self.is_server_environment else os.path.abspath(self._filepath_isserver_false)
        self.app_id = appId
        self.username = userName
        self.log_days_retention = logDaysRetention
        self.days_to_upload_failed_logs = daysToUploadFailedLogs
        self.datetime_started = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        self.datetime_ended = None
        self.header = {
            "LogPart": "Header",
            "AppId": self.app_id,
            "IPAddress": socket.gethostbyname(socket.gethostname()),
            "RunTimeArgument": self.runtime_argument,
            "FileName": self._filename,
            "FilePath": self.filepath,
            "AppVersion": self.app_version,
            "ProjectId": self.project_id,
            "DateTimeStarted": self.datetime_started,
            "DaysToUploadFailedLogs": self.days_to_upload_failed_logs,
            "UploadFailedLogsAtEnd": False,
            "ServerId": self.server_id,
            "StorageName": self.storage_name,
            "IsServerEnvironment": self.is_server_environment,
            "Username": self.username,  # Add the username if available
            "ComputerName": socket.gethostname(),
            "MACAddress": get_mac_address(),
            "DateTimeEnded": self.datetime_ended,
            "LogDaysRetention": self.log_days_retention
        }
        self.service_requirements = {
            "LogPart": "Detail",
            "DateTimeStamp": self.datetime_started,
            "CodeTrigger": "Property", 
            "LogType": "Info",
            "Message": self._get_installed_packages,
            "MethodName": "_get_installed_packages", 
            "ErrorMessages": None, 
            "Tags": None
        }
        with open(self._log_file_path, 'w') as file:
            file.write(json.dumps(self.header) + ',\n')
            service_requirements_result = self.service_requirements.copy()
            service_requirements_result["Message"] = self._get_installed_packages()
            file.write(json.dumps(service_requirements_result) + ',\n')

    def write(self, codeTrigger, logType, message, **kwargs):
        log_entry = {
            "codeTrigger": codeTrigger.name,
            "logType": logType.name,
            "msg": message,
            "methodName": inspect.stack()[1].function,
            "tags": kwargs["tags"] if "tags" in kwargs.keys() else None,
            "exception": kwargs["ex"] if "ex" in kwargs.keys() else None
        }
        self.file_handler.emit(log_entry)

    def set_datetime_ended(self):
        try:
            # Open the log file in append mode
            with open(self._log_file_path, 'a') as file:
                # Create a new header JSON with DateTimeEnded filled in
                new_header = {
                    "LogPart": "Header",
                    "AppId": self.app_id,
                    "IPAddress": socket.gethostbyname(socket.gethostname()),
                    "RunTimeArgument": self.runtime_argument if not None else 0,
                    "FileName": self._filename,
                    "FilePath": self.filepath,
                    "AppVersion": self.app_version,
                    "ProjectId": self.project_id,
                    "DateTimeStarted": self.datetime_started,
                    "DaysToUploadFailedLogs": self.days_to_upload_failed_logs,
                    "UploadFailedLogsAtEnd": False,
                    "ServerId": self.server_id,
                    "StorageName": self.storage_name,
                    "IsServerEnvironment": self.is_server_environment,
                    "Username": self.username,  # Add the username if available
                    "ComputerName": socket.gethostname(),
                    "MACAddress": get_mac_address(),
                    "DateTimeEnded": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                    "LogDaysRetention": self.log_days_retention
                }
                # Append the new header to the end of the file
                file.write(json.dumps(new_header) + ',\n')
        except Exception as e:
            print(f"Error updating DateTimeEnded in the log file: {e}")



    def _get_installed_packages(self):
        installed_packages = []
        for package in pkg_resources.working_set:
            installed_packages.append({
                "PackageName": package.project_name,
                "PackageVersion": package.version
            })
        return str(installed_packages)

    def close(self):
        try:
            # Get the current log file path
            log_file_path = os.path.abspath(self._log_file_path)
            # Rename the file by adding "_done" to the filename
            if not log_file_path.endswith("_done.json"):
                done_log_file_path = os.path.splitext(log_file_path)[0] + "_done.json"
            else:
                print("Log file already marked as '_done'. Skipping processing.")
            # If the log file has not been marked as "_done," append "_done" to the filename
            if not self._filename.endswith("_done.json"):
                self._filename = self._filename.replace(".json", "_done.json")
                self._log_file_path = self._log_file_path.replace(".json", "_done.json")
                os.rename(log_file_path, done_log_file_path)
            else:
                print("Log file already marked as '_done'. Skipping processing.")
            # Set DateTimeEnded before closing the logger
            self.set_datetime_ended()
            if not self.is_server_environment and self.username:
                remote_path = f"{self._filepath_isserver_false}{self.username}/{self._filename}"
            else:
                remote_path = f"{self._filepath_isserver_true}/{self._filename}"
            # Check if the log file is marked as "_done"
            if self._filename.endswith("_done.json"):
                # Check if the file is older than one day
                current_time = datetime.now()
                file_time = datetime.utcfromtimestamp(os.path.getmtime(self._log_file_path))
                if (current_time - file_time).days > 1:
                    # Set the flag to True
                    self._marked_as_done = True
                    # Upload the log file
                    remote_path += "_done"
                    self.connectivity.upload_file(self._log_file_path, remote_path)
                    # Move the local file to the transferred_logs folder
                    local_transferred_path = os.path.join(self.transferred_logs_path, self._filename)
                    os.rename(self._log_file_path, local_transferred_path)
            else:
                print("Log file not marked as '_done'. Skipping upload.")
        except Exception as e:
            print(f"Error uploading log file: {e}")
        try:
            # Transfer remaining files in the "logs" directory to the same remote path
            logs_directory = "logs"
            if os.path.exists(logs_directory):
                log_files = glob.glob(os.path.join(logs_directory, "*.json"))
                for log_file in log_files:
                    # Check if the file is older than one day and has "_done" at the end
                    current_time = datetime.now()
                    file_time = datetime.utcfromtimestamp(os.path.getmtime(log_file))
                    if (current_time - file_time).days >= 0 and log_file.endswith("_done.json"):
                        self.connectivity.upload_file(log_file, remote_path)
                        local_transferred_path = os.path.join(self.transferred_logs_path, os.path.basename(log_file))
                        os.rename(log_file, local_transferred_path)
                    elif not log_file.endswith("_done.json") and (current_time - file_time).days > self.days_to_upload_failed_logs:
                        # Upload the log file
                        # remote_path = self.get_remote_path()
                        remote_path = f"{self._filepath_isserver_false}/{self.username}/{self._filename}" if not self.is_server_environment else f"{self._filepath_isserver_true}/{self._filename}"
                        self.connectivity.upload_file(log_file, remote_path)
                        # Move the local file to the transferred_logs folder
                        local_transferred_path = os.path.join(self.transferred_logs_path, os.path.basename(log_file))
                        os.rename(log_file, local_transferred_path)
        except Exception as e:
            print(f"Error uploading `failed-to-upload` log files: {e}")
        try:
            # Delete old logs in transferred_logs folder based on LogDaysRetention value
            retention_days = self.header["LogDaysRetention"]
            transferred_logs_files = glob.glob(os.path.join(self.transferred_logs_path, "*.json"))
            current_time = datetime.now()
            for file_path in transferred_logs_files:
                file_time = datetime.utcfromtimestamp(os.path.getmtime(file_path))
                if (current_time - file_time).days > retention_days:
                    os.remove(file_path)
        except Exception as e:
            print(f"Error deleting log files based on retention days: {e}")

# # Example Usage:
# if not os.path.exists('logs'):
#     os.makedirs('logs')
# if not os.path.exists('transferred_logs'):
#     os.makedirs('transferred_logs')
# logger = CustomLogger(storageName="StorageA", appId="APP1000PY", runTimeArgument="level2,ZRD", appVersion="1.0.0.4", 
#                       projectId=1, serverId="Server86", isServerEnvironment=False, userName="lance.lopez0912@gmail.com")

# # Writing log entries
# def do_something():
#     logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
#     logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
#     logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
#     logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
#     logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
#     logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
#     logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
#     logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
#     logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
#     logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
#     logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
#     logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
#     logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
#     logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
#     logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
#     logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
#     logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
#     logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")
#     logger.write(CodeTrigger.Property, LogType.Info, "total filtered record - 36")
#     logger.write(CodeTrigger.Property, LogType.Info, "total processed record - 2000")
#     logger.write(CodeTrigger.Property, LogType.Info, "Operation completed (level2)")


# do_something()
# logger.close()
