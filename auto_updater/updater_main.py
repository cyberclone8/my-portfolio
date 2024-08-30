import os
import requests
import json
import subprocess
import socket
import paramiko
from time import sleep
from datetime import datetime
import sys
import ctypes
from cryptography.fernet import Fernet
import shutil
import argparse
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
from retrying import retry
from custom_logger.logger import CustomLogger, CodeTrigger, LogType

UPDATER_VERSION = "1.0.0.4"
APP_UPDATER_ID = "APP1001PY"

# Create logs folder and initialize logger
if not os.path.exists('logs'):
    os.makedirs('logs')
if not os.path.exists('transferred_logs'):
    os.makedirs('transferred_logs')
logger = CustomLogger(storageName="StorageA", appId="APP1001PY", runTimeArgument=None, appVersion="1.0.0.4", 
                      projectId=1, serverId="Server170", isServerEnvironment=False, userName="lance.lopez0912@gmail.com")

class AppUpdater:

    def __init__(self, host, port, username, password):
        self.sftp = paramiko.SSHClient()
        self.sftp.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.sftp.connect(username=username, password=password, hostname=host, port=port)
        except Exception as e:
            logger.write(CodeTrigger.Event, LogType.FatalError, "Failed to establish SSH connection!", ex=e)
            sys.exit(1)

    @retry(wait_exponential_multiplier=1000, wait_exponential_max=10000, stop_max_attempt_number=5)
    def get_version(self, App_Id, Current_Version):
        try:
            sys.stdout.write(f"Local Version -> {Current_Version}\n")
            results = requests.post("https://localhost:5000/api/v1/data/getlatestappversion",
                                    headers={
                                            "Authorization": "Bearer {access_token}".format(access_token=self.token)
                                            },
                                    json={
                                            "AppID": "{app_id}".format(app_id=App_Id),
                                            "CurrentAppVersion": "{current_version}".format(current_version=Current_Version),
                                            "SystemName": "{system_name}".format(system_name=self.system_name),
                                            "UtilityUserId": self.utility_user_id
                                        }
                                    )
            api = json.loads(results.text)
            sys.stdout.write(f"Response -> {api}\n")
            api = api['Result']
            return api
        except Exception as e:
            logger.write(CodeTrigger.Function, LogType.Error, "Retrying due to error!", ex=e)
            sys.stdout.write(f"{e}\n")

    def stop_task(self, stop_files_list):
        for filename in stop_files_list:
            sys.stdout.write('Stopping Task instance\n')
            try:
                subprocess.run(f"Taskkill /f /im {filename}")
            except Exception as e:
                sys.stdout.write(f'{e}\n')
    
    def stop_updater(self):
        sys.stdout.write('Stopping Updater instance\n')
        try:
            subprocess.run("Taskkill /f /im updater_main.exe")
        except Exception as e:
            sys.stdout.write(f'{e}\n')

    def read_app_config(self, access_token, APP_ID, APP_VERSION):
        with open(os.path.join(os.getcwd(), 'app_config.json'), 'r') as f:
            self.config = json.load(f)
            self.app_id = APP_ID
            self.local_version = APP_VERSION
            # app_config.json currently in the blacklist so that it don't get deleted when updater deletes and moves downloaded files
            self.blacklist = self.config['IGNORE_FILES']
            self.token = access_token
            # self.utility_user_id = int(self.config['UTILITY_USER_ID'])
            self.utility_user_id = 0
            # self.task_names = self.config['TASK_NAMES']
            self.project_dir = os.getcwd()

        self.system_name = socket.gethostname()

    def read_updater_config(self, access_token):
        # with open(os.path.join(os.getcwd(), 'updater_config.json'), 'r') as f:
        #     self.config = json.load(f)
        self.app_updater_id = APP_UPDATER_ID
        self.local_updater_version = UPDATER_VERSION
        # updater_config.json currently in the blacklist so that it don't get deleted when updater deletes and moves downloaded files
        self.token = access_token
        self.utility_user_id = 0
        # self.task_names = self.config['TASK_NAMES']
        self.project_dir = os.getcwd()

        self.system_name = socket.gethostname()

    @retry(wait_exponential_multiplier=1000, wait_exponential_max=10000, stop_max_attempt_number=5)
    def update_app(self, access_token, APP_ID, APP_VERSION):
        self.read_app_config(access_token, APP_ID, APP_VERSION)
        
        # if self.task_names:
        #     self.stop_service()

        # this copy of updater_main file is from last update so, now we can safely remove it
        if os.path.exists(self.project_dir + "\\updater_main_copy.exe"):
            os.remove(self.project_dir + "\\updater_main_copy.exe")
            sys.stdout.write("Deleted Copy -> updater_main_copy.exe\n")
        try:
            sys.stdout.write(f"Checking App Version\n")
            response = self.get_version(self.app_id, self.local_version)
            sys.stdout.write(f"Version Check finished\n")
            if response:
                latest_app_version = response
                is_outdated = self.compare_version(self.local_version, latest_app_version)
                if is_outdated:
                    sftp = self.sftp.open_sftp()
                    sftp.chdir(str(self.app_id))
                    local_files = set(os.listdir(self.project_dir))
                    remote_files = set(sftp.listdir())
                    sys.stdout.write(f"Local Files -> {local_files}\n")
                    sys.stdout.write(f"Remote Files -> {remote_files}\n")
                    self.blacklist = set(self.blacklist)
                    # Download and replace all files except the files self.config/IGNORE_FILES
                    # check/create Download Folder
                    files_to_update = remote_files - self.blacklist
                    sys.stdout.write(str(files_to_update)+"\n")
                    downloaded_files_count = 0
                    download_attempt = 0
                    while downloaded_files_count < len(files_to_update):
                        # create download folder also handles if there are files still remaining in the folder then delete
                        self.create_download_folder()
                        sys.stdout.write('Downloading files...\n')
                        if download_attempt == 10:
                            sys.stdout.write(f'Maximum Attempt, closing app\n')
                            break
                        else:
                            download_attempt += 1
                            sys.stdout.write(f'Download Attempt...{download_attempt}\n')
                        for filename in files_to_update:
                            remote_file_path ="/{app_id}/{filename}".format(app_id = self.app_id, filename = filename)
                            local_file_path ="{download_dir}/{filename}".format(download_dir = self.download_dir, filename = filename)
                            sftp.get(remote_file_path, local_file_path)
                            downloaded_files_count += 1
                        if len(os.listdir(self.download_dir)) != len(files_to_update):
                            downloaded_files_count = 0
                        sys.stdout.write(
                            f"Total Remote files: {len(files_to_update)}; Total Downloaded Files: {len(os.listdir(self.download_dir))}\n")
                    sftp.close()
                    
                    if os.listdir(self.download_dir):
                        allfiles = os.listdir(self.download_dir)
                        for file in allfiles:
                            if file in self.blacklist:
                                # if a file is in blacklist but is downloaded then we need to whitelist that and replace the local, whitelist simply means remove from the list blacklist
                                self.blacklist.remove(file)
                        local_files -= self.blacklist
                        
                        try:
                            sys.stdout.write(f'Moving files from {self.download_dir} <-- to --> {self.project_dir}\n')
                            executable = [file for file in allfiles if file.endswith(".exe")]
                            for file in allfiles:
                                count = 1
                                pending_file_movement = True
                                while pending_file_movement:
                                    stop_files_list = executable
                                    if count > 2000:
                                        sys.stdout.write(f'Update Unsuccessful...\n')
                                        return
                                    try:
                                        sys.stdout.write(f'Moving -> {file}\n')
                                        src_path = os.path.join(self.download_dir, file)
                                        dst_path = os.path.join(self.project_dir, file)
                                        shutil.move(src_path, dst_path)
                                        pending_file_movement = False
                                    except Exception as e:
                                        sys.stdout.write(f"{e}\n")
                                        sys.stdout.write(f'Failed -> moving {file}, Retrying...\n')
                                        stop_files_list.append(file)
                                        # self.stop_service()
                                        self.stop_task(stop_files_list)
                                        pending_file_movement = True
                                    count += 1
                            sys.stdout.write(f'Finished Moving files from {self.download_dir} <-- to --> {self.project_dir}\n')
                            sys.stdout.write("Update Successful\n")
                        except Exception as e:
                            sys.stdout.write(f'{e}')
                else:
                    sys.stdout.write(f"No new Updates found for App\n")
                    sys.stdout.write(f"Running Latest App Version: {self.local_version}\n")
                
                new_updates_in_appupdater = self.check_appupdater_update()
                if new_updates_in_appupdater:

                    self.make_updater_copy_in_project_directory()
                    sys.stdout.write(f'Copied {self.project_dir}\\updater_main_copy.exe\n')

                    sys.stdout.write(f"Relaunching to update App-Updater\n")
                    # subprocess.call("updater_main_copy.exe -u")
                    subprocess.Popen('cmd /k ' + "updater_main_copy.exe -u")
                    sys.exit(0)
                else:
                    sys.stdout.write(f"No new Updates found for App Updater\n")
                    sys.stdout.write(f"Running Latest App Updater Version\n")
                    
            else:
                print("API request failed with status code: ", response)
        except Exception as e:
            print(f"An error occurred while trying to update: {e}")
            logger.write(CodeTrigger.Event, LogType.Error, "Error occured while trying to update!", ex=e)

    def create_download_folder(self):
        self.download_dir = os.path.join(self.project_dir, 'Download Folder')
        if not os.path.exists(self.download_dir):
            sys.stdout.write(f'Creating "Download Folder ->{self.download_dir}"\n')
            os.makedirs(self.download_dir)
        else:
            for file in os.listdir(self.download_dir):
                os.remove(self.download_dir + '/' + file)
                sys.stdout.write(f"Deleted Download Folder/{file}\n")


    # methods to update app updater

    def make_updater_copy_in_project_directory(self):
        src_path = os.path.join(self.project_dir, "updater_main.exe")
        dst_path = os.path.join(self.project_dir, "updater_main_copy.exe")
        shutil.copy(src_path, dst_path)
        # shutil.copy(__file__, self.project_dir + "\\updater_main_copy.exe")

    # Compare local and latest version
    def compare_version(self, local_version, latest_version):
        try:
            # Split the version numbers into individual components
            v1_components = local_version.split('.')
            v2_components = latest_version.split('.')
            # print(v1_components, v2_components)
            # Pad the components with zeros to ensure they have the same number of digits
            max_length = max(len(v1_components), len(v2_components))
            # print(max_length)
            v1_components += ['0'] * (max_length - len(v1_components))
            v2_components += ['0'] * (max_length - len(v2_components))
            # print(v1_components, v2_components)
            # Compare the components one by one
            for v1_comp, v2_comp in zip(v1_components, v2_components):
                if int(v1_comp) < int(v2_comp):
                    sys.stdout.write("Outdated Version\n")
                    return True
        except Exception as e:
            sys.stdout.write(f"{e}\n")
        # If all components are equal, the versions are the same
        return False

    def check_appupdater_update(self):
        self.read_updater_config(access_token)
        try:
            sys.stdout.write(f"Checking App Updater Version\n")
            response = self.get_version(self.app_updater_id, self.local_updater_version)
            sys.stdout.write(f"Version Check finished\n")

            if response != None:
                latest_updater_version = response
                is_outdated = self.compare_version(self.local_updater_version, latest_updater_version)
                # if self.local_updater_version != latest_updater_version:
                if is_outdated:
                    sys.stdout.write(f"Latest Version Available [App Updater {latest_updater_version}]\n")
                    sys.stdout.write(f"Updating from Version {self.local_updater_version} to Latest Version {latest_updater_version}\n")
                    return True
                else:
                    sys.stdout.write(f"Running Latest App Updater Version: {self.local_updater_version}\n")
        except Exception as e:
            sys.stdout.write(f"{e}\n")
            sleep(10)
        return False

    def update_updater_exe(self, access_token):
        self.read_updater_config(access_token)

        try:
            # if self.task_names:
            #     self.stop_service()

            is_outdated = self.check_appupdater_update()
            
            if is_outdated:
                sftp = self.sftp.open_sftp()
                sftp.chdir(str(self.app_updater_id))
                sys.stdout.write(f"Checking SFTP Server for updated files\n")
                remote_files = set(sftp.listdir())
                files_to_update = remote_files
                sys.stdout.write(f"Remote Files  -> {remote_files}\n")
                sys.stdout.write('Downloading files...\n')

                downloaded_files_count = 0
                download_attempt = 0

                while downloaded_files_count < len(files_to_update):
                    # create download folder also handles if there are files still remaining in the folder then delete
                    self.create_download_folder()
                    sys.stdout.write('Downloading files...\n')
                    if download_attempt == 10:
                        sys.stdout.write(f'Maximum Attempt, closing app\n')
                        break
                    else:
                        download_attempt += 1
                        sys.stdout.write(f'Download Attempt - {download_attempt}\n')
                    for filename in files_to_update:
                        remote_file_path = "/{app_updater_id}/{filename}".format(app_updater_id=self.app_updater_id, filename=filename)
                        local_file_path = "{download_dir}\\{filename}".format(download_dir=self.download_dir, filename=filename)
                        sftp.get(remote_file_path, local_file_path)
                        downloaded_files_count += 1
                    
                    sys.stdout.write(
                        f"Total Remote files: {len(files_to_update)}; Total Downloaded Files: {downloaded_files_count}\n")
                    if len(os.listdir(self.download_dir)) != len(files_to_update):
                            downloaded_files_count = 0
                    sftp.close()
                
                if os.listdir(self.download_dir):
                    allfiles = os.listdir(self.download_dir)
                    sys.stdout.write(f"Downloaded files -> {allfiles}\n")
                    try:
                        sys.stdout.write(f'Moving files from {self.download_dir} <-- to --> {self.project_dir}\n')
                        executable = [file for file in allfiles if file.endswith(".exe")]
                        for file in allfiles:
                            count = 1
                            pending_file_movement = True
                            while pending_file_movement:
                                stop_files_list = executable
                                if count > 2000:
                                    sys.stdout.write(
                                        f'Update Unsuccessful...\n')
                                    return
                                try:
                                    sys.stdout.write(f'Moving -> {file}\n')
                                    src_path = os.path.join(self.download_dir, file)
                                    dst_path = os.path.join(self.project_dir, file)
                                    shutil.move(src_path, dst_path)
                                    pending_file_movement = False
                                except Exception as e:
                                    sys.stdout.write(f'{e}\n')
                                    sys.stdout.write(
                                        f'Failed -> moving {file}, Retrying...\n')
                                    stop_files_list.append(file)
                                    # self.stop_service()
                                    # self.stop_updater()
                                    self.stop_task(stop_files_list)
                                    pending_file_movement = True
                                count += 1
                        sys.stdout.write(f'Finished Moving files from {self.download_dir} <-- to --> {self.project_dir}\n')
                        sys.stdout.write("Update Successful\n")
                    except Exception as e:
                        sys.stdout.write(f'{e}')
                        raise Exception(f"Moving Failed {e}")
        except Exception as e:
            sys.stdout.write(f"{e}\n")
            # sleep(30)

class Access:

    def old_api_cred_decrypt(key_filepath):
        API_CRED_key = b'39eIx78FTYWgbhxQQkPrOo36c-Sm1lyKiFhzgrYqYd0='
        with open(key_filepath, 'r', encoding='utf-8') as k:
            key = k.readline()
            if " " in key:
                key = key.replace(" ", "")
            f = Fernet(API_CRED_key)
            decrypted_string = f.decrypt(bytes(key, 'utf-8'))
            JSON_decrypted_string = json.loads(decrypted_string)
            return JSON_decrypted_string

    def new_api_cred_decrypt(key_filepath):
        cred = None
        try:
            with open(os.path.join(key_filepath), 'r', encoding='utf-8') as k:
                key = k.readline()
                if " " in key:
                    key = key.replace(" ", "")
                cred = Decrypt.decrypt(key)
                cred = json.loads(cred)
                if cred == None:
                    raise Exception(KeyError)
            k.close()
            return cred
        except Exception as e:
            sys.stdout.write(f"{e}")

    def request_access_token(username, secret_key, api_key):
        results = requests.post("https://localhost:5000/api/v1/auth/login", json={
            "UserName": "{user}".format(user=username),
            "SecretKey": "{secret}".format(secret=secret_key),
            "ApiKey": "{key}".format(key=api_key)
        })
        if results.text:
            api = json.loads(results.text)
            api = api['Result']
            return api['AccessToken']
        else:
            return None

class Decrypt:

    keyString = "Tree@Cross@Core@"

    def decrypt(combinedString):
        combinedData = base64.b64decode(combinedString)
        aes = AES.new(Decrypt.keyString.encode(), AES.MODE_ECB)
        iv = combinedData[:aes.block_size]
        cipherText = combinedData[aes.block_size:]

        aes.iv = iv
        plainText = aes.decrypt(cipherText)
        plainText = unpad(plainText, AES.block_size).decode()
        return plainText

if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    argument_parser.add_argument("-v", "--version", help="Check Local App Updater Version", action="store_true")
    argument_parser.add_argument("-a", "--appid", help="Update to Latest App Version", action="store")
    argument_parser.add_argument("-u", "--update", help="Update to Latest App Updater Version", action="store_true")

    args = vars(argument_parser.parse_args())
    VERSION = args["version"]
    Updater_UPDATE = args["update"]
    try:
        APP_ID, APP_VERSION = args["appid"].split("_")
    except Exception as e:
        # sys.stdout.write(f'{e}\n')
        pass

    if VERSION:
        local_app_updater_version = UPDATER_VERSION
        sys.stdout.write(f"App Updater v{local_app_updater_version}\n")
        sys.exit(0)

    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        sys.stdout.write('Not running as admin, relaunching...\n')
        argument = f' -a {APP_ID}_{APP_VERSION}'
        if Updater_UPDATE:
            argument = f' -u'
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__ + argument, None, 1)
        sys.exit(0)
    else:
        project_dir = os.getcwd()

        sys.stdout.write('Checking for Updates...\n')
        # __________ Just for Deployment of New Encryption Method __________
        creds = None

        key_filepath = f"{project_dir}\\SysFiles\\sysfile.txt"
        
        try:
            if os.path.exists(key_filepath) and os.path.getsize(key_filepath) != 0:
                creds = Access.new_api_cred_decrypt(key_filepath)
            elif os.path.exists('user/keys/key.txt') and os.path.getsize('user/keys/key.txt') != 0:
                try:
                    creds = Access.old_api_cred_decrypt('user/keys/key.txt')
                except:
                    creds = Access.new_api_cred_decrypt('user/keys/key.txt')
            else:
                raise Exception(RuntimeError)
            if creds == None:
                raise Exception("Key methods didn't worked")
        except Exception as e:
            sys.stdout.write(f'Error with key {e}\n')
        # _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
        try:
            try:
                access_token = Access.request_access_token(creds["UserName"], creds["SecretKey"], creds["APIKey"])
            except:
                access_token = Access.request_access_token(creds['username'], creds['SecretKey'], creds['APIKey'])
            # connect with sftp
            folder_cred = Decrypt.decrypt("")
            sftp_cred = folder_cred.split(",")
            updater = AppUpdater(sftp_cred[0], int(sftp_cred[1]), sftp_cred[2], sftp_cred[3])
            # updater = AppUpdater("sample.domain.com", 22, "lance", "9n2sy9aR@zjvJv10")

            if Updater_UPDATE:
                sys.stdout.write("Relaunched with argument -u\n")
                sys.stdout.write("Updating App Updater...\n")
                updater.update_updater_exe(access_token)
            else:
                updater.update_app(access_token, APP_ID, APP_VERSION)
            sys.stdout.write("End of Execution!\n")
        except Exception as e:
            sys.stdout.write(f'Error: {e}')

    # write date-time in last_checked.txt
    try:
        project_dir = os.getcwd()
        file_path = f'{project_dir}/Last Update Check/last_checked.txt'

        if not os.path.exists(file_path):
            folder_path = os.path.dirname(file_path)
            os.makedirs(folder_path, exist_ok=True)
            sys.stdout.write(f"creating folder 'Last Update Check'")
        with open(file_path, 'w', encoding="utf-8") as file:
            currentdatetime = datetime.utcnow()
            file.write(str(currentdatetime.strftime('%d-%m-%Y %H:%M:%S')))
            sys.stdout.write(f"File '{file_path}': {currentdatetime} created successfully")
    except Exception as e:
        sys.stdout.write(f'Error: {e}\n')
    logger.close()