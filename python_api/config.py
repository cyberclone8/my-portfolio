import pyodbc
import enum


# MSSQL Connector
SERVER = ''
DATABASE = ''
USERNAME = ''
PASSWORD = ''

DUMP_DIR = './dump'

# MongoDB Connection String
CONNECTION_STRING = ""

# Azure creds
AZURE_STORAGE_CONNECTION_STRING=""
AZURE_FILES_DIR = './uploads'
AZURE_CONTAINER_NAME = 'rootcontainer'
AZURE_REMOTE_PATH_TWITTER = 'UploadedDoc/CentralizedStandAlone/Twitter/'
AZURE_REMOTE_PATH_FACEBOOK = 'UploadedDoc/CentralizedStandAlone/Facebook/'
SECRET_KEY = ''
CRYPTO_KEY = ''


class StandAloneModule(enum.Enum):
    Social_Media = 1
    Mobile_App = 2

class StandAlonePlatform(enum.Enum):
    Twitter = 1
    Facebook = 2

class StandAlonePlatformClassification(enum.Enum):
    People = 1
    Pages = 2
    Groups = 3

class ScrapingStatus(enum.Enum):
    New = 1
    For_Upload = 2
    Uploaded = 3
    Upload_Failed = 4
    For_Download = 5
    Downloaded = 6
    Download_Failed = 7
    Parsing = 8
    Parsed = 9
    Parsed_Failed = 10

class ScanRequestStatus(enum.Enum):
    Pending = 1
    Running = 2
    Completed = 3
