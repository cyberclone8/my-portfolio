import pyodbc
import enum


# MSSQL Connector
SERVER = '10.147.18.59'
DATABASE = 'intellizoo'
USERNAME = 'lance2'
PASSWORD = 'wEh1zqsZZ0kSNEp1'
# cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+server+';DATABASE='+database+';UID='+username+';PWD='+ password)
# # cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+server+';DATABASE='+database, Trusted_connection='Yes')
# cnxn.autocommit = True
# cursor = cnxn.cursor()

DUMP_DIR = './dump'

# MongoDB Connection String
CONNECTION_STRING = "mongodb://izoo:rSTaCmGRS573amuq@54.38.232.79:27017/?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&directConnection=true&ssl=false"

# Azure creds
AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=izooblobuat;AccountKey=quV4RJ0BB0ffel5mqZ28Xjqnuy9rwmrmJRfZ0SXgmPlO4y0upuVWOQcbsDqX9ZmF4YC1IQ1jYxlp9FTvat/+og==;EndpointSuffix=core.windows.net"
AZURE_FILES_DIR = './uploads'
AZURE_CONTAINER_NAME = 'rootcontainer'
AZURE_REMOTE_PATH_TWITTER = 'UploadedDoc/CentralizedStandAlone/Twitter/'
AZURE_REMOTE_PATH_FACEBOOK = 'UploadedDoc/CentralizedStandAlone/Facebook/'
SECRET_KEY = 'hRZYpJz0YBxuAwvPQaHfue5Oja'
CRYPTO_KEY = b'OivegknqMox4wXHHTh2m8DOY7pAru-q8dmnJggG3wsU='


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
