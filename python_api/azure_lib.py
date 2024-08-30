import os, uuid
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient, __version__
from config import AZURE_FILES_DIR
from security import Security


class AzureBlob:
    def create_container(self, container_name, connection_string):
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service_client.create_container(container_name)
    
    def upload_blob(self, container_name, file_name, data, connection_string):
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=file_name)
        blob_client.upload_blob(data)
    
    def download_blob(self, container_name, file_name, connection_string):
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=file_name)
        download_file_path = os.path.join(AZURE_FILES_DIR, 'DOWNLOAD' + file_name + '.txt')
        with open(download_file_path, 'wb') as download_file:
            download_file.write(blob_client.download_blob().readall())
    
    def delete_blob_container(self, container_name, connection_string):
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service_client.create_container(container_name)
        container_client.delete_container()