import pyodbc
from config import SERVER, DATABASE, USERNAME, PASSWORD


class Connections:
    def insert_scraping_repo(
            self, 
            module_id, 
            platform_id, 
            classification_id, 
            reference_code, 
            source_code_file_name, 
            keyword, 
            ip_address, 
            username, 
            status
        ):
        cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+SERVER+';DATABASE='+DATABASE+';UID='+USERNAME+';PWD='+ PASSWORD)
        cnxn.autocommit = True
        cursor = cnxn.cursor()
        cursor.execute(
            """
            EXEC InsertScrappingRepository 
            @ModuleId='{module_id}',
            @PlatformId='{platform_id}',
            @ClassificationId='{classification_id}',
            @ReferenceCode='{reference_code}',
            @SourceCodeFileName='{source_code_file_name}',
            @Keyword='{keyword}',
            @IPAddress='{ip_address}',
            @Username='{username}',
            @Status='{status}'
            """.format(
                module_id=module_id,
                platform_id=platform_id,
                classification_id=classification_id,
                reference_code=reference_code,
                source_code_file_name=source_code_file_name,
                keyword=keyword,
                ip_address=ip_address,
                username=username,
                status=status
            )
        )
        cursor.close()
        cnxn.close()

    def get_scrapping_repo(self, status):
        cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+SERVER+';DATABASE='+DATABASE+';UID='+USERNAME+';PWD='+ PASSWORD)
        cnxn.autocommit = True
        cursor = cnxn.cursor()
        cursor.execute(
            """
            EXEC GetScrappingRepository
            @Status='{status}'
            """.format(status=status)
        )
        data = cursor.fetchall()
        cursor.close()
        cnxn.close()
        return data

    def update_scrapping_repo(self, reference_code, status):
        cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+SERVER+';DATABASE='+DATABASE+';UID='+USERNAME+';PWD='+ PASSWORD)
        cnxn.autocommit = True
        cursor = cnxn.cursor()
        cursor.execute(
            """
            EXEC UpdateStatusScrappingRepository
            @ReferenceCode='{reference_code}',
            @Status='{status}'
            """.format(reference_code=reference_code, status=status)
        )
        cursor.close()
        cnxn.close()

    def insert_asset_discovery_scan_request(self, scan_request_id, domain):
        cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+SERVER+';DATABASE='+DATABASE+';UID='+USERNAME+';PWD='+ PASSWORD)
        cnxn.autocommit = True
        cursor = cnxn.cursor()
        cursor.execute(
            """
            EXEC InsertAssetDiscoveryScanRequest
            @ScanRequestID='{scan_request_id}',
            @Domain='{domain}'
            """.format(
                scan_request_id=scan_request_id,
                domain=domain
            )
        )
        cursor.close()
        cnxn.close()

    def get_asset_discovery_scan_request_status(self, scan_request_id):
        cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+SERVER+';DATABASE='+DATABASE+';UID='+USERNAME+';PWD='+ PASSWORD)
        cnxn.autocommit = True
        cursor = cnxn.cursor()
        cursor.execute(
            """
            EXEC GetAssetDiscoveryScanRequest
            @ScanRequestID='{scan_request_id}'
            """.format(
                scan_request_id=scan_request_id
            )
        )
        data = cursor.fetchall()
        cursor.close()
        cnxn.close()
        return data
    
    def insert_subdirectory_traversal_scan_request(self, scan_request_id, domain):
        cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+SERVER+';DATABASE='+DATABASE+';UID='+USERNAME+';PWD='+ PASSWORD)
        cnxn.autocommit = True
        cursor = cnxn.cursor()
        cursor.execute(
            """
            EXEC InsertSubdirectoryTraversalScanRequest
            @ScanRequestID='{scan_request_id}',
            @Domain='{domain}'
            """.format(
                scan_request_id=scan_request_id,
                domain=domain
            )
        )
        cursor.close()
        cnxn.close()

    def get_subdirectory_traversal_scan_request_status(self, scan_request_id):
        cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+SERVER+';DATABASE='+DATABASE+';UID='+USERNAME+';PWD='+ PASSWORD)
        cnxn.autocommit = True
        cursor = cnxn.cursor()
        cursor.execute(
            """
            EXEC GetSubdirectoryTraversalScanRequest
            @ScanRequestID='{scan_request_id}'
            """.format(
                scan_request_id=scan_request_id
            )
        )
        data = cursor.fetchall()
        cursor.close()
        cnxn.close()
        return data