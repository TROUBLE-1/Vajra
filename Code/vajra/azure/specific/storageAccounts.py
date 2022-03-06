from email import message
import socket, requests, crayons, json, xmltodict, threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from vajra import db
from vajra.models import azureStorageAccountConfig, specificAttackStatus, specificAttackStorageLogs, specificAttackStorageResults
from sqlalchemy.sql import text

class storageEnum():
    def start(uuid):
        #db.engine.execute("UPDATE specific_attack_status SET storageAccounts = 'True' WHERE uuid = '{uuid}'")
        status = specificAttackStatus.query.filter_by(uuid=uuid).first()
        status.storageAccounts = "True"
        db.session.commit()
        MAIN_DOMAIN = ".blob.core.windows.net"
        full_domain_list = []
        valid_domains = []
        public_storage = []

        config = azureStorageAccountConfig.query.filter_by(uuid=uuid).first()
        PERMUTATION = config.permutations.splitlines()
        BASE_DOMAIN = config.commonWord
        full_domain = BASE_DOMAIN + MAIN_DOMAIN
        full_domain_list.append(full_domain)

        def validate_existence(domain):
            try:
                socket.gethostbyname(domain)
                valid_domains.append(domain)
                try:
                    log = (f"<br><span style=\"color:#7FFFD4\">[+] Valid: {domain}</span>" )
                    db.session.add(specificAttackStorageLogs(uuid=uuid, message=log))
                    db.session.commit()
                except:
                    db.session.rollback()
            except:
                pass

        for word in PERMUTATION:
            full_domain_1 = word + BASE_DOMAIN + MAIN_DOMAIN
            full_domain_2 = BASE_DOMAIN + word + MAIN_DOMAIN
            full_domain_3 = word + MAIN_DOMAIN
            full_domain_list.append(full_domain_1)
            full_domain_list.append(full_domain_2)
            full_domain_list.append(full_domain_3)
        
        for domain in full_domain_list:
            validate_existence(domain)

        def validate_container(domain):
            url = f"https://{domain}/?restype=container&comp=list"
            response = requests.get(url, timeout=5)
            try:
                if response.status_code == 200:
                    log = (f"<br><span style=\"color:#61a0d9\">[+] Found public container\r\n&nbsp;&nbsp;{url}</span>" )
                    db.session.add(specificAttackStorageLogs(uuid=uuid, message=log))
                    db.session.commit()
                    res = json.loads(json.dumps(xmltodict.parse(response.text)))
                    for blob in res["EnumerationResults"]["Blobs"]["Blob"]:
                        name = blob["Name"]
                        public_files = (f"https://{domain}/{name}")
                        public_storage.append(public_files)
            except:
                pass

        # enumerate public containers 
        processes = []
        for domain in valid_domains:

            with ThreadPoolExecutor(max_workers=20) as executor:
                for word in PERMUTATION:
                    new_domain = domain + "/" + word
                    processes.append(executor.submit(validate_container, new_domain))

            for task in as_completed(processes):
                (task.result())

        for url in public_storage:
            db.session.add(specificAttackStorageResults(valid=url, uuid=uuid))

        status.storageAccounts = "False"
        db.session.commit()