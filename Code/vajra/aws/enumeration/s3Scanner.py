# Copyright (C) 2022 Raunak Parmar, @trouble1_raunak
# All rights reserved to Raunak Parmar

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

# This tool is meant for educational purposes only. 
# The creator takes no responsibility of any mis-use of this tool.

import socket, requests, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from vajra import db
from vajra.models import awsS3Scanner

# url, status, content-length

class s3ScannerEnum():
    def start(uuid, commonWord):
        MAIN_URL = ".s3.amazonaws.com"
        full_domain_list = []
        valid_domains = []
        public_storage = []

        config = awsS3Scanner.query.filter_by(uuid=uuid, name=commonWord).first()
        PERMUTATION = config.permutations.splitlines()
        BASE_DOMAIN = config.name
        full_domain = MAIN_URL + BASE_DOMAIN
        full_domain_list.append(full_domain)

        def validate_existence(domain):
            try:
                #socket.gethostbyname(domain)
                url = "https://"+domain
                req = requests.get(url, timeout=3)
                if req.status_code != 404:
                    valid_domains.append(url +" "+ str(req.status_code)+ " " + str(len(req.content)))
            except:
                pass

        for word in PERMUTATION:
            full_domain_1 = word + BASE_DOMAIN + MAIN_URL
            full_domain_2 = BASE_DOMAIN + word + MAIN_URL
            full_domain_3 = word + MAIN_URL
            full_domain_list.append(full_domain_1)
            full_domain_list.append(full_domain_2)
            full_domain_list.append(full_domain_3)
        

        processes = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            for domain in full_domain_list:
                processes.append(executor.submit(validate_existence, domain))

        for task in as_completed(processes):
            (task.result())

        bucketList = "\r\n".join(valid_domains)
        s3bucket = awsS3Scanner.query.filter_by(uuid=uuid, name=commonWord).first()
        s3bucket.valid = bucketList
        s3bucket.progress = "completed"
        db.session.commit()
        print(s3bucket.valid)
        print("Done")
        return

        def validate_container(domain):
            url = f"https://{domain}/?restype=container&comp=list"
            response = requests.get(url, timeout=5)
            try:
                if response.status_code == 200:
                    log = (f"<br><span style=\"color:#61a0d9\">[+] Found public container\r\n&nbsp;&nbsp;{url}</span>" )
                    db.session.add(awsS3Scanner(uuid=uuid, message=log))
                    public_storage = re.findall('<Url>([\s\S]*?)<\/Url>', response.text, flags=0)
                    for url in public_storage:
                        db.session.add(awsS3Scanner(name=url, uuid=uuid)) 
                    db.session.commit()    
            except Exception as e:
                print(e)
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

        

        