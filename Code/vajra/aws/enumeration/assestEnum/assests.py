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


import requests
from bs4 import BeautifulSoup
s = requests.Session()
s.get("https://www.google.com/")
page = s.get("https://www.google.com/search?q=see")
print(page.status_code)
soup = BeautifulSoup(page.content, features="lxml")
import re
links = soup.findAll("a")
for link in  soup.find_all("a",href=re.compile("(?<=/url\?q=)(htt.*://.*)")):
    print(re.split(":(?=http)",link["href"].replace("/url?q=","")))
exit()



page = urllib.request.urlopen("https://www.google.com/search?q=see")
soup = BeautifulSoup(page.read())
links = soup.findAll("a")
for link in links:
    print(link["href"])