# Script to interact with the Viper Framework API to bulk upload files,
#  calculate imphash for each uploaded file, and tag the file with imphash
#  value and any additional values you define.

import requests
from os import listdir
from os.path import isfile, join
import hashlib
import re


url_upload = 'http://localhost:8080/file/add'
url_tag = 'http://localhost:8080/file/tags/add'
url_run = 'http://localhost:8080/modules/run'

# Define file upload directory and any additional tags to affix to files
filepath = '/home/mrrobot/asprox_samples'
extratags = 'asprox'

filelist = [ f for f in listdir(filepath) if isfile(join(filepath,f)) ]

for file in filelist:
    fullpath = join(filepath,file)
    files = {'file': open(fullpath, 'rb')}
    r = requests.post(url_upload, files=files)
    filesha = hashlib.sha256(open(join(filepath,file)).read()).hexdigest()
    params = {'sha256': filesha, 'cmdline': 'pe imphash'}
    r = requests.post(url_run, params)
    data = r.json()
    searchobj = re.search(r'Imphash\:\ \\x1b\[1m(.+?)\\x1b\[0m', data)
    imphash = searchobj.group(1)
    print(imphash)
    params = {'sha256': filesha, 'tags': imphash + "," + extratags }
    r = requests.post(url_tag, params)
