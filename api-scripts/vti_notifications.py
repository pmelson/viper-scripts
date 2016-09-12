import requests
import json
import re
import sys

vti_api_key = '[your vti key here]'
filepath = '/tmp'

url_vti_notifications = 'https://www.virustotal.com/intelligence/hunting/notifications-feed/?key='+vti_api_key
url_vti_download = 'https://www.virustotal.com/vtapi/v2/file/download'
url_viper_find = 'http://localhost:8080/file/find'
url_viper_run = 'http://localhost:8080/modules/run'
url_viper_upload = 'http://localhost:8080/file/add'

rules_list=["your","vti","hunting","rule","names"]

def getImphash(hash):
  params = {'sha256': hash, 'cmdline': 'pe imphash'}
  r = requests.post(url_viper_run, params)
  result = r.json()
  try:
    m = re.search(r'Imphash\:\ \\x1b\[1m([0-9a-f]+)\\x1b\[0m', result)
    imphash = m.group(1)
  except:
    imphash = "na"
  return imphash

r=requests.get(url_vti_notifications)
notifications = r.json()
for notification in notifications["notifications"]:
  id = notification["id"]
  hash = notification["sha256"]
  md5 = notification["md5"]
  rule = notification["ruleset_name"]
  filetype = notification["type"]
  subject = notification["subject"]
  if any(rule.lower() == rulename.lower() for rulename in rules_list) and ((filetype == "Win32 EXE") or (filetype == "Win32 DLL")):
    print "Match for rule: " + rule + ": " + subject + " (" + filetype + ")"
    r = requests.post(url_viper_find, 'sha256='+hash)
    result = r.json()
    try:
      asdf = result["default"]
      print " - Skipping " + md5 + ", already in repo."
    except:
      print " - Downloading " + md5 + " from VTI..."
      params = {'apikey': vti_api_key, 'hash': hash}
      r = requests.get(url_vti_download, params)
      if r.status_code == 200:
        path = filepath + '/' +md5
        with open(path, 'wb') as f:
          r.raw.decode_content = True
          f.write(r.content)
        f.close()
        print " - Uploading " + md5 + " to Viper..."
        files = {'file': open(path, 'rb')}
        r = requests.post(url_viper_upload, files=files)
        print " - Analyzing & tagging file..."
        params = {'sha256': hash, 'cmdline': 'yara scan -t'}
        r = requests.post(url_viper_run, params)
        imphash = getImphash(hash)
        if imphash != "na":
          params = {'sha256': hash, 'cmdline': 'tags -a '+imphash}
          r = requests.post(url_viper_run, params)
