import requests
import json
import re
import sys

url_vti_report = 'https://www.virustotal.com/vtapi/v2/file/report'
url_find = 'http://localhost:8080/file/find'
url_run = 'http://localhost:8080/modules/run'
vti_api_key = '[your vti key here]'


def getVTIreport(sha256):
    params = {'apikey': vti_api_key, 'resource': sha256, 'allinfo': 1}
    r = requests.get(url_vti_report, params)
    if r.status_code == 200:
        report = r.json()
        try:
            firstdate = report["first_seen"]
        except:
            firstdate = "unknown"
        try:
            lastdate = report["last_seen"]
        except:
            lastdate = "unknown"
        try:
            vtinames = report["submission_names"]
            vtins = ""
            for vtin in vtinames:
                vtins+=str(vtin+",")
        except:
            vtins = "unknown"
    else:
        print "Error! Unable to get VTI report for " + sha256
    return (firstdate,lastdate,vtins)


def getHashes(sha256):
    params = {'sha256': sha256, 'cmdline': 'info'}
    r = requests.post(url_run, params)
    result = r.json()
    try:
        md5 = result["results"][0]["data"]["rows"][6][1]
    except:
        md5 = "na"
    try:
        sha1 = result["results"][0]["data"]["rows"][7][1]
    except:
        sha1 = "na"
    try:
        size = result["results"][0]["data"]["rows"][3][1]
    except:
        size = "na"
    return md5,sha1,size


def getImphash(sha256):
    params = {'sha256': sha256, 'cmdline': 'pe imphash'}
    r = requests.post(url_run, params)
    result = r.json()
    try:
        m = re.search(r'Imphash\:\ \x1b\[1m([a-f0-9]+)\x1b\[0m', result["results"][0]["data"])
        imphash = m.group(1)
    except:
        imphash = "na"
    return imphash


def getCompiletime(sha256):
    params = {'sha256': sha256, 'cmdline': 'pe compiletime'}
    r = requests.post(url_run, params)
    result = r.json()
    m = re.search(r'Compile\ Time\:\ \x1b\[1m(.+?)\x1b\[0m', result["results"][0]["data"])
    try:
        compiletime = m.group(1)
    except:
        compiletime = "na"
    return compiletime


def extractB64(sha256):
    params = {'sha256': sha256, 'cmdline': 'b64dec'}
    r = requests.post(url_run, params)
    result = r.json()
    basesixfour = ""
    for entry in result["results"]:
        basesixfour += str(entry["data"]+",")
    return basesixfour


def extractHoststrings(sha256):
    params = {'sha256': sha256, 'cmdline': 'newstrings -H'}
    r = requests.post(url_run, params)
    result = r.json()
    hoststrings = ""
    for entry in result["results"]:
        hoststrings += str(entry["data"]+",")
    return hoststrings


def extractURLstrings(sha256):
    params = {'sha256': sha256, 'cmdline': 'newstrings -U'}
    r = requests.post(url_run, params)
    result = r.json()
    urlstrings = ""
    for entry in result["results"]:
        urlstrings += str(entry["data"]+",")
    return urlstrings


def extractUASstrings(sha256):
    params = {'sha256': sha256, 'cmdline': 'newstrings -b'}
    r = requests.post(url_run, params)
    result = r.json()
    uasstrings = ""
    for entry in result["results"]:
        uasstrings += str(entry["data"]+",")
    return uasstrings


if len(sys.argv) <= 1:
    print("Usage: bigextractor.py [viper keyword]")
    sys.exit()
tag = str(sys.argv[1])

r = requests.post(url_find, str('tag=' + tag))
samples = r.json()
shas_of_sunset = []
sha_filenames = []
for entry in samples["results"]["default"]:
    shas_of_sunset.append(entry["sha256"])
    sha_filenames.append(entry["name"])

print("sha256|md5|sha1|size|vti_upload_names|first_seen_date|last_seen_date|pe_compiletime|imphash|ip_or_fqdn_strings|url_strings|base64_decoded_strings|user-agent_strings")
for sha256 in shas_of_sunset:
    md5, sha1, size = getHashes(sha256)
    firstdate, lastdate, vtinames = getVTIreport(sha256)
    imphash = getImphash(sha256)
    compiletime = getCompiletime(sha256)
    basesixfour = extractB64(sha256)
    hoststrings = extractHoststrings(sha256)
    urlstrings = extractURLstrings(sha256)
    uasstrings = extractUASstrings(sha256)
    print('%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' % (sha256,md5,sha1,size,vtinames,firstdate,lastdate,compiletime,imphash,hoststrings,urlstrings,basesixfour,uasstrings))
