import sys
import requests

url_del = 'http://localhost:8080/file/delete'
url_find = 'http://localhost:8080/file/find'


if len(sys.argv) <= 1:
    print("Usage: viper_massdelete.py [keyword]")
    sys.exit()
tag = str(sys.argv[1])

r = requests.post(url_find, str('tag=' + tag))
samples = r.json()
md5_hashes = []
for entry in samples["results"]["default"]:
    md5_hashes.append(entry["md5"])

question = 'Preparing to delete ' + str(len(md5_hashes)) + ' entries from the Viper repo, proceed? '
reply = str(raw_input(question+' (y/n): ')).lower().strip()
if reply[0] == 'y':
    for md5_hash in md5_hashes:
        r = requests.get(url_del + '/' + md5_hash)
else:
    print('Exiting without deleting.')
    sys.exit()
