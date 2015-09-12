# Interact with Viper Framework API to graph relationships based on ssdeep fuzzy hashing

import requests
from json import JSONDecoder
from functools import partial
import networkx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as pyplot
import hashlib
import re

url_find = 'http://localhost:8080/file/find'
url_run = 'http://localhost:8080/modules/run'

# Query all collections, all files, and build a list of nodes using sha256 values
r1 = requests.post(url_find, 'all=all')
allfiles = r1.json()
shas_of_sunset = []
sha_filenames = []
for key, sublist in allfiles.iteritems():
  i = 0
  for asdf in sublist:
    shas_of_sunset.append(allfiles[key][i]['sha256'])
    sha_filenames.append(allfiles[key][i]['name'])
    i += 1

# Create graph nodes and edges by querying fuzzy hash module for each unique sha256 hash
g=networkx.Graph()
labels={}
count=0
for sha in shas_of_sunset:
  name = sha_filenames[count]
  params = {'sha256': sha, 'cmdline': 'fuzzy'}
  r = requests.post(url_run, params)
  data = r.json()
  pattern = re.compile(r"\['(\d{2})%', u'(.+?)', u'(.+?)'")
  for (pct, name_match, sha_match) in re.findall(pattern, data):
    g.add_edge(name, name_match, weight=pct)
  count+=1

# Draw graph, write to file
networkx.draw(g, with_labels=True,font_size=8)
pyplot.savefig("Fuzzy.png")
networkx.write_gexf(g, "Fuzzy.gexf")
