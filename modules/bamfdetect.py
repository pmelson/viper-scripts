# Call bamfdetect externally and parse the JSON
# - https://github.com/bwall/bamfdetect

import os
import json
import magic
from viper.common.out import cyan
from viper.common.abstracts import Module
from viper.core.session import __sessions__

bamf = "/home/ubuntu/src/bamfdetect/bamfdetect"

class BAMFDetect(Module):

    cmd = 'bamfdetect'
    description = 'Call bamfdetect to extract C2 info'
    authors = ['Paul Melson']

    def __init__(self):
        super(BAMFDetect, self).__init__()
        self.parser.add_argument('-c', '--c2', action='store_true', help='only priny C2 values found')

    def run(self):
        super(BAMFDetect, self).run()
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return
        if os.path.exists(__sessions__.current.file.path):
            filepath = __sessions__.current.file.path.replace("projects/../", "")
            runcmd = bamf + " " + filepath
            try:
                rawoutput = os.popen(runcmd).read().rstrip(',\n')
                result = json.loads(rawoutput)
                if self.args.c2:
                    for c2 in result[filepath]["information"]["c2s"]:
                      self.log('info', c2["c2_uri"])
                else:
                    malstype = result[filepath]["type"]
                    self.log('info', "Malware Type: " + malstype)
                    description = result[filepath]["description"]
                    self.log('info', "Description: " + description)
                    self.log('info', "C2 URLs:")
                    for c2 in result[filepath]["information"]["c2s"]:
                        self.log('item', c2["c2_uri"])
            except:
                return
