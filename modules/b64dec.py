# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import base64

from viper.common.out import cyan
from viper.common.abstracts import Module
from viper.core.session import __sessions__

BASE64_REGEX = re.compile('[A-Za-z0-9/]{24,}[\=]{0,2}')

class b64dec(Module):
    cmd = 'b64dec'
    description = 'Find and decode short (C2-ish)  base64 strings from file'
    authors = ['pmelson', 'Paul Melson']

    def __init__(self):
        super(b64dec, self).__init__()

    def run(self):
        super(b64dec, self).run()

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        regexp = re.compile(ur'(?:[\x20-\x7E][\x00]){3,}')
        if os.path.exists(__sessions__.current.file.path):
            strings = [w.decode('utf-16le') for w in regexp.findall(__sessions__.current.file.data)]
            for w in strings:
                if BASE64_REGEX.search(w):
                  match = BASE64_REGEX.search(w)
                  try:
                    decstr = base64.b64decode(match.group(0)).decode('ascii')
#                    self.log('info', 'base64 string found: %s' % (match.group(0)))
                    self.log('info', 'decoded string: %s' % decstr)
                  except:
                    pass
            regexp = '[\x20\x30-\x39\x41-\x5a\x61-\x7a\-\.:\=]{4,}'
            strings = re.findall(regexp, __sessions__.current.file.data)
            for w in strings:
                if BASE64_REGEX.search(w):
                  match = BASE64_REGEX.search(w)
                  try:
                    decstr = base64.b64decode(match.group(0)).decode('ascii')
#                    self.log('info', 'base64 string found: %s' % (match.group(0)))
                    self.log('info', 'decoded string: %s' % decstr)
                  except:
                    pass
        else:
            self.log('error', 'No matches found')
