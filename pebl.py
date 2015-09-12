# Viper Framework plugin to scan a PE binary for blacklisted functions.
# To use, download PEStudio from http://www.winitor.com
#  then extract functions.xml from the PEStudio install directory,
#  copy it to a path Viper has access to, and define below (pestudio_fct)

import magic

from viper.common.out import cyan
from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    import pefile
    import peutils
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

class PEBL(Module):
    cmd = 'pebl'
    description = 'Read file header and display type, uses magic'
    authors = ['Paul Melson']

    def __init__(self):
        super(PEBL, self).__init__()
        self.pe = None

    def run(self):

        super(PEBL, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        if not self.pe:
            try:
                self.pe = pefile.PE(__sessions__.current.file.path)
            except pefile.PEFormatError as e:
                self.log('error', "Unable to parse PE file: {0}".format(e))
                return False
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            pestudio_fct = '/home/mrrobot/viper/modules/functions.xml'
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    self.log('info', "DLL: {0}".format(entry.dll))
                    for symbol in entry.imports:
                        self.log('item', "{0}: {1}".format(hex(symbol.address), symbol.name))
                        searchstr1 = 'bl="1" ad="1">' + symbol.name + '</fct>'
                        searchstr2 = 'bl="1" ad="0">' + symbol.name + '</fct>'
                        if searchstr1 in open(pestudio_fct).read():
                            self.log('warning', " BLACKLISTED FUNCTION!")
                        if searchstr2 in open(pestudio_fct).read():
                            self.log('warning', " BLACKLISTED FUNCTION!") 

                except:
                    continue
