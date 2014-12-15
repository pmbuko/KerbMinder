"""
Pashua.py - Interface to Pashua
Pashua is an application that can be used to provide some type of dialog GUI
for Python and shell applications on Mac OS X. Pashua.py is the glue between
your script and Pashua. To learn more about Pashua, take a look at the
application's Readme file. Pashua's homepage is www.bluem.net/jump/pashua
Please note in order for the example to work, the Pashua application
must be in the current path, in /Applications/ or in ~/Applications/
If none of these paths apply, you will have to specify it manually:
Pashua.PATH = '/path/to/appfolder';
... before you call Pashua.run(). Alternatively, you may specify the
path (the directory that contains Pashua.app, without trailing slash)
as 3rd argument to run().
"""

import os.path
import sys
import tempfile

# Configuration variables

VERSION = '0.9.5'
PATH = ''
BUNDLE_PATH = "Pashua.app/Contents/MacOS/Pashua"

PASHUA_PLACES = [
    os.path.join(os.path.dirname(sys.argv[0]), "Pashua"),
    os.path.join(os.path.dirname(sys.argv[0]), BUNDLE_PATH),
    os.path.join(".", BUNDLE_PATH),
    os.path.join("/Applications", BUNDLE_PATH),
    os.path.join(os.path.expanduser("~/Applications"), BUNDLE_PATH),
    os.path.join("/usr/local/bin", BUNDLE_PATH)
]


# Globals

PashuaDir = None

# Search for the pashua binary

def locate_pashua(places):
    """
    Find Pashua by looking in each of places in order, returning the path,
    or None if no Pashua was found.
    """
    for folder in places:
        if os.path.exists(folder):
            return folder


# Calls the pashua binary, parses its result
# string and generates a dictionary that's returned.

def run(ConfigData, Encoding = None, PashuaPath = None):
    """
    Create a temporary config file holding ConfigData, and run
    Pashua passing it the pathname of the config file on the
    command line.
    """

    # Write configuration to temporary config file
    configfile = tempfile.mktemp()

    try:
        CONFIGFILE = file(configfile, "w")
        CONFIGFILE.write(ConfigData)
        CONFIGFILE.close()
    except IOError, Diag:
        # pass it on up, but with an extra diagnostic clue
        raise IOError, "Error accessing Pashua config file '%s': %s" % (configfile, Diag)

    # Try to figure out the path to pashua
    if PashuaPath:
        PASHUA_PLACES.insert(0, PashuaPath + '/' + BUNDLE_PATH)

    global PashuaDir
    if not PashuaDir:
        if PATH:
            PASHUA_PLACES.insert(0,PATH)
        PashuaDir = locate_pashua(PASHUA_PLACES)
        if not PashuaDir:
            raise IOError, "Unable to locate the Pashua application."

    # Pass encoding as command-line argument, if necessary
    # Take a look at Pashua's documentation for a list of encodings
    if Encoding:
        encarg = "-e %s" % (Encoding)
    else:
        encarg = ""

    # Call pashua binary with config file as argument and read result
    path = "'%s' %s %s" % (PashuaDir, encarg, configfile)

    result = os.popen(path, "r").readlines()

    # Remove config file
    os.unlink(configfile)

    # Parse result
    result_dict = {}
    for Line in result:
        parm, value = Line.split('=')
        result_dict[parm] = value.rstrip()

    return result_dict
