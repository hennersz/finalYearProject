"""Interface to produce cryptographic random data

The underlying implementation will vary from platform to platform and
installation to installation.  The interface is simple:

random(num) -- returns string of random data containing num bytes
implementation -- a string describing the implementation

"""

import os
import sys
import string
module = __import__('random')

def bogusRandom(num):
    l = []
    for i in range(num):
        l.append(module.randint(0, 255))
    return string.join(map(chr, l), '')

def useBogus():
    global random, implementation
    sys.stderr.write('No cryptographic random number generated found. '\
                     "Using Python's random module.\n")
    implementation = "bogus"
    random = bogusRandom

class EGDWrapper:
    def __init__(self, egd):
        self.egd = egd

    def getRandomBytes(self, num):
        buf = ''
        while num > 0:
            # this can lead to a bit of busy looping, but oh well
            size = min(num, 255)
            new = self.egd.getRandomBytes(size)
            num = num - len(new)
            buf = buf + new
        return buf

def useYarrow():
    """Check for a Yarrow server on port 12000"""
    global random, implementation
    import sys
    # XXX need to figure out where to put yarrow...
    sys.path.append('/home/jhylton/projects/goodies/pyarrow/')
    import client
    c = client.YarrowClient()
    try:
        c.connect()
    except client.error:
        return None
    random = c.random
    implementation = "pyarrow"
    return 1
    
def useEGD():
    global random, implementation
    try:
        import egdlib
    except ImportError:
        return None
    path = os.path.join(os.environ['HOME'], '.gnupg', 'entropy')
    if not os.path.exists(path):
        return None
    try:
        egd = egdlib.EGD(path)
        pid = egd.getPID()
    except:
        # oh, well. something went wrong
        return None
    implementation = "EGD"
    random = EGDWrapper(egd).getRandomBytes
    return 1

if sys.platform in ["linux2","darwin"]:
    class DevRandom:
	def __init__(self):
	    self.dev = None
	def __call__(self, num):
	    if self.dev is None:
		self.dev = open("/dev/urandom")
	    return self.dev.read(num)
    random = DevRandom()
    implementation = "/dev/urandom"
else:
    # try Yarrow, EGD, librand, then bogus
    if useYarrow():
        pass
    elif useEGD():
        # we're okay
        pass
    else:
        try:
            import librand
        except ImportError:
            useBogus()
        else:
            random = librand.trand
            implementation = "librand"
