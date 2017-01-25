from pisces.spkilib import spki, sexp, keystore

import getopt
import os
import sys
import ConfigParser

error = getopt.error

class HelpError(Exception):
    def __init__(self, args):
        self.args = args

def parseHashOrName(buf):
    try:
        o = spki.parseText(buf)
    except sexp.ParseError:
        pass
    else:
        return o
    # apparently it wasn't a hash...
    base = getDefaultKey()
    return spki.FullyQualifiedName(base, (buf,))

def resolveName(name):
    """Convert a name in the local namespace to a key

    The return value is an object with a getPrincipal method.
    """
    opts = getOptions()
    namecerts = opts.keys.lookupName(name)
    if not namecerts:
        raise ValueError, "unbound SPKI name: %s" % name
    cert = spki.extractSignedCert(namecerts[0])
    return cert.getSubject()

def getDefaultKey(hash=1):
    opts = getOptions()
    priv_key_hash = opts.keys.getDefaultKey()
    key = opts.keys.lookupKey(priv_key_hash)
    if hash:
	return key.getPrincipal()
    else:
	return key

def getOptions():
    if Options._instance is None:
        raise ValueError, "no options instantiated"
    return Options._instance

class Options:
    _instance = None # this is a singleton class
    
    def __init__(self):
        if Options._instance is not None:
            raise RuntimeError("Options already instantiated: %s" %
                               `Options._instance`)
        
        self.verbose = 0
        self.dir = None
        Options._instance = self

	# stuff to be over-ridden by subclass
	self.opts = ''
	self.opthandler = None
	self.arghandler = None

    def __repr__(self):
        return "<%s dir=%s>" % (self.__class__, self.dir)

    def init(self, args):
        # call parseArgs first so that command-line options can be
        # used to affect other configuration settings
        self.parseArgs(args)
        self.getSPKIDir()
        self.getConfFile()
        self.getKeyServer()

    def parseArgs(self, args):
        try:
            opts, args = getopt.getopt(args, 'vhd:' + self.opts)
        except getopt.error, err:
            raise ValueError, err
            
        for k, v in opts:
            if k == '-v':
                self.verbose = 1
            elif k == '-d':
                self.dir = v
            elif k == '-h':
                raise HelpError(args)
	    else:
		self.opthandler(k, v)
	if args and self.arghandler:
	    self.arghandler(args)

    def getSPKIDir(self):
        """Find the base SPKI directory and make sure it exists"""
        if self.dir:
            # command-line
            dir = self.dir
        elif os.environ.has_key('SPKIHOME'):
            dir = os.environ['SPKIHOME']
        else:
            dir = os.path.expanduser('~/.spki')
        if not os.path.exists(dir):
            print "SPKI home directory does not exist\n%s" % dir
            print "Exiting"
            sys.exit(0)
        if not os.path.isdir(dir):
            print "Specified SPKI home directory is not a file\n%s" % dir
            print "Exiting"
            sys.exit(0)
        if self.verbose:
            print "Using SPKI dir: %s" % dir
        self.dir = dir

    def getConfFile(self):
        path = os.path.join(self.dir, 'conf')
        self.config = ConfigParser.ConfigParser()
	if not os.path.exists(path):
	    # XXX issue warning about missing config file?
	    return
        try:
            # when std. library gets fixed, this can be readfp
            f = open(path)
            if hasattr(self.config, 'readfp'):
                self.config.readfp(f)
            else:
                self.config._ConfigParser__read(f)
        except IOError, msg:
            print "Could not read config file: %s" % path
            print msg
            sys.exit(0)

    def getKeyServer(self):
        local = keystore.KeyStore(self.dir)
        try:
            codepath = self.config.get('extensions', 'keyserver')
        except (ConfigParser.NoOptionError,
                ConfigParser.NoSectionError):
            self.keys = local
        else:
            ext = loadExtension(codepath)
            if ext:
                remote = ext.getKeyServer()
            if ext is None or remote is None:
                print "Warning: Could not connect to keyserver"
                self.keys = local
            else:
                self.keys = keystore.MultiKeyStore(both=(remote,),
						   private=(local,))
	return self.keys

    def requireKeyServer(self, msg=None, exit=1):
        """Exit if there is no keyserver, optionally printing msg"""
        if self.keys is None:
            if msg:
                print msg
            if exit:
                sys.exit(exit)
        return 1
        
def loadExtension(path):
    path = os.path.expanduser(path)
    path, module = os.path.split(path)
    module, ext = os.path.splitext(module)
    if path:
        import sys
        sys.path.insert(0, path)
    d = {}
    s = "import %s; mod = %s" % (module, module)
    try:
        exec s in d
    except ImportError:
        mod = None
    else:
        mod = d["mod"]
    if path:
        del sys.path[0]
    return mod
    
