"""Some common support routines for client and server"""

import pisces.spkilib.config
from pisces import spkilib
from pisces.spkilib import spki, verify, sexp, database, store, \
     sexpsocket

import sys
import getopt
import string
import ConfigParser

class Options(spkilib.config.Options):
    # A random assortment of constants, data handling routines, etc.
    # Lots of this stuff should be moved to configuration files.
    super__init__ = spkilib.config.Options.__init__
    super_init = spkilib.config.Options.init
    super_getConfFile = spkilib.config.Options.getConfFile

    def __init__(self, args, isClient):
        self.port = 14000 # need an arbitrary default
        self.isClient = isClient
        self.super__init__(args)

    def init(self, args):
        self.super_init(args)
        self.getVerifier()

    def parseArgs(self, args):
        try:
            opts, args = getopt.getopt(args, 'vhd:k:')
        except getopt.error, err:
            raise ValueError, err
            
        for k, v in opts:
            if k == '-v':
                self.verbose = 1
            elif k == '-d':
                self.dir = v
            elif k == '-h':
                raise HelpError(args)
            elif k == '-k':
                self.key = self.parseHash(v)
        
    def parseHash(self, hashstr):
        """Create a hash object from user-supplied input"""
        if hashstr[0] == '(':
            hash = sexp.parseText(hashstr)
            if not isinstance(hash, spki.Hash):
                raise ValueError, "invalid hash object: %s" % hash
        else:
            digest = sexp.b64_to_str(hashstr)
            hash = spki.Hash('md5', digest)
        return hash

    def getConfFile(self):
        self.super_getConfFile()
        
        self.config.read("ttls.conf")
        self.acl = database.ACL(self.config.get('spki', 'acl'))
        self.port = self.config.getint('DEFAULT', 'port')
        self.host = self.config.get('server', 'host')

        if self.isClient:
            self.hash = spki.parseText(self.config.get('client',
                                                      'key')) 
        else:
            private = self.config.get('server', 'key')
            self.hash = spkilib.config.parseHashOrName(private)

        # and muck with a class variable here
        if self.config.getboolean('DEFAULT', 'verbose'):
            self.verbose = 1
        if self.verbose == 1:
            sexpsocket.SexpSocket.VERBOSE = 1

    def getVerifier(self):
        # the keyserver comes from the base class. yuck.
        self.verifier = verify.KeyServerVerifier(self.acl, self.keyserver)
        if self.verbose:
            self.verifier.VERBOSE = 1
            
    def lookupKey(self, hash):
        return self.keyserver.lookupKey(hash)
        
    class Pair:
        def __init__(self, pub, priv):
            self.pub = pub
            self.priv = priv
        
    def getKeyPair(self):
        private = self.keyserver.lookupPrivateKey(self.hash)
        public = self.keyserver.lookupKey(self.hash)
        return self.Pair(public, private)

    def getChain(self, key):
        chain = self.verifier.verify(key.pub.getPrincipal(),
                                     spki.Tag(spki.TagStar()))
        if chain is None:
            return None
        chain = chain[1:] # remove the ACL entry
        chain.reverse()
        seq = chain[0].getSequence()
        for cert in chain[1:]:
            seq.extend(cert.getSequence())
        return seq

def parseopt(isClient):
    opt = Options(sys.argv[1:], isClient)
    return opt
