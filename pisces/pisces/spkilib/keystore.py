"""Access keys and certificates stored in database"""

from pisces.spkilib import sexp, spki, database
from pisces import pwcrypt

import os
import string
import cPickle
import types

def getPrincipal(obj):
    if isinstance(obj, spki.Hash):
        return obj
    return obj.getPrincipal()

def checkType(pos, obj, *types):
    """Check the type and raise an exception if it doesn't match"""
    for type in types:
        if isinstance(obj, type):
            return 1
    try:
        name = obj.__class__.__name__
    except AttributeError:
        name = `obj`
    valid = map(lambda x:x.__name__, types)
    valid = string.join(valid, ', ')
    raise TypeError, "arg %d: expect %s, got %s" % (pos, valid, name)

class KeyStore:
    """High-level interface for managing stored keys and certs"""

    def __init__(self, path):
        self.path = path
        keyPath = os.path.join(path, 'keys')
        self.keys = database.PrincipalDatabase(keyPath, create=1)
        privPath = os.path.join(path, 'private')
        self.private = database.PrivateKeyDatabase(privPath, create=1)
        certPath = os.path.join(path, 'certs')
        self.certs = database.CertificateDatabase(certPath, create=1)
        self.default = None
        self.needSave = 0

    def close(self):
        if self.needSave:
            self.save()

    def save(self):
        self.keys.rewrite()
        self.private.rewrite()
        self.certs.rewrite()
        self.needSave = 0

    def setDefaultKey(self, hash):
        self.private.setDefault(hash)
        self.needSave = 1

    def getDefaultKey(self):
        return self.private.getDefault()

    def addPrivateKey(self, key, pub, pword, bogus=None):
        """Add private key with corresponding public key using password

        The arguments are the private key, its corresponding public
        key (or hash), and a password to use to encrypt it. 
        """
        checkType(1, key, spki.PrivateKey)
        checkType(2, pub, spki.PublicKey, spki.Hash)
        enc = spki.encryptWithPassword(key, pword, bogus=bogus)
        pub = getPrincipal(pub)
        self.private.add(pub, enc)
        self.needSave = 1

    def addPublicKey(self, key):
        checkType(1, key, spki.PublicKey)
        hash = key.getPrincipal()
        self.keys.add(key)
        self.needSave = 1

    def addCert(self, cert):
        checkType(1, cert, spki.Sequence, spki.Cert)
        self.certs.add(cert)
        self.needSave = 1

    def addName(self, cert):
        checkType(1, cert, spki.Sequence, spki.Cert)
        self.certs.add(cert)
        self.needSave = 1

    def lookupKey(self, hash):
        return self.keys.lookup(hash)

    def lookupPrivateKey(self, pub):
        checkType(1, pub, spki.PublicKey, spki.Hash)
        pub = getPrincipal(pub)
        return self.private.lookup(pub)

    def lookupName(self, name, namespace=None):
        """Return certs for specified name

        The name can either be a SPKI name object or a simple string.
        If it is a string, the key for the namespace must be passed as
        the second argument.
        """
        if type(name) == types.StringType:
            checkType(2, namespace, spki.PublicKey, spki.Hash)
            if spki.isa(namespace, spki.PublicKey):
                p = namespace.getPrincipal()
            else:
                p = namespace
            name = spki.Name(p, name)
        checkType(1, name, spki.Name)
        certs = self.lookupCertByIssuer(name)
        names = []
        for cert in certs:
            if isinstance(cert, spki.Sequence):
                for elt in cert:
                    if isinstance(elt, spki.Cert):
                        if elt.isNameCert():
                            names.append(cert)
                        break
            elif cert.isNameCert():
                names.append(cert)
        return names

    def lookupCertBySubject(self, subj):
        return self.certs.lookupBySubject(subj)

    def lookupCertByIssuer(self, iss):
        return self.certs.lookupByIssuer(iss)

    def listPublicKeys(self):
        return self.keys.getObjects()

    def listPrivateKeys(self):
        return self.private.listPublicKeys()

    def listCerts(self):
        return self.certs.getObjects()

class MultiKeyStore:
    """Wrapper around multiple KeyStore objects

    Intended to support the use of local and remote KeyStore instances
    at the same time.  A user might use a local store for private keys
    and a second shared store of public keys and certs.
    """
    def __init__(self, readers=None, writers=None, both=None,
                 private=None):
        """Create a new object that fronts several backend KeyStores

        Each argument should be a sequence of KeyStore objects.
        Keyword argument invocation is recommended.

        Arguments:
        readers -- KeyStores that should only be used for lookups
        writers -- KeyStores that should only be used for adds
        both -- KeyStores that should be used for lookups and adds
        private -- KeyStores that should store private keys

        Private keys are only stored in keystores specified in the
        private argument.  A private KeyStore is implicitly both.
        """
        self.readers = readers and list(readers) or []
        self.writers = writers and list(writers) or []
        for ks in both or []:
            self.readers.append(ks)
            self.writers.append(ks)
        self.private = private and list(private) or []
        for ks in self.private:
            self.readers.append(ks)
            self.writers.append(ks)
        self.saveWriters = []
        for ks in self.writers:
            if hasattr(ks, 'save'):
                self.saveWriters.append(ks)

    def addPrivateKey(self, key, pub, pword):
        # XXX is this a good invocation mechanism?  by deferring
        # encryption to the underlying KeyStore, we run the risk of
        # passing both key and password around longer than necessary.
        for ks in self.private:
            ks.addPrivateKey(key, pub, pword)

    def setDefaultKey(self, hash):
        for ks in self.private:
            ks.setDefaultKey(hash)

    def getDefaultKey(self):
        # XXX does it make sense to have more than one private; if so,
        # do we simply assume that the all have the same default key
        ks = self.private[0]
        return ks.getDefaultKey()

    def addPublicKey(self, key):
        for ks in self.writers:
            ks.addPublicKey(key)

    def lookupName(self, name, namespace=None):
        names = []
        for ks in self.readers:
            r = ks.lookupName(name, namespace)
            if r:
                names = names + r
        return names

    def lookupCertByIssuer(self, hash):
        certs = []
        for ks in self.readers:
            r = ks.lookupCertByIssuer(hash)
            if r:
                certs = certs + r
        return certs

    def listPublicKeys(self):
        keys = []
        for ks in self.readers:
            r = ks.listPublicKeys()
            if r:
                keys = keys + r
        return keys

    def listPrivateKeys(self):
        keys = []
        for ks in self.readers:
            r = ks.listPrivateKeys()
            if r:
                keys = keys + r
        return keys

    def listCerts(self):
        certs = []
        for ks in self.readers:
            c = ks.listCerts()
            if c:
                certs = certs + c
        return certs

    def save(self):
        for ks in self.saveWriters:
            ks.save()

