"""Support for storing keys and certificates in text files"""

from pisces.spkilib import spki, sexp
from pisces.spkilib.spki import getIssuerAndSubject

import base64
import re
import string

# XXX for now, we will assume only one process accesses the
# databases at a time 

class _SPKIDatabase:
    """A generic format for storing S-expressions in a text file

    Notes of format:
    The contents of the database are a series of SPKI sexps, in base64
    format.

    Comment lines begin with \#.  Convention is to include a
    human-readable summary of the encode S-exp in a comment.
    """

    READ_SIZE_HINT = 128 * 1024
    rxComment = re.compile('\s*#')

    def read(self, io):
        objs = []
        cur = []
        keepGoing = 1
        while keepGoing:
            keepGoing = 0
            for line in io.readlines(self.READ_SIZE_HINT):
                keepGoing = 1
                m = self.rxComment.match(line)
                if m:
                    continue
                cur.append(line)
                if '}' in line:
                    b64 = string.join(cur, '')
                    canon = base64.decodestring(b64)
                    cur = []
                    objs.append(sexp.SExp(canon))
        return objs

SPKIDatabase = _SPKIDatabase()

class AbstractDatabase:

    # XXX general SPKI problem -- we often refer to things by their
    # hash, but if we have two hashes with two different hash
    # functions then there is no way to tell if they refer to the same 
    # object.  the minimally sane approach is to only use one hash
    # function.  If you have to interoperate with other
    # applications that use other hash functions, you'll probably lose.
    
    def reload(self, create=0):
        try:
            f = open(self.path, "r")
        except IOError:
            if create:
                return
            else:
                raise
        sexps = SPKIDatabase.read(f)
        f.close()
        for raw in sexps:
            obj = spki.eval(raw)
            self.loadObject(obj)

    def rewrite(self):
        f = open(self.path, "w")
        for obj in self.getObjects():
            self.writeStorageHint(obj, f)
            f.write(obj.sexp().encode_base64())
            f.write("\n\n")
        f.close()

class DebugDatabase(AbstractDatabase):
    def __init__(self, path):
        self.path = path
        self.objects = []
        self.reload()

    def loadObject(self, obj):
        self.objects.append(obj)

    def rewrite(self):
        print "Not implemented for debugging databases"

def stripNewlines(obj):
    """Convert to str and then do just what the name says"""
    buf = str(obj)
    return string.join(string.split(buf, "\n"), " ")

class ACL(AbstractDatabase):
    def __init__(self, path, create=0):
        self.path = path
        self.entries = {}
        self.reload(create)

    def loadObject(self, obj):
        if not spki.isa(obj, spki.Entry):
            print "Warning: Not an acl entry.  Skipping."
            print sexp.pprint(obj.sexp())
            return
        l = self.entries.get(obj.subject, [])
        l.append(obj)
        self.entries[obj.subject] = l

    def getObjects(self):
        all = []
        for some in self.entries.values():
            all.extend(some)
        return all

    def writeStorageHint(self, obj, io):
        io.write('# %s\n' % stripNewlines(obj.subject.sexp()))
        io.write('# %s\n' % stripNewlines(obj.tag.sexp()))

    add = loadObject

    def lookup(self, subject):
        return self.entries.get(subject, [])

class CertificateDatabase(AbstractDatabase):
    """Stores certificates and allows lookups by issuer and subject"""

    def __init__(self, path, create=0):
        self.path = path
        self.byIssuer = {}
        self.bySubject = {}
        self.identity = {}
        self.reload(create)

    # next three methods are part of the IO model of AbstractDatabase

    def loadObject(self, obj):
        # expect object to be a Sequence containing a certificate, 
        # but will accept a plain certificate too (for now)
        issuer, subject = getIssuerAndSubject(obj, 1)
        if issuer is None or subject is None:
            print "Warning: Unexpected SPKI object. Skipping."
            print sexp.pprint(obj.sexp())
            return

        sexpr = obj.sexp().encode_canonical()
        if self.identity.has_key(sexpr):
            print "Warning: Duplicate certificate ignored."
            return

        issuer = issuer.getPrincipal()
        subject = subject.getPrincipal()

        l = self.byIssuer.get(issuer, [])
        l.append(obj)
        self.byIssuer[issuer] = l

        # if the issuer is a name, then we will enter the certificate
        # in multiple slots. one for the full name, and one for the
        # base issuer.
        if isinstance(issuer, spki.FullyQualifiedName):
            prin = issuer.principal
            l = self.byIssuer.get(prin, [])
            l.append(obj)
            self.byIssuer[prin] = l

        l = self.bySubject.get(subject, [])
        l.append(obj)
        self.bySubject[subject] = l

        self.identity[sexp] = sexp

    def getObjects(self):
        all = []
        for some in self.bySubject.values():
            all.extend(some)
        return all

    def writeStorageHint(self, obj, io):
        issuer, subject = getIssuerAndSubject(obj)
        # XXX need to get rid of newlines in issuer and subject
        io.write("# %s\n# %s\n" % (stripNewlines(issuer.sexp()),
                                   stripNewlines(subject.sexp())))
        
    # XXX current interface is lookupBySubject and
    # lookupByIssuer. might want to have two dictionary-like
    # interfaces. 

    def lookupBySubject(self, subject):
        return self.bySubject.get(subject, [])

    def lookupByIssuer(self, issuer):
        return self.byIssuer.get(issuer, [])

    add = loadObject

    def delete(self, obj):
        sexp = obj.sexp().encode_canonical()
        if not self.identity.has_key(sexp):
            raise KeyError, "object not in database: %s" % str(obj)
        del self.identity[sexp]

        issuer, subject = getIssuerAndSubject(obj, 1)
        issuer = issuer.getPrincipal()
        subject = subject.getPrincipal()

        # these shouldn't raise exceptions if the identity dictionary
        # test succeeded 
        self.byIssuer[issuer].remove(obj)
        self.bySubject[subject].remove(obj)

class PrincipalDatabase(AbstractDatabase):
    """Stores public keys and allows lookups"""
    def __init__(self, path, create=0):
        self.path = path
        self.principals = {}
        self.reload(create)

    # next three methods are part of the IO model of AbstractDatabase

    def loadObject(self, obj):
        if not spki.isa(obj, spki.PublicKey):
            print "Warning: Unexpected SPKI object. Skipping."
            print obj.__class__
            print sexp.pprint(obj.sexp())
            return
        p = obj.getPrincipal()
        if self.principals.has_key(p):
            print "Warning: Duplicate definition of %s" % str(p)
            print "Old definition:"
            print sexp.pprint(self.principals[p].sexp())
            print "New definition:"
            print sexp.pprint(obj.sexp())
        self.principals[p] = obj

    def getObjects(self):
        return self.principals.values()

    def writeStorageHint(self, obj, io):
        p = obj.getPrincipal()
        io.write("# %s\n" % stripNewlines(p.sexp()))

    # XXX the current public interface is just the lookup method.  it
    # might make more sense to have a dictionary-style interface

    def lookup(self, p):
        return self.principals.get(p, None)

    add = loadObject

    def delete(self, p):
        if not isinstance(p, spki.Hash):
            p = p.getPrincipal()
        del self.principals[p]

class PrivateKeyDatabase(AbstractDatabase):

    # states for loadObject
    LOAD_PUB = 0
    LOAD_PRIV = 1
    LOAD_DONE = 2
    
    def __init__(self, path, create=0):
        self.path = path
        self.keys = {}
        self.default = None
        self.loadState = self.LOAD_PUB
        self.reload(create)

    # next three methods are part of the IO model of AbstractDatabase

    # This class is different than other subclasses because it depends
    # on the order in which objects are loaded.  This is a bit of a
    # hack, because a user could totally trash things by editing the
    # file and messing up the order.  Need to rethink this later.

    def loadObject(self, obj):
        if self.loadState == self.LOAD_PUB:
            self.loadPublic(obj)
        elif self.loadState == self.LOAD_PRIV:
            self.loadPrivate(obj)
        else:
            raise RuntimeError, "invalid loadState"
        if self.loadState == self.LOAD_DONE:
            self.keys[self._prin] = self._priv
            if self._default:
                self.default = self._prin
            self.loadState = self.LOAD_PUB

    def getObjects(self):
        objs = []
        if self.default:
            objs.append(self.default)
            objs.append(self.DEFAULT)
            objs.append(self.keys[self.default])
        for prin, priv in self.keys.items():
            if prin is self.default:
                continue
            objs.append(prin)
            objs.append(priv)
        return objs

    def writeStorageHint(self, obj, io):
        if spki.isa(obj, spki.Hash):
            io.write("# %s\n" % stripNewlines(obj.sexp()))
        elif spki.isa(obj, 'default'):
            io.write('# default private key\n')

    # some helper functions used by loadObject

    DEFAULT = spki.parse('(7:default)')

    def loadPublic(self, obj):
        if not spki.isa(obj, spki.Hash):
            print "Warning: Unexpected SPKI object. Skipping."
            print obj.__class__
            print sexp.pprint(obj.sexp())
            return
        self._prin = obj
        self._default = 0
        self._priv = None
        self.loadState = self.LOAD_PRIV

    def loadPrivate(self, obj):
        if spki.isa(obj, 'default'):
            self._default = 1
        elif spki.isa(obj, spki.PasswordEncrypted):
            self._priv = obj
            self.loadState = self.LOAD_DONE
        else:
            print "Warning: Unexpected SPKI object. Skipping."
            print obj.__class__
            print sexp.pprint(obj.sexp())

    def lookup(self, hash):
        return self.keys.get(hash, None)

    def setDefault(self, hash):
        self.default = hash

    def getDefault(self):
        return self.default

    def add(self, pub, priv):
        if spki.isa(pub, spki.Hash):
            p = pub
        else:
            try:
                p = pub.getPrincipal()
            except AttributeError:
                raise TypeError, "arg 1 must be hash or public key"
        if not spki.isa(priv, spki.PasswordEncrypted) \
           or not priv.type == 'private-key':
            raise TypeError, "arg 2 must be encrypted private key"
        self.keys[p] = priv

    def listPublicKeys(self):
        return self.keys.keys()

    def listPrivateKeys(self):
        return self.keys.values()

