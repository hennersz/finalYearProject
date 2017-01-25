"""SPKI implementation 

Parsing and convertions functions:

parse -- convert from a canonical S-exp encoding to a SPKI object

eval -- convert from a spkilib.sexp.SExp object to a SPKI object

Evaluator -- a class for constructing functions like eval.  See the
    class doc string for details.

reating new SPKI objects:

setHashAlgorithm(alg):
Takes an algorithm (either an implementation or an OID) and makes it
the module's default hash algorithm.

makePublicKey(key):
Takes an RSA key object (as created by PCT) and returns a SPKI
PublicKey object, which can be used to verify signature.

makePrivateKey(key):
Takes an RSA key object (as created by PCT) and returns a SPKI
PrivateKey object, which can be used to create signatures.

makeCert(issuer, subject, privileges):
Create a SPKI certificate object.

TODO list:

Check each object to make sure that it rejects malformed sexps.

Signature types other than rsa-pkcs1-md5 should be implemented: 
rsa-pkcs1-sha1, rsa-pkcs1, dsa-sha1.  At the minimum, need to know the 
oids.

Online tests for validity.

A Validity object that holds multiple constraints, supports intersect.

Threshold subjects.

All the various optional parts of certificates, like issuer-info and
version.

"""

import md5
import re
import struct
import string
import time
import types
from UserList import UserList

from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

from pisces import asn1
from pisces.spkilib import sexp
from pisces import cryptrand, pwcrypt, pkcs1

def name_to_impl(name):
    if name == '*':
        return 'TagExpr'
    if name[0] not in 'abcdefghijklmnopqrstuvwxyz':
        name = '_' + name
    parts = string.split(name, '-')
    return string.join(map(lambda s:string.upper(s[0]) + s[1:], parts), '')

def isa(obj, kind):
    if type(kind) == types.ClassType:
        return isinstance(obj, kind)
    else:
        if isinstance(obj, object):
            return obj.name == kind
        try:
            return obj.__class__.__name__ == kind
        except AttributeError:
            return 0

def parse(buf):
    return eval(sexp.parse(buf))

def parseText(s):
    return eval(sexp.parseText(s))

class Evaluator:
    def __init__(self, *namespaces):
        """Create Evaluator with given namespaces

        Each namespace should be a dictionary containing mappings from 
        string to classes, where the strings are SPKI object names in
        the special python-class style, e.g. "foo-bar" becomes
        "FooBar".

        If a name exists in multiple namespaces, the first occurence
        is used.

        Note: If you just pass in a module's namespace, that should be 
        fine.  The Evaluator will ignore names that are not also used
        by some SPKI-based protocol.  Thus, it fine if there's a name
        called __doc__ or __name__.
        """
        self.impls = {}
        l = list(namespaces)
        l.reverse()
        for ns in l:
            self.impls.update(ns)

    def eval(self, s, tag=0):
        # XXX is this just a hack? inside a tag set, there may be sexp
        # with labels like "name" that are meant to be simple key-value
        # pairs and *not* the spki Name objects.  the tag flag tells eval
        # to inpret names in a tag context rather than the normal
        # context.
        name = s[0]
        if not sexp.atom(name):
            # not sure we actually see this case
            name = self.eval(name)
        if tag:
            if name == '*':
                func = 'TagExpr'
            else:
                func = None
        else:
            func = name_to_impl(name)
        if name == 'tag':
            tag = 1
        args = []
        try:
            for elt in s[1:]:
                if sexp.atom(elt):
                    args.append(elt)
                else:
                    args.append(self.eval(elt, tag))
        except IndexError:
            pass
        if self.impls.has_key(func):
            try:
                return apply(self.impls[func], tuple(args))
            except TypeError, err:
                print "Type error in eval:", err, func, `args`
                raise
        else:
            if tag:
                return AppTag(name, args)
            else:
                return object(name, args)

class VerifyError(ValueError):
    pass

def isPrincipal(obj):
    return isinstance(obj, PublicKey) or isinstance(obj, Hash)

#
# classes for SPKI objects

class SPKIObject:

    def sexp(self):
        methname = 'sexpFor' + self.__class__.__name__
        try:
            meth = getattr(sexp, methname)
        except AttributeError:
            return '***' + self.__class__.__name__ + '***'
        return meth(self)

    def __repr__(self):
        return str(self.sexp())

    def __cmp__(self, other):
	if isinstance(other, SPKIObject):
	    sexp2 = other.sexp().encode_canonical()
	elif type(other) == types.StringType:
	    sexp2 = other
	else:
	    return -1
        sexp1 = self.sexp().encode_canonical()
        return cmp(sexp1, sexp2)

    def __hash__(self):
        return hash(self.sexp().encode_canonical())


class object(SPKIObject):
    def __init__(self, name, args=None):
	self.name = name
	self.args = args

class PublicKey(SPKIObject):
    def __init__(self, key):
	self.key = key
	# delegate several methods
	self.principal = None

    def verify(self, obj, sig):
	return self.key.verify(obj, sig, self.getPrincipal())

    def getPrincipal(self):
	if self.principal is None:
	    self.principal = Md5Hash(self)
	return self.principal

    def encrypt(self, plain):
        return self.key.encrypt(plain)

    def decrypt(self, cipher):
        return self.key.decrypt(cipher)

    def __repr__(self):
	return '(public-key %s)' % repr(self.key)

def pad(buf, size):
    if len(buf) < size:
	return chr(0) * (size - len(buf)) + buf
    else:
	return buf[len(buf) - size:]

def shorten(buf, pre=None):
    for i in range(len(buf)):
	if buf[i] != chr(0):
	    break
    short = buf[i:]
    if pre:
	return chr(0) + short
    return short

class RSAKey(SPKIObject):
    """Abstract base class for RSAPublicKey and RSAPrivateKey
    
    This class, specifically, the RSAPublicKey and RSAPrivateKey
    subclasses, will be incomplete if simply instantiated.  A helper
    function must add a signer attribute to the key in order to
    complete initialization. RsaPkcs1Md5 is an example of such a
    function.
    """

    def __init__(self, args=None, impl=None):
	if args:
	    self.args = args
	    self._sexp_to_impl()
	elif impl:
	    self.impl = impl
	    self._impl_to_sexp()
	# otherwise the KeyMaker is responsible for proper initialization
	self.principal = None

    # unlike the sign and verify methods of the Public and Private
    # subclasses, these methods expect and return binary data.  They
    # do not accept or return SPKI objects or sexpressions.

    def encrypt(self, plain):
        pass

    def decrypt(self, cipher):
        pass


class RSAPublicKey(RSAKey):
    def _sexp_to_impl(self):
	for obj in self.args:
            # XXX don't think the for loop is necessary
	    if obj.name == 'e':
		e = bytes_to_long(obj.args[0])
	    elif obj.name == 'n':
		n = bytes_to_long(obj.args[0])
	    else:
		raise ValueError, "unknown part: %s" % `obj`
	# order of args defined by RSA impl
	self.impl = pkcs1.RSA_pkcs1((n, e))

    def _impl_to_sexp(self):
	e, n = self.impl.getPublicComponents()
	e_enc = object('e', [shorten(long_to_bytes(e))])
	n_enc = object('n', [shorten(long_to_bytes(n), 1)])
	self.args = e_enc, n_enc

    def verify(self, obj, sig, princ):
 	if isinstance(obj, SPKIObject):
	    canon = obj.sexp().encode_canonical()
	elif isinstance(obj, sexp.SExp):
	    canon = obj.encode_canonical()
	else:
            # assume it is in canonical form
            canon = obj

        testhash = Md5Hash(canon)
        if testhash != sig.hash:
            return 0
	if sig.principal != princ:
            return 0

        return self.signer.verify(canon, sig.value)

    def encrypt(self, plain):
        return self.impl.encryptPublic(plain)

    def decrypt(self, cipher):
        return self.impl.decryptPublic(cipher)
	
class RSAPrivateKey(RSAKey):
    # XXX the examples draft mentions paramters a,b,c.  PCT doesn't
    # have them.  what are they? 

    def sign(self, obj, princ):
	if isinstance(obj, SPKIObject):
	    canon = obj.sexp().encode_canonical()
	elif isinstance(obj, sexp.SExp):
	    canon = obj.encode_canonical()
	else:
            # assume object is in canonical form
            canon = obj
	value = self.signer.sign(canon)
	hash = Md5Hash(canon)
	return Signature(hash, princ, value)

    def _impl_to_sexp(self):
	e, n = map(long_to_bytes, self.impl.getPublicComponents())
	d, p, q = map(long_to_bytes, self.impl.getPrivateComponents())
	
        self.args = (object('e', (shorten(e), )),
                     object('n', (shorten(n, 1), )),
                     object('d', (shorten(d, 1), )),
                     object('p', (shorten(p), )),
                     object('q', (shorten(q), )),
                     )

    def _sexp_to_impl(self):
        # XXX don't think the for loop is necessary
        for obj in self.args:
            if obj.name == 'e':
                e = bytes_to_long(obj.args[0])
            elif obj.name == 'n':
                n = bytes_to_long(obj.args[0])
            elif obj.name == 'd':
                d = bytes_to_long(obj.args[0])
            elif obj.name == 'p':
                p = bytes_to_long(obj.args[0])
            elif obj.name == 'q':
                q = bytes_to_long(obj.args[0])
            else:
                raise ValueError, "unknown part: %s" % `obj`
        self.impl = pkcs1.RSA_pkcs1((n, e, d, p, q))

    def encrypt(self, plain):
        return self.impl.encryptPrivate(plain)

    def decrypt(self, cipher):
        return self.impl.decryptPrivate(cipher)

def RsaPkcs1Md5(*args):
    """Generate an RSAPublicKey or RSAPrivateKey using pkcs1.MD5withRSA"""
    if len(args) == 2:
	key = RSAPublicKey(args)
    else:
	key = RSAPrivateKey(args)
    key.algorithm_name = 'rsa-pkcs1-md5'
    key.signer = pkcs1.MD5withRSA(key.impl)
    return key

class PrivateKey(SPKIObject):
    def __init__(self, key):
	self.key = key
	self.principal = None
	self.pub_key = None

    def sign(self, obj):
	return self.key.sign(obj, self.getPrincipal())
    
    def getPrincipal(self):
	if self.principal is None:
	    rkm = RSAKeyMaker()
	    self.principal = Md5Hash(self.getPublicKey())
	return self.principal

    def getPublicKey(self):
	if self.pub_key is None:
	    rkm = RSAKeyMaker()
	    self.pub_key = rkm.makePublicKey(self.key.impl)
	return self.pub_key

    def encrypt(self, plain):
        return self.key.encrypt(plain)

    def decrypt(self, cipher):
        return self.key.decrypt(cipher)

    def __repr__(self):
	return '(private-key %s)' % repr(self.key)

class SecretKey(SPKIObject):
    def __init__(self, sec_sig_alg_id, *args):
	self.algorithm = sec_sig_alg_id
	self.args = args

class Hash(SPKIObject):
    def __init__(self, hash_alg_name, hash_value, uri=None):
	self.alg_name = hash_alg_name
	self.value = hash_value
	self.uri = uri
	self.__hash = None

    def __hash__(self):
	if self.__hash is None:
	    self.__hash = struct.unpack('i', self.value[:4])[0]
	return self.__hash
        
    def __cmp__(self, other):
        if not isinstance(other, Hash):
	    # XXX this won't work when we implement other hashes!!!
	    other = Md5Hash(other)
        if self.alg_name != other.alg_name:
            return 1
        if self.value != other.value:
            return -1
        return 0

def Md5Hash(obj):
    if isinstance(obj, SPKIObject):
        canon = obj.sexp().encode_canonical()
    elif isinstance(obj, sexp.SExp):
        canon = obj.encode_canonical()
    else:
        # assume obj is in canonical form
        canon = obj
    digest = md5.new(canon).digest()
    return Hash('md5', digest)

class Signature(SPKIObject):
    def __init__(self, hash, principal, sig_value):
	self.hash = hash
	self.principal = principal
	self.value = sig_value

class Do(SPKIObject):
    def __init__(self, opcode, *args):
	assert opcode == 'hash', "invalid opcode for hash-op"
	self.opcode = opcode
	self.args = args

    def __repr__(self):
        return '(do %s %s)' % (self.opcode, self.args[0])

    def get_hash(self):
	if self.args[0] == 'md5':
	    return lambda s:md5.new(s).digest()
	else:
	    raise RuntimeError, "unimplemented hash: %s" % self.args[0]

class Sequence(SPKIObject, UserList):
    def __init__(self, *ent, **kw):
        if kw.has_key('list'):
            self.data = kw['list']
        else:
            self.data = list(ent)

    def __repr__(self):
	return '(sequence ' + string.join(map(repr,  self.data), ' ') + ')'

class Valid(SPKIObject):
    pass

class NotAfter(Valid):
    def __init__(self, time):
        if not checkTime(time):
            raise ValueError, "bad time format: %s" % time
        self.time = time

    def isValid(self):
        if getTime() <= self.time:
            return 1
        return 0

class NotBefore(Valid):
    def __init__(self, time):
        if not checkTime(time):
            raise ValueError, "bad time format: %s" % time
        self.time = time

    def isValid(self):
        if getTime() >= self.time:
            return 1
        return 0

class Online(Valid):
    def __init__(self, type, uris, principal, *sparts):
        self.type = type
        self.uris = uris
        self.principal = principal
        self.sparts = sparts

    def isValid(self):
        raise RuntimeError, "not implemented"

class Cert(SPKIObject):
    """The basic SPKI certificate object

    The implementation is messy here, because SPKI has two different
    objects that use the "cert" in the first slot of the sexp.  One is 
    the "regular" certificate, the other is a name certificate.  A
    regular certificate must have a tag, while a name certificate must 
    not.

    BNF:
    <cert>:: "(" "cert" <version>? <cert-display>? <issuer> <issuer-loc>?
    <subject> <subject-loc>? <deleg>? <tag> <valid>? <comment>? ")" ;

   <name-cert>:: "(" "cert" <version>? <cert-display>? <issuer-name>
   <subject> <valid> <comment>? ")" ;

   <issuer-name>:: "(" "issuer" "(" "name" <principal> <byte-string> ")"
   ")" ;
    """

    version = 0

    def __init__(self, *args):
        # defaults
        self.cert_display = None
        self.issuer_info = None
        self.subject_info = None
        self.propagate = None
        self.valid = []
        self.comment = None
	self.kind = None               # kind of SPKI certificate
	# XXX replace kind attr with different subclasses?
        if args:
            self.parse(args)
        else:
            self.issuer = None
            self.subject = None

    def parse(self, args):
        for arg in args:
            if isinstance(arg, Issuer):
                self.setField('issuer', arg)
                if self.issuer.isName():
                    self.kind = 'name-cert'
                else:
                    self.kind = 'cert'
            elif isinstance(arg, Subject):
                self.setField('subject', arg)
            elif isa(arg, 'propagate'):
                self.setField('propagate', arg)
            elif isa(arg, 'version'):
                self.setField('version', arg)
            elif isa(arg, 'cert-display'):
                self.setField('cert_display', arg)
            elif isa(arg, 'issuer-info'):
                self.setField('issuer_info', arg)
            elif isa(arg, 'subject-info'):
                self.setField('subject_info', arg)
            elif isa(arg, 'comment'):
                self.setField('comment', arg)
            elif isinstance(arg, Valid):
                self.valid.append(arg)
            elif isinstance(arg, Tag):
                self.setField('tag', arg)

    def setField(self, field, val):
        if hasattr(self, field) and getattr(self, field) != None:
            raise ValueError, "duplicate %s field: %s" % (field, val)
        setattr(self, field, val)
            
    def getTag(self):
        return self.tag.tag

    def isValid(self):
	for elt in self.valid:
	    if not elt.isValid():
		return 0
	return 1

    def isNameCert(self):
        return self.kind == 'name-cert'

    def getSubject(self):
        return self.subject

    def getIssuer(self):
        return self.issuer

class Issuer(SPKIObject):
    def __init__(self, principal):
        self.principal = principal
    def isName(self):
	return isinstance(self.principal, Name)
    def getPrincipal(self):
        return self.principal

class Entry(SPKIObject):
    """An assertion place in an access control list

    <acl-entry>:: "(" "entry" <subj-obj> <deleg>? <tag> <valid>?
    <comment>? ")" ;
    """

    def __init__(self, *args):
        self.deleg = None
        self.valid = []
        self.comment = None
        if args:
            self.parse(args)
        else:
            self.subject = None
            self.tag = None

    def parse(self, args):
        args = list(args)
        args.reverse()
        self.subject = args.pop()
        if isa(args[-1], 'propagate'):
            self.deleg = args.pop()
        self.tag = args.pop()
        while args and isa(args[-1], Valid):
            self.valid.append(args.pop())
        if args and isa(args[-1], 'comment'):
            self.comment = args.pop()

    def getTag(self):
        return self.tag

    def isValid(self):
        for elt in self.valid:
            if not elt.isValid():
                return 0
        return 1

class Subject(SPKIObject):
    """The minimal subject implementation

    full implementation would ne:
    subject>:: "(" "subject" <subj-obj> ")" ;

    <subj-obj>:: <principal> | <name> | <obj-hash> | <keyholder> | <subj-
    thresh> 
    """
    def __init__(self, subjobj):
	self.subjobj = subjobj

    def isName(self):
	return isinstance(self.subjobj, Name)

    def getPrincipal(self):
        if isa(self.subjobj, Hash):
            return self.subjobj
        elif isa(self.subjobj, Name):
            return self.subjobj
        else:
            return self.subjobj.getPrincipal()

class Keyholder(SPKIObject):
    def __init__(self, principal):
        # principal could be a name
        self.principal = principal
    def getPrincipal(self):
        return self.principal

class Name(SPKIObject):
    def __init__(self, *names):
        # XXX could be key or hash of key.  otherwise it's a byte
        # string, which I believe is the special case of an object
        # defined by SPKI that is not implemented as a SPKIObject.
        if isinstance(names[0], SPKIObject):
            # XXX get rid of this magic
            self.__class__ = FullyQualifiedName
            FullyQualifiedName.__init__(self, names[0], names[1:])
            return
        self.names = names

class FullyQualifiedName(Name):
    def __init__(self, principal, names):
        if type(names) == types.StringType:
            raise TypeError, "2nd arg: expected sequence, found string"
        self.principal = principal
        self.names = names
	self.__hash = None

    def __hash__(self):
	if self.__hash is None:
	    h = hash(self.principal)
	    for name in self.names:
		h = h ^ hash(name)
	    self.__hash = h
	return self.__hash

    def __cmp__(self, other):
	if not isinstance(other, FullyQualifiedName):
	    # what if we compare a FQN to a reg. Name?
	    return 1
	x = cmp(self.principal, other.principal)
	if x != 0:
	    return x
	if len(self.names) != len(other.names):
	    return -1
	for i in range(len(self.names)):
	    x = cmp(self.names[i], other.names[i])
	    if x != 0:
		return x
	return 0

class Tag(SPKIObject):
    '''
    tag-relevant BNF from SPKI draft
    <tag>:: <tag-star> | "(" "tag" <tag-expr>  ")" ;
    <tag-star>:: "(" "tag" "(*)" ")" ;
    <tag-expr>:: <simple-tag> | <tag-set> | <tag-string> ;
    <simple-tag>:: "(" <byte-string> <tag-expr>* ")" ;
    <tag-set>:: "(" "*" "set" <tag-expr>* ")" ;
    <tag-string>:: <byte-string> | <tag-range> | <tag-prefix> ;
    <tag-range>:: "(" "*" "range" <range-ordering> <low-lim>? <up-lim>?
    <tag-prefix>:: "(" "*" "prefix" <byte-string> ")" ;
    <range-ordering>:: "alpha" | "numeric" | "time" | "binary" | "date" ;
    <low-lim>:: <gte> <byte-string> ;
    <up-lim>:: <lte> <byte-string> ;
    <gte>:: "g" | "ge" ;
    <lte>:: "l" | "le" ;

    <tag-expr> would be more clearly defined by getting rid of
       <tag-string> and just using this:
    <tag-expr>:: <byte-string> | <simple-tag> | <tag-set> | <tag-range> 
               | <tag-prefix> ;
    '''
    def __init__(self, tag=None):
        self.tag = tag
	self.star = 0
	if isinstance(tag, TagStar):
	    self.star = 1

    def __nonzero__(self):
        if self.tag:
            return 1
        return 0

    def __cmp__(self, other):
	return cmp(self.tag, other.tag)

    def intersect(self, atag):
	# XXX there is some generic infrastructure here, but it is
	# hard to see how tag meanings can be compared without
	# appealing to the application that defines them
	assert isinstance(atag, Tag), atag
	if self.star:
	    return Tag(atag.tag.copy())
	if atag.star or self == atag:
	    return Tag(self.tag.copy())
	if self.tag.__class__ == atag.tag.__class__:
	    return Tag(self.tag.intersect(atag.tag))
	return None

    def __and__(self, atag):
        return self.intersect(atag)

def TagExpr(*args):
    """Factory function for producing _TagExpr subclasses"""
    if len(args) == 0: # (*)
        return TagStar()
    kind = args[0]
    if kind == 'set':
        return apply(TagSet, args)
    if kind == 'range':
        return apply(TagRange, args)
    if kind == 'prefix':
        return apply(TagPrefix, args)

class _TagExpr(SPKIObject):
    """<tag-star>, <tag-set>, <tag-range>, <tag-prefix>

    Subclasses must implement:
    parse -- convert from sexp input args to object
    copy -- create a copy of the object
    intersect -- return new set that is the intersection of permissions
    """
    def __init__(self, *args):
        self.parse(args[1:])

class TagStar(_TagExpr):
    def __cmp__(self, other):
	if isinstance(other, TagStar):
	    return 0
	return 1

    def parse(self, arg):
        assert arg == ()

    def copy(self):
	return self

    def intersect(self, other):
	return other.copy()

    def contains(self, other):
	return 1

class TagSet(_TagExpr):
    """<tag-set>:: "(" "*" "set" <tag-expr>* ")"; """
    def __nonzero__(self):
        if self.data:
            return 1
        return 0

    def parse(self, args):
	self.data = {}
	for arg in args:
            self.data[arg] = arg
	self.elts = tuple(args)

    def add(self, arg):
        if not self.data.has_key(arg):
            self.data[arg] = arg
            self.elts = self.elts + (arg,)

    def copy(self):
	new = TagSet()
	new.data = {}
	new.data.update(self.data)
	new.elts = self.elts
	return new

    def __cmp__(self, other):
	if not isinstance(other, TagSet):
	    return -1
	return cmp(self.elts, other.elts)

    def contains(self, key):
	return self.data.has_key(key)

    def intersect(self, other):
	set = {}
	for elt in self.data.keys():
	    set[elt] = set.get(elt, 0) + 1
	for elt in other.data.keys():
	    set[elt] = set.get(elt, 0) + 1
	new = TagSet()
        for elt, num in set.items():
            if num == 2:
                new.add(elt)
	return new

    def sexp(self):
        return SPKIObject.sexp(self)
        if self.dirty:
            elts = []
            done = {}
            for k in self.data.keys():
                done[k] = k
            for elt in self.elts:
                try:
                    newelt = self.data[elt.name]
                except KeyError:
                    pass
                else:
                    elts.append(newelt)
                    del done[elt.name]
            for k in done.keys():
                elts.append(self.data[k])
            self.elts = tuple(elts)
            self.dirty = 0
        return SPKIObject.sexp(self)


class TagRange(_TagExpr):
    '''<tag-range>:: "(" "*" "range" <range-ordering> <low-lim>? <up-lim>?
    <range-ordering>:: "alpha" | "numeric" | "time" | "binary" | "date" ;
    <low-lim>:: <gte> <byte-string> ;
    <up-lim>:: <lte> <byte-string> ;
    <gte>:: "g" | "ge" ;
    <lte>:: "l" | "le" ;
    '''
    def parse(self, args):
	self.order = args[0]
	if self.order not in ['alpha', 'numeric', 'time', 'binary', 'date']:
	    raise ValueError, "invalid range-ordering: %s" % self.order
	self.lower = self.upper = None
	if len(args) > 1:
	    self.lower = (args[1], args[2])
	if len(args) > 3:
	    self.upper = (args[3], args[4])

    def copy(self):
	new = TagRange()
	new.order = self.order
	new.lower = self.lower
	new.upper = self.upper
	return new

    def __cmp__(self, other):
	if not isinstance(other, TagRange):
	    return -1
	x = cmp(self.order, other.order)
	if x != 0:
	    return x
	x = cmp((self.lower, self.upper), (other.lower, other.upper))
	return x

    def intersect(self, other):
        raise RuntimeError, "not implemented yet"

class TagPrefix(_TagExpr):
    """<tag-prefix>:: "(" "*" "prefix" <byte-string> ")" ;"""
    def parse(self, (prefix,)):
	self.prefix = prefix

    def copy(self):
	new = TagPrefix()
	new.prefix = self.prefix
	return new

    def __cmp__(self):
	if not isinstance(other, TagPrefix):
	    return -1
	return cmp(self.prefix, other.prefix)

    def intersect(self, other):
	new = TagPrefix()
	l1 = len(self.prefix)
	l2 = len(other.prefix)
	if l1 < l2:
	    l = l1
	else:
	    l = l2
	for i in range(l):
	    if self.prefix[i] != other.prefix[i]:
		break
	new.prefix = self.prefix[:i+1]
	return new

class AppTag(SPKIObject):
    """An application-defined tag object"""
    def __init__(self, name, args):
	self.name = name
	self.args = tuple(args)

    def copy(self):
	new = AppTag()
	new.name = self.name
	new.args = self.args
	return new

# my own extensions to the default SPKI stuff to support storing
# encrypted private key objects
class PasswordEncrypted(SPKIObject):
    def __init__(self, _type, keyinfo, cipher, bogus=None):
        self.type = _type
        self.keyinfo = keyinfo
        self.cipher = cipher
	self.bogus = bogus

    def _checkPassword(self, pw):
	if pw is None:
	    if self.bogus is None:
		raise TypeError, "expected 1 argument, got 0; " \
		      "must specify password"
	    import os
	    pw = str(os.getuid())
	return pw

    def getKey(self, pw=None):
	pw = self._checkPassword(pw)
        return self.keyinfo.getKey(pw)

    def decrypt(self, pw=None):
	pw = self._checkPassword(pw)
        try:
            key = self.getKey(pw)
            return self.cipher.decrypt(key)
        except ValueError:
            # XXX need to make sure there aren't other errors that can
            # be raised  
            raise ValueError, "invalid decryption key"

    def isBogus(self):
        """Return true if a bogus password was used"""
        return self.bogus == 'bogus'

class Pbes2Hmac(SPKIObject):
    def __init__(self, salt, iters, hash, keylen):
        self.salt = salt
        self.iters = iters
        self.hash = hash
        self.keylen = keylen

    def getKey(self, pw):
        keylen = int(self.keylen)
        saltlen = len(self.salt)

        if self.hash == 'MD5':
            from Crypto.Hash import MD5
            hash = MD5
        elif self.hash == 'SHA':
            from Crypto.Hash import SHA
            hash = SHA
        else:
            raise ValueError, "unsuppported hash: %s" % self.hash
        iters = int(self.iters)
        kdf = pwcrypt.KeyDerivationFactory(keylen, saltlen,
                                           iters, hash)
        return kdf.recreateKey(pw, self.salt)

class _3desCipher(SPKIObject):
    def __init__(self, mode, iv, ciphertext):
        self.mode = mode
        self.iv = iv
        self.ciphertext = ciphertext

    def decrypt(self, key):
        from Crypto.Cipher import DES3
        mode = getattr(DES3, self.mode)
        cipher = DES3.new(key, mode, self.iv)
        raw = unpad(cipher.decrypt(self.ciphertext))
        return parse(raw)

# XXX I do not want to rewrite these everywhere
def pad(buf):
    n = len(buf) % 8
    n = 8 - n
    if n == 0:
	n = 8
    return buf + str(n) * n

def unpad(buf):
    n = int(buf[-1])
    return buf[:-n]

def encryptWithPassword(object, pw, bogus=None):
    """Will create a PasswordEncrypted object

    This function makes a bunch of choices for you, e.g. hash and
    cipher.  You'll need to roll your own code if you want to do
    something else.
    """
    from Crypto.Cipher import DES3

    kdf = pwcrypt.KeyDerivationFactory(16, 8) # 16-byte key, 8-byte salt
    salt, iters, hash, key = kdf.createKey(pw)
    iv = cryptrand.random(8)
    cipher = DES3.new(key, DES3.CBC, iv)
    ct = cipher.encrypt(pad(object.sexp().encode_canonical()))
    
    c = _3desCipher('CBC', iv, ct)
    k = Pbes2Hmac(salt, str(iters), hash, str(len(key)))
    return PasswordEncrypted(object.sexp()[0], # it's name,
                             k, c, (bogus is None and None or "bogus"))

def getTime(t=None):
    # XXX timezone stuff?
    if t is None:
	t = time.gmtime(time.time())
    if type(t) in (types.IntType, types.FloatType):
	t = time.gmtime(t)
    return "%04d-%02d-%02d_%02d:%02d:%02d" % t[:6]

rxTime = re.compile('\d\d\d\d-\d\d-\d\d_\d\d:\d\d:\d\d')

def checkTime(t):
    """Check that a time value passed in is syntacticly valid"""
    if rxTime.match(t):
        return 1
    return 0

#
class SignedCert:
    """A combination of a cert and its signature"""
    def __init__(self, cert, sig):
        # original objects
        self.cert = cert
        self.sig = sig

        # references to parts of original objects
        self.issuer = cert.issuer
        self.subject = cert.subject
        self.propagate = cert.propagate
        self.kind = cert.kind
        self.isValid = cert.isValid
        if not cert.isNameCert():
            self.tag = cert.tag

	# delegate a bunch of methods
	self.getTag = cert.getTag
	self.isValid = cert.isValid
	self.isNameCert = cert.isNameCert
	self.getSubject = cert.getSubject
	self.getIssuer = cert.getIssuer

    def getSequence(self):
        return Sequence(self.cert, self.sig)

    def verifySignature(self, keys):
        signer = keys.lookupKey(self.sig.principal)
        if not signer:
            return 0
        return signer.verify(self.cert, self.sig)

def getIssuerAndSubject(obj, warning=0):
    """Retrieve issuer and subject from a cert, possibly in a Sequence

    This is a helper function for the CertificationDatabase.  It will
    search through a sequence looking for a cert object or use a cert
    object passed directly.
    """
    subject = None
    issuer = None
    if isinstance(obj, Sequence):
        for elt in obj:
            if isinstance(elt, Cert):
                issuer = elt.issuer
                subject = elt.subject
                break
        if issuer is None and warning:
            print "Warning: Sequence did not contain cert."
    elif isinstance(obj, Cert):
        issuer = obj.issuer
        subject = obj.subject
    return issuer, subject
        
def extractSignedCert(seq):
    """Extract cert and signature from sequence"""
    cert = sig = None
    for elt in seq:
        # probably a little too simplistic
        if isinstance(elt, Cert):
            cert = elt
        elif isinstance(elt, Signature):
            sig = elt
    if cert is None:
	raise ValueError, "could not find cert"
    if sig is None:
	raise ValueError, "could not find sig"
    return SignedCert(cert, sig)

# functions for clients to create SPKI oibjects
class RSAKeyMaker:
    """Use this interface to create SPKI objects for real keys"""

    names = {pkcs1.MD5withRSA.oid: 'rsa-pkcs1-md5',
	     }

    def __init__(self, algid=pkcs1.MD5withRSA):
        if isinstance(algid, asn1.OID):
	    self.hash_class = pkcs1.getSignatureImpl(oid)
        elif type(algid) == types.ClassType:
            self.hash_class = algid
	else:
	    raise ValueError, "must specify hash algorithm"
	self.name = RSAKeyMaker.names[self.hash_class.oid]
	self.cache = {}

    def makePublicKey(self, impl):
	if self.cache.has_key(impl):
	    return self.cache[impl]
	key = RSAPublicKey()
	key.impl = impl
	key._impl_to_sexp()
	key.signer = self.hash_class(key.impl)
	key.algorithm_name = self.name
	self.cache[impl] = key
	return PublicKey(key)

    def makePrivateKey(self, impl):
	key = RSAPrivateKey()
	key.impl = impl
	key._impl_to_sexp()
	key.signer = self.hash_class(key.impl)
	key.algorithm_name = self.name
	key.principal = Md5Hash(PublicKey(self.makePublicKey(impl)))
	return PrivateKey(key)

def setHashAlgorithm(alg):
    global _keymaker
    _keymaker = RSAKeyMaker(alg)

_keymaker = RSAKeyMaker()
makePublicKey = _keymaker.makePublicKey
makePrivateKey = _keymaker.makePrivateKey

def makeRSAKeyPair(bits):
    rawkey = RSA.generate(bits, cryptrand.random)
    pkcskey = pkcs1.RSA_pkcs1(rawkey)
    pub = makePublicKey(pkcskey)
    priv = makePrivateKey(pkcskey)
    return pub, priv

def makeCert(issuer, subject, tag, propagate=0, valid=None):
    """Creates a basic certificate object"""
    c = Cert()
    c.issuer = Issuer(issuer)
    c.subject = Subject(subject)
    c.tag = tag
    c.valid = valid or []
    if propagate:
        c.propagate = object('propagate')
    return c

def makeNameCert(issuer, subject, name, valid=None):
    c = Cert()
    c.kind = 'name-cert'
    if not isinstance(issuer, Hash):
	issuer = Md5Hash(issuer)
    c.issuer = Issuer(Name(issuer, name))
    c.subject = Subject(subject)
    c.valid = valid or []
    return c

def makeAclEntry(subject, valid, propagate, permissions):
    c = Entry()
    c.subject = subject
    c.valid = valid
    if propagate:
        c.propagate = object('propagate')
    else:
        c.propagate = None
    c.tag = Tag(permissions)
    return c

# need to be done _after_ all the object definitions
_default_evaluator = Evaluator(globals())
eval = _default_evaluator.eval

