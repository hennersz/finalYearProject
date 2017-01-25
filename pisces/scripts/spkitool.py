#! /usr/bin/env python

"""A simple command interface to create, manage, and use spki keys

Some notes about how to use the program (and understand its code).

.spki directory

The user needs to store private keys in a directory.  spkitool will
create a couple of anydbm files in that directory.  The user can
specify configuration options in the conf file in that directory.
The default spki directory is ~/.spki.  You can change it by setting
the SPKIHOME environment variable or using the -d option to spkitool.

default key and namespace

spkitool will use a default key when the user doesn't specify one on
the command line.  Create a key that which has your username (LOGNAME)
as its label, and spkitool will use it if you don't specify a label.
The default key effectively creates a default namespace.  Any name
cert issued by this key will create a name that can be used on the
spkitool command line instead of a hash.

Data organization:

Each command that spkitool executes is implemented by a class that has
the same name as the command.  (When the command is a Python keyword,
it has an '_' prefix.)  The command class defines three methods:
    __init__ -- receives a single argument, the global Options instance
                which sets options that apply to all commands
    parseArgs -- parse the command line arguments that apply to this
                 command.  the argument to this call is analogous to
                 sys.argv[1:] .
                 If this command raises a ValueError, the caller will
                 take care of printing an error message and exiting.
    run -- takes no arguments. does the real work.

"""

from pisces.spkilib import spki, sexp, database, config
from pisces.spkilib.config import parseHashOrName, resolveName

# standard
import os
import sys
import getopt
import string
import getpass
import types
import ConfigParser

class CmdError(Exception):
    """An error occured parsing arguments or executing a command

    If a command raises this exception in its run method, the main
    function will catch the exception and print an error message.
    """
    pass

def parseTime(s):
    """Parse a time value entered by the user"""
    if s == 'now':
	return spki.getTime()
    if not spki.checkTime(s):
        raise ValueError, "invalid date format: %s" % s
    return s

def load(path):
    if path == '-':
	f = sys.stdin
    else:
	f = open(path, 'rb')
    buf = f.read()
    f.close()
    return buf

def dump(path, obj):
    if path == '-':
	f = sys.stdout
    else:
	f = open(path, 'ab')
    if isinstance(obj, spki.SPKIObject):
	f.write(obj.sexp().encode_base64())
    else:
	f.write(obj)
    f.write("\n")
    if path != '-':
	f.close()

def getPassword(prompt):
    """Prompt the user for a password and get her to type it twice"""
    while 1:
        first = getpass.getpass(prompt)
        second = getpass.getpass('Re-enter password: ')
        if first == second:
            break
        print "Passwords do not match"
    return first

def loadPrivateKey(hash=None, prompt=None):
    """Load a private key and decrypt it, prompting user if needed

    If no argument is provided, the default private key will be
    loaded. 
    """
    if hash is None:
        hash = gopts.keys.getDefaultKey()
    encrypted = gopts.keys.lookupPrivateKey(hash)
    if encrypted.isBogus():
        return encrypted.decrypt()

    if prompt:
        print prompt
    pw = getPassword('Enter password for private key %s: ' % hash)
    return encrypted.decrypt(pw)

def parseKeyInput(buf):
    """Parse input that could be a hash or a key name"""
    # If it is a hash, it will either be an sexp or the 20+ byte
    # base64 encoded hash value.  Assume that if it isn't either of
    # those it must be a name.
    try:
        p = spki.parseText(buf)
    except sexp.ParseError:
        # isn't an sexp
        pass
    else:
        return p
    # XXX this code assume a lot about how hashes are represented,
    # would need to be modified to support other hash lengths.
    if len(buf) == 24 and buf[-2:] == '==':
        digest = sexp.b64_to_str(buf)
        p = spki.Hash('md5', digest)
    else:
        ns = gopts.keys.getDefaultKey()
        if ns is None:
            raise CmdError, "no default key specified"
        certs = gopts.keys.lookupName(buf, ns)
        # XXX should check signature of certificate
        matches = []
        for seq in certs:
            for elt in seq:
                if isinstance(elt, spki.Cert) and elt.isNameCert():
                    subj = elt.getSubject().getPrincipal()
                    matches.append(subj)
        l = len(matches)
        if l != 1:
            raise CmdError, \
                  "ambiguous name: %s matches %d keys" % (buf, l)
        p = matches[0]
    return p

class template:
    def __init__(self):
        pass

    def parseArgs(self, args):
        opts, args = getopt.getopt(args, '')

    def run(self):
        pass

class create:
    """create [-b bits] [--unsafe] [--replace] [--dup] [--default|name]

    Create a key pair with label as specified by user.  Add the key
    pair to the user's key file and add the public key to the user's
    ACL.  The user will be prompted for a pass phrase to encrypt the
    private key.  Currently on the rsa-pkcs1-md5 algorithm is
    supported.

    options:
    --unsafe: use the user's PID as pass phrase
    --replace: replace an existing default key
    -b NNNN: number of bits for key pair (default 1024)
    --dup: create a name cert even if name is already used

    Note: The SPKI protocol allows multiple keys to be bound to the
    same name, which allows the creation of a group.  But multiple
    keys with the same name presents a problem for naming private
    keys, because the name no longer unambiguously refers to a single
    key. 
    """
    def __init__(self):
        self.algorithm = 'RSA'  # interfaces aren't general enough to
                                # support other algorithms yet
        self.name = None
        self.bits = 1024
        self.unsafe = 0
        self.replace = 0
        self.default = 0
        self.dup = 0

    def parseArgs(self, args):
        opts, args = getopt.getopt(args, 'b:',
                                   ['unsafe', 'replace', 'default',
                                    'dup']) 
        for k, v in opts:
            if k == '-b':
                self.bits = string.atoi(v)
            elif k == '--unsafe':
                self.unsafe = 1
            elif k == '--replace':
                self.replace = 1
            elif k == '--default':
                self.default = 1
            elif k == '--dup':
                self.dup = 1
        try:
            (self.name,) = args
        except ValueError:
            if not self.default:
                raise ValueError, "must specify name or --default"

        dk = gopts.keys.getDefaultKey()
        if dk is None and not self.default:
            raise ValueError, "must create default key first"
        if dk and self.default and not self.replace:
            raise ValueError, "default key already exists. "\
                  "Use --replace to replace it"
        if self.default and self.name:
            raise ValueError, "can not give name to default key"
        if dk and gopts.keys.lookupName(self.name, dk)\
           and not self.dup:
            raise ValueError, "name already exists. use --dup to override"

    def run(self):
        if VERBOSE:
            print "Creating %d-bit key pair using %s algorithm" % (self.bits,
                                                               self.algorithm)
            from pisces import cryptrand
            print "Random data source:", cryptrand.implementation
        pub, priv = spki.makeRSAKeyPair(self.bits)
        print "Generated key: %s" % str(pub.getPrincipal())
        self.save(pub, priv)
        if self.default:
            # XXX need way to check if default is already set
            gopts.keys.setDefaultKey(pub.getPrincipal())
            if VERBOSE:
                print "Set as default key"
        if self.name:
            self.createName(priv, pub, self.name)

    def save(self, pub, priv):
        if self.unsafe:
            if VERBOSE:
                print "Saving private key with bogus encryption"
            pword = str(os.getuid())
        else:
            label = pub.getPrincipal()
            pword = getPassword('Password for storing key %s: ' % label)
	if self.unsafe:
	    gopts.keys.addPrivateKey(priv, pub, pword, 1)
	else:
	    gopts.keys.addPrivateKey(priv, pub, pword)
        gopts.keys.addPublicKey(pub)

    __prompt = "\nEnter password for default key. " \
               "Needed to generate name cert."

    def createName(self, priv, pub, name):
        defkey = gopts.keys.getDefaultKey()
        try:
            private = loadPrivateKey(defkey, prompt=self.__prompt)
        except ValueError, err:
            print "Could not load private key:", err
            raise
        n = spki.makeNameCert(defkey, pub.getPrincipal(), name)
        sig = private.sign(n)
        namecert = spki.Sequence(n, sig)
        gopts.keys.addCert(namecert)
        if VERBOSE:
            print "Name cert created:"
            print "\t", n.getIssuer()
            print "\t", n.getSubject()

class list:
    """list [--public] [--private] [--name]

    List all the keys stored in the KeyStore and all the name
    certificates issued by the private keys.  For private keys, the
    hash of the corresponding public key is listed.  As a result, the
    same hash should appear in the private and public lists.  

    Specifying the options, limits the listing to only the specified
    sections.
    """

    PUBLIC = 0x1
    PRIVATE = 0x2
    NAME = 0x4

    def __init__(self):
        self.kinds = 0

    def parseArgs(self, args):
	opts, args = getopt.getopt(args, 'urn',
                                   ['public', 'private', 'name'])
        for k, v in opts:
            if k == '-u' or k == '--public':
                self.kinds = self.kinds | list.PUBLIC
            if k == '-r' or k == '--private':
                self.kinds = self.kinds | list.PRIVATE
            if k == '-n' or k == '--name':
                self.kinds = self.kinds | list.NAME

    def run(self):
        if not self.kinds or self.kinds & list.PRIVATE:
            self.private()
        if not self.kinds or self.kinds & list.NAME:
            self.name()
        if not self.kinds or self.kinds & list.PUBLIC:
            self.public()

    def private(self):
        print "PRIVATE KEYS"
        default = gopts.keys.getDefaultKey()
        print default, "default"
        for key in gopts.keys.listPrivateKeys():
            if key == default:
                continue
            print key
        print

    def name(self):
        print "NAMES"
        for key in gopts.keys.listPrivateKeys():
            used = 0
            certs = gopts.keys.lookupCertByIssuer(key) or []
            for cert in certs:
                if isinstance(cert, spki.Sequence):
                    for elt in cert:
                        if isinstance(elt, spki.Cert):
                            cert = elt
                            break
                if cert.isNameCert():
                    if used == 0:
                        print "Names issued by key %s" % key
                        used = 1
                    subject = cert.getSubject().getPrincipal()
                    name = cert.getIssuer().getPrincipal()
                    print '"%s": %s' % (string.join(name.names, ' '),
                                        subject)
        print

    def public(self):
        print "PUBLIC KEYS"
        for key in gopts.keys.listPublicKeys():
            print key.getPrincipal()
        print
            
class name:
    """name [-i/--issuer principal] -n/--name name -h/--hash hash
    [-o output]

    Create a name certificate.  Can be used to associate a name with a
    public key on the key server.

    The hash designates the public key that the name will be bound
    to.  The hash can either by the advanced form of a SPKI hash
    object, or just the base64 encoded digest.  Thus, either of the
    following is allowed: '(hash md5 |hTK6mv8Nbspy9jsljfb2DQ==|)' or
    'hTK6mv8Nbspy9jsljfb2DQ=='.

    By default, the issuer is the user's default key.  To use a
    different key, the user should specify the name or hash of the key
    with the --issuer argument.

    The -o option can be used to make a local copy of the name cert.

    This command needs to be extended with validity handling.
    """
    
    def __init__(self):
	self.issuer = None
        self.name = None
        self.hash = None
	self.output = None

    def parseArgs(self, args):
	opts, args = getopt.getopt(args, 'i:n:h:o:',
                                   ['issuer=', 'name=', 'hash='])
	for k, v in opts:
	    if k in ('-i', '--issuer'):
		self.issuer = parseKeyInput(v)
            elif k in ('-n', '--name'):
                self.name = v
            elif k in ('-h', '--hash'):
                self.hash = parseKeyInput(v)
	    elif k == '-o':
		self.output = v
	self.args = args

        if self.name is None:
            raise ValueError, "must specify name"
        if self.hash is None:
            raise ValueError, "must specify hash"
        if gopts.keys is None and self.output is None:
            raise ValueError, "must specify output location for name cert"

    def run(self):
        if self.issuer is None:
            self.issuer = gopts.keys.getDefaultKey()
            if VERBOSE:
                print "Using default key to issue certificate"
        elif VERBOSE:
            print "Using key %s to issue certificate" % self.issuer
        private = loadPrivateKey(self.issuer)
	n = spki.makeNameCert(self.issuer, self.hash, self.name)
	sig = private.sign(n)
	namecert = spki.Sequence(n, sig)
        if gopts.keys:
            gopts.keys.addCert(namecert)
        if self.output:
            dump(self.output, namecert)
        if VERBOSE:
            print "Name cert created:"
            print "\t", n.getIssuer()
            print "\t", n.getSubject()

class sign:
    """sign [-s/--signer name] [-o output] file 

    Create a digital signature for the contents of the specified
    file.  By default, the signature is placed stored as file.sig, but
    you can use the -o option to specify a different output location.

    The signature is created using the default key, unless the
    --signer option is used to specify a different key.  The --signer
    option will accept the name or hash of a key.
    """

    EXT = '.sig'

    def __init__(self):
        self.file = None
        self.output = None
        self.signer = None

    def parseArgs(self, args):
        opts, args = getopt.getopt(args, 's:o:', ['signer='])
        for k, v in opts:
            if k in ('-s', '--signer'):
                self.signer = parseKeyInput(v)
            elif k == '-o':
                self.output = v
        try:
            self.input = args[0]
        except IndexError:
            raise ValueError, "must specify file to sign"
        if self.output is None:
            self.output = self.input + self.EXT
        
    def run(self):
        prompt = "Using key %s to sign" % self.signer
        key = loadPrivateKey(self.signer, prompt=prompt)
        f = open(self.input, 'rb')
        buf = f.read()
        f.close()
        sig = key.sign(buf)
        f = open(self.output, 'wb')
        f.write(sig.sexp().encode_base64())
        f.close()
        if VERBOSE:
            print "Wrote signature to %s" % self.output

class verify:
    """verify [-i signaturefile] file

    Verify a digital signature of a file.  The default behavior is to
    look for the signature in file.sig.  The -i option can be used to
    specify a different path for the signature.
    """

    EXT = sign.EXT

    def __init__(self):
        self.file = None
        self.input = None

    def parseArgs(self, args):
        opts, args = getopt.getopt(args, 'i:')
        for k, v in opts:
            if k == '-i':
                self.input = v
        try:
            self.file = args[0]
        except IndexError:
            raise ValueError, "must specify file that has been signed"

    def run(self):
        f = open(self.file, 'rb')
        contents = f.read()
        f.close()
        if self.input:
            sigPath = self.input
        else:
            sigPath = self.file + self.EXT
        f = open(sigPath, 'rb')
        try:
            sig = spki.parse(f.read())
        except sexp.ParseError, msg:
            if VERBOSE:
                print msg
            ok = 0
        else:
            ok = self.verify(contents, sig)
        f.close()
        if ok:
            print "successfully verified signature on: %s" % self.file
        else:
            print "could not verify signature on: %s" % self.file
        return ok

    def verify(self, buf, sig):
        try:
            key = gopts.keys.lookupKey(sig.principal)
        except KeyError:
            key = None

        if key is None:
            if VERBOSE:
                print "Could not find key for %s" % sig.principal
            return
	try:
	    return key.verify(buf, sig)
	except CmdError, err:
            if VERBOSE:
                print "could not verify %s: %s" % (self.file, err)

class _import:
    """import [path]

    Load a new public key or certificate into the keystore.  The
    object will be loaded from a file containing either the canonical
    or base64 encoding of the s-expression.  If no path is specified,
    the object will be read from stdin.

    For a certificate to be useful in verifying a certificate chain,
    it must be signed.  A public key, however, needs no signature.
    """
    def __init__(self):
        self.input = '-'

    def parseArgs(self, args):
        l = len(args)
        if l > 1:
            raise ValueError, "must specify single input file"
        if l == 1:
            self.input = args[1]

    def run(self):
        buf = load(self.input)
        obj = spki.parse(load(self.input))
        if spki.isa(obj, spki.PublicKey):
            self.saveKey(obj)
        elif spki.isa(obj, spki.Sequence):
            self.saveCert(obj)
        else:
            cname = obj.__class__.__name__
            raise CmdError, "unexpected object type: %s" % cname

    def saveKey(self, obj):
        gopts.keys.addPublicKey(obj)
        if VERBOSE:
            print "imported key %s" % obj.getPrincipal()

    def saveCert(self, seq):
        # first do some extended type checking: the sequence could
        # contain a public key.  it will definitely contain a
        # certificate and a signature. 
        key = None
        cert = None
        sig = None
        for elt in seq:
            if spki.isa(elt, spki.PublicKey):
                if key is not None:
                    raise CmdError, "multiple keys in cert sequence"
                key = elt
            elif spki.isa(elt, spki.Cert):
                if cert is not None:
                    raise CmdError, "multiple certificates found"
                cert = elt
            elif spki.isa(elt, spki.Signature):
                if sig is not None:
                    raise CmdError, "multiple signatures found"
                sig = elt
        if key:
            self.saveKey(key)
            if key.getPrincipal() != sig.principal:
                raise CmdError, "key and signature principal do not match"
        else:
            key = gopts.keys.lookupKey(sig.principal)
        if key is None:
            raise CmdError, "could not find key to verify signature"
        if not key.verify(cert, sig):
            raise CmdError, "could not verify signature for cert"
        gopts.keys.addCert(spki.Sequence([cert, sig]))
        if VERBOSE:
            print "imported cert\n", sexp.pprint(cert.sexp())
        
class export:
    """export [-o output] [--canonical] <hash-or-name>

    Export a public key from the store.  The key may be specified by
    its hash or its name.  The -o flag can be used to specify a file
    to place the key; if no file is specified, the key will be printed
    on stdout.

    Keys are output in base64 encoding by default.  Use the
    --canonical flag to specify the canonical (binary) encoding instead.
    """
    def __init__(self):
	self.output = '-'
        self.canonical = None

    def parseArgs(self, args):
	opts, args = getopt.getopt(args, 'o:',
				   ['canonical'])
	for k, v in opts:
	    if k == '-o':
		self.output = v
	    elif k == '--canonical':
		self.canonical = 1

        if len(args) != 1:
            raise ValueError, "must specify one key to export"
        self.key = parseKeyInput(args[0])

    def run(self):
        key = gopts.keys.lookupKey(self.key)
        if key is None:
            raise CmdError, "unknown key"
	if self.canonical:
	    dump(self.output, key.sexp().encode_canonical())
	else:
	    dump(self.output, key)

class show:
    """show [-i input] [-o output]

    Read in an arbitrary SPKI object and display it in human-readable
    form.  The show command will read the object from stdin and
    display it on stdout.  The source and destination can be changed
    with the -i and -o arguments.
    """
    def __init__(self):
        self.input = '-'
        self.output = '-'

    def parseArgs(self, args):
        opts, args = getopt.getopt(args, 'i:o:')
        for k, v in opts:
            if k == '-i':
                self.input = v
            elif k == '-o':
                self.output = v

    def run(self):
        try:
            buf = load(self.input)
        except IOError, msg:
            raise CmdError, "Could not read %s: %s" % (self.input,
                                                       msg)
        try:
            obj = sexp.parse(buf)
        except (TypeError, sexp.ParseError):
            raise CmdError, "invalid s-expression"
        dump(self.output, sexp.pprint(obj))

class cert:
    """cert [-i/--issuer] -s/--subject subject
    [-b/--before time] [-a/--after time] [-t/--test URI]
    -p/--permission permission [-d/--delegate] [-k/--key]

    Create a new certificate.  The certificate has the following
    parts: subject, issuer, validity, and permissions.  It may also
    have a delegation tag.  Each of these parts can be specified using
    a different option; each option has a short name and a long name.

    Note: To create a name certificate, use the name command.

    The options for the cert command are list below.  Each take a
    single argument following the option name.

    optional: --issuer (-i)
    The hash or name of the key to use as issuer.  Will use the
    default key as issuer otherwise.

    required: --subject (-s)
    The hash or name of the key that is the subject of the
    certificate.

    optional: --before (-b)
    optional: --after (-a)
    These options limit the period of time for which the certificate
    is valid.  The time format is YYYY-MM-DD_HH:MM:SS.  You can also
    use the string "now" to indicate the current time.

    optional: --test (-t)
    Specify an online validity test for the certificate.  The argument
    should be the URL for the test.  This optional currently has no
    associated implementation; although it can be included in the
    certificate, the test will not be performed.

    required: --permission (-p)
    Specify the permissions that are being granted to the subject
    key.  The argument must be an s-expression in human-readable
    form for the permissions.  The permissions will be wrapped in a
    (tag ...) s-expression.

    optional: --delegate (-d)
    Allow subject to delegate permission.  Default is to disallow
    delegation. 

    optional: --key (-k)
    Include the key of the issuer with the certificate.  By default,
    the certificate does not include the key itself, only the hash of
    the key. 
    """
    def __init__(self):
        self.issuer = None
        self.subject = None
        self.valid = []
        self.output = '-'
        self.delegate = 0
        self.withkey = 0
        self.perm = None
        self.name = None
        self.kind = 'cert'

    def parseArgs(self, args):
        opts, args = getopt.getopt(args, 'i:s:b:a:p:o:t:dk',
                                   ['before=', 'after=', 'test=', 
                                    'key', 'delegate', 'subject=',
                                    'issuer=', 'permission='])
        for k, v in opts:
            if k in ('-i', '--issuer'):
                self.issuer = v
            elif k in ('-s', '--subject'):
                self.subject = parseHashOrName(v)
            elif k == '-o':
                self.output = v
            elif k in ('-b', '--before'):
                self.valid.append(spki.NotAfter(parseTime(v)))
            elif k in ('-a', '--after'):
                self.valid.append(spki.NotBefore(parseTime(v)))
            elif k in ('-t', '--test'):
                self.valid.append(spki.Online(v))
            elif k in ('-d', '--delegate'):
                self.delegate = 1
            elif k in ('-k', '--key'):
                self.withkey = 1
	    elif k in ('-p', '--permission'):
		self.perm = spki.eval(sexp.parseText(v))

        if self.subject is None:
            raise ValueError, "must specify subject"
        if self.perm is None:
            raise ValueError, "must specify permissions"
        self.issuer = self.getIssuer()

    def getIssuer(self):
        # could be a hash or a name or nothing
        if self.issuer is None:
            return config.getDefaultKey()
        else:
            obj = parseHashOrName(self.issuer)
            if isinstance(obj, spki.Name):
                return resolveName(obj).getPrincipal()
            else:
                return obj

    def run(self):
        enc_privkey = gopts.keys.lookupPrivateKey(self.issuer)
	privkey = enc_privkey.decrypt()
        c = spki.makeCert(self.issuer, self.subject,
                          spki.Tag(self.perm), self.delegate, 
                          self.valid)
        if self.withkey:
            seq = spki.Sequence(privkey.getPublicKey())
        else:
            seq = spki.Sequence()
        seq.extend([c, privkey.sign(c)])
        if self.output == '-':
            print sexp.pprint(seq.sexp())
        elif self.output:
            dump(self.output, seq)
        if gopts.keys:
            gopts.keys.addCert(seq)
        
class acl:
    """acl -s/--subject key -p permissions [-o output]
    [-b/--before time] [-a/--after time] [--test URI] [-d/--delegate]
    [--db acl] 

    Creates a certificate for an access control list (Entry).  The
    subject can be a hash of a key or a name.  If the subject is a
    name, the name is interpreted relative to the user's default key.

    The permissions should be a text representation of a SPKI sexp.
    This is a little clunky, but it's hard to come up with a general
    interface for something that is essentially application-specific.

    If the --db option is used, the Entry is added to the
    database.ACL file at the specified path.  If this option is used,
    it overrides the -o option.  Will create a new ACL if one does not
    exist.

    The -d/--delegate option allows permissions to be delegated.  By
    default, delegation is disabled.

    The before/after/test modifiers are the same as for the cert
    command.  They affect the validity constraints.
    """
    def __init__(self):
        self.key = None
        self.permissions = None
        self.output = '-'
        self.acl = None
        self.valid = []
        self.delegate = 0
	self.db = None

    def parseArgs(self, args):
        opts, args = getopt.getopt(args, 's:p:o:b:a:t:d',
                                   ['before=', 'after=', 'test=',
                                    'delegate', 'acl=', 'db=',
                                    'subject=']) 
        for k, v in opts:
            if k in ('-s', '--subject'):
                self.key = parseHashOrName(v)
            elif k == '-o':
                self.output = v
            elif k == '-p':
                s = sexp.parseText(v)
                self.permissions = spki.eval(sexp.parseText(v))
            elif k == '-b' or k == '--before':
                self.valid.append(spki.NotAfter(parseTime(v)))
            elif k == '-a' or k == '--after':
                self.valid.append(spki.NotBefore(parseTime(v)))
            elif k == '--test':
                self.valid.append(spki.Online(v))
            elif k == '-d' or k == '--delegate':
                self.delegate = 1
            elif k == '-l' or k == '--acl' or k == '--db':
                self.acl = v
        if self.key is None or self.permissions is None:
            print "Must specify key (-k) and permisssions (-p)"
        if not (isinstance(self.key, spki.Hash) \
                or isinstance(self.key, spki.Name)):
            raise ValueError, \
                  "Must specify a hash or name for the subject: " \
		  "got %s" % self.key


    def run(self):
        if isinstance(self.key, spki.Hash):
            key = gopts.keys.lookupKey(self.key)
        else:
	    key = resolveName(self.key)
        p = key.getPrincipal()
        c = spki.makeAclEntry(p, self.valid, self.delegate,
                              self.permissions)
        if self.acl:
            acl = database.ACL(self.acl, create=1)
            acl.add(c)
            acl.rewrite()
        else:
            dump(self.output, c)

def help(short=0, args=[]):
    print "generic usage: spki.py [-v] [-d dir] command [options]"
    print "for help:      spki.py -h [command|all]"
    if short:
        return 1
    if not args:
        print "available commands are:"
    commands = []
    for k, v in globals().items():
        if k == 'template': continue
        if k[0] == '_':
            k = k[1:]
        if type(v) == types.ClassType and hasattr(v, 'run'):
            commands.append((k, v))
            
    commands.sort()
    if not args:
        for cmd, klass in commands:
            print cmd
    else:
        all = args[0] == "all"
        for cmd, klass in commands:
            if all or args[0] == cmd:
                if klass.__doc__:
                    print klass.__doc__
                else:
                    print cmd, "(no __doc__ available)"

def main():
    commands = globals()
    for cmd in (gopts.cmd, '_'+gopts.cmd):
        klass = commands.get(cmd)
        if isinstance(klass, types.ClassType) and hasattr(klass, "run"):
            obj = klass()
            break
    else:
        print "invalid command: %s" % gopts.cmd
        help(short=1)
        return
    try:
        obj.parseArgs(gopts.args)
    except (getopt.error, ValueError), err:
        print "Invalid arguments:"
        print err
        print obj.__doc__
    else:
        return obj.run()

class Options(config.Options):
    super_init = config.Options.__init__

    def __init__(self):
	self.super_init()
	self.arghandler = self.getCommand

    def getCommand(self, args):
	try:
	    self.cmd = args[0]
	except IndexError:
	    raise ValueError, "no command specified"
        self.args = args[1:]

if __name__ == "__main__":
    # gopts is used as a global variable
    # turn it into two global variables??? KEYS & VERBOSE
    gopts = Options()
    try:
	gopts.init(sys.argv[1:])
    except (config.error, ValueError), err:
        print err
        help(short=1)
    except config.HelpError, herr:
        help(args=herr.args)
    else:
        VERBOSE = gopts.verbose
        try:
            status = main()
        except CmdError, msg:
            print "Error executing command"
            print msg
	    status = -1
        gopts.keys.close()
        if status:
            sys.exit(status)
