#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pisces.spkilib import spki, sexp
from twisted.internet.defer import inlineCallbacks, returnValue
import getpass


def getPassword(prompt):
    """
    Prompt the user for a password and get them to type it twice

    Taken from spkitool
    """
    while 1:
        first = getpass.getpass(prompt)
        second = getpass.getpass('Re-enter password: ')
        if first == second:
            break
        print "Passwords do not match"
    return first


def getDefaultKey(keyStore, returnHash=True):
    """Gets the default key from a keystore
    """
    privKeyHash = keyStore.getDefaultKey()

    if privKeyHash is None:
        raise ValueError('No default key set')

    key = keyStore.lookupKey(privKeyHash)
    if returnHash:
        return key.getPrincipal()
    else:
        return key


def resolveName(name, keyStore):
    """Convert a name in the local namespace to a key

    The return value is an object with a getPrincipal method.

    Based on the pisces spkitool function but without global variables
    """
    nameCerts = keyStore.lookupName(name)

    if not nameCerts:
        raise ValueError("unbound SPKI name: %s" % name)
    cert = spki.extractSignedCert(nameCerts[0])

    return cert.getSubject()


def parseHashOrName(buf, keyStore):
    """Try parsing into a hash or a name
    """

    try:
        o = spki.parseText(buf)
    except sexp.ParseError:
        pass
    else:
        return o

    # It wasn't a hash, try as name
    base = getDefaultKey(keyStore)
    return spki.FullyQualifiedName(base, (buf,))


def getHash(issuer, keyStore):
    """Gets a hash object for issuer from a hash string
    or name
    """
    # could be a hash or a name
    obj = parseHashOrName(issuer, keyStore)
    if isinstance(obj, spki.Name):
        return resolveName(obj, keyStore).getPrincipal()
    else:
        return obj


def loadPrivateKey(keystore, hash=None):
    """Loads a private key object from the keystore
    given a hash value.

    If no hash is given the default key is used

    Based on the pisces spkitool function but without
    using global variables.
    """

    if hash is None:
        enc = getDefaultKey(keystore, returnHash=False)
    else:
        enc = keystore.lookupPrivateKey(hash)

    if enc.isBogus():
        return enc.decrypt()

    pw = getPassword('Enter password for private key %s: ' % hash)
    return enc.decrypt(pw)


def getCertSubjectHash(cert, keystore):
    issuer, subject = spki.getIssuerAndSubject(cert)
    if subject.isName():
        names = subject.getPrincipal().names
        for name in names:
            try:
                #  Gets hash object for name then converts to base 64 string
                return sexp.str_to_b64(getHash(name, keystore).value)
            except ValueError:
                continue
        raise ValueError("Unbound spki name: %s" % name)
    else:
        return sexp.str_to_b64(getHash(name, keystore).value)


def hashToB64(h):
    """Converts a hash object to its base 64 representation
    """
    return sexp.str_to_b64(h.value)


class VerifyError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def verifyCertSig(certSeq, keyStore):
    """Verifies that the signature on the certificate is valid
    """
    key = None
    cert = None
    sig = None
    for elt in certSeq:
        if spki.isa(elt, spki.PublicKey):
            if key is not None:
                raise VerifyError('More than 1 key found')
            key = elt
        elif spki.isa(elt, spki.Cert):
            if cert is not None:
                raise VerifyError('multiple certificates found')
            cert = elt
        elif spki.isa(elt, spki.Signature):
            if sig is not None:
                raise VerifyError('multiple signatures found')
            sig = elt
    if key:
        keyStore.addPublicKey(key)
        if key.getPrincipal() != sig.principal:
            raise VerifyError('Key and signature principal do not match')
    else:
        key = keyStore.lookupKey(sig.principal)
    if key is None:
        raise VerifyError("could not find key to verify signature")
    if not key.verify(cert, sig):
        raise VerifyError("could not verify signature for cert")
    return spki.Sequence([cert, sig])


class CertManager():
    def __init__(self, dht, keyStore):
        self.dht = dht
        self.keystore = keyStore

    def trust(self, subject, issuer=None):
        if issuer is None:
            i = getDefaultKey(self.keystore)
        else:
            i = getHash(issuer, self.keystore)

        s = parseHashOrName(subject, self.keystore)

        enc_privkey = self.keystore.lookupPrivateKey(i)
        privkey = enc_privkey.decrypt()

        perm = spki.eval(sexp.parseText('(* set Trusted)'))

        c = spki.makeCert(i, s, spki.Tag(perm))
        seq = spki.Sequence(c, privkey.sign(c))
        self.storeCert(seq)
        self.keystore.addCert(seq)
        self.keystore.save()

    def name(self, subjectHash, name, issuer=None):
        if issuer is None:
            i = getDefaultKey(self.keystore)
        else:
            i = getHash(issuer, self.keystore)

        private = loadPrivateKey(self.keystore, i)
        n = spki.makeNameCert(i, subjectHash, name)
        sig = private.sign(n)
        namecert = spki.Sequence(n, sig)
        self.keystore.addCert(namecert)
        self.keystore.save()

    @inlineCallbacks
    def storeCert(self, certificate):
        h = getCertSubjectHash(certificate)
        key = str(h) + '-certificates'
        self.dht.set(key, str(certificate.sexp().encode_canonical()))

    @inlineCallbacks
    def getCertificates(self, keyHash):
        key = hashToB64(keyHash) + -'certificates'
        certs = yield self.dht.get(key)
        verifiedCerts = []
        for cert in certs:
            try:
                c = spki.parse(cert)
                v = verifyCertSig(c, self.keystore)
                verifiedCerts.append(v)
            except (sexp.ParseError, VerifyError):
                # Ignore data we cant parse or verify
                continue
        returnValue(verifiedCerts)
