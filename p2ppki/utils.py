#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pisces.spkilib import spki, sexp
import binascii
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


def parseKeyIdInput(buf, keystore):
    """Parses a string into a spki.Hash object

    String  could be a sexp, a base 64 encoded version of the hash or a name

    Taken from the spkitool.py in pisces but doesn't use global variables
    and raises different exceptions.
    """

    try:
        p = spki.parseText(buf)
    except sexp.ParseError:
        # It wasnt an sexp, try next potential format
        pass
    else:
        if spki.isa(p, spki.Hash):
            return p

    #  Parse an MD5 hash in B64 representation
    #  Will always be 24 chars long and end in ==

    if len(buf) == 24 and buf[-2:] == '==':
        try:
            digest = sexp.b64_to_str(buf)
            p = spki.Hash('md5', digest)
        except binascii.Error:
            pass
        else:
            return p

    ns = keystore.getDefaultKey()
    if ns is None:
        raise ValueError('No default key specified')

    certs = keystore.lookupName(buf, ns)

    matches = []
    for seq in certs:
        for elt in seq:
            if isinstance(elt, spki.Cert) and elt.isNameCert():
                subj = elt.getSubject().getPrincipal()
                matches.append(subj)
    l = len(matches)
    if l != 1:
        raise NameError('Ambiguous name: %s matches %d keys' % (buf, l))

    p = matches[0]
    return p


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
        if enc is None:
            raise ValueError('No default key set')
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
                return hashToB64(getHash(name, keystore))
            except ValueError:
                continue
        raise ValueError("Unbound spki name: %s" % name)
    else:
        return hashToB64(subject.getPrincipal())


def hashToB64(h):
    """Converts a hash object to its base 64 representation
    """
    if spki.isa(h, spki.Hash):
        return sexp.str_to_b64(h.value)
    else:
        raise ValueError("Hash object not supplied")
