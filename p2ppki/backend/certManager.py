#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
.. module:: certManager
    :platform: UNIX
    :synopsis: Handles the creation, storage, retrieval and parsing of certificates

.. moduleauthor:: Henry Mortimer <henry@morti.net>

"""

from pisces.spkilib import spki, sexp
from twisted.internet.defer import inlineCallbacks, returnValue
from ..utils import getDefaultKey, loadPrivateKey,\
                  hashToB64, getCertSubjectHash


class VerifyError(Exception):
    """Simple exception for verifiying signatures"""

    def __init__(self, value):
        """Initialise error with some value, normally a string"""

        self.value = value

    def __str__(self):
        """Defines str method for error, simply returns string of value"""
        return repr(self.value)


def verifyCertSig(certSeq, keyStore):
    """Verifies that the signature on the certificate is valid.
    Will store a valid key that is found in the keystore.

    Args:
        certSeq: An spki.Sequence object. To correctly verify
        the sequence it must contain exactly one spki.Cert object and
        one spki.Signature object. Can also contain one spki.PublicKey
        object.

        keyStore: A keystore.KeyStore object or a subclass of it. Must
        provide addPublicKey and lookupKey methods.

    Returns:
       An spkiSequence with the spki.Cert and spki.Sequence objects from
       certSeq

    Raises:
        VerifyError: If any stage of verification fails this is raised.
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
    return spki.Sequence(cert, sig)


class CertManager():
    """Manages certificates. Provides methods for creation,
    storage and retrieval.
    """

    def __init__(self, dht, keyStore):
        """Initialise certificate manager

        Args:
            dht: Some persistent key value storage object that provides
            get and set methods

            keyStore: KeyStore object or subclass to store and retrieve 
            certificates and keys locally
        """
        self.dht = dht
        self.keystore = keyStore

    def trust(self, subject, issuer=None):
        """Create trust certificate.
        If issuer is none it uses the default 
        key from the keystore.
        Stores certificate in local keystore only

        Args:
            subject: spki.Hash object

            issuer: spki.Hash object or None. Must have private
            key for issuer.

        Returns:
            None
        """

        if issuer is None:
            issuer = getDefaultKey(self.keystore)

        privkey = loadPrivateKey(self.keystore, issuer)

        perm = spki.eval(sexp.parseText('(* set Trusted)'))

        c = spki.makeCert(issuer, subject, spki.Tag(perm))
        seq = spki.Sequence(c, privkey.sign(c), privkey.getPublicKey())

        self.keystore.addCert(seq)
        self.keystore.save()

    @inlineCallbacks
    def addCA(self, subject, delegate, issuer=None):
        """Creates a CA certificate.
        Can also delegate permission
        If issuer is None uses default key from
        keystore.
        Stores certificate locally and in dht.

        Args:
            subject: spki.Hash

            delegate: Bool - If this is true the subject 
            of the certificate will now also be able to issue 
            valid CA certificates

            issuer: spki.Hash object or None. Must have private
            key for issuer.

        Returns:
            Bool: If dht storage was successful.
        """
        if issuer is None:
            issuer = getDefaultKey(self.keystore)

        privkey = loadPrivateKey(self.keystore, issuer)

        perm = spki.eval(sexp.parseText('(* set CATrusted)'))

        c = spki.makeCert(issuer, subject, spki.Tag(perm), delegate)
        seq = spki.Sequence(c, privkey.sign(c), privkey.getPublicKey())

        ret = yield self.storeCert(seq)
        self.keystore.addCert(seq)
        self.keystore.save()
        returnValue(ret)

    @inlineCallbacks
    def name(self, subject, name, issuer=None):
        """Associates name with a public key
        If issuer is none it uses the default key 
        for the keystore
        Stores certificates in the dht and locally

        Args:
            subject: spki.Hash

            name: string or list of strings.

            issuer: spki.Hash or None, Must have private key 
            locally

        Returns:
            Bool: If dht storage was successful.
        """

        if issuer is None:
            issuer = getDefaultKey(self.keystore)

        private = loadPrivateKey(self.keystore, issuer)
        pub = private.getPublicKey()

        n = spki.makeNameCert(issuer, subject, name)
        sig = private.sign(n)
        namecert = spki.Sequence(pub, n, sig)

        ret = yield self.storeCert(namecert)
        self.keystore.addCert(namecert)
        self.keystore.save()
        returnValue(ret)

    @inlineCallbacks
    def storeCert(self, certificate):
        """Stores a certificate in the dht

        Args:
            certificate: spki.Sequence object, should contain a spki.Cert
            and spki.Signature and could contain the public key for the 
            signer as well

        Returns:
            Bool: If dht storage was successful.
        """

        h = getCertSubjectHash(certificate, self.keystore)
        key = hashToB64(h) + '-certificates'
        ret = yield self.dht.set(key, str(certificate.sexp().encode_canonical()))
        returnValue(ret)

    @inlineCallbacks
    def getCertificates(self, keyHash):
        """Gets certificates from dht that correspond to the supplied 
        key hash

        Args:
            keyHash: spki.Hash object.

        Returns:
            list: A list containing all found certificates
            that parse correctly and are well formed.
        """

        key = hashToB64(keyHash) + '-certificates'

        certs = yield self.dht.get(key)
        
        if certs is None:
            returnValue(None)

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
