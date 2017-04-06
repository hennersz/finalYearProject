#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pisces.spkilib import spki, sexp
from twisted.internet.defer import inlineCallbacks, returnValue
from ..utils import getDefaultKey, loadPrivateKey,\
                  hashToB64, getCertSubjectHash


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
    return spki.Sequence(cert, sig)


class CertManager():
    def __init__(self, dht, keyStore):
        self.dht = dht
        self.keystore = keyStore

    def trust(self, subject, issuer=None):
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
        h = getCertSubjectHash(certificate, self.keystore)
        key = hashToB64(h) + '-certificates'
        ret = yield self.dht.set(key, str(certificate.sexp().encode_canonical()))
        returnValue(ret)

    @inlineCallbacks
    def getCertificates(self, keyHash):
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
