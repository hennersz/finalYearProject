#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pisces.spkilib import spki, sexp
from twisted.internet.defer import inlineCallbacks, returnValue
from utils import getDefaultKey, parseHashOrName, getHash, loadPrivateKey,\
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
        self.keystore.addCert(seq)
        self.keystore.save()

    def addCA(self, subject, issuer=None):
        if issuer is None:
            i = getDefaultKey(self.keystore)
        else:
            i = getHash(issuer, self.keystore)

        s = parseHashOrName(subject, self.keystore)

        enc_privkey = self.keystore.lookupPrivateKey(i)
        privkey = enc_privkey.decrypt()

        perm = spki.eval(sexp.parseText('(* set CAVerified)'))

        c = spki.makeCert(i, s, spki.Tag(perm), 1)
        seq = spki.Sequence(c, privkey.sign(c))
        self.keystore.addCert(seq)
        self.keystore.save()

    def name(self, subjectHash, name, issuer=None):
        if issuer is None:
            i = getDefaultKey(self.keystore)
        else:
            i = getHash(issuer, self.keystore)

        private = loadPrivateKey(self.keystore, i)
        pub = private.getPublicKey()
        n = spki.makeNameCert(i, subjectHash, name)
        sig = private.sign(n)
        namecert = spki.Sequence(pub, n, sig)
        self.storeCert(namecert)
        self.keystore.addCert(namecert)
        self.keystore.save()

    @inlineCallbacks
    def storeCert(self, certificate):
        h = getCertSubjectHash(certificate)
        key = str(h) + '-certificates'
        self.dht.set(key, str(certificate.sexp().encode_canonical()))

    @inlineCallbacks
    def getCertificates(self, keyHash):
        key = hashToB64(keyHash) + '-certificates'
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
