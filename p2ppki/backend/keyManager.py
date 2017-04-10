#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pisces.spkilib import sexp, spki
from twisted.internet.defer import inlineCallbacks, returnValue
from ..utils import hashToB64


class KeyManager():

    def __init__(self, dht, keyStore):
        self.dht = dht
        self.keystore = keyStore

    @inlineCallbacks
    def insertKey(self, keyHash):
        h = hashToB64(keyHash)
        k = h + '-key'

        key = self.keystore.lookupKey(keyHash)
        if key is None:
            raise ValueError("No key corresponding to hash: %s" % h)

        certs = self.keystore.lookupCertBySubject(keyHash)

        nameCerts = []
        for seq in certs:
            for elt in seq:
                if isinstance(elt, spki.Cert) and elt.isNameCert():
                    nameCerts.append(elt)

        names = []
        for cert in nameCerts:
            names.extend(cert.getIssuer().getPrincipal().names)

        keyData = key.sexp().encode_canonical()

        ret = yield self.dht.set(k, keyData)
        for name in names:
            r = yield self.dht.set(name+'-key', keyData)
            ret = ret and r
        returnValue(ret)

    @inlineCallbacks
    def getKey(self, keyId):
        if isinstance(keyId, spki.Hash):
            key = hashToB64(keyId) + '-key'
        else:
            key = keyId + '-key'
        keys = yield self.dht.get(key)

        if keys is None:
            returnValue(None)

        parsedKeys = []
        for key in keys:
            try:
                k = spki.parse(key)
                if isinstance(keyId, spki.Hash):
                    if k.getPrincipal() == keyId:
                        returnValue(k)
                        break
                else:
                    parsedKeys.append(k)
            except sexp.ParseError:
                # ignore invalid data from dht
                continue
        if parsedKeys != []:
            returnValue(parsedKeys)
        else:
            returnValue(None)

    def listLocalKeys(self, private=False):
        pubs = self.keystore.listPublicKeys()
        if private:
            privs = self.keystore.listPrivateKeys()
        else:
            privs = None
        return (pubs, privs)
