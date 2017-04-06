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

        ret = yield self.dht.set(k, str(key.sexp().encode_canonical()))
        returnValue(ret)

    @inlineCallbacks
    def getKey(self, keyHash):
        key = hashToB64(keyHash) + '-key'
        keys = yield self.dht.get(key)

        if keys is None:
            returnValue(None)

        for key in keys:
            try:
                k = spki.parse(key)
                if k.getPrincipal() == keyHash:
                    returnValue(k)
                    break
            except sexp.ParseError:
                # ignore invalid data from dht
                continue
        returnValue(None)

    def listLocalKeys(self, private=False):
        pubs = self.keystore.listPublicKeys()
        if private:
            privs = self.keystore.listPrivateKeys()
        else:
            privs = None
        return (pubs, privs)
