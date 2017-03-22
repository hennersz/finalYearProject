#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pisces.spkilib import sexp, spki
from twisted.internet.defer import inlineCallbacks, returnValue


class KeyManager():

    def __init__(self, dht, keyStore):
        self.dht = dht
        self.keystore = keyStore

    def insertKey(self, key):
        h = sexp.str_to_b64(key.getPrincipal().value)
        key = h + '-key'
        self.dht.set(key, str(key.sexp().encode_canonical()))

    @inlineCallbacks
    def getKey(self, keyHash):
        key = sexp.str_to_b64(keyHash.value) + '-key'
        keys = yield self.dht.get(key)
        for key in keys:
            try:
                k = spki.parse(key)
                if k.getPrincipal() == keyHash:
                    returnValue(k)
            except sexp.ParseError:
                # ignore invalid data from dht
                continue

    def listLocalKeys(self, private=False):
        pubs = self.keystore.listPublicKeys()
        if private:
            privs = self.keystore.listPrivateKeys()
        else:
            privs = None
        return (pubs, privs)
