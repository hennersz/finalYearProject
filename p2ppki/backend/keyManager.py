#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
.. module:: keyManager
    :platform: UNIX
    :synopsis: Handles storage a retrieval of keys from dht.

.. moduleauthor:: Henry Mortimer <henry@morti.net>

"""

from pisces.spkilib import sexp, spki
from twisted.internet.defer import inlineCallbacks, returnValue
from ..utils import hashToB64


class KeyManager():
    """Stores keys in dht and locally and retrieves keys
    from dht but doesn't store them locally.
    """

    def __init__(self, dht, keyStore):
        """Initialise key manager

        Args:
            dht: Some persistent key value storage object that provides
            get and set methods

            keyStore: KeyStore object or subclass to store and retrieve
            keys locally
        """

        self.dht = dht
        self.keystore = keyStore

    @inlineCallbacks
    def insertKey(self, keyHash):
        """Inserts a key into the dht. Uses keyhash and local
        Names as dht key.

        Args:
            keyHash: spki.Hash object. Public key must be available
            locally.

        Returns:
            Bool: If dht storage was successful.

        Raises:
            ValueError. Raised if public key not found locally.
        """

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
        """Retrieves keys from dht.

        Args:
            keyId: String or spki.Hash

        Returns:
            List or None: List of parsed spki.PublicKeys or None if 
            they didn't parse or none were found.
        """

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
        """Gets a list of locally stored keys

        Args:
            private: Bool. Returns private keys if true
            
        Returns:
            ([spki.PublicKey], [spki.PrivateKey]). Private keys may be None. 
        """
        pubs = self.keystore.listPublicKeys()
        if private:
            privs = self.keystore.listPrivateKeys()
        else:
            privs = None
        return (pubs, privs)
