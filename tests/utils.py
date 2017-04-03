#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet import defer
from pisces.spkilib import spki, sexp
from context.p2ppki.utils import hashToB64, getCertSubjectHash
import base64
import json
import os


def encode_list(l):
    encoded = [base64.standard_b64encode(x) for x in l]
    return json.dumps(encoded)


def genNKeys(n):
    keys = []
    for i in range(n):
        pub, priv = spki.makeRSAKeyPair(1024)
        keys.append((pub, priv))
    return keys


def saveKey(pub, priv, keystore):
    pword = str(os.getuid())
    keystore.addPrivateKey(priv, pub, pword, 1)
    keystore.addPublicKey(pub)


def makeNameCert(issuer, subject, name):
    n = spki.makeNameCert(issuer.getPrincipal(), subject.getPrincipal, name)
    sig = issuer.sign(n)
    seq = spki.Sequence(n, sig, issuer.getPublicKey())
    return seq


def makeTrustCert(issuer, subject):
    perm = spki.eval(sexp.parseText('(* set Trusted)'))
    c = spki.makeCert(issuer.getPrincipal(), subject.getPrincipal(), perm)
    sig = issuer.sign(c)
    seq = spki.Sequence(c, sig, issuer.getPublicKey())
    return seq


def makeCACert(issuer, subject, intermediate):
    perm = spki.eval(sexp.parseText('(* set CATrusted)'))
    c = spki.makeCert(issuer.getPrincipal(), subject.getPrincipal(), perm,
                      intermediate)
    sig = issuer.sign(c)
    seq = spki.Sequence(c, sig, issuer.getPublicKey())
    return seq


def initACL(acl, keystore):
    key = keystore.getDefaultKey()
    perm = spki.eval(sexp.parseText('(*)'))
    c = spki.makeAclEntry(key.getPrincipal(), [], 1, perm)
    acl.add(c)


class FakeDHT(object):
    def __init__(self, keys=[], certs=[], keystore=None):
        self.data = {
                # No data
                'key1': None,
                # Data to be parsed by dhtServer
                'key2': encode_list(['123', 'abc']),
                'key3': json.dumps(['a', 'b']),
                'key4': 'Non json data'
                }

        for key in keys:
            k = hashToB64(key.getPrincipal())
            self.data[k+'-key'] = str(key.sexp().encode_canonical())

        for cert in certs:
            h = getCertSubjectHash(cert, keystore)
            k = str(h) + '-certificates'
            self.data[k] = str(cert.sexp().encode_canonical())

    def set(self, key, value):
        """Imitates kademlia DHT server set function

        Args:
            key (string): The key to store

            value (string): The value to be stored

        Returns:
            Deffered Boolean. Will always return True unless the key is 'fail'
        """

        # defer.succeed will return instantly and doesn't
        # need to touch rector event loop
        if key == 'fail':
            return defer.succeed(False)
        else:
            return defer.succeed(True)

    def get(self, key):
        """Imitates kademlia DHT server get function

        Args:
            key (string): The key to search for

        Returns:
            Array or None: Returns an array of values for the key
            or None if there is no data for the key
        """
        # defer.succeed will return instantly and
        # doenst need to touch rector event loop
        return defer.succeed(self.data[key])
