#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet import defer
from p2ppki.backend.keyManager import KeyManager
from p2ppki.utils import hashToB64
from helpers import FakeDHT, createKeystore, InMemKeyStore
from pisces.spkilib import spki
import mock
import pytest


@pytest.fixture()
def ks():
    return createKeystore()


@pytest.inlineCallbacks
def test_insert(ks):
    keystore = ks[0]
    keys = ks[1]

    dht = mock.create_autospec(FakeDHT)
    dht.set.return_value = defer.succeed(True)

    k = KeyManager(dht, keystore)
    res = yield k.insertKey(keys[0][0].getPrincipal())
    key = hashToB64(keys[0][0].getPrincipal()) + '-key'
    value = str(keys[0][0].sexp().encode_canonical())
    dht.set.assert_called_with(key, value)
    assert res

    pub, priv = spki.makeRSAKeyPair(1024)

    with pytest.raises(ValueError) as e:
        res = yield k.insertKey(pub.getPrincipal())
    assert 'No key corresponding to hash' in str(e.value)


@pytest.inlineCallbacks
def test_get(ks):
    keystore = ks[0]
    keys = ks[1]
    pubs = [x[0] for x in keys]
    dht = FakeDHT(pubs[1:], [], keystore)

    k = KeyManager(dht, keystore)

    res = yield k.getKey(keys[0][0].getPrincipal())
    assert res is None

    res = yield k.getKey(keys[1][0].getPrincipal())
    assert isinstance(res, spki.PublicKey)
    assert res.getPrincipal() == keys[1][0].getPrincipal()


def test_listLocalKeys(ks):
    keystore = ks[0]
    keys = ks[1]
    pubs = [x[0] for x in keys]
    dht = FakeDHT(pubs[1:], [], keystore)

    k = KeyManager(dht, keystore)

    pubs, privs = k.listLocalKeys()
    assert len(pubs) == 5
    assert privs is None

    pubs, privs = k.listLocalKeys(True)
    assert len(pubs) == 5
    assert len(privs) == 5
