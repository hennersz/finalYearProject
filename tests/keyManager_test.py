#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet import defer
from p2ppki.backend.keyManager import KeyManager
from p2ppki.utils import hashToB64
from helpers import FakeDHT, createKeystore
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
