#!/usr/bin/env python
# -*- coding: utf-8 -*-

from context import p2ppki
from utils import FakeDHT, genNKeys,  saveKey,\
                  makeNameCert, makeTrustCert, makeCertChain, initACL
from pisces.spkilib import keystore, database
from p2ppki.certManager import CertManager
from p2ppki.verifier import Verifier

import pytest


@pytest.fixture(scope='module')
def keys():
    return genNKeys(20)


@pytest.fixture(scope='module')
def ks(keys):
    keyStore = keystore.KeyStore('./')
    mainKey = keys[0]
    trusted = keys[1]
    saveKey(mainKey[0], mainKey[1], keyStore)
    saveKey(trusted[0], trusted[1], keyStore)
    saveKey(keys[5][0], keys[5][1], keyStore)
    keyStore.setDefaultKey(mainKey[0].getPrincipal())
    return keyStore


@pytest.fixture(scope='module')
def acl(ks):
    acl = database.ACL('./', create=1)
    initACL(acl, ks)
    return acl


@pytest.fixture(scope='module')
def certs(keys, ks):
    mainKey = keys[0]
    trusted = keys[1]
    named = keys[2]
    localName = keys[3]
    caNamed = keys[4]
    t = makeTrustCert(mainKey[1], trusted[0])
    ks.addCert(t)
    n = makeNameCert(trusted[1], named[0], 'Alice')
    l = makeNameCert(mainKey[1], localName[0], 'Bob')
    c = makeNameCert(keys[9][1], caNamed[0], 'charlie')
    chain1 = makeCertChain(keys[5:10], mainKey[1])
    chain2 = makeCertChain(keys[10:], mainKey[1])
    ks.addCert(l)
    return [n, c] + chain1 + chain2


@pytest.fixture(scope='module')
def dht(certs, ks):
    return FakeDHT([], certs, ks)


@pytest.fixture(scope='module')
def ver(dht, ks, acl):
    certman = CertManager(dht, ks)
    return Verifier(certman, ks, acl, 7)


def test_localNames(ver, keys):
    h = keys[3][0].getPrincipal()
    names = ver.checkLocalNames(h)
    assert len(names) == 1
    assert names[0] == 'Bob'


@pytest.inlineCallbacks
def test_trusted(ver, keys):
    h = keys[2][0].getPrincipal()
    names, _ = yield ver.checkTrusted(h)
    assert len(names) == 1
    assert names[0] == 'Alice'


@pytest.inlineCallbacks
def test_chain(ver, keys):
    h = keys[9][0].getPrincipal()
    res = yield ver.findChain(h, 1)
    assert res
    h = keys[19][0].getPrincipal()
    res = yield ver.findChain(h, 1)
    assert not res



@pytest.inlineCallbacks
def test_identify(ver, keys):
    h = keys[4][0].getPrincipal()
    names = yield ver.identify(h)
    assert len(names) == 1
    assert names[0] == 'charlie'
