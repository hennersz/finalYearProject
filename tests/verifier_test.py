#!/usr/bin/env python
# -*- coding: utf-8 -*-

from context import p2ppki
from utils import FakeDHT, genNKeys,  saveKey,\
                  makeNameCert, makeTrustCert, makeCACert, initACL
from pisces.spkilib import keystore
from p2ppki.certManager import CertManager
from p2ppki.keyManager import KeyManager
from p2ppki.verifier import Verifier

import pytest


@pytest.fixture(scope='module')
def keys():
    return genNKeys(5)


@pytest.fixture(scope='module')
def ks(keys):
    keyStore = keystore.KeyStore('./')
    mainKey = keys[0]
    saveKey(mainKey[0], mainKey[1], keyStore)
    keyStore.setDefaultKey(mainKey[0].getPrincipal())
    return keyStore


@pytest.fixture(scope='module')
def
