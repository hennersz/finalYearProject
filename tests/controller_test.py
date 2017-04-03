#!/usr/bin/env python
# -*- coding: utf-8 -*-

from context import p2ppki
from utils import FakeDHT
from pisces.spkilib import keystore
from p2ppki.localServer import ControlFactory
from p2ppki.certManager import CertManager
from p2ppki.keyManager import KeyManager
from p2ppki.verifier import Verifier
from twisted.test import proto_helpers
from os import path
import pytest


@pytest.fixture
def protocol():
    dht = FakeDHT()
    keyStore = keystore.KeyStore('./')
    keys = KeyManager(dht, keyStore)
    certs = CertManager(dht, keyStore)
    aclDir = path.join('./', 'acl')
    verifier = Verifier(certs, keyStore, aclDir, 10)
    factory = ControlFactory(FakeDHT(), keys, certs, verifier, keyStore)
    proto = factory.buildProtocol(('127.0.0.1', 0))
    return proto


@pytest.fixture
def transport(protocol):
    tr = proto_helpers.StringTransport()
    protocol.makeConnection(tr)
    return tr


def test_connect(protocol, transport):
    assert transport.value() == 'Connected\r\n'
    transport.clear()


@pytest.mark.xfail
def test_hendleGet(protocol, transport):
    transport.clear()  # clear connect message

    protocol.lineReceived('GET too many args')
    assert transport.value() == 'GET usage: GET <key>\r\n'
    transport.clear()

    protocol.lineReceived('GET key2')
    assert transport.value() == 'Found data: [\'a\', 2]\r\n'
    transport.clear()

    protocol.lineReceived('GET key1')
    assert transport.value() == 'No data for key: key1\r\n'


@pytest.mark.xfail
def test_handleSet(protocol, transport):
    transport.clear()  # clear connect message

    protocol.lineReceived('SET too many arguments')
    assert transport.value() == 'SET usage: SET <key> <value>\r\n'
    transport.clear()

    protocol.lineReceived('SET key value')
    assert transport.value() == 'Setting value value for key key in DHT'\
                                '\r\nSuccess!\r\n'
    transport.clear()

    protocol.lineReceived('SET fail value')
    assert transport.value() == 'Setting value value for key fail in DHT'\
                                '\r\nFaliure :(\r\n'


@pytest.mark.xfail
def test_handleUnknown(protocol, transport):
    transport.clear()  # clear connect message

    protocol.lineReceived('an unknown command')
    assert transport.value() == 'Unknown command: an'\
                                '\r\nSupported commands: [\'GET\', \'SET\']'\
                                '\r\n'
