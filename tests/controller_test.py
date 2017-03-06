#!/usr/bin/env python
# -*- coding: utf-8 -*-

from context import p2ppki
from utils import FakeDHT
from p2ppki.localServer import ControlFactory
from twisted.test import proto_helpers
import pytest


@pytest.fixture
def protocol():
    factory = ControlFactory(FakeDHT())
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


def test_hendleGet(protocol, transport):
    transport.clear()  # clear connect message

    protocol.lineReceived('GET too many args')
    assert transport.value() == 'GET usage: GET <key>\r\n'
    transport.clear()

    protocol.lineReceived('GET key4')
    assert transport.value() == 'Found data: [\'a\', 2]\r\n'
    transport.clear()

    protocol.lineReceived('GET key5')
    assert transport.value() == 'No data for key: key5\r\n'


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


def test_handleUnknown(protocol, transport):
    transport.clear()  # clear connect message

    protocol.lineReceived('an unknown command')
    assert transport.value() == 'Unknown command: an'\
                                '\r\nSupported commands: [\'GET\', \'SET\']'\
                                '\r\n'
