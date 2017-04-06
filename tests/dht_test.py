#!/usr/bin/env python
# -*- coding: utf-8 -*-

from helpers import FakeDHT
from p2ppki.backend.dhtServer import DHTServer
import mock
import pytest
import base64


@mock.patch.object(FakeDHT, 'set')
def test_set(mock_set):
    dht = DHTServer(FakeDHT())

    b64 = base64.standard_b64encode('a value')
    dht.set('a key', 'a value')

    # check set is called
    mock_set.assert_called_with('a key', b64)
    # check specific instance of dht was called
    dht.dht.set.assert_called_with('a key', b64)


@pytest.inlineCallbacks
def test_get():
    dht = DHTServer(FakeDHT())
    res = yield dht.get('key1')
    assert res is None
    res = yield dht.get('key2')
    assert res == ['123', 'abc']
    res = yield dht.get('key3')
    assert res is None
    res = yield dht.get('key4')
    assert res is None
