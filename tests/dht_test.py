#!/usr/bin/env python
# -*- coding: utf-8 -*-

from context import p2ppki
from utils import FakeDHT
from p2ppki.dhtServer import DHTServer
import mock
import pytest


@mock.patch.object(FakeDHT, 'set')
def test_set(mock_set):
    dht = DHTServer(FakeDHT())

    dht.set('a key', 'a value')

    # check set is called
    mock_set.assert_called_with('a key', 'a value')
    # check specific instance of dht was called
    dht.dht.set.assert_called_with('a key', 'a value')


@pytest.inlineCallbacks
def test_get():
    dht = DHTServer(FakeDHT())
    res = yield dht.get('key 1')
    assert res is None
    res = yield dht.get('key 2')
    assert res == ['a', 2]
    res = yield dht.get('key 3')
    assert res is None
