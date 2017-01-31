#!/usr/bin/env python
# -*- coding: utf-8 -*-

from context import p2ppki
from p2ppki.dhtServer import DHTServer
from twisted.internet import defer, reactor
from twisted.internet.defer import inlineCallbacks
import mock
import json
import pytest

class FakeDHT(object):
    def __init__(self):
        self.data = {
                'key 1': None,
                'key 2': json.dumps(['a', 2]),
                'key 3': 'a string that is not json'
                }

    def set(self, key, value):
        return

    def get(self, key):
        d = defer.Deferred()
        reactor.callLater(0, d.callback, self.data[key])
        return d
        
@pytest.fixture(scope="module")
def runReactor(request):
    yield reactor.run()
    reactor.stop()

@mock.patch.object(FakeDHT, 'set')
def test_set(mock_set):
    dht = DHTServer(FakeDHT())

    dht.set('a key', 'a value')

    #check set is called
    mock_set.assert_called_with('a key', 'a value')
    #check specific instance of dht was called
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
