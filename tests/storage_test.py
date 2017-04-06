#!/usr/bin/env python
# -*- coding: utf-8 -*-

from p2ppki.backend.storage import ListStorage
import mock
import json


def test_singleInsert():
    store = ListStorage()
    store.__setitem__('a key', 'a value')
    data = json.loads(store.get('a key'))
    assert len(data) == 1
    assert data[0] == 'a value'


def test_multiInsert():
    store = ListStorage()
    store.__setitem__('a key', 'a value')
    store.__setitem__('a key', 'b value')
    data = json.loads(store.get('a key'))
    assert len(data) == 2
    assert data[0] == 'a value'
    assert data[1] == 'b value'


@mock.patch('p2ppki.backend.storage.time')
def test_overwrite(mock_time):
    store = ListStorage()

    mock_time.time.return_value = 5
    store.__setitem__('a key', 'a value')
    assert store.data['a key'][0][0] == 5

    mock_time.time.return_value = 10
    store.__setitem__('a key', 'a value')
    assert store.data['a key'][0][0] == 10


def test_iterator():
    store = ListStorage()

    store.__setitem__('a key', 'a value')
    store.__setitem__('a key', 'b value')
    store.__setitem__('b key', 'a value')

    values = list(store.iteritems())
    assert ('a key', 'a value') in values
    assert ('a key', 'b value') in values
    assert ('b key', 'a value') in values


@mock.patch('p2ppki.backend.storage.time')
def test_iterItemsOlderThan(mock_time):
    store = ListStorage()

    mock_time.time.return_value = 1
    store.__setitem__('a key', 'a value')

    mock_time.time.return_value = 5
    store.__setitem__('b key', 'a value')

    mock_time.time.return_value = 10
    store.__setitem__('c key', 'a value')

    mock_time.time.return_value = 20
    values = list(store.iteritemsOlderThan(20))
    assert not values

    values = list(store.iteritemsOlderThan(18))
    assert len(values) == 1
    assert ('a key', 'a value') in values

    values = list(store.iteritemsOlderThan(14))
    assert len(values) == 2
    assert ('a key', 'a value') in values
    assert ('b key', 'a value') in values

    values = list(store.iteritemsOlderThan(9))
    assert len(values) == 3
    assert ('a key', 'a value') in values
    assert ('b key', 'a value') in values
    assert ('c key', 'a value') in values
