#!/usr/bin/env python
# -*- coding: utf-8 -*-

from context import p2ppki
from p2ppki.storage import ListStorage
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
