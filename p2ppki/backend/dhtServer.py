#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet.defer import inlineCallbacks, returnValue
import base64
import json


class DHTServer(object):
    def __init__(self, dht):
        self.dht = dht

    @inlineCallbacks
    def set(self, key, value):
        b64 = base64.standard_b64encode(value)
        success = yield self.dht.set(key, b64)
        returnValue(success)

    @inlineCallbacks
    def get(self, key):
        response = yield self.dht.get(key)

        if response is None:
            returnValue(None)

        try:
            l = json.loads(response)
        except ValueError:
            returnValue(None)

        decodedItems = []
        for item in l:
            try:
                d = base64.standard_b64decode(item)
                decodedItems.append(d)
            except TypeError:
                continue

        if decodedItems == []:
            returnValue(None)

        returnValue(decodedItems)
