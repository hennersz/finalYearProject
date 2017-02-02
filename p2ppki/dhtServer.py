from twisted.python import log
from twisted.internet.defer import inlineCallbacks, returnValue
import json
import sys, time

class DHTServer(object):
    def __init__(self, dht):
        self.dht = dht

    @inlineCallbacks
    def set(self, key, value):
        success = yield self.dht.set(key, value)
        returnValue(success)

    @inlineCallbacks
    def get(self, key):
        response = yield self.dht.get(key)
        if response is not None:
            try:
                returnValue(json.loads(response))
            except ValueError:
                returnValue(None)
        else:
            returnValue(None)
