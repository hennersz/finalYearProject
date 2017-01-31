from twisted.python import log
from twisted.internet.defer import inlineCallbacks, returnValue
import json
import sys, time

class DHTServer(object):
    def __init__(self, dht):
        self.dht = dht

    def set(self, key, value):
        return self.dht.set(key, value)

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
