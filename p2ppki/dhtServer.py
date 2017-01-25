from twisted.python import log
from twisted.internet.defer import inlineCallbacks, returnValue
import json
import sys, time

class DHTServer(object):
    def __init__(self, dht):
        self.dht = dht

    def set(self, key, value, callback=None):
        #callback takes 1 argument - result of set operation
        if callback is None:
            return self.dht.set(key, value)
        else:
            return self.dht.set(key, value).addCallback(callback)

    @inlineCallbacks
    def get(self, key):
        #callback function takes 1 argument - the result of the get operation
        response = yield self.dht.get(key)
        if response is not None:
            returnValue(json.loads(response))
        else:
            returnValue(None)

    
