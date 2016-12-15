#!/usr/bin/env python

from twisted.internet import reactor
from twisted.python import log
from kademlia.network import Server
from kademlia.storage import ForgetfulStorage
import sys, time

class ListStorage(ForgetfulStorage):
    def __setitem__(self, key, value):
        if key in self.data:
            self.data[key].append((time.time(), value))
	else:
            self.data[key] = [value]	
    def get(self, key, default=None):
        if key in self.data:
            return self[key]
        return default

    def __getitem__(self, key):
        result = []
        for item in self.data[key]:
            result.append(item[1])
        return str(result)


def quit(result):
    print "Key result: ", result
    reactor.stop()

def get(result, server):
    return server.get("a key").addCallback(quit)

def done(found, server):
    log.msg("Found nodes: %s" % found)
    return server.set("a key", "a value").addCallback(get, server)

if(__name__ == "__main__"):
    log.startLogging(sys.stdout)
    server = Server(storage=ListStorage())

    server.listen(8468)
    server.bootstrap([("192.168.62.128", 8468)]).addCallback(done, server)

    reactor.run()
