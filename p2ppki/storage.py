from kademlia.storage import IStorage
from zope.interface import implements

import json
import time
from itertools import imap
from itertools import takewhile
import operator
from collections import OrderedDict

class ListStorage(object):
    implements(IStorage)

    def __init__(self):
        self.data = OrderedDict()

    def __setitem__(self, key, value):
        if key in self.data:
            for item in self.data[key]:
                if item[1] == value:
                    index = self.data[key].index(item)
                    self.data[key][index] = (time.time(), item[1])
                    return
            self.data[key].append((time.time(), value))

        else:
            self.data[key] = [(time.time(), value)]	

    def __getitem__(self, key):
        result = []
        for item in self.data[key]:
            result.append(item[1])
        return json.dumps(result)
    
    def get(self, key, default=None):
        if key in self.data:
            return self[key]
        return default

    def iteritemsOlderThan(self, secondsOld):
        minBirthday = time.time() - secondsOld
        zipped = self._tripleIterable()
        matches = takewhile(lambda r: minBirthday >= r[1], zipped)
        return imap(operator.itemgetter(0, 2), matches)
        
    def _tripleIterable(self):
        items = []
        for key in self.data:
            values = self.data[key]
            for value in values:
                items.append(key, value[0], value[1])
        return iter(items)

    def iteritems(self):
        items = []
        for key in self.data:
            values = self.data[key]
            for value in values:
                items.append(key, value[1])
        return iter(items)
