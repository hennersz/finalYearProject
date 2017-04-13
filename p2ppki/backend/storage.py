#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
.. module:: storage
    :platform: UNIX
    :synopsis: Creates list storage that allows multiple values per key.

.. moduleauthor:: Henry Mortimer <henry@morti.net>

"""

from kademlia.storage import IStorage
from zope.interface import implements

import json
import time
from itertools import imap
from itertools import takewhile
import operator
from collections import OrderedDict


class ListStorage(object):
    """Implements a storage object for 
    a kademlia dht.
    """

    implements(IStorage)

    def __init__(self):
        """Creates ordered dict.
        """
        self.data = OrderedDict()

    def __setitem__(self, key, value):
        """Stores an item in the dict. If the
        item already exits just update the time
        it was inserted.

        Args:
            key: String

            value: String

        Returns:
            None
        """

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
        """Get all values from dict

        Args:
            key: String

        Returns:
            String. A JSON encoded list.
        """
        result = []
        for item in self.data[key]:
            result.append(item[1])
        return json.dumps(result)

    def get(self, key, default=None):
        """Gets item from dict or
        returns default value if it
        doesn't exist.

        Args:
            key: String

            default: object.

        Return:
            String. JSON encoded list.
        """

        if key in self.data:
            return self[key]
        return default

    def iteritemsOlderThan(self, secondsOld):
        """Gets all items older than
        seconds old and creates an iterator.

        Args:
            secondsOld: Int.

        Returns:
            Iterator.
        """

        minBirthday = time.time() - secondsOld
        zipped = self._tripleIterable()
        matches = takewhile(lambda r: minBirthday >= r[1], zipped)
        return imap(operator.itemgetter(0, 2), matches)

    def _tripleIterable(self):
        """Creates iterable of tuples contining
        key value and time inserted from the dict

        Returns:
            Iterator.
        """

        items = []
        for key in self.data:
            values = self.data[key]
            for value in values:
                items.append((key, value[0], value[1]))
        return iter(items)

    def iteritems(self):
        """Creates iterator of tuples
        containing keys and values from
        dict.

        Returns:
            Iterator.
        """

        items = []
        for key in self.data:
            values = self.data[key]
            for value in values:
                items.append((key, value[1]))
        return iter(items)
