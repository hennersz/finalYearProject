#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
.. module:: dhtServer
    :platform: UNIX
    :synopsis: Provides a wrapper around a key value storage object to encode and decode data.

.. moduleauthor:: Henry Mortimer <henry@morti.net>

"""

from twisted.internet.defer import inlineCallbacks, returnValue
import base64
import json


class DHTServer(object):
    """Provides a wrapper around a key value storage object
    to encode and decode data.
    Designed to work with a kademlia dht and list storage
    so because data must be transported as strings 
    data is encoded as base 64 before storage 
    and retrieves lists encoded as json strings
    """

    def __init__(self, dht):
        """Initialse class

        Args:
            dht: Key value storage object with get and set methods
            get must return json string
        """
        self.dht = dht

    @inlineCallbacks
    def set(self, key, value):
        """Sets values in the dht.
        encodes data as base 64 because value is 
        expected to be a binary string which doesnt 
        play well with json encoding.

        Args:
            key: String

            value: anything that can be converted to 
            base 64.

        Returns:
            Bool. If setting was successful
        """

        b64 = base64.standard_b64encode(value)
        success = yield self.dht.set(key, b64)
        returnValue(success)

    @inlineCallbacks
    def get(self, key):
        """Retrieves data from dht for given key and
        parses it into list

        Args:
            key: String

        Returns:
            List or None: List of base64 decoded items from dht or None
            if nothing found or nothing parsed correctly.
        """

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
