#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet import defer
import json


class FakeDHT(object):
    def __init__(self):
        self.data = {
                # No data
                'key1': None,
                # Data to be parsed by dhtServer
                'key2': ['a', 2],
                }

    def set(self, key, value):
        """Imitates kademlia DHT server set function

        Args:
            key (string): The key to store

            value (string): The value to be stored

        Returns:
            Deffered Boolean. Will always return True unless the key is 'fail'
        """

        # defer.succeed will return instantly and doesn't
        # need to touch rector event loop
        if key == 'fail':
            return defer.succeed(False)
        else:
            return defer.succeed(True)

    def get(self, key):
        """Imitates kademlia DHT server get function

        Args:
            key (string): The key to search for

        Returns:
            Array or None: Returns an array of values for the key
            or None if there is no data for the key
        """
        # defer.succeed will return instantly and
        # doenst need to touch rector event loop
        return defer.succeed(self.data[key])
