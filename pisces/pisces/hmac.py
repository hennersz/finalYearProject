"""This file implements message authentication (HMAC).

A MAC is a message authentication code, which is essentially a fancy hash of
some input text.  The text is sent along with the MAC and the receiver can
verify the text by computing their own MAC and comparing results.  The sender
and receiver share a secret key which is used by HMAC.

HMAC is defined in the informational RFC 2104, which describes a procedure for
authenticating messages using pluggable hash functions.  The user of HMAC must 
choose which hash function to use (e.g. SHA-1 or MD5) and this is designated
by HMAC-SHA or HMAC-MD5.  See the RFC for details.

This module is a revised version of the one written by Barry Warsaw
and included in Andrew Kuchling's crypto package.
"""

from pisces.utils import xor

import struct

class HMAC:
    """Class implementing HMAC as defined in RFC 2104.

    Public Methods:

        __init__(hashmodule)
            Constructor for the class.  hashmodule is a module implementing
            the hashing algorithm to use.  In essence it must provide the
            following interface:

            hashmodule.digest_size
                The length of the hash's output in bytes

            hashmodule.new(key)
                Function which returns a new instance of a hash object,
                initialized to key.  The returned object must have a digest()
                method that returns a string of size hashmodule.digest_size,
                and an update() method that accepts strings to add to the
                digest.

        hash(key, block):
            Produce the HMAC hash for the given block.  Key is the shared
            secret authentication key, as a string.  For best results RFC 2104
            recommends that the length of key should be at least as large as
            the underlying hash's output block size, but this is not
            enforced.

            If the key length is greater than the hash algorithm's basic
            compression function's block size (typically 64 bytes), then it is
            hashed to get the used key value.  If it is less than this block
            size, it is padded by appending enough zero bytes to the key.
    """
    def __init__(self, hashmodule):
        self.hashmodule = hashmodule

    __IPAD = 0x36
    __OPAD = 0x5c

    def hash(self, key, text):
        # L is the byte length of hash outputs.
        # B is the byte length of hash algorithm's basic compression
        # function's block size (64 for most hashes)
        #
        # Sanitize the key.  RFC 2104 recommends key length be at least L and
        # if it is longer than B, it should be hashed and the resulting L
        # bytes will be used as the key
        #
        L = self.hashmodule.digest_size
        B = 64                                    # can't get from module
        keylen = len(key)
        if keylen > B:
            key = self.hashmodule.new(key).digest()
            keylen = len(key)
            assert keylen == L
        elif keylen < B:
            # append enough zeros to get it to length B
            key = key + '\000' * (B - keylen)
        keylen = len(key)
        #
        # Precompute the inner and outer intermediate values
        kipad = xor(key, chr(self.__IPAD) * keylen)
        kopad = xor(key, chr(self.__OPAD) * keylen)
        #
        # perform the inner hashes
        hash = self.hashmodule.new(kipad)
        hash.update(text)
        inner = hash.digest()
        #
        # preform the outer hashes
        hash = self.hashmodule.new(kopad)
        hash.update(inner)
        outer = hash.digest()
        return outer

class HMACSpecializer:
    """Create a faster HMAC for a specific key

    Note: This class behaves like Barry's original HMAC class, but
    preserves the pad state as instance variables rather than local
    variables within a single hash call.
    """

    def __init__(self, hashmodule, key):
        self.hashmodule = hashmodule
        L = self.hashmodule.digest_size
        # XXX what is B?
        B = 64                                    # can't get from module
        keylen = len(key)
        if keylen > B:
            key = self.hashmodule.new(key).digest()
            keylen = len(key)
            assert keylen == L
        elif keylen < B:
            # append enough zeros to get it to length B
            key = key + '\000' * (B - keylen)
        keylen = len(key)
        self.kipad = xor(key, chr(self.IPAD) * keylen)
        self.kopad = xor(key, chr(self.OPAD) * keylen)

    IPAD = 0x36
    OPAD = 0x5c

    def hash(self, text):
        """Produces the HMAC hash for the block text"""
        inner = self.hashmodule.new(self.kipad + text).digest()
        return self.hashmodule.new(self.kopad + inner).digest()

def test():
    from types import StringType
    from Crypto.Util.number import long_to_bytes, bytes_to_long

    # Test data taken from RFC 2104
    testdata = [
        # (key, data, digest)
        (0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0bL,
         'Hi There',
         0x9294727a3638bb1c13f48ef8158bfc9dL),
        ("Jefe",
         "what do ya want for nothing?",
         0x750c783e6ab0b503eaa86e310a5db738L),
        (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL,
         0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDL,
         0x56be34521d144c88dbb8c733f0e8b3f6L),
        ]

    # RFC 2104 uses MD5
    from Crypto.Hash import MD5
    for key, data, digest in testdata:
        if type(key) <> StringType:
            key = long_to_bytes(key)
        if type(data) <> StringType:
            data = long_to_bytes(data)

        h = HMAC(MD5)
        d = h.hash(key, data)
        d = bytes_to_long(d)
        assert d == digest, "pisces.hmac: HMAC digest failed"

    # now check the specializer the same way
    for key, data, digest in testdata:
        if type(key) <> StringType:
            key = long_to_bytes(key)
        if type(data) <> StringType:
            data = long_to_bytes(data)

        h = HMACSpecializer(MD5, key)
        d = h.hash(data)
        d = bytes_to_long(d)
        assert d == digest, "pisces.hmac: HMACSpecializer digest failed"

if __name__ == '__main__':
    test()
