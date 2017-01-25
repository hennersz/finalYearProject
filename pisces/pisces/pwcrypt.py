"""Support library for password-based cryptography

This module supports the use of password-based cryptography for
encryption and message authentication using key derivation
functions.  This module is based on recommendations in PKCS 5 v2.0:
Password-Based Crypotgraphy, RSA Laboratories, March 25, 1999.
http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html
"""

from pisces import cryptrand, hmac
from pisces.utils import xor
from Crypto.Hash import SHA

import struct
import string

class KeyDerivationFactory:
    """Instances of this class will create keys from passwords

    The design is explained carefully in PKCS 5.  This implementation
    uses HMAC plus a hash function as its pseudorandom function; the
    default hash is SHA.

    Each instance of the scheme will generate keys with the same size
    salt and the same pseudorandom function.

    WARNING: It is not very practical to use Python for this
    operation; it is merely convenient.  The key derivation process
    should take a long time, to thwart an attacker who attempts a
    dictionary attack on the password.  But it can't take so long that
    the user grows impatient waiting for the key to be generated.  The
    attacker could implement her brute force search in optimized C,
    which would be much faster than this implementation.  So the
    Python version provides less security-for-the-wait that a C
    version would.
    """

    ITERATIONS = 1000
    
    def __init__(self, keylen, saltlen, iterations=None, hash=None,
                 labels=None):
        """KeyDerivationFactory(keylen, saltlen, [iters, hash, labels])
        
        Arguments:
        keylen -- the size of the output key in bytes
        saltlen -- the size of the salt in bytes
        (rest of arguments are optional)
        iters -- the number of iterations to use (default 1000)
        hash -- theh hash function to use (default SHA)
        labels -- a sequence of labels

        Labels are an optional feature.  If several keys with the same
        generation parameters are going to be created, the salt should
        contain some text that identifies this use of the key.  These
        are the labels.  The input argument is a sequence containing
        valid labels.  When createKey is called, it will check to see
        if the label used is valid.
        """
        self.saltlen = saltlen
        self.iterations = iterations or self.ITERATIONS
        self.keylen = keylen
        self.hash = hash or SHA
        self.labels = labels or []
        # XXX should check that keylen is <= (2**32 - 1) * hlen,
        # where hlen is the size of the hash used by the PRF.
        # but it is unlikely that we'll need a key that big...

        # computed how many blocks of prf output we need
        self.l, self.r = divmod(self.keylen,
                                self.hash.digest_size)
        if self.r != 0:
            # always round up
            self.l = self.l + 1

        # figure out the hash name
        name = self.hash.__name__
        i = string.rfind(name, '.')
        if i == -1:
            self.name = name
        else:
            self.name = name[i+1:]

    def createKey(self, password, label=''):
        """Create a key from the password and optional label

        Return value is a tuple containing:
        salt, iteration count, hash name, and key
        """
        if label or self.labels:
            if not label in self.labels:
                raise ValueError, "invalid label"
        salt = label + cryptrand.random(self.saltlen)
        return self._makeKey(password, salt)

    def recreateKey(self, password, salt):
        salt2, iters, hash, key = self._makeKey(password, salt)
        return key

    def _makeKey(self, password, salt):
        h = hmac.HMACSpecializer(self.hash, password)
        blocks = []
        for i in range(self.l):
            blocks.append(self._f(h, salt, self.iterations, i))
        blocks[-1] = blocks[-1][:self.r]
        return salt, self.iterations, self.name, string.join(blocks, '')

    def _f(self, prf, s, c, i):
        """The F function for PBKDF2 from PKCS 5"""
        istr = struct.pack('>i', i)[0]
        u = prf.hash(s + istr)
        for j in range(c):
            u = xor(u, prf.hash(u))
        return u

if __name__ == "__main__":
    import sys

    kdf = KeyDerivationFactory(8, 8)
    import time
    t0 = time.time()
    key = kdf.createKey(sys.argv[1])
    t1 = time.time()
    print t1 - t0
