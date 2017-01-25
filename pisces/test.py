#! /usr/bin/env python

"""Minimal test harness for pisces package

Every test should raise AssertionError if it fails.  The script prints
"test okay" when it finishes, which would be misleading if a test
failed but didn't raise an exception.
"""

from pisces.spkilib import spki
from pisces.utils import loadModule

import fileinput
import string

class TestPasswordEncrypted(spki.PasswordEncrypted):
    """A variant of PasswordEncrypted object that has a static password

    This class is for testing purposes only.  It allows a key to be
    encrypted with a static password and decrypted by anyone.  This is
    not at all secure, but useful for distributing a test key that
    should work on any system.
    """

    password = "Spanish Inquisition"

    def _checkPassword(self, pw):
        return self.password

def test_pwcrypt():
    from pisces import pwcrypt
    password = "Spanish Inquisition"
    for line in fileinput.input('test/pwcrypt_input'):
        salt, iters, hashname, key = eval(line)
        hash = loadModule('Crypto.Hash.%s' % hashname)
        kdf = pwcrypt.KeyDerivationFactory(len(key), len(salt), iters,
                                           hash=hash)
        regen = kdf.recreateKey(password, salt)
        assert key == regen, \
               "pisces.pwcrypt: failed to recreate key, %s" % line

def _cleanup(elts):
    """Decode b64 encoding uses in test/sexps.py"""
    from pisces.spkilib import sexp
    clean = []
    for elt in elts:
        if not sexp.atom(elt):
            elt = _cleanup(elt)
        if elt[0] == '|':
            elt = sexp.b64_to_str(elt)
        clean.append(elt)
    return clean

def test_spkilib():
    """Test based on spki examples draft

    The base64 encoded s-expressions form the draft are include in
    test/sexps.
    """
    from pisces.spkilib import sexp
    
    chunks = []
    chunk = []
    for line in fileinput.input('test/sexps'):
        if line.strip():
            chunk.append(line)
        else:
            chunks.append("\n".join(chunk))
            chunk = []
    chunks.append("\n".join(chunk))
    consts = eval(open("test/sexps.py").read())
    assert len(consts) == len(chunks), \
           "pisces.spkilib: error loading spkilib tests"
    for i in range(len(consts)):
        chunk = chunks[i]
        const = consts[i]
        sx1 = sexp.parse(chunk)
        sx2 = sexp.construct_seq(_cleanup(const))
        assert sx1 == sx2, \
               "pisces.spkilib: #%d: parsed s-exp differs " \
               "from constructed s-exp" % i
        enc1 = sx1.encode_canonical()
        enc2 = sx1.encode_base64()
        sx11 = sexp.parse(enc1)
        sx12 = sexp.parse(enc2)
        assert sx11 == sx12, "pisces.spkilib: s-exp parsing failed"
        assert sx11 == sx1, "pisces.spkilib: s-exp parsing failed"
        buf = str(sx1)
        if '\n' in buf:
            continue # parseText doesn't handle multi-line base64 data
        sx3 = sexp.parseText(buf)
        assert sx1 == sx3, "pisces.spkilib: parseText failed"

# The following modules all define test functions
modules = ('pisces.algid', 'pisces.hmac', 'pisces.utils', 'pisces.pkcs1')
#modules = ('pisces.algid', 'pisces.hmac', 'pisces.utils') # TODO: PKCSL needs some work

def test_modules1():
    """Test standard modules that have internal test functions defined"""
    for name in modules:
    	print "MODULES1: Testing " + name
        mod = loadModule(name)
        test = getattr(mod, 'test')
        test()
        print "MODULES1: Done test on " + name

def test_modules2():
    """Test modules using test cases in this script"""
    print "\n\nMODULES2: Testing PWCrypt"
    test_pwcrypt()
    print "MODULES2: Testing SPKILib"
    test_spkilib()

def main():
    test_modules1()
    print "MODULE 1 TESTS COMPLETE"
    test_modules2()
    print "MODULE 2 TESTS COMPLETE"
    print "\n\nALL TESTS COMPLETE"

if __name__ == "__main__":
    main()
    
