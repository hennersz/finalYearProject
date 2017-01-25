"""Miscellaneous helper functions for the pisces package"""

import operator
import string

def loadModule(name):
    """Load a module, possibly from a package, and return it"""
    parts = string.split(name, '.')[1:]
    base = __import__(name)
    for part in parts:
        base = getattr(base, part)
    return base

def xor(s1, s2):
    """XOR two strings"""
    return string.join(map(chr,
                           map(operator.xor,
                               map(ord, s1),
                               map(ord, s2))), '')

def test():
    nil = "\000"
    s1 = "a" * 100
    assert xor(s1, s1) == nil * len(s1), "pisces.utils: bad xor"
    assert xor(s1, nil * len(s1)) == s1, "pisces.utils: bad xor"

    s2 = '\001i\373\221<\246I\030YI\235\223>"\213\222\257\213'
    s3 = '\006>]Sf\267\255\021\246\345yw2\036\367\346;F'
    s4 = '\007W\246\302Z\021\344\011\377\254\344\344\014<|t\224\315'
    assert xor(s2, s3) == s4, "pisces.utils: bad xor"
    assert xor(s3, s4) == s2, "pisces.utils: bad xor"
    assert xor(s4, s2) == s3, "pisces.utils: bad xor"
    assert xor(s3, s2) == s4, "pisces.utils: bad xor"
    assert xor(s4, s3) == s2, "pisces.utils: bad xor"
    assert xor(s2, s4) == s3, "pisces.utils: bad xor"

if __name__ == "__main__":
    test()
    
