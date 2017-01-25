"""A Yarrow-160 cryptographic pseudorandom number generator for Unix

This implemenation is based on a design described in the following paper: 
John Kelsey, Bruce Schneier, and Niels Ferguson.  "Yarrow-160: Notes on
the Design and Analysis of the Yarrow Cryptographic Pseudorandom
Number Generator."  http://www.counterpane.com/yarrow.html

Counterpane also provides an implementation, Yarrow 0.8.71, for
Windows developed by Ari Benbasat.  The implementation appears to
diverge from the design document in numerous respects, e.g. entropy
estimation and generating pseudorandom ouputs from the pool values.

Implementation notes:

The Yarrow design paper uses 3DES in counter mode.  Counter mode is
fairly unusual.  It is not implemented in the Python Crypto Toolkit or
OpenSSL; it only merits a one-paragraph mention in Applied
Cryptography.  Since I don't want to write C code to extend PCT, I'll
try another option.  If I understand correctly, I can used 3DES in ECB
mode; encrypt the counter; then, XOR the counter with the plaintext.
We'll see if this makes sense.
"""

import os, sys
import threading
import string
import struct
import time
import zlib
import sha # get the Python std. module
try:
    from crypto.zap import zap
except ImportError:
    print "Warning: Could not import zap module"
    def zap(x): pass

# should probably be able to use mxCrypto too
from Crypto.Cipher import DES3
from Crypto.Util.number import bytes_to_long, long_to_bytes

class EntropySource:
    """Track the amout of entropy from a single source

    The design document proposes three different methods for Entropy
    Estimation.  The design is conservative, so it estimates the
    entropy using all three methods and returns the lowest result.

    The Benbasat implementation uses two estimates, one provided by
    the programming who supplies the input and another generator from
    zlib.  The same approach is taken here.
    """
    def __init__(self):
        self.input = ''
	self.reset()

    def addInput(self, buf, estbits):
        """Update the estimate to account for buf"""
	self.input = self.input + buf
	self.estBits = self.estBits + estbits
	# Need a more efficient way to deal with this!
	self.zEstBits = len(zlib.compress(self.input)) * 4

    def getEntropy(self):
        """Get the minimum estimated entropy"""
	return min(self.estBits, self.zEstBits)

    def reset(self):
        """Reset the estimates to zero"""
	self.estBits = 0   # the user's estimate
	self.zEstBits = 0  # the zlib estimate
        zap(self.input)
	self.input = ''

class EntropyPool:
    """Collects samples from entropy sources.

    The design document describes an Entropy Accumulator, which
    collects samples from entropy sources and puts them into two
    pools.  This class implements the pools.

    A pool contains the running hash of all inputs fed into it since
    the accumulate method was called.  The accumulate method is called
    by the Yarrow class during reseed operations.

    The pool keeps estimates about the entropy of each individual
    source, although the digest is over all sources.  Each souce must
    be initialized by calling addSouce and passing the source's name.
    The instance variable sources maps from names to EntropySource
    instances.

    The constructor takes two arguments, the threshold and a count.  A
    pool is ready to be used when at least count of its source have an
    entropy greater than or equal to threshold.  The isReady method
    returns true when this condition is met.

    EntropyPool instances are thread safe, because a typical use is to
    have multiple threads adding entropy to the pool.
    """
    MAX_ENTROPY = 160  # hash size

    def __init__(self, threshold, count):
	self.hash = sha.new()
        self.threshold = threshold
        self.count = count
	self.sources = {}
        self.lock = threading.Lock()

    def addSource(self, name):
        """Prepare pool for accepting input from source named name"""
	if self.sources.has_key(name):
	    raise KeyError, "source with name '%s' already exists" % name
	self.sources[name] = EntropySource()

    def addInput(self, source, buf, estbits):
        """Update pool hash with buf containing estbits estimated entropy

        If the source was not initialized via addSource, this method
        will raise a KeyError.
        """
        self.lock.acquire()
	self.hash.update(buf)
	self.sources[source].addInput(buf, estbits)
        self.lock.release()

    def isReady(self):
        """Returns true if there is enough entropy in the pool.

        Enough is defined by the threshold and count arguments to the
        constructor."""
        self.lock.acquire()
        entropies = map(lambda x:x.getEntropy(),
                        self.sources.values())
        entropies.sort()
        self.lock.release()

        # there must be at least self.count sources with an entropy
        # above the threshold.  the list gets sorted in ascending
        # order, so the end contains the highest vaues.
        try:
            entropy = entropies[-self.count]
        except IndexError:
            return 0
        if entropy < self.threshold:
            return 0
        return 1

    def accumulate(self):
        """Return the current pool digest and reset"""
        self.lock.acquire()
        for src in self.sources.values():
            src.reset()
        digest = self.hash.digest()
        self.hash = sha.new()
        self.lock.release()
        return digest

class Yarrow:
    """Generates pseudorandom outputs and provides reseed control.

    The Yarrow class generates random data and managed the fast and
    slow entropy pools for seeding the PRNG.  These functions are
    described as three seperate entities in the design document:
    "generating pseudorandom outputs," "reseed mechanism", and "reseed
    control."

    The main API for this class is three methods:
    getOutput(size) -- return size bytes of random output
    addSource(name) -- initialize a new source
    addInput(source, input, estbits) -- add new entropy from source

    A client may also call forceReseed and allowReseed to cause a
    reseed to occur.  However, reseed control is implemented
    internally and should occur regularly even if the client does not
    call these methods.

    The reseed methods take an optional ticks argument that
    affects how long the reseed will take.  The class implements a
    default number, which should be sufficient, but the user can
    override it.

    The Yarrow class is not threadsafe.

    XXX Need to provide some more documentation of the internal
    structure.
    """
    RESEED_TIME = 100     # called Pt in the paper
    KEY_SIZE = 2 * 8 * 8   # 2-key triple DES
    BLOCK_SIZE = 8
    HASH_SIZE = EntropyPool.MAX_ENTROPY
    GATE_LIMIT = 10
    RESEED_INPUT_LIMIT = 100

    # entropy threshholds for entropy pools
    FAST_THRESHOLD = 100
    SLOW_THRESHOLD = 160

    def __init__(self):
	# initialization based on the PRNG state structure
	self.slow = EntropyPool(self.SLOW_THRESHOLD, 2)
	self.fast = EntropyPool(self.FAST_THRESHOLD, 1)
        self.fast.addSource('slow')
	self.whichPool = 0
        # XXX need to deal with startup correctly.  should probably
        # wait for enough input to do a reseed. 
	self.key = '0' * (self.KEY_SIZE / 8)
	self.counter = 0L
        self.gateCounter = 0
        self.inputCounter = 0
	# XXX need to implement counter mode?
	self.cipher = DES3.new(self.key, DES3.ECB)

    def _nextBlock(self):
        self.gateCounter = self.gateCounter + 1
        if self.gateCounter == self.GATE_LIMIT:
            # Now we must either reseed or generator a new key
            self.gateCounter = 0
            if self.allowReseed():
                return self._cipher()
            
            # need 16 key bytes, or three cipher outputs
            self.key = self._cipher() + self._cipher()
        return self._cipher()

    def _cipher(self):
        self.counter = self.counter + 1
        counter = pad64(long_to_bytes(self.counter))
        return self.cipher.encrypt(counter)

    def getOutput(self, num):
	"""Return num of random data"""
        q, m = divmod(num, self.BLOCK_SIZE)
        if m:
            q = q + 1
        blocks = []
        for i in range(q):
            blocks.append(self._nextBlock())
        if m:
            blocks[-1] = blocks[-1][:m]
        return string.join(blocks, '')

    def stretch(self, buf, need):
        """Stretch the input buf to need bytes"""
        # XXX not implemented
	pass

    def addSource(self, sourceName):
        """Initialize a new entropy source"""
	self.slow.addSource(sourceName)
	self.fast.addSource(sourceName)

    def addInput(self, source, input, estbits):
	"""Add input string to specified pool, estimating estbits of entropy"""
	# alternate between fast and slow pools
	if self.whichPool:
	    self.slow.addInput(source, input, estbits)
	    self.whichPool = 0
	else:
	    self.fast.addInput(source, input, estbits)
	    self.whichPool = 1
        if self.inputCounter == self.RESEED_INPUT_LIMIT:
            self.allowReseed()
            self.inputCounter = 0
        else:
            self.inputCounter = self.inputCounter + 1

    def forceReseed(self, ticks=None):
        """Force a reseed of the PRNG"""
        while not self.allowReseed(ticks):
            # just wait for entropy to be available
            time.sleep(0.5)

    def allowReseed(self, ticks=None):
	"""Perform a reseed of the PRNG in enough entropy is available"""
        if self.slow.isReady():
            self.slowIntoFast()
            self.reseed(ticks)
            return 1
        elif self.fast.isReady():
            self.reseed(ticks)
            return 1

    def reseed(self, ticks=None):
        """Use entropy to generate new seed for PRNG"""
        if ticks is None:
            ticks = self.RESEED_TIME
        v0 = self.fast.accumulate()
        v_i = hash(v0 + v0 + chr(0) * 4)
	# now compute Vp_t
	for i in range(1, ticks):
            # XXX how many bits should I extend i to?
	    istr = struct.pack('i', i)[0]
            prev = v_i
	    v_i = hash(v_i + v0 + istr)
            zap(prev)
        zap(self.key)
	self.key = hash_ex(hash(v_i + self.key), self.KEY_SIZE)
	self.cipher = DES3.new(self.key, DES3.ECB)
	self.counter = bytes_to_long(self.cipher.encrypt('\000' * 8))

    def slowIntoFast(self):
        """Feed hash of slow pool into fast pool, then reseed"""
        buf = self.slow.accumulate()
        self.fast.addInput('slow', buf, self.HASH_SIZE)

class ThreadedYarrow(Yarrow):
    super_init = Yarrow.__init__
    super_getOutput = Yarrow.getOutput
    super_addInput = Yarrow.addInput
    super_allowReseed = Yarrow.allowReseed
    
    def __init__(self):
        self.super_init()
        self.lock = threading.RLock()

    # XXX is it sufficient to lock these two calls?

    def addInput(self, source, input, estbits):
        self.lock.acquire()
        try:
            self.super_addInput(source, input, estbits)
        finally:
            self.lock.release()

    def getOutput(self, size):
        self.lock.acquire()
        try:
            return self.super_getOutput(size)
        finally:
            self.lock.release()

    def allowReseed(self, ticks=None):
        self.lock.acquire()
        try:
            return self.super_allowReseed(self, ticks)
        finally:
            self.lock.release()
        

def pad64(s):
    """Pad a string to 64 bits"""
    if len(s) > 8:
        raise ValueError, "can not pad string longer than 64 bits"
    return '\000' * (8 - len(s)) + s

def hash(x):
    """Compute the SHA digest of input x"""
    return sha.new(x).digest()
	
def hash_ex(m, k):
    """Extend input m to k bytes via hashing"""
    # hash_ex called h' in the paper
    # XXX What to do if k is not multiple of eight?
    need = k - len(m) * 8
    s = [m] 
    while need > 0:
	next_s = hash(string.join(s, ''))
	s.append(next_s)
	need = need - len(next_s) * 8
    return string.join(s, '')[:k/8]

class EntropyGatherer(threading.Thread):
    """Run a bunch of system utilities periodically

    One gatherer should be created for each collection of programs
    that should be run at the same period.
    """
    super_init = threading.Thread.__init__
    
    def __init__(self, jobs, yarrow):
        self.super_init()
        self.setDaemon(1)
        self.jobs = {}
        for cmd, period, entropy in jobs:
            self.jobs[cmd] = entropy
            yarrow.addSource(cmd)
        self.period = period
        self.yarrow = yarrow
        
    def run(self):
        while 1:
            next = time.time() + self.period
            for cmd, entropy in self.jobs.items():
                buf = os.popen(cmd).read()
                self.yarrow.addInput(cmd, buf, entropy)
            delta = next - time.time()
            if delta > 0:
                time.sleep(delta)

