"""Support routines for SPKI-style S-expressions

The SPKI S-expression format is documented in drafts available from:
    http://www.clark.net/pub/cme/html/spki.html
An experimental RFC is expected sometime in the future.  The current
definition of a canonical S-expression is:

   We define a canonical S-expression as containing binary byte strings,
   each with a given length, and punctuation "()[]" for forming lists.
   The length of a byte string is a non-negative ASCII decimal number,
   with no unnecessary leading "0" digits, terminated by ":".  We
   further require that there be no empty lists and that the first list
   element be a byte string (as defined below).  This form is a unique
   representation of an S-expression and is used as the input to all
   hash and signature functions.  If canonical S-expressions need to be
   transmitted over a 7-bit channel, there is a form defined for base64
   encoding them.

S-expressions may also be represented by advanced S-expression form.
Advanced form is basically a visual form more suitable for
reading and manipulation by people.

This module defines a number of public functions for manipulating
them, and a collection of helper functions that are used by
spkilib.spki to create S-expressions for standard SPKI objects.

Public functions:
    
parse -- convert an S-expression in canonical form, either binary or
    base64 encoded, into an SExp object.  Can raise ParseError.
    
parseText -- convert the advanced form of an S-expression to
    an SExp object.  Warning: Will produce invalid output for invalid
    input. 

construct -- build an SExp from a Python sequence object containing
    a string for each element in the S-expression.
    
object_to_sexp -- deprecated.  Convert a SPKI object into an S-exp.
    Most objects can be convert to S-expressions by calling their sexp
    method.

Public classes:

SExp -- an object represented a parsed S-expression.  It has two
    methods for creating correctly encoded output:
    encode_canonical -- the canonical form
    encode_base64 -- the canonical form wrapped in base64
    __str__ -- generate the advanced form
    Also behaves like a Python sequence

ParseError -- Exception raised when the parse function encounters
    invalid input.  The exception has three attributes:
    exp -- the token expected
    got -- the token found
    ref -- the string being parsed (can be None)
"""

import string
from types import StringType
import re
from binascii import a2b_base64, b2a_base64
from UserList import UserList

# a few simple helper routines

def atom(elt):
    return type(elt) == StringType

def printable(s):
    if not s: # XXX why?
	return 1
    n = ord(min(s))
    x = ord(max(s))
    if n >= 32 and x <= 126:
	return 1
    return 0

def str_to_b64(c):
    lines = []
    for i in range(0, len(c), 54):
	lines.append(b2a_base64(c[i:i+54]))
    lines[-1] = lines[-1][:-1]
    if len(lines) == 1:
	return lines[0]
    else:
	return string.join(lines)

def b64_to_str(c):
    return a2b_base64(c)

def parse(buf):
    """Return an SExp instance representing the canonical s-exp buf"""
    return SExp(canon=buf)

def construct(*elts):
    """Return an SExp constructed from a Python sequence"""
    conv = []
    for elt in elts:
	if isinstance(elt, SExp):
	    conv.append(elt)
	elif atom(elt):
            conv.append(elt)
        else:
            conv.append(apply(construct, elt))
    return SExp(repr=conv)

def construct_seq(seq):
    return apply(construct, seq)

def parseText(t):
    """Parse the text representation of an sexp"""
    try:
        sexp = _parseText(t)[0]
    except ValueError:
        raise ParseError('<na>', '<na>', t)
    if type(sexp) == StringType:
	raise ParseError('(', t[0], t)
    convertDisplay(sexp) # side-effect!
    return SExp(repr=sexp)

def convertDisplay(t):
    """Convert strings in spki display format to binary

    Modifies its argument in place!
    """
    for i in range(len(t)):
        elt = t[i]
        if atom(elt):
            if elt[0] == '|' and elt[-1] == '|':
                t[i] = b64_to_str(elt[1:-1])
        else:
            convertDisplay(elt)
    
SPACE = 'SPACE'; intern(SPACE)
LPAREN = 'LPAREN'; intern(LPAREN)
RPAREN = 'RPAREN'; intern(RPAREN)
ERROR = 'ERROR'; intern(ERROR)

def _getDelim(t):
    find = string.find
    # somewhat feeble attempt to treat quoted strings as atomic
    if t[0] == '"':
	offset = 2 + string.find(t[1:], '"')
	if offset != 1:
	    find = lambda t, char, offset=offset: \
		   string.find(t[offset:], char) + offset
    i = find(t, ' ')
    j = find(t, '(')
    k = find(t, ')')
    list = []
    if i != -1:
        list.append(i)
    if j != -1:
        list.append(j)
    if k != -1:
        list.append(k)
    which = min(list)
    if not list:
        return ERROR, 0
    if which == i:
        return SPACE, i
    elif which == j:
        return LPAREN, j
    else:
        return RPAREN, k
    
def _parseText(t):
    # XXX no error handling!
    # XXX doesn't deal with leading whitespace
    # XXX doesn't grok multiline base64 strings
    t = string.strip(t)  # XXX is this necessary?
    if t[0] != '(':
        # assume it's an atom
        return t, ''
    repr = []
    t = t[1:]
    while t:
        action, location = _getDelim(t)
        atom = t[:location]
        t = t[location:]
        if action is SPACE:
            repr.append(atom)
            t = t[1:]
        elif action is LPAREN:
            sub, rest = _parseText(t)
            repr.append(sub)
            t = string.strip(rest[1:])
        elif action is RPAREN:
            # could be end of multiple sexps, so no atom
            if atom:
                repr.append(atom)
            return repr, string.strip(t)
        else:
            break
    return repr, t

def _parseTextX(t):
    t = t.strip()
    if t[0] != '(':
        # assume it's an atom
        return t, ''
    repr = []
    t = t[1:]
    while t:
        action, location = _getDelim(t)
        atom = t[:location]
        t = t[location:]
        if action is SPACE:
            repr.append(atom)
            t = t[1:]
        elif action is LPAREN:
            sub, rest = _parseText(t)
            repr.append(sub)
            t = rest[1:].strip()
        elif action is RPAREN:
            # could be end of multiple sexps, so no atom
            if atom:
                repr.append(atom)
            return repr, t.strip()
        else:
            break
    return repr, t

def condense_parens(s):
    while 1:
	s1 = re.sub('\)\s+\)', '))', s)
	if s1 == s:
	    break
	s = s1
    return s

def pprint(s, indent=0):
    buf = []
    if atom(s):
	buf.append("   " * indent)
	if printable(s):
	    buf.append(str(s) + " ")
	else:
	    buf.append("|%s| " % str_to_b64(s))
	return string.join(buf, '')
    subsexp = 0
    buf.append("   " * indent)
    buf.append("(%s " % s[0])
    for elt in s[1:]:
	if atom(elt):
	    if subsexp:
		buf.append("   " * indent)
		subsexp = 0
	    if printable(elt):
		buf.append(str(elt) + " ")
	    else:
		buf.append("|%s| " % str_to_b64(elt))
	else:
	    if not subsexp:
		buf.append("\n")
	    buf.append(pprint(elt, indent+1))
	    subsexp = 1
    if subsexp:
	buf.append("   " * indent)
    else:
        # check for unnecessary trailing spaces
        end = buf[-1]
        del buf[-1]
        while end[-1] == ' ':
            end = end[:-1]
        buf.append(end)
    buf.append(")\n")
    return condense_parens(string.join(buf, ''))

class ParseError(ValueError):

    def __init__(self, exp, got, ref=None):
	self.exp = exp
	self.got = got
	self.ref = ref

    def __str__(self):
	return "ParseError: expected %s, got %s" % (self.exp, `self.got`)

class SExp(UserList):
    def __init__(self, canon=None, repr=None):
	self.data = []
        if canon is not None and repr is not None:
            raise ValueError, "must specify either canon or repr, not both"
	if canon is not None:
	    canon = string.strip(canon)
            if len(canon) == 0:
                raise ParseError('(', '<no data>')
	    if canon[0] == '{':
		canon = self._base64_to_canonical(canon)
	    self._consumed = 0
	    self._parse_canonical(canon)
	elif repr is not None:
	    if isinstance(repr, SExp):
		raise TypeError, "repr of SExp can not be SExp"
	    self.data = repr[:]
	else:
	    raise ValueError, "no valid arguments"
	    
    def encode_base64(self):
	c = self.encode_canonical()
	return '{%s}' % str_to_b64(c)

    def encode_canonical(self):
	parts = []
	for elt in self.data:
            if atom(elt):
		parts.append('%d:%s'% (len(elt), elt))
	    else:
		parts.append(elt.encode_canonical())
	return '(%s)' % string.join(parts, '')
    
    def encode_advanced(self):
	pass

    def _base64_to_canonical(self, wrapped):
	assert wrapped[0] == '{', `wrapped`
	assert wrapped[-1] == '}', `wrapped`
	return a2b_base64(wrapped[1:-1])

    def _parse_canonical(self, canon):
	if canon[0] != '(':
	    raise ParseError('(', canon[0], canon)
	canon = canon[1:]
	try:
	    while canon:
		if canon[0] == '(':
		    v = SExp(canon)
		    self.data.append(v)
		    canon = canon[v._consumed+1:]
		    self._consumed = self._consumed + v._consumed + 1
		    continue
		i = string.find(canon, ':')
		try:
		    l = string.atoi(canon[:i])
		except ValueError:
		    raise ParseError('[0-9]', canon[:i], canon)
		v = canon[i+1:i+1+l]
		self.data.append(v)
		canon = canon[i+1+l:]
		self._consumed = self._consumed + i + 1 + l
	except ParseError, pe:
	    if canon[0] == ')':
		self._consumed = self._consumed + 1
		return
	    else:
		raise pe
	raise ParseError('unexpected end of data', '')

    def __len__(self):
	return len(self.data)

    def __str__(self):
	# it's formatted nicely when a string has an unprintable element
	rep = []
	for s in self.data:
	    if atom(s):
		if not printable(s):
		    rep.append('|%s|' % str_to_b64(s))
		else:
		    rep.append(s)
	    else:
		rep.append(str(s))
	return '(%s)' % (string.join(rep))

    def __repr__(self):
	return "SExp(repr=%s)" % repr(self.data)

    def __getitem__(self, i):
	return self.data[i]

    def __getslice__(self, i, j):
	return SExp(repr=self.data[i:j])

# XXX can we get rid of object_to_sexp now?  it is useful for SPKI
# objects that are just strings and don't have sexp() methods, but
# maybe there aren't any raw strings floating around anymore

# methods for generating sexp from SPKI objects
def object_to_sexp(obj):
    if type(obj) == StringType:
	return obj
    else:
        try:
            return obj.sexp()
        except AttributeError:
            if hasattr(obj, '__class__'):
                print "failed for %s: %s" % (obj.__class__.__name__, obj)
                return '<*%s*>' % obj.__class__.__name__
            else:
                raise ValueError, \
                      "can not make sexp for object of type %s" % type(obj)

def sexpForobject(obj):
    if obj.args:
        return construct_seq([obj.name] + map(object_to_sexp, obj.args))
    else:
        return construct(obj.name)

def sexpForKeyholder(obj):
    return construct('keyholder', object_to_sexp(obj.ident))

def sexpForPublicKey(obj):
    return construct('public-key', object_to_sexp(obj.key))

def sexpForDo(obj):
    return construct('do', obj.opcode, object_to_sexp(obj.args[0]))

def sexpForRSAPublicKey(obj):
    return construct_seq([obj.algorithm_name] + \
			 map(object_to_sexp, obj.args))

sexpForRSAPrivateKey = sexpForRSAPublicKey

def sexpForRSA_PKCS1_MD5_PublicKey(obj):
    return construct_seq(['rsa-pkcs1-md5'] + map(object_to_sexp,
						 obj.args))

def sexpForPrivateKey(obj):
    return construct('private-key', object_to_sexp(obj.key))

def sexpForHash(obj):
    if obj.uri is None:
        return construct('hash', obj.alg_name, obj.value)
    else:
        return construct('hash', obj.alg_name, obj.value, obj.uri)  

def sexpForSignature(obj):
    return construct('signature', obj.hash.sexp(),
                           obj.principal.sexp(), obj.value)

def sexpForSecretKey(obj):
    return construct_seq(['secret-key', obj.algorithm] + \
                     map(object_to_sexp, obj.args))

def sexpForSequence(obj):
    return construct_seq(['sequence'] + map(object_to_sexp, obj.data))

def sexpForValid(obj):
    return construct(obj.args)

def sexpForIssuer(obj):
    return construct('issuer', object_to_sexp(obj.principal))

def sexpForSubject(obj):
    return construct('subject', object_to_sexp(obj.subjobj))

def sexpForKeyholder(obj):
    return construct('keyholder', object_to_sexp(obj.principal))

def sexpForNotAfter(obj):
    return construct('not-after', obj.time)

def sexpForNotBefore(obj):
    return construct('not-before', obj.time)

def sexpForName(obj):
    return construct_seq(['name'] + list(obj.names))

def sexpForFullyQualifiedName(obj):
    return construct_seq(['name', object_to_sexp(obj.principal)] +
			 list(obj.names)) 

def sexpForTag(obj):
    return construct('tag', object_to_sexp(obj.tag))

def sexpForAppTag(obj):
    return construct_seq([obj.name] + map(object_to_sexp, obj.args))

def sexpForTagSet(obj):
    if obj.data:
        return construct_seq(['*', 'set'] + map(object_to_sexp, obj.elts))
    else:
        return construct('*', 'set')

def sexpForTagRange(obj):
    repr = ['*', 'range']
    if obj.lower:
	repr = repr + list(obj.lower)
    if obj.upper:
	repr = repr + list(obj.upper)
    return construct_seq(repr)

def sexpForTagPrefix(obj):
    return construct('*', 'prefix', obj.prefix)

def sexpForTagStar(obj):
    # need to explicitly pass 
    return construct('*')

def sexpForCert(obj):
    # fairly complicated I think
    repr = ['cert']
    append_sexp = lambda obj,r=repr:r.append(obj.sexp())
    if obj.version != 0:
        append_sexp(obj.version)
    if obj.cert_display:
        append_sexp(obj.display)
    append_sexp(obj.issuer)
    if obj.issuer_info:
        append_sexp(obj.issuer_info)
    append_sexp(obj.subject)
    if obj.subject_info:
        append_sexp(obj.subject_info)
    if obj.propagate:
        append_sexp(obj.propagate)
    if obj.kind != 'name-cert':
	append_sexp(obj.tag)
    for v in obj.valid:
        append_sexp(v)
    if obj.comment:
        append_sexp(obj.comment)
    return construct_seq(repr)

def sexpForEntry(obj):
    repr = ['entry']
    append_sexp = lambda obj,r=repr:r.append(obj.sexp())
    append_sexp(obj.subject)
    if obj.deleg:
        append_sexp(obj.deleg)
    append_sexp(obj.tag)
    for v in obj.valid:
        append_sexp(v)
    if obj.comment:
        append_sexp(obj.comment)
    return construct_seq(repr)

def sexpForNameCert(obj):
    repr = ['cert']
    append_sexp = lambda obj,r=repr:r.append(obj.sexp())
    if obj.version:
        append_sexp(obj.version)
    if obj.cert_display:
        append_sexp(obj.cert_display)
    append_sexp(obj.issuer)
    append_sexp(obj.subject)
    for elt in obj.valid:
        append_sexp(elt)
    if obj.comment:
        append_sexp(obj.comment)
    return construct_seq(repr)

def sexpForPasswordEncrypted(obj):
    args = ('password-encrypted', obj.type, obj.keyinfo.sexp(),
	    obj.cipher.sexp())
    if obj.bogus:
	args = args + (obj.bogus,)
    return construct_seq(args)

def sexpForPbes2Hmac(obj):
    return construct('pbes2-hmac', obj.salt, obj.iters, obj.hash,
                 obj.keylen)

def sexpFor_3desCipher(obj):
    return construct('3des-cipher', obj.mode, obj.iv, obj.ciphertext)
    

