from pisces.spkilib import spki, sexp

class SecurityError(RuntimeError):
    pass

class Verifier:
    VERBOSE = 0

    def __init__(self, acl, keys, verbose=None):
	self.acl = acl
	self.keys = keys
	if verbose:
	    self.VERBOSE = 1
        
    def verify(self, prin, perm, delegate=0):
	"""Find a valid certificate chain from ACL to prin for reqPerm.

	prin is the principal making the request.  perm is the
	permission request.

        If verify finds a valid certificate chain from the principal
        making the request to the ACL, it will return a list
        containing the certificates in the chain.  The first element
        in the list will be the ACL entry.  Each subsequent element
        will be a certificate delegating some permissions from the
        previous element to the next element.  The last element will
        delegate permissions to the principal.

        There is a delegate argument because there can't be more than
        one certificate between a valid delegate-able certificate and
        the principal requesting permission.  That one certificate is
        the one that grants permissions to the principal, but doesn't
        allow the principal to delegate further.  The delegate flag
        should always be true when called recursively.
	"""
        if self.VERBOSE:
            print "verify", prin, perm

        if not perm:
            if self.VERBOSE:
                print "cert", "permissions did not delegate"
            return None

        # A valid chain is always created here and modified as
        # recursive calls to verify return and add the current
        # certificate to the list.
        entry = self.checkACL(prin, perm)
        if entry:
            return [entry]

        certs = self.keys.lookupCertBySubject(prin)
        if self.VERBOSE:
            print "%d certs authorize %s" % (len(certs), prin)
        for certobj in certs:
            cert = spki.extractSignedCert(certobj)
            if self.VERBOSE:
                print sexp.pprint(cert.cert.sexp())

            # next method call with recurse
            if cert.kind == 'name-cert':
                chain = self.verifyNameCert(cert, perm, delegate)
            else:
                chain = self.verifyCert(cert, perm, delegate)
                
            # defer signature verification until we actually have a
            # potential chain from ACL to requested permissions
	    if not chain:
		continue
            if not cert.verifySignature(self.keys):
		if self.VERBOSE:
		    print "invalid signature on", cert.cert
                continue
            # Everythin looks good, so add the current certificate to
            # the chain and return
            chain.append(cert)
            return chain
        return None

    def verifyNameCert(self, cert, perm, delegate):
        issuer = cert.issuer.getPrincipal()
        if not cert.isValid():
            return None
        chain = self.verify(issuer, perm, 1)
        if chain:
            if self.VERBOSE:
                print "name verification okay"
            return chain
        return None
    
    def verifyCert(self, cert, perm, delegate):
        issuer = cert.issuer.getPrincipal()
        if not cert.isValid():
            print "cert is invalid"
            return None
        if not (cert.subject.isName() \
                or (not delegate or cert.propagate)):
            print "bad name or delegate"
            return None
        chain = self.verify(issuer, perm & cert.tag, 1)
        if chain:
            if self.VERBOSE:
                print "verification okay"
            return chain
        return None

    def checkACL(self, prin, requested):
        """Check if prin has requested permissions in ACL"""
        for entry in self.acl.lookup(prin):
            if requested & entry.tag:
                return entry
        return None

class ReferenceMonitor:
    def __init__(self, acl, keys, verbose=None):
        self.verifier = Verifier(acl, keys, verbose)
        self.caller = None
        
    def checkPermission(self, caller, perm):
        # convert string perm into a Tag containing (* set perm)
        set = spki.TagSet()
        set.add(perm)
        chain = self.verifier.verify(caller, spki.Tag(set)) 
        if not chain:
            raise SecurityError

def extractCert(spkiobj):
    if spki.isa(spkiobj, spki.Sequence):
        for elt in spkiobj:
            if spki.isa(elt, spki.Cert):
                return elt
    elif spki.isa(spkiobj, spki.Cert):
        return spkiobj

def showChain(caller, chain):
    for obj in chain:
        if isinstance(obj, spki.SignedCert):
            print "cert", obj.issuer, obj.subject
        elif isinstance(obj, spki.Entry):
            print "ACL", obj.subject
    print "caller", caller
