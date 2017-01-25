from pisces import ttls
from pisces.spkilib import sexpsocket

import string

def signMessages(key, msgs):
    canon = []
    for msg in msgs:
        canon.append(msg.sexp().encode_canonical())
    buf = string.join(canon, '')
    sig = key.priv.sign(buf)
    return sig

def do_handshake(sess):
    key = opts.getKeyPair()
    certs = opts.getChain(key)
    opts.store.close()
    if not certs:
        print "failed to get certificate chain"
        return 0

    msg = ttls.newClientHello()
    sess.setClientRandom(msg.rand)
    sess.send_sexp(msg)

    sendCert = 0
    serverKey = None
    svr = ttls.eval(sess.read_sexp())
    sess.setServerRandom(svr.rand)
    while 1:
        # still need to verify that these arrive in the right order
        msg = ttls.eval(sess.read_sexp())
        if isinstance(msg, ttls.ServerHelloDone):
            break
        if isinstance(msg, ttls.CertificateRequest):
            # server needs our certificate
            sendCert = 1
        if isinstance(msg, ttls.Certificate):
            if not msg.verify():
                # send error message
                msg = ttls.Error("bad server certificate chain")
                sess.send_sexp(msg)
                raise msg
            serverPrin = msg.getPrincipal()
            sess.setServerKey(opts.lookupKey(serverPrin))

    if sendCert:
        msg = ttls.newCertificate(certs)
        sess.send_sexp(msg)

    secret = ttls.newPreMasterSecret()
    sess.setPreMasterSecret(secret)
    msg = ttls.newClientKeyExchange(sess, secret)
    sess.send_sexp(msg)

    # in real TLS, wouldn't need CV for DH keys
    sig = key.priv.sign(sess.getMessages())
    msg = ttls.CertificateVerify(sig)
    sess.send_sexp(msg)

    # there is no change-cipher-spec message here, because we
    # always use the same cipher 

    sess.makeMasterSecret()
    msg = ttls.newFinished(sess.makeVerifyData())
    sess.send_sexp(msg)
    msg = ttls.eval(sess.read_sexp())
    if not sess.checkVerifyData(msg.verify):
	msg = ttls.Error("bad verify_data")
	sess.send_sexp(msg)
	raise msg
    return 1

def main():
    global opts
    opts = ttls.parseopt(1)
    port = opts.port
    host = opts.host

    # a spki socket
    sock = sexpsocket.socket(sexpsocket.AF_INET,
                             sexpsocket.SOCK_STREAM)  
    sock.connect((host, port))
    sess = ttls.Session(sock, 1)

    if not do_handshake(sess):
        print "handshake failed"
        return
    sess.makeKeys()
    for i in range(128):
	sess.send('Message #%d' % i)
	buf = None
	while buf is None:
	    buf = sess.recv()
	print `buf`
    sess.close()
    
if __name__ == "__main__":
    main()
    
