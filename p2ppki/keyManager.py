import gnupg
from dhtServer import DHTServer

class keyManager(object):
    def __init__(self, homedir, dht):
        self.gpg = gnupg.GPG(homedir=homedir)
        self.dht = dht

    def getEmailFromUID(self, uid):
        emailStart = uid.find('<')
        return uid[emailStart + 1: -1]

    def storeKey(self, fingerprint):
        keys = self.gpg.list_keys()
        key = None
        for k in keys:
            if k.fingerprint == fingerprint:
                key = k
                break
        if key is not None:
            data = self.gpg.export(fingerprint)
            dht.set('key-' + fingerprint, data)
            emails = []
            for uid in key['uids']:
                email = getEmailFromUID(uid)
                emails.append(email)

            for email in emails:
                dht.set('key-' + email, data)

    def getKey(self, ident, callback):
        key = u'key-' + ident
        self.dht.get(key, callback)

    def parseData(self, data):
        
