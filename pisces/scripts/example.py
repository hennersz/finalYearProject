#! /usr/bin/env python

"""Use SPKI to perform access control on an object"""

from pisces.spkilib import spki, verify, database, keystore
from pisces.spkilib.config import parseHashOrName, resolveName, Options

import os
import pickle
import string
import sys

class BankAccount:
    """A simple object to test the AccessController

    Possible BankAccount permissions are: deposit, withdraw, check, set.
    """
    def __init__(self, balance=0):
	self.balance = balance

    def deposit(self, amount):
	self.balance = self.balance + amount

    def withdraw(self, amount):
	if amount > self.balance:
            raise ValueError, "balance too low: %d" % self.balance
        self.balance = self.balance - amount
    
    def checkBalance(self):
	return self.balance

    def setBalance(self, amount):
	self.balance = amount

class GuardedBankAccount:
    def __init__(self, account, acl, keys, verbose=None):
        self.guard = verify.ReferenceMonitor(acl, keys, verbose)
        if verbose:
            self.guard.VERBOSE = 1
        self.account = account

    def deposit(self, amount, caller):
        self.guard.checkPermission(caller, 'deposit')
        self.account.deposit(amount)

    def withdraw(self, amount, caller):
        self.guard.checkPermission(caller, 'withdraw')
        self.account.withdraw(amount)

    def checkBalance(self, caller):
        self.guard.checkPermission(caller, 'checkBalance')
        return self.account.checkBalance()

    def setBalance(self, amount, caller):
        self.guard.checkPermission(caller, 'setBalance')
        self.account.setBalance(amount)

class Args(Options):
    """Each of the following arguments must be specified:

    -o path: path of pickled BankAccount object
    -a path: path of ACL for object
    -k path: path of the keystore
    -p path: name or hash of a principal in the keystore
    -m method: name of method to invoke on account. If the method
    takes any arguments, they are specified as arguments to the
    script.
    -v: verbose
    """

    super_init = Options.__init__
    
    def __init__(self):
	self.super_init()
        self.__object = None
        self.__method = None
        self.__certs = None
        self.__keys = None
        self.__acl = None
        self.__principal = None
        self.__args = ()

	self.opts = 'o:m:c:k:a:p:v'
	self.opthandler = self.handleOpt
	self.arghandler = self.handleArgs

    def handleOpt(self, k, v):
	if k == '-o':
	    self.__object = v
	if k == '-m':
	    self.__method = v
	if k == '-k':
	    self.__keys = v
	if k == '-a':
	    self.__acl = v
	if k == '-p':
	    self.__principal = v
	if k == '-d':
	    self.__dir = v

    def handleArgs(self, args):
        if args:
            # try to convert stuff when possible
            values = []
            for arg in args:
                try:
                    o = string.atof(arg)
                except ValueError:
                    try:
                        o = string.atoi(arg)
                    except ValueError:
                        o = arg
                values.append(o)
            self.__args = tuple(values)

    def getAccount(self):
	f = open(self.__object, "rb")
	acct = pickle.load(f)
	f.close()
	return acct

    def setAccount(self, obj):
        f = open(self.__object, "wb")
        pickle.dump(obj, f)
        f.close()

    def getPrincipal(self):
	hn = parseHashOrName(self.__principal)
	if isinstance(hn, spki.Hash):
	    return hn
	else:
	    return resolveName(hn).getPrincipal()

    def getACL(self):
	return database.ACL(self.__acl)

    def getMethod(self):
	return self.__method

    def getMethodArgs(self):
	return self.__args

if __name__ == "__main__":
    args = Args()
    args.init(sys.argv[1:])

    caller = args.getPrincipal()
    gba = GuardedBankAccount(args.getAccount(),
			     args.getACL(),
			     args.getKeyServer(),
                             args.verbose)
    meth = getattr(gba, args.getMethod())

    # method invocation code is ugly because we need to use apply to
    # append the caller as an argument to the method.  in production
    # code, it would probably make sense to pass the caller in some
    # other way.  also note that in Python 1.6, the call would look
    # like thos: ret = meth(*args.getMethodArgs() + (caller,))
    try:
        methargs = args.getMethodArgs() + (caller,)
        ret = apply(meth, methargs)
    except verify.SecurityError:
        print "access denied"
        sys.exit(-1)
        
    if ret is not None:
        print ret

    args.setAccount(gba.account)
