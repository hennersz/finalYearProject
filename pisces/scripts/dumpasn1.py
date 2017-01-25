#! /usr/bin/env python

"""Parse and display ASN.1 objects stored in BER encoding

Usage: dumpasn1.py [-c file] file1 ... fileN

The -c file can be used to specify a config file that maps from object
identifiers to human-readable names.  The only known configuration
file is http://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg.
"""

from pisces import asn1

def main():
    import sys
    import getopt

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'c:')
        for o, a in opts:
            if o == '-c':
                f = open(a)
                oids = asn1.parseCfg(f)
                f.close()
                display = asn1.Displayer(oids)
    except (getopt.error, IOError), msg:
        print "Error", msg
        print __doc__
        return

    for path in args:
        try:
            f = open(path, 'rb')
        except IOError, msg:
            print "Error", msg
            continue
        obj =  asn1.parse(f.read())
        f.close()
        print path
        display(obj)
    
if __name__ == "__main__":
    main()
