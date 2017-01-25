#! /usr/bin/env python

from pisces.spkilib import sexp
from pisces.spkilib.database import DebugDatabase

import sys

if __name__ == "__main__":
    for file in sys.argv[1:]:
        print file
        db = DebugDatabase(file)
        for obj in db.objects:
            print sexp.pprint(obj.sexp())
            print

