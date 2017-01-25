#!/usr/bin/env python

"""Setup script for the Pisces package distribution.

For more information see the Pisces Web pages at
http://www.cnri.reston.va.us/software/pisces/ 
"""

from distutils.core import setup

setup(# Distribution meta-data
    name = "Pisces",
    version = "1.0",
    description = "Python library for SPKI certificates",
    author = "Jeremy Hylton",
    author_email = "jeremy@alum.mit.edu",
    url = "http://www.cnri.reston.va.us/software/pisces/",
    
    # Description of the modules and packages in the distribution
    packages = ['pisces', 'pisces.spkilib', 'pisces.ttls']
    )

