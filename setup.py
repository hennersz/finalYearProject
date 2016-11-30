from setuptools import setup, find_packages
import os

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "p2ppki",
    version = "0.0.1",
    author = "Henry Mortimer",
    author_email = "henry@ucl.ac.uk",
    description = ("A peer to peer public key infrastrucutre for the sharing and verification of openpgp public keys"),
    long_description = read("README.md"),
    license = "GNU",
    keywords = "public key infrastructure peer to peer",
    url = "https://github.com/hennersz/finalYearProject",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: GNU Licence",
    ],
    include_package_data = True
)
