from setuptools import setup

setup(
    name = "p2ppki",
    version = "0.0.1",
    author = "Henry Mortimer",
    author_email = "henry@ucl.ac.uk",
    description = ("A peer to peer public key infrastrucutre for the sharing and verification of openpgp public keys"),
    license = "GNU",
    keywords = "public key infrastructure peer to peer",
    url = "https://github.com/hennersz/finalYearProject",
    packages=['p2ppki', 'tests'],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: GNU Licence",
    ],
)
