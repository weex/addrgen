## addrgen - minimal Bitcoin address generator in Python

This script generates a single Bitcoin address using the compressed public key format and prints it with its private key.

The idea was to have the smallest source code possible so that it would be easy to audit and hard for anyone to hide anything nepharious. If you like this idea, you may want to check out [TweetNaCl](http://tweetnacl.cr.yp.to/software.html).

### Usage

Python 3.9 or newer. Install the pinned secp256k1 dependency, then run:

    pip install -r requirements.txt
    python3 addrgen.py

Keys are derived with libsecp256k1 through [coincurve](https://github.com/ofek/coincurve). The address hash is SHA-256 followed by RIPEMD-160. If this Python build's hashlib cannot provide RIPEMD-160, `ripemd160.py` uses a pure-Python implementation instead.

### Generating other types of addresses

Supply the version number for your desired address  with the --otherversion switch. (supported by pywallet at least)

    python3 addrgen.py --otherversion=48

If you wish to generate addresses based on a passphrase, a given private key, or some other option look at the commented lines in the test() function.

Created and Licensed Public Domain by Joric/bitcoin-dev June 2012 with minor modifications by David Sterry.
