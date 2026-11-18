## addrgen - minimal Bitcoin address generator in Python

This script generates a single Bitcoin address using the compressed public key format and prints it with its private key.

The idea was to have the smallest source code possible so that it would be easy to audit and hard for anyone to hide anything nepharious. If you like this idea, you may want to check out [TweetNaCl](http://tweetnacl.cr.yp.to/software.html).

### Usage 

    python addrgen.py

### Generating other types of addresses

Supply the version number for your desired address  with the --otherversion switch. (supported by pywallet at least)

    python addrgen.py --otherversion=48

To generate an address from a raw private key, or to re-encode an existing key, look at the commented lines in the test() function.

Passphrase (brainwallet) mode has been removed. The old path turned a passphrase into a private key with one unsalted SHA-256 (`rounds` defaulted to 1). Guessing those keys is cheap, and bots sweep addresses funded from them. Generate the random key this script prints, and store that private key. Do not hash a passphrase into a key.

Created and Licensed Public Domain by Joric/bitcoin-dev June 2012 with minor modifications by David Sterry.
