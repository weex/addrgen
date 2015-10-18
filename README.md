## addrgen - minimal Bitcoin address generator in Python

This script generates a single Bitcoin address using the compressed public key format and prints it with its private key.

### Usage 

    python addrgen.py

### Generate Litecoin or other types of addresses, you can use the --otherversion=48 switch which is supported by pywallet and other Bitcoin wallet tools.

    python addrgen.py --otherversion=48

If you wish to generate addresses based on a passphrase, a given private key, or some other option look at the commented lines in the test() function.

Created and Licensed Public Domain by Joric/bitcoin-dev June 2012 with minor modifications by David Sterry.
