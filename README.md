## addrgen - minimal Bitcoin address generator in Python

This script generates a single Bitcoin address using the compressed public key format and prints it with its private key.

The idea was to have the smallest source code possible so that it would be easy to audit and hard for anyone to hide anything nepharious. If you like this idea, you may want to check out [TweetNaCl](http://tweetnacl.cr.yp.to/software.html).

### Usage 

    python addrgen.py

### Mac OS X

For some reason, the script segfaults on OS X unless it's run in in 32-bit mode. Instead, those on OS X should run:

    bash addrgen.sh

or run a compatible python version if you have troubles with bash script above:

    arch -32 /System/Library/Frameworks/Python.framework/Versions/2.7/bin/python addrgen.py 

### Generating other types of addresses

Supply the version number for your desired address  with the --otherversion switch. (supported by pywallet at least)

    python addrgen.py --otherversion=48

If you wish to generate addresses based on a passphrase, a given private key, or some other option look at the commented lines in the test() function.

Created and Licensed Public Domain by Joric/bitcoin-dev June 2012 with minor modifications by David Sterry.
