addrgen - Minimal Bitcoin address generator in Python

Created and Licensed Public Domain by Joric/bitcoin-dev June 2012 with minor modifications by David Sterry.

This script generates a single Bitcoin address and prints it with its private key.

The Bitcoin address is generated using the compressed public key format.

If you wish to generate Litecoin or other types of addresses, you can use the --otherversion=48 (or other version number) switch which is supported by pywallet and other low-level tools.

If you wish to generate addresses based on a passphrase, a given private key, or some other option look at the commented lines in the test() function.

This script was created for You Can Learn Bitcoin by David R. Sterry available from
 [Apple's iBookstore](https://itunes.apple.com/us/book/you-can-learn-bitcoin/id569230042?mt=11), [Barnes & Noble's Nook](http://www.barnesandnoble.com/w/you-can-learn-bitcoin-david-r-sterry/1113581990), and  [Lulu](http://davidsterry.com/youcan).
