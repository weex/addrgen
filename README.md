## addrgen - minimal Bitcoin address generator in Python

This script generates a single Bitcoin address using the compressed public key format and prints it with its private key.

The idea was to have the smallest source code possible so that it would be easy to audit and hard for anyone to hide anything nepharious. If you like this idea, you may want to check out [TweetNaCl](http://tweetnacl.cr.yp.to/software.html).

### Usage 

    python addrgen.py

### Generating other types of addresses

Supply the version number for your desired address  with the --otherversion switch. (supported by pywallet at least)

    python addrgen.py --otherversion=48

If you wish to generate addresses based on a passphrase, a given private key, or some other option look at the commented lines in the test() function.

### Private keys

The script prints the private key (WIF) on standard output. Anyone who can read that output can spend coins sent to the address.

- On a terminal, the key stays on screen and in scrollback after the script exits. addrgen writes a one-line warning to standard error in that case. Copy the key, then clear the scrollback and close the window.
- Do not redirect standard output to a file (`python addrgen.py > key.txt`) unless you can keep that file private and delete it securely. The warning is not printed when standard output is not a terminal, and the file is a copy of the key.
- `addrgen.bat` used to end with `pause`, which left the private key on screen. After a successful run it asks you to copy the key, then clears the console window. A failed run leaves the error on screen. Run it from a command prompt you can close. Some terminals keep scrollback after `cls`; close the window if they do.

Temporary OpenSSL numbers that hold the secret are wiped before they are freed, and the key object does not keep a second Python copy of the secret. The process still has to hold the key long enough to print it, so do not leave it running.

Created and Licensed Public Domain by Joric/bitcoin-dev June 2012 with minor modifications by David Sterry.
