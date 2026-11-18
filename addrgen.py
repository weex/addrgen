#!/usr/bin/env python3
# Joric/bitcoin-dev, june 2012, public domain
#
# New private keys come from the OS CSPRNG. coincurve/libsecp256k1 only
# derives the public key. RIPEMD-160 comes from hashlib when OpenSSL
# provides it, and from ripemd160.py otherwise.

import hashlib
import os
import sys

try:
    import secrets
except ImportError:
    secrets = None

from coincurve import PrivateKey

from ripemd160 import ripemd160

# Order of secp256k1 (SEC 2). A private key is valid iff 1 <= k < n.
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def os_random_bytes(n):
    """Bytes from the OS CSPRNG. secrets.token_bytes, else os.urandom."""
    token_bytes = getattr(secrets, 'token_bytes', None) if secrets is not None else None
    if token_bytes is not None:
        return token_bytes(n)
    return os.urandom(n)

def secret_in_range(raw):
    """True when raw is a 32-byte scalar in [1, n-1]."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        return False
    value = int.from_bytes(raw, 'big')
    return 1 <= value < SECP256K1_ORDER

def random_secret():
    """New private key from the OS CSPRNG, retried until it is in [1, n-1].

    Rejection sampling (not reduction modulo n) so the result is unbiased.
    A draw outside the range is vanishingly rare; giving up means the RNG
    is not returning usable bytes.
    """
    for _ in range(128):
        raw = os_random_bytes(32)
        if len(raw) != 32:
            raise RuntimeError('OS CSPRNG returned %d bytes, expected 32' % len(raw))
        if secret_in_range(raw):
            return raw
    raise RuntimeError('OS CSPRNG failed to produce a private key in [1, n-1]')

class KEY:
    def __init__(self):
        self.private_key = None
        self.compressed = False

    def generate(self, secret=None):
        # Fresh keys are drawn here. coincurve only multiplies the generator
        # by that scalar; it is not asked to mint the private key.
        if not secret:
            secret = random_secret()
        if isinstance(secret, bytearray):
            secret = bytes(secret)
        if not isinstance(secret, bytes) or len(secret) != 32:
            raise ValueError('secret must be 32 bytes')
        self.private_key = PrivateKey(secret)
        return self.private_key

    def get_pubkey(self):
        return self.private_key.public_key.format(compressed=self.compressed)

    def get_secret(self):
        return self.private_key.secret

    def set_compressed(self, compressed):
        self.compressed = compressed

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    return ripemd160(hashlib.sha256(s).digest())

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(b58_digits[r]))
    return ''.join(l)

def base58_decode(s):
    n = 0
    for ch in s:
        n *= 58
        digit = b58_digits.index(ch)
        n += digit
    return n

def base58_encode_padded(s):
    res = base58_encode(int.from_bytes(s, 'big'))
    pad = 0
    for c in s:
        if c == 0:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def base58_decode_padded(s):
    pad = 0
    for c in s:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    n = base58_decode(s)
    if n:
        res = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    else:
        res = b''
    return b'\x00' * pad + res

def base58_check_encode(s, version=0):
    vs = bytes([version]) + s
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)

def base58_check_decode(s, version=0):
    k = base58_decode_padded(s)
    v0, data, check0 = k[0:1], k[1:-4], k[-4:]
    check1 = dhash(v0 + data)[:4]
    if check0 != check1:
        raise BaseException('checksum error')
    if version != v0[0]:
        raise BaseException('version mismatch')
    return data

def gen_eckey(passphrase=None, secret=None, pkey=None, compressed=False, rounds=1, version=0):
    k = KEY()
    if passphrase:
        secret = passphrase.encode('utf8')
        for i in range(rounds):
            secret = hashlib.sha256(secret).digest()
    if pkey:
        secret = base58_check_decode(pkey, 128+version)
        compressed = len(secret) == 33
        secret = secret[0:32]
    k.generate(secret)
    k.set_compressed(compressed)
    return k

def get_addr(k,version=0):
    pubkey = k.get_pubkey()
    secret = k.get_secret()
    hash160 = rhash(pubkey)
    addr = base58_check_encode(hash160,version)
    payload = secret
    if k.compressed:
        payload = secret + b'\x01'
    pkey = base58_check_encode(payload, 128+version)
    return addr, pkey

def reencode(pkey,version=0):
    payload = base58_check_decode(pkey,128+version)
    secret = payload[:-1]
    payload = secret + b'\x01'
    pkey = base58_check_encode(payload, 128+version)
    print(get_addr(gen_eckey(pkey)))

def test(otherversion):
    # random compressed
    print(get_addr(gen_eckey(compressed=True,version=otherversion),version=otherversion))

    # uncomment these to create addresses via a different method
    # random uncompressed
    #print(get_addr(gen_eckey()))
    # by secret
    #print(get_addr(gen_eckey(secret=bytes.fromhex('%064x' % 0xdeadbabe))))
    # by passphrase
    #print(get_addr(gen_eckey(passphrase='Satoshi Nakamoto')))
    # by private key
    # Public test vectors from the Bitcoin wiki "Wallet import format" page
    # (same secret: uncompressed, then compressed). These keys are public.
    # WARNING: never send or store funds on them.
    #print(get_addr(gen_eckey(pkey='5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')))
    #print(get_addr(gen_eckey(pkey='KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')))

    # uncomment this to reencode the private keys created by early versions of this script
    #reencode(sys.argv[1])

if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option("--otherversion", dest="otherversion", default=0,
                    help="Generate address with different version number")
    (options, args) = parser.parse_args()
 
    test(int(options.otherversion))
