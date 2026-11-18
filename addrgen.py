#!/usr/bin/env python3
# Joric/bitcoin-dev, june 2012, public domain
#
# secp256k1 keys come from libsecp256k1 via coincurve. HASH160 is SHA-256
# followed by RIPEMD-160; ripemd160.py uses hashlib when this interpreter
# has it and a pure-Python implementation when it does not.

import hashlib

from coincurve import PrivateKey

from ripemd160 import ripemd160

b58_digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class KEY:
    def __init__(self):
        self.private_key = None
        self.compressed = False

    def generate(self, secret=None):
        if secret is None:
            self.private_key = PrivateKey()
        else:
            if isinstance(secret, bytearray):
                secret = bytes(secret)
            if not isinstance(secret, bytes) or len(secret) != 32:
                raise ValueError("secret must be 32 bytes")
            self.private_key = PrivateKey(secret)
        return self.private_key

    def get_pubkey(self):
        return self.private_key.public_key.format(compressed=self.compressed)

    def get_secret(self):
        return self.private_key.secret

    def set_compressed(self, compressed):
        self.compressed = compressed


def dhash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def rhash(data):
    return ripemd160(hashlib.sha256(data).digest())


def base58_encode(number):
    digits = []
    while number > 0:
        number, remainder = divmod(number, 58)
        digits.append(b58_digits[remainder])
    digits.reverse()
    return "".join(digits)


def base58_decode(text):
    number = 0
    for char in text:
        number *= 58
        number += b58_digits.index(char)
    return number


def base58_encode_padded(data):
    encoded = base58_encode(int.from_bytes(data, "big"))
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + encoded


def base58_decode_padded(text):
    pad = 0
    for char in text:
        if char == b58_digits[0]:
            pad += 1
        else:
            break
    number = base58_decode(text)
    if number == 0:
        body = b""
    else:
        body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * pad + body


def base58_check_encode(payload, version=0):
    versioned = bytes([version]) + payload
    checksum = dhash(versioned)[:4]
    return base58_encode_padded(versioned + checksum)


def base58_check_decode(text, version=0):
    decoded = base58_decode_padded(text)
    if len(decoded) < 5:
        raise BaseException("checksum error")
    version_byte, data, checksum = decoded[0], decoded[1:-4], decoded[-4:]
    expected = dhash(bytes([version_byte]) + data)[:4]
    if checksum != expected:
        raise BaseException("checksum error")
    if version != version_byte:
        raise BaseException("version mismatch")
    return data


def gen_eckey(passphrase=None, secret=None, pkey=None, compressed=False, rounds=1, version=0):
    if passphrase:
        secret = passphrase.encode("utf-8")
        for _ in range(rounds):
            secret = hashlib.sha256(secret).digest()
    if pkey:
        secret = base58_check_decode(pkey, 128 + version)
        compressed = len(secret) == 33
        secret = secret[:32]
    key = KEY()
    key.generate(secret)
    key.set_compressed(compressed)
    return key


def get_addr(key, version=0):
    pubkey = key.get_pubkey()
    secret = key.get_secret()
    addr = base58_check_encode(rhash(pubkey), version)
    payload = secret + (b"\x01" if key.compressed else b"")
    pkey = base58_check_encode(payload, 128 + version)
    return addr, pkey


def reencode(pkey, version=0):
    payload = base58_check_decode(pkey, 128 + version)
    secret = payload[:-1]
    payload = secret + b"\x01"
    pkey = base58_check_encode(payload, 128 + version)
    print(get_addr(gen_eckey(pkey)))


def test(otherversion):
    # random compressed
    print(get_addr(gen_eckey(compressed=True, version=otherversion), version=otherversion))

    # uncomment these to create addresses via a different method
    # random uncompressed
    #print(get_addr(gen_eckey()))
    # by secret
    #print(get_addr(gen_eckey(secret=bytes.fromhex("%064x" % 0xdeadbabe))))
    # by passphrase
    #print(get_addr(gen_eckey(passphrase="Satoshi Nakamoto")))
    # by private key
    #print(get_addr(gen_eckey(pkey="5K1HkbYffstTZDuV4riUWMbAMkQh57b8798uoy9pXYUDYeUHe7F")))
    #print(get_addr(gen_eckey(pkey="L3ATL5R9Exe1ubuAnHVgNgTKZEUKkDvWYAWkLUCyyvzzxRjtgyFe")))

    # uncomment this to reencode the private keys created by early versions of this script
    #import sys
    #reencode(sys.argv[1])


if __name__ == "__main__":
    import optparse

    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option("--otherversion", dest="otherversion", default=0,
                      help="Generate address with different version number")
    (options, args) = parser.parse_args()

    test(int(options.otherversion))
