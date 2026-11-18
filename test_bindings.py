#!/usr/bin/env python
# Checks for the OpenSSL ctypes bindings in addrgen.py.
# Known keys are the Bitcoin wiki secp256k1 vectors.

import binascii
import os
import re
import sys

import addrgen


def unhex(s):
    return binascii.unhexlify(s)


def first_byte(buf):
    b = buf[0]
    if not isinstance(b, int):
        b = ord(b)
    return b


def expect_raises(fn, text):
    try:
        fn()
    except ValueError as exc:
        if text is not None and text not in str(exc):
            raise AssertionError('expected %r in %r' % (text, exc))
        return
    raise AssertionError('expected ValueError')


def private_key_bytes(key):
    """Return the 32-byte scalar via BN_bn2bin.

    Same calls as get_secret(), but the pad byte matches the buffer type so
    the check does not depend on Python 2 chr().
    """
    bn = addrgen.ssl.EC_KEY_get0_private_key(key.k)
    nbytes = (addrgen.ssl.BN_num_bits(bn) + 7) // 8
    mb = addrgen.ctypes.create_string_buffer(nbytes)
    n = addrgen.ssl.BN_bn2bin(bn, mb)
    if n != nbytes:
        raise AssertionError('BN_bn2bin returned %s, expected %s' % (n, nbytes))
    return mb.raw.rjust(addrgen.SECRET_LEN, b'\x00')


WIKI = unhex('18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725')
WIKI_UNCOMPRESSED = unhex(
    '0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'
    '2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6')
WIKI_COMPRESSED = unhex(
    '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')
# 16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM / 1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs

GENERATOR = b'\x00' * 31 + b'\x01'
GENERATOR_COMPRESSED = unhex(
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')


def test_known_vectors():
    key = addrgen.gen_eckey(secret=WIKI)
    assert type(key.k) is addrgen.VoidP
    assert key.get_pubkey() == WIKI_UNCOMPRESSED
    assert private_key_bytes(key) == WIKI
    key.set_compressed(True)
    assert key.get_pubkey() == WIKI_COMPRESSED

    # Leading NUL bytes must be part of the scalar, not a C-string terminator.
    key = addrgen.KEY()
    key.generate(GENERATOR)
    key.set_compressed(True)
    assert key.get_pubkey() == GENERATOR_COMPRESSED
    assert private_key_bytes(key) == GENERATOR

    # An interior NUL must still count. c_char_p is a pointer plus a length.
    interior = b'\x7f' + (b'\x00' * 30) + b'\x02'
    key = addrgen.KEY()
    key.generate(interior)
    assert private_key_bytes(key) == interior


def test_random_keys_encode():
    for _ in range(20):
        key = addrgen.KEY()
        assert type(key.generate(None)) is addrgen.VoidP
        pub = key.get_pubkey()
        assert len(pub) == 65 and first_byte(pub) == 4
        key.set_compressed(True)
        pub = key.get_pubkey()
        assert len(pub) == 33 and first_byte(pub) in (2, 3)
        assert len(private_key_bytes(key)) == 32

        secret = os.urandom(32)
        key = addrgen.gen_eckey(secret=secret, compressed=True)
        fresh = addrgen.KEY()
        fresh.generate(secret)
        fresh.set_compressed(True)
        assert fresh.get_pubkey() == key.get_pubkey()
        assert private_key_bytes(fresh) == secret


def test_secret_length_is_enforced():
    seen = []
    real = addrgen.ssl.BN_bin2bn

    def wrapped(buf, length, ret):
        seen.append(length)
        return real(buf, length, ret)

    addrgen.ssl.BN_bin2bn = wrapped
    try:
        for bad in (b'', b'\x01', b'\x00' * 31, b'\x00' * 33, u'1' * 32, 32):
            before = len(seen)
            key = addrgen.KEY()
            expect_raises(lambda: key.generate(bad), '32 bytes')
            assert len(seen) == before, 'rejected secret still reached BN_bin2bn'
        key = addrgen.KEY()
        key.generate(WIKI)
        assert seen == [32]
    finally:
        addrgen.ssl.BN_bin2bn = real

    # None is the random-key path and must not be treated as an empty secret.
    key = addrgen.KEY()
    key.generate(None)
    assert len(key.get_pubkey()) == 65


def test_openssl_failures_raise():
    expect_raises(lambda: addrgen.ssl.EC_KEY_new_by_curve_name(0),
                  'EC_KEY_new_by_curve_name')
    expect_raises(lambda: addrgen.ssl.EC_KEY_generate_key(None),
                  'EC_KEY_generate_key')
    expect_raises(lambda: addrgen.ssl.i2o_ECPublicKey(None, None),
                  'i2o_ECPublicKey')
    key = addrgen.KEY()
    expect_raises(lambda: addrgen.ssl.EC_KEY_set_private_key(key.k, None),
                  'EC_KEY_set_private_key')
    expect_raises(lambda: addrgen.ssl.EC_KEY_set_public_key(key.k, None),
                  'EC_KEY_set_public_key')


def test_every_openssl_call_has_a_prototype():
    source = open(addrgen.__file__).read()
    names = sorted(set(re.findall(r'\bssl\.([A-Za-z_][A-Za-z0-9_]*)', source)))
    assert names, 'no OpenSSL calls found'
    for name in names:
        fn = getattr(addrgen.ssl, name)
        assert fn.argtypes is not None, name + ' has no argtypes'
    # A no-argument function still has an explicit empty prototype.
    assert list(addrgen.ssl.BN_CTX_new.argtypes) == []


def test_zero_scalar_is_not_a_pubkey():
    key = addrgen.KEY()
    try:
        key.generate(b'\x00' * 32)
        key.get_pubkey()
    except ValueError:
        return
    raise AssertionError('zero secret produced a public key')


def main():
    test_known_vectors()
    test_random_keys_encode()
    test_secret_length_is_enforced()
    test_openssl_failures_raise()
    test_every_openssl_call_has_a_prototype()
    test_zero_scalar_is_not_a_pubkey()
    print('ok')


if __name__ == '__main__':
    sys.exit(main())
