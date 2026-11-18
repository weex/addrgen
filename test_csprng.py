#!/usr/bin/env python
"""Checks for OS-CSPRNG private keys and loud crypto-library failure.

The rest of addrgen still has separate Python 2/3 issues (xrange, hex codecs,
integer division in get_secret). These tests cover only the key-generation
change: scalar source, range, public-key derivation, and library loading.
"""

import binascii
import ctypes
import ctypes.util
import unittest

import addrgen


def be32(n):
    return binascii.unhexlify('%064x' % n)


def pubkey(secret, compressed):
    key = addrgen.KEY()
    key.generate(secret)
    key.set_compressed(compressed)
    return key.get_pubkey()


def stored_secret(key):
    bn = addrgen.ssl.EC_KEY_get0_private_key(key.k)
    nbytes = (addrgen.ssl.BN_num_bits(bn) + 7) // 8
    if nbytes == 0:
        return b'\x00' * 32
    buf = ctypes.create_string_buffer(nbytes)
    addrgen.ssl.BN_bn2bin(bn, buf)
    return buf.raw.rjust(32, b'\x00')


class _Fn(object):
    def __init__(self, fn):
        self.fn = fn
        self.restype = None

    def __call__(self, *args):
        return self.fn(*args)


class _FakeLib(object):
    def __init__(self, symbols, curve_result=0x1):
        self._fns = {}
        for name in symbols:
            self._fns[name] = _Fn(lambda *args: None)
        self._fns['EC_KEY_new_by_curve_name'] = _Fn(lambda nid: curve_result)
        self.freed = []

        def free(key):
            self.freed.append(key)

        self._fns['EC_KEY_free'] = _Fn(free)

    def __getattr__(self, name):
        if name in self._fns:
            return self._fns[name]
        raise AttributeError(name)


class RangeTests(unittest.TestCase):
    def test_bounds(self):
        n = addrgen.SECP256K1_ORDER
        self.assertFalse(addrgen.secret_in_range(b'\x00' * 32))
        self.assertFalse(addrgen.secret_in_range(be32(n)))
        self.assertFalse(addrgen.secret_in_range(b'\xff' * 32))
        self.assertFalse(addrgen.secret_in_range(b'\x01' * 31))
        self.assertTrue(addrgen.secret_in_range(be32(1)))
        self.assertTrue(addrgen.secret_in_range(be32(n - 1)))
        self.assertTrue(addrgen.secret_in_range(be32(0xdeadbeef)))

    def test_retries_out_of_range_samples(self):
        n = addrgen.SECP256K1_ORDER
        samples = [b'\x00' * 32, be32(n), b'\xff' * 32, be32(n - 1)]
        seen = []

        def fake(nbytes):
            self.assertEqual(nbytes, 32)
            raw = samples.pop(0)
            seen.append(raw)
            return raw

        orig = addrgen.os_random_bytes
        addrgen.os_random_bytes = fake
        try:
            got = addrgen.random_secret()
        finally:
            addrgen.os_random_bytes = orig
        self.assertEqual(got, be32(n - 1))
        self.assertEqual(
            seen,
            [b'\x00' * 32, be32(n), b'\xff' * 32, be32(n - 1)])
        self.assertFalse(samples)

    def test_short_rng_output_fails(self):
        def fake(nbytes):
            return b'\x11'

        orig = addrgen.os_random_bytes
        addrgen.os_random_bytes = fake
        try:
            with self.assertRaises(RuntimeError) as caught:
                addrgen.random_secret()
        finally:
            addrgen.os_random_bytes = orig
        self.assertIn('expected 32', str(caught.exception))

    def test_stuck_rng_fails_loudly(self):
        def fake(nbytes):
            return b'\x00' * 32

        orig = addrgen.os_random_bytes
        addrgen.os_random_bytes = fake
        try:
            with self.assertRaises(RuntimeError) as caught:
                addrgen.random_secret()
        finally:
            addrgen.os_random_bytes = orig
        self.assertIn('[1, n-1]', str(caught.exception))

    def test_live_rng_is_in_range_and_not_constant(self):
        secrets = [addrgen.random_secret() for _ in range(8)]
        for raw in secrets:
            self.assertEqual(len(raw), 32)
            self.assertTrue(addrgen.secret_in_range(raw))
        self.assertGreater(len(set(secrets)), 1)


class CsprngSourceTests(unittest.TestCase):
    def test_prefers_secrets_token_bytes(self):
        if addrgen.secrets is None:
            self.skipTest('secrets is unavailable')
        calls = []

        def fake(n):
            calls.append(n)
            return b'\x42' * n

        orig = addrgen.secrets.token_bytes
        addrgen.secrets.token_bytes = fake
        try:
            self.assertEqual(addrgen.os_random_bytes(32), b'\x42' * 32)
        finally:
            addrgen.secrets.token_bytes = orig
        self.assertEqual(calls, [32])

    def test_falls_back_to_os_urandom(self):
        calls = []

        def fake(n):
            calls.append(n)
            return b'\x24' * n

        orig_secrets = addrgen.secrets
        orig_urandom = addrgen.os.urandom
        addrgen.secrets = None
        addrgen.os.urandom = fake
        try:
            self.assertEqual(addrgen.os_random_bytes(32), b'\x24' * 32)
        finally:
            addrgen.secrets = orig_secrets
            addrgen.os.urandom = orig_urandom
        self.assertEqual(calls, [32])


class DerivationTests(unittest.TestCase):
    # Independent secp256k1 vectors (generator, n-1, and a small scalar).
    VECTORS = (
        (1, True, '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
        (1, False, '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
                   '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
        (addrgen.SECP256K1_ORDER - 1, True,
         '0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
        (addrgen.SECP256K1_ORDER - 1, False,
         '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
         'b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777'),
        (0xdeadbeef, True, '0276d2fdf1302d1fa9556f4df94ec84cefba6d482e54f47c6c2a238c1baa560f0e'),
    )

    def test_known_public_keys(self):
        for scalar, compressed, expect in self.VECTORS:
            got = pubkey(be32(scalar), compressed)
            self.assertEqual(binascii.hexlify(got).decode('ascii'), expect)

    def test_random_key_uses_csprng_and_not_library_rng(self):
        def boom(*args, **kwargs):
            raise AssertionError('EC_KEY_generate_key must not be used')

        previous = getattr(addrgen.ssl, 'EC_KEY_generate_key', None)
        addrgen.ssl.EC_KEY_generate_key = boom
        try:
            key = addrgen.KEY()
            key.generate()
            key.set_compressed(True)
            self.assertTrue(addrgen.secret_in_range(key.prikey))
            self.assertEqual(stored_secret(key), key.prikey)
            again = addrgen.KEY()
            again.generate(key.prikey)
            again.set_compressed(True)
            self.assertEqual(again.get_pubkey(), key.get_pubkey())
        finally:
            if previous is not None:
                addrgen.ssl.EC_KEY_generate_key = previous

    def test_caller_supplied_secret_is_not_replaced(self):
        # Range checks for caller-supplied secrets are a separate change.
        secret = b'\x00' * 32
        key = addrgen.KEY()
        key.generate(secret)
        self.assertEqual(key.prikey, secret)

    def test_random_keys_match_cryptography(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            self.skipTest('cryptography is not installed')
        for _ in range(5):
            key = addrgen.KEY()
            key.generate()
            key.set_compressed(True)
            scalar = int(binascii.hexlify(key.prikey), 16)
            priv = ec.derive_private_key(scalar, ec.SECP256K1())
            expect = priv.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint)
            self.assertEqual(key.get_pubkey(), expect)


class LibraryLoadTests(unittest.TestCase):
    def test_real_library_is_usable(self):
        self.assertIsNone(addrgen._reject_reason(addrgen.ssl))
        loaded = addrgen.load_ssl()
        self.assertTrue(hasattr(loaded, 'EC_POINT_mul'))

    def test_missing_file_fails_loudly(self):
        with self.assertRaises(RuntimeError) as caught:
            addrgen.load_ssl(['libdoesnotexist_addrgen.so'])
        message = str(caught.exception)
        self.assertIn('Could not load', message)
        self.assertIn('libdoesnotexist_addrgen.so', message)

    def test_library_without_symbols_fails_loudly(self):
        with self.assertRaises(RuntimeError) as caught:
            addrgen.load_ssl(['libc.so.6'])
        message = str(caught.exception)
        self.assertIn('missing symbols', message)
        self.assertIn('EC_POINT_mul', message)
        self.assertNotIn('EC_KEY_generate_key', message)

    def test_bad_library_falls_through_to_a_good_one(self):
        names = ['libc.so.6', 'libdoesnotexist_addrgen.so'] + addrgen._ssl_library_names()
        loaded = addrgen.load_ssl(names)
        self.assertTrue(hasattr(loaded, 'EC_POINT_mul'))

    def test_no_candidates(self):
        with self.assertRaises(RuntimeError) as caught:
            addrgen.load_ssl([])
        self.assertIn('No crypto library', str(caught.exception))

    def test_find_library_miss_still_tries_libeay32(self):
        orig = ctypes.util.find_library

        def missing(name):
            return None

        ctypes.util.find_library = missing
        try:
            self.assertEqual(addrgen._ssl_library_names(), ['libeay32'])
        finally:
            ctypes.util.find_library = orig

    def test_missing_curve_is_rejected(self):
        lib = _FakeLib(addrgen._SSL_SYMBOLS, curve_result=None)
        self.assertEqual(
            addrgen._reject_reason(lib),
            'secp256k1 (NID 714) is not available')
        self.assertEqual(lib.freed, [])

    def test_missing_symbol_is_rejected_without_calling_curve(self):
        symbols = [sym for sym in addrgen._SSL_SYMBOLS if sym != 'EC_POINT_mul']
        lib = _FakeLib(symbols, curve_result=0x1)
        reason = addrgen._reject_reason(lib)
        self.assertIn('EC_POINT_mul', reason)
        self.assertEqual(lib.freed, [])

    def test_complete_fake_library_is_accepted(self):
        lib = _FakeLib(addrgen._SSL_SYMBOLS, curve_result=0x55)
        self.assertIsNone(addrgen._reject_reason(lib))
        self.assertEqual(len(lib.freed), 1)


if __name__ == '__main__':
    unittest.main()
