#!/usr/bin/env python
"""Checks that private scalars are exactly 32 bytes and lie in [1, n-1]."""

import binascii
import sys
import unittest

import addrgen

# secp256k1 order, confirmed against OpenSSL's explicit curve parameters.
ORDER_HEX = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
ORDER_MINUS_1_HEX = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140'
ONE_HEX = '00' * 31 + '01'

# Generator point, private key 1.
G_UNCOMPRESSED = (
    '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
)
G_COMPRESSED = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'


def raw(hex_text):
    return binascii.unhexlify(hex_text)


def hexlify(buf):
    text = binascii.hexlify(buf)
    if not isinstance(text, str):
        text = text.decode('ascii')
    return text


class PrivkeyRangeTests(unittest.TestCase):
    def assert_value_error(self, fn, snippet):
        try:
            fn()
        except ValueError as exc:
            self.assertIn(snippet, str(exc))
        else:
            self.fail('expected ValueError')

    def test_order_matches_secp256k1(self):
        self.assertEqual(addrgen.SECP256K1_ORDER, int(ORDER_HEX, 16))

    def test_validate_accepts_boundaries_inside_range(self):
        one = raw(ONE_HEX)
        upper = raw(ORDER_MINUS_1_HEX)
        self.assertEqual(addrgen.validate_privkey(one), one)
        self.assertEqual(addrgen.validate_privkey(upper), upper)

    def test_validate_rejects_bad_scalars(self):
        self.assert_value_error(lambda: addrgen.validate_privkey(raw('00' * 32)), 'out of range')
        self.assert_value_error(lambda: addrgen.validate_privkey(raw(ORDER_HEX)), 'out of range')
        self.assert_value_error(lambda: addrgen.validate_privkey(raw('ff' * 32)), 'out of range')
        self.assert_value_error(lambda: addrgen.validate_privkey(raw('00' * 31)), 'got 31')
        self.assert_value_error(lambda: addrgen.validate_privkey(raw('00' * 33)), 'got 33')
        self.assert_value_error(lambda: addrgen.validate_privkey(raw('')), 'got 0')
        if sys.version_info[0] >= 3:
            text = '1' * 32
        else:
            text = u'1' * 32
        self.assert_value_error(lambda: addrgen.validate_privkey(text), '32 bytes')

    def test_generate_uses_checked_scalar(self):
        key = addrgen.KEY()
        key.generate(raw(ONE_HEX))
        key.set_compressed(False)
        self.assertEqual(hexlify(key.get_pubkey()), G_UNCOMPRESSED)

        key = addrgen.KEY()
        key.generate(raw(ORDER_MINUS_1_HEX))
        self.assertEqual(len(key.get_pubkey()), 65)

        rejected = addrgen.KEY()
        self.assert_value_error(lambda: rejected.generate(raw('00' * 32)), 'out of range')
        self.assertFalse(hasattr(rejected, 'prikey'))
        self.assert_value_error(lambda: addrgen.KEY().generate(raw('aa')), 'got 1')
        self.assert_value_error(lambda: addrgen.KEY().generate(raw(ONE_HEX) + raw('ff')), 'got 33')
        self.assert_value_error(lambda: addrgen.KEY().generate(b''), 'got 0')

    def test_random_key_still_generates(self):
        key = addrgen.gen_eckey()
        pubkey = key.get_pubkey()
        self.assertEqual(len(pubkey), 65)
        first = pubkey[0] if isinstance(pubkey[0], int) else ord(pubkey[0])
        self.assertEqual(first, 0x04)

    def test_supplied_secret_and_compression(self):
        key = addrgen.gen_eckey(secret=raw(ONE_HEX))
        self.assertFalse(key.compressed)
        self.assertEqual(hexlify(key.get_pubkey()), G_UNCOMPRESSED)

        key = addrgen.gen_eckey(secret=raw(ONE_HEX), compressed=True)
        self.assertTrue(key.compressed)
        self.assertEqual(hexlify(key.get_pubkey()), G_COMPRESSED)

        self.assert_value_error(lambda: addrgen.gen_eckey(secret=raw('00' * 32)), 'out of range')
        self.assert_value_error(lambda: addrgen.gen_eckey(secret=raw(ORDER_HEX)), 'out of range')
        self.assert_value_error(lambda: addrgen.gen_eckey(secret=raw('11' * 31)), 'got 31')

    def _enable_passphrase_loop(self):
        # The script targets Python 2 and calls xrange. Resolve it on the
        # module so this process can exercise the passphrase entry.
        if 'xrange' not in dir(addrgen):
            addrgen.xrange = range

    def test_passphrase_derivation_is_checked(self):
        self._enable_passphrase_loop()
        derived = addrgen.gen_eckey(passphrase='abc', rounds=1)
        self.assertEqual(len(derived.get_pubkey()), 65)
        again = addrgen.gen_eckey(passphrase='abc', rounds=1)
        self.assertEqual(derived.get_pubkey(), again.get_pubkey())

        # rounds=0 leaves the passphrase bytes as the scalar.
        self.assert_value_error(
            lambda: addrgen.gen_eckey(passphrase='abc', rounds=0), 'got 3')
        self.assert_value_error(
            lambda: addrgen.gen_eckey(passphrase='\x00' * 32, rounds=0), 'out of range')
        key = addrgen.gen_eckey(passphrase='\x00' * 31 + '\x01', rounds=0)
        self.assertEqual(hexlify(key.get_pubkey()), G_UNCOMPRESSED)

    def test_wif_payload_length_and_range(self):
        secret, compressed = addrgen.wif_payload_to_secret(raw(ONE_HEX))
        self.assertEqual(secret, raw(ONE_HEX))
        self.assertFalse(compressed)

        secret, compressed = addrgen.wif_payload_to_secret(raw(ONE_HEX) + raw('01'))
        self.assertEqual(secret, raw(ONE_HEX))
        self.assertTrue(compressed)

        self.assert_value_error(
            lambda: addrgen.wif_payload_to_secret(raw(ONE_HEX)[:-1]), 'got 31')
        self.assert_value_error(
            lambda: addrgen.wif_payload_to_secret(raw(ONE_HEX) + raw('00')), '0x01')
        self.assert_value_error(
            lambda: addrgen.wif_payload_to_secret(raw(ONE_HEX) + raw('0100')), 'got 34')
        self.assert_value_error(
            lambda: addrgen.wif_payload_to_secret(raw('00' * 32)), 'out of range')
        self.assert_value_error(
            lambda: addrgen.wif_payload_to_secret(raw(ORDER_HEX) + raw('01')), 'out of range')

    def test_gen_eckey_wif_entry(self):
        original = addrgen.base58_check_decode

        def decode(pkey, version=0):
            self.assertEqual(pkey, 'WIF')
            self.assertEqual(version, 128 + 5)
            return raw(ONE_HEX) + raw('01')

        addrgen.base58_check_decode = decode
        try:
            key = addrgen.gen_eckey(pkey='WIF', version=5)
        finally:
            addrgen.base58_check_decode = original
        self.assertTrue(key.compressed)
        self.assertEqual(hexlify(key.get_pubkey()), G_COMPRESSED)

        def decode_short(pkey, version=0):
            return raw('00' * 16)

        addrgen.base58_check_decode = decode_short
        try:
            self.assert_value_error(lambda: addrgen.gen_eckey(pkey='WIF'), 'got 16')
        finally:
            addrgen.base58_check_decode = original


if __name__ == '__main__':
    unittest.main()
