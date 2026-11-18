#!/usr/bin/env python
# Round-trip checks for base58_encode_padded / base58_decode_padded.

import random
import unittest

import addrgen


class Base58RoundTripTests(unittest.TestCase):
    def assert_round_trip(self, raw):
        text = addrgen.base58_encode_padded(raw)
        self.assertEqual(addrgen.base58_decode_padded(text), raw)
        self.assertEqual(addrgen.base58_encode_padded(
            addrgen.base58_decode_padded(text)), text)

    def test_empty_and_all_zero(self):
        self.assertEqual(addrgen.base58_encode_padded(''), '')
        self.assertEqual(addrgen.base58_decode_padded(''), '')
        self.assert_round_trip('')
        for n in range(1, 9):
            raw = '\x00' * n
            # A string of only '1's is exactly n zero bytes, not n + 1.
            self.assertEqual(addrgen.base58_encode_padded(raw), '1' * n)
            self.assertEqual(addrgen.base58_decode_padded('1' * n), raw)
            self.assert_round_trip(raw)

    def test_leading_and_interior_zeros(self):
        samples = [
            '\x0f',
            '\x00\x0f',
            '\x00\x00\xff\xff',
            '\x01\x00',
            'hello',
            '\x00hello',
            '\xff' * 4,
            '\x00\x00\x01',
            '\x80' + '\x00' * 31,
        ]
        for raw in samples:
            self.assert_round_trip(raw)
        self.assertEqual(
            addrgen.base58_encode_padded('\x00\x00\xff\xff'), '11LUv')
        self.assertEqual(
            addrgen.base58_decode_padded('11LUv'), '\x00\x00\xff\xff')
        self.assertEqual(addrgen.base58_encode_padded('\x01\x00'), '5R')
        self.assertEqual(addrgen.base58_decode_padded('5R'), '\x01\x00')

    def test_random_payloads(self):
        rng = random.Random(0)
        for length in range(0, 33):
            for zeros in range(0, min(length, 4) + 1):
                body = ''.join(chr(rng.randrange(256))
                               for _ in range(length - zeros))
                self.assert_round_trip('\x00' * zeros + body)


if __name__ == '__main__':
    unittest.main()
