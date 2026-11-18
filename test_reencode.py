#!/usr/bin/env python
"""Tests for addrgen.reencode.

Public vectors:

* Secret 0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
  from the Bitcoin wiki Wallet Import Format example (and Bitcoin Core's
  historical base58_keys_valid.json).
* Secret 0x01, whose last byte is 0x01 and must not be treated as the
  compression suffix. Same Bitcoin Core base58 key vectors.
"""

import sys
import unittest

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import addrgen

# Wiki / Bitcoin Core vector. Last secret byte is 0x1d, not a suffix.
WIKI_UNCOMPRESSED = '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
WIKI_COMPRESSED = 'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'

# Private key 1. Uncompressed payload ends in 0x01, which is secret data.
ONE_UNCOMPRESSED = '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf'
ONE_COMPRESSED = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'

# Same wiki secret with the testnet WIF version (0xef == 128 + 111).
TESTNET_UNCOMPRESSED = '91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2'
TESTNET_COMPRESSED = 'cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx'


class ReencodeTests(unittest.TestCase):
    def reencode(self, wif, version=0):
        buf = StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            result = addrgen.reencode(wif, version)
        finally:
            sys.stdout = old_stdout
        self.assertEqual(buf.getvalue(), result + '\n')
        return result

    def test_uncompressed_wiki_vector_keeps_full_secret(self):
        secret = addrgen.base58_check_decode(WIKI_UNCOMPRESSED, 128)
        self.assertEqual(len(secret), 32)
        self.assertEqual(ord(secret[-1]), 0x1d)
        compressed = self.reencode(WIKI_UNCOMPRESSED)
        self.assertEqual(compressed, WIKI_COMPRESSED)
        self.assertEqual(
            addrgen.base58_check_decode(compressed, 128),
            secret + chr(1))

    def test_compressed_wiki_vector_round_trips(self):
        secret = addrgen.base58_check_decode(WIKI_COMPRESSED, 128)
        self.assertEqual(len(secret), 33)
        self.assertEqual(ord(secret[-1]), 1)
        self.assertEqual(self.reencode(WIKI_COMPRESSED), WIKI_COMPRESSED)

    def test_uncompressed_secret_ending_in_compression_byte(self):
        secret = addrgen.base58_check_decode(ONE_UNCOMPRESSED, 128)
        self.assertEqual(len(secret), 32)
        self.assertEqual(ord(secret[-1]), 1)
        compressed = self.reencode(ONE_UNCOMPRESSED)
        self.assertEqual(compressed, ONE_COMPRESSED)
        self.assertNotEqual(compressed, ONE_UNCOMPRESSED)
        self.assertEqual(
            addrgen.base58_check_decode(compressed, 128),
            secret + chr(1))

    def test_compressed_secret_one_round_trips(self):
        self.assertEqual(self.reencode(ONE_COMPRESSED), ONE_COMPRESSED)

    def test_preserves_wif_version(self):
        secret = addrgen.base58_check_decode(TESTNET_UNCOMPRESSED, 128 + 111)
        self.assertEqual(len(secret), 32)
        compressed = self.reencode(TESTNET_UNCOMPRESSED, 111)
        self.assertEqual(compressed, TESTNET_COMPRESSED)
        self.assertEqual(
            addrgen.base58_check_decode(compressed, 128 + 111),
            secret + chr(1))
        self.assertEqual(self.reencode(TESTNET_COMPRESSED, 111), TESTNET_COMPRESSED)

    def test_rejects_other_payload_lengths_and_bad_suffix(self):
        payloads = [
            chr(2) * 31,
            chr(2) * 34,
            chr(2) * 30,
            chr(2) * 32 + chr(0),
            chr(2) * 32 + chr(2),
        ]
        for payload in payloads:
            wif = addrgen.base58_check_encode(payload, 128)
            self.assertRaises(ValueError, self.reencode, wif)


if __name__ == '__main__':
    unittest.main()
