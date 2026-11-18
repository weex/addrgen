#!/usr/bin/env python
"""base58_check_decode reports bad checksums and versions as ValueError.

The padded decoder and double-SHA256 are stubbed. Those helpers still use
Python 2 hex codecs and accept 8-bit strings; this test only covers the
checksum and version checks.
"""

import unittest

import addrgen


class Base58CheckDecodeTests(unittest.TestCase):
    def setUp(self):
        self._decode_padded = addrgen.base58_decode_padded
        self._dhash = addrgen.dhash

    def tearDown(self):
        addrgen.base58_decode_padded = self._decode_padded
        addrgen.dhash = self._dhash

    def install(self, decoded, digest):
        def decode_padded(s):
            self.seen_input = s
            return decoded

        def dhash(s):
            self.seen_hashed = s
            return digest

        addrgen.base58_decode_padded = decode_padded
        addrgen.dhash = dhash

    def test_checksum_error_is_valueerror(self):
        # Version byte 0x00, payload "abcd", checksum that will not match.
        self.install('\x00abcdXXXX', 'YYYY')
        with self.assertRaises(ValueError) as caught:
            addrgen.base58_check_decode('token', 0)
        self.assertEqual(str(caught.exception), 'checksum error')
        self.assertIs(type(caught.exception), ValueError)
        self.assertEqual(self.seen_input, 'token')
        self.assertEqual(self.seen_hashed, '\x00abcd')

    def test_corrupt_checksum_is_reported_before_version(self):
        # Wrong checksum and a version byte that is not the expected one.
        self.install('\x05abcdXXXX', 'YYYY')
        with self.assertRaises(ValueError) as caught:
            addrgen.base58_check_decode('token', 0)
        self.assertEqual(str(caught.exception), 'checksum error')

    def test_version_mismatch_names_expected_and_actual(self):
        # Valid checksum, address version 0 decoded as a WIF version (128).
        self.install('\x00abcdWXYZ', 'WXYZ')
        with self.assertRaises(ValueError) as caught:
            addrgen.base58_check_decode('token', 128)
        self.assertEqual(
            str(caught.exception),
            'version mismatch: expected 128, got 0')
        self.assertIs(type(caught.exception), ValueError)

    def test_matching_checksum_and_version_returns_payload(self):
        self.install('\x6fabcdWXYZ', 'WXYZ')
        self.assertEqual(addrgen.base58_check_decode('token', 111), 'abcd')

    def test_valueerror_is_caught_without_system_exits(self):
        self.install('\x00abcdXXXX', 'YYYY')
        try:
            addrgen.base58_check_decode('token', 0)
        except (KeyboardInterrupt, SystemExit):
            self.fail('checksum failure raised KeyboardInterrupt or SystemExit')
        except ValueError as exc:
            self.assertEqual(str(exc), 'checksum error')
        else:
            self.fail('checksum failure did not raise')


if __name__ == '__main__':
    unittest.main()
