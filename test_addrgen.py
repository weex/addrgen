#!/usr/bin/env python3
"""Known-answer tests for compressed and uncompressed WIF and P2PKH.

Published vectors (do not send coins to these addresses):

- Bitcoin Wiki, "Wallet import format":
  https://en.bitcoin.it/wiki/Wallet_import_format
  The page publishes the private key and the uncompressed WIF. The compressed
  WIF is that same key with the 0x01 suffix defined on the page.
- Bitcoin Core src/test/key_tests.cpp publishes the four WIF/address pairs.

A secret with a leading 0x00 and a secret with interior 0x00 bytes cover
left-padding and embedded NUL bytes. Those two are not published vectors;
their addresses were checked with an independent secp256k1 implementation.
"""

import os
import subprocess
import sys
import unittest

import addrgen

ROOT = os.path.dirname(os.path.abspath(__file__))

WIKI_SECRET = bytes.fromhex(
    '0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D')

# secret, compressed, wif, p2pkh address, pubkey hex
CASES = [
    (
        WIKI_SECRET,
        False,
        '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ',
        '1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S',
        '04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c'
        'd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a',
    ),
    (
        WIKI_SECRET,
        True,
        'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617',
        '1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK',
        '02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c',
    ),
    # Bitcoin Core key_tests.cpp, first secret, both forms.
    (
        bytes.fromhex('12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747'),
        False,
        '5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj',
        '1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ',
        None,
    ),
    (
        bytes.fromhex('12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747'),
        True,
        'Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw',
        '1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs',
        None,
    ),
    # Bitcoin Core key_tests.cpp, second secret, both forms.
    (
        bytes.fromhex('b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117'),
        False,
        '5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3',
        '1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ',
        None,
    ),
    (
        bytes.fromhex('b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117'),
        True,
        'L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g',
        '1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs',
        None,
    ),
    # Top byte is 0x00, so BN_bn2bin omits it and get_secret must left-pad.
    (
        bytes.fromhex('000c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa'),
        False,
        '5HpJo479wUgNTL5jePwAXtwuhtJzbFn2kbtVBdgeZjPT8UYqrwp',
        '17hJxygMXRSux9bDiB1Jt4Pcf5VxPkwfA8',
        '040b0310538394f7fe0a3e512d76c8c598e36712ae8ea8bd05e28fb98791c823e7'
        'b38d674f245539253e612da77a78d48ba09e49a66938081fbfdc38a6dfb3d8d2',
    ),
    (
        bytes.fromhex('000c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa'),
        True,
        'KwDoYGiATTAmhDDuE4E55NHMdTURCCDkjSzFPvuzoU66KkDkUtbQ',
        '15Jp2BhgPhNmiQw7LWQRvxd6cw4JfjvKUr',
        '020b0310538394f7fe0a3e512d76c8c598e36712ae8ea8bd05e28fb98791c823e7',
    ),
    # Interior 0x00 bytes must be preserved in the secret and in the WIF.
    (
        bytes.fromhex('0c28fca386c7a227600b2fe50b7cae11000000001fbe471be89827e19d72aa1d'),
        False,
        '5HueCGU8rMjxEXxiPuD5BDkqmEeTKzjP9tCBHKhgCh29TuRCxDb',
        '1HLfaALuQcQnEK8tDw6BRHb6oBBUCqJcJq',
        None,
    ),
    (
        bytes.fromhex('0c28fca386c7a227600b2fe50b7cae11000000001fbe471be89827e19d72aa1d'),
        True,
        'KwdMAjGmerYanjeui5SHS7JWEFEKCqp4nCxLP3YY2be4MjLsudnW',
        '1Phfyf2NhpmhyQvZhNY7bSRNWAZf2hh1zL',
        None,
    ),
]


class AddrgenTests(unittest.TestCase):
    def test_wiki_wif_payload_bytes(self):
        # Steps 6 and 7 of the wiki worked example, including the checksum.
        raw = bytes.fromhex(
            '800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D'
            '507A5B8D')
        text = '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
        self.assertEqual(addrgen.base58_encode_padded(raw), text)
        self.assertEqual(addrgen.base58_decode_padded(text), raw)

    def test_leading_zero_bytes_in_base58(self):
        self.assertEqual(addrgen.base58_encode_padded(b'\x00'), '1')
        self.assertEqual(addrgen.base58_decode_padded('1'), b'\x00')
        self.assertEqual(addrgen.base58_encode_padded(b'\x00\x00'), '11')
        self.assertEqual(addrgen.base58_decode_padded('11'), b'\x00\x00')
        self.assertEqual(addrgen.base58_encode_padded(bytes.fromhex('0000ffff')), '11LUv')
        self.assertEqual(addrgen.base58_decode_padded('11LUv'), bytes.fromhex('0000ffff'))
        # An interior zero must survive a round trip (not only leading ones).
        self.assertEqual(addrgen.base58_encode_padded(b'\x01\x00'), '5R')
        self.assertEqual(addrgen.base58_decode_padded('5R'), b'\x01\x00')

    def test_known_wif_and_p2pkh(self):
        for secret, compressed, wif, address, pubkey in CASES:
            key = addrgen.gen_eckey(secret=secret, compressed=compressed)
            got_addr, got_wif = addrgen.get_addr(key)
            self.assertEqual(got_wif, wif)
            self.assertEqual(got_addr, address)
            self.assertEqual(key.get_secret(), secret)
            pub = key.get_pubkey()
            if compressed:
                self.assertEqual(len(pub), 33)
                self.assertIn(pub[:1], (b'\x02', b'\x03'))
            else:
                self.assertEqual(len(pub), 65)
                self.assertEqual(pub[:1], b'\x04')
            if pubkey is not None:
                self.assertEqual(pub.hex(), pubkey)

            # Importing the WIF must select the same compression flag.
            imported = addrgen.gen_eckey(pkey=wif)
            imp_addr, imp_wif = addrgen.get_addr(imported)
            self.assertEqual(imp_addr, address)
            self.assertEqual(imp_wif, wif)
            self.assertEqual(imported.get_secret(), secret)
            self.assertEqual(imported.compressed, compressed)

    def test_rejects_bad_checksum_and_version(self):
        good = '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
        bad = good[:-1] + ('K' if good[-1] != 'K' else 'L')
        with self.assertRaises(BaseException):
            addrgen.base58_check_decode(bad, 128)
        with self.assertRaises(BaseException):
            addrgen.base58_check_decode(good, 0)

    def test_random_keys_round_trip(self):
        for compressed, prefixes in ((True, 'KL'), (False, '5')):
            address, wif = addrgen.get_addr(addrgen.gen_eckey(compressed=compressed))
            self.assertTrue(address.startswith('1'), address)
            self.assertIn(wif[0], prefixes)
            again, wif2 = addrgen.get_addr(addrgen.gen_eckey(pkey=wif))
            self.assertEqual(again, address)
            self.assertEqual(wif2, wif)

    def test_cli_prints_compressed_pair(self):
        script = os.path.join(ROOT, 'addrgen.py')
        out = subprocess.check_output([sys.executable, script], text=True, cwd=ROOT)
        self.assertRegex(
            out.strip(),
            r"\('1[1-9A-HJ-NP-Za-km-z]+', '[KL][1-9A-HJ-NP-Za-km-z]+'\)")
        # Executing the file directly must honor the python3 shebang.
        out = subprocess.check_output([script], text=True, cwd=ROOT)
        self.assertRegex(
            out.strip(),
            r"\('1[1-9A-HJ-NP-Za-km-z]+', '[KL][1-9A-HJ-NP-Za-km-z]+'\)")


if __name__ == '__main__':
    unittest.main()
