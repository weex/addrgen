"""Known-answer tests for secp256k1 address generation and RIPEMD-160."""

import ast
import hashlib
import os
import random
import subprocess
import sys
import unittest
from unittest import mock

import addrgen
import ripemd160 as ripemd160_mod
from ripemd160 import _ripemd160_pure, ripemd160

ROOT = os.path.dirname(os.path.abspath(__file__))

# https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
# The current page walks the compressed key. The uncompressed public key and
# HASH160 are the same key's historical vector (and the scriptPubKey in the
# coinbin basic-transaction fixture).
WIKI_SECRET = bytes.fromhex(
    "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
)
WIKI_PUB_COMPRESSED = bytes.fromhex(
    "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
)
WIKI_SHA_COMPRESSED = bytes.fromhex(
    "0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98"
)
WIKI_HASH160_COMPRESSED = bytes.fromhex("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31")
WIKI_ADDR_COMPRESSED = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
WIKI_PUB_UNCOMPRESSED = bytes.fromhex(
    "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    "2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
)
WIKI_SHA_UNCOMPRESSED = bytes.fromhex(
    "600ffe422b4e00731a59557a5cca46cc183944191006324a447bdb2d98d4b408"
)
WIKI_HASH160_UNCOMPRESSED = bytes.fromhex("010966776006953d5567439e5e39f86a0d273bee")
WIKI_ADDR_UNCOMPRESSED = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"

# Private key 1 is the secp256k1 generator. WIF and address pairs are the
# bitcoinjs-lib and "secret exponent 1" fixtures.
KEY1 = (1).to_bytes(32, "big")
KEY1_PUB_COMPRESSED = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
KEY1_PUB_UNCOMPRESSED = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
KEY1_ADDR_COMPRESSED = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
KEY1_WIF_COMPRESSED = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
KEY1_ADDR_UNCOMPRESSED = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
KEY1_WIF_UNCOMPRESSED = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"

# https://en.bitcoin.it/wiki/Wallet_import_format
WIF_SECRET = bytes.fromhex(
    "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
)
WIF_EXTENDED = bytes.fromhex(
    "800c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d507a5b8d"
)
WIF_TEXT = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"

# Official RIPEMD-160 vectors:
# https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
RIPEMD_VECTORS = [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
    ),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
    (b"a" * 1000000, "52783243c1697bdbe16d37f97f68f08325dc1528"),
]


class Ripemd160Tests(unittest.TestCase):
    def tearDown(self):
        ripemd160_mod._impl = None

    def test_official_vectors_pure(self):
        for message, digest in RIPEMD_VECTORS:
            self.assertEqual(_ripemd160_pure(message).hex(), digest, message[:20])

    def test_official_vectors_public_api(self):
        for message, digest in RIPEMD_VECTORS:
            self.assertEqual(ripemd160(message).hex(), digest)

    def test_pure_matches_hashlib_across_block_boundaries(self):
        try:
            hashlib.new("ripemd160")
        except ValueError:
            self.skipTest("this interpreter's hashlib has no ripemd160")
        rng = random.Random(1234)
        payloads = [bytes(rng.getrandbits(8) for _ in range(length)) for length in range(0, 192)]
        payloads.append(WIKI_SHA_COMPRESSED)
        payloads.append(WIKI_SHA_UNCOMPRESSED)
        for payload in payloads:
            openssl = hashlib.new("ripemd160", payload).digest()
            self.assertEqual(_ripemd160_pure(payload), openssl)

    def test_fallback_when_hashlib_rejects_ripemd160(self):
        real_new = hashlib.new

        def fake_new(name, data=b"", *args, **kwargs):
            if name == "ripemd160":
                raise ValueError("unsupported hash type ripemd160")
            return real_new(name, data, *args, **kwargs)

        ripemd160_mod._impl = None
        with mock.patch.object(ripemd160_mod.hashlib, "new", fake_new):
            digest = ripemd160(b"abc")
            self.assertIs(ripemd160_mod._impl, _ripemd160_pure)
            # A second call must keep using the pure function without retrying OpenSSL.
            again = ripemd160(b"message digest")
        self.assertEqual(digest.hex(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        self.assertEqual(again.hex(), "5d0689ef49d2fae572b881b123a85ffa21595f36")

    def test_string_input_is_rejected(self):
        with self.assertRaises(TypeError):
            ripemd160("abc")


class AddressVectorTests(unittest.TestCase):
    def tearDown(self):
        ripemd160_mod._impl = None

    def test_base58check_wiki_address_and_wif_bytes(self):
        raw_address = bytes.fromhex(
            "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8"
        )
        self.assertEqual(addrgen.base58_encode_padded(raw_address), WIKI_ADDR_COMPRESSED)
        self.assertEqual(addrgen.base58_decode_padded(WIKI_ADDR_COMPRESSED), raw_address)
        self.assertEqual(addrgen.base58_encode_padded(WIF_EXTENDED), WIF_TEXT)
        self.assertEqual(
            addrgen.base58_check_encode(WIF_SECRET, 128),
            WIF_TEXT,
        )
        self.assertEqual(addrgen.base58_check_decode(WIF_TEXT, 128), WIF_SECRET)

    def test_leading_zero_bytes_roundtrip(self):
        self.assertEqual(addrgen.base58_encode_padded(b"\x00"), "1")
        self.assertEqual(addrgen.base58_encode_padded(b"\x00\x00"), "11")
        self.assertEqual(addrgen.base58_encode_padded(b"\x00\x0a"), "1B")
        rng = random.Random(0)
        for _ in range(40):
            data = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 40)))
            if rng.randrange(2):
                data = b"\x00" * rng.randint(1, 4) + data
            self.assertEqual(
                addrgen.base58_decode_padded(addrgen.base58_encode_padded(data)),
                data,
            )

    def test_wiki_compressed_key(self):
        self.assertEqual(hashlib.sha256(WIKI_PUB_COMPRESSED).digest(), WIKI_SHA_COMPRESSED)
        self.assertEqual(ripemd160(WIKI_SHA_COMPRESSED), WIKI_HASH160_COMPRESSED)
        self.assertEqual(addrgen.rhash(WIKI_PUB_COMPRESSED), WIKI_HASH160_COMPRESSED)
        key = addrgen.gen_eckey(secret=WIKI_SECRET, compressed=True)
        self.assertEqual(key.get_secret(), WIKI_SECRET)
        self.assertEqual(key.get_pubkey(), WIKI_PUB_COMPRESSED)
        address, wif = addrgen.get_addr(key)
        self.assertEqual(address, WIKI_ADDR_COMPRESSED)
        self.assertEqual(addrgen.base58_check_decode(wif, 128), WIKI_SECRET + b"\x01")

    def test_wiki_uncompressed_key(self):
        self.assertEqual(hashlib.sha256(WIKI_PUB_UNCOMPRESSED).digest(), WIKI_SHA_UNCOMPRESSED)
        self.assertEqual(ripemd160(WIKI_SHA_UNCOMPRESSED), WIKI_HASH160_UNCOMPRESSED)
        key = addrgen.gen_eckey(secret=WIKI_SECRET, compressed=False)
        self.assertEqual(key.get_pubkey(), WIKI_PUB_UNCOMPRESSED)
        address, wif = addrgen.get_addr(key)
        self.assertEqual(address, WIKI_ADDR_UNCOMPRESSED)
        self.assertEqual(addrgen.base58_check_decode(wif, 128), WIKI_SECRET)
        self.assertTrue(wif.startswith("5"))

    def test_generator_point_key(self):
        compressed = addrgen.gen_eckey(secret=KEY1, compressed=True)
        self.assertEqual(compressed.get_pubkey(), KEY1_PUB_COMPRESSED)
        address, wif = addrgen.get_addr(compressed)
        self.assertEqual(address, KEY1_ADDR_COMPRESSED)
        self.assertEqual(wif, KEY1_WIF_COMPRESSED)

        uncompressed = addrgen.gen_eckey(secret=KEY1, compressed=False)
        self.assertEqual(uncompressed.get_pubkey(), KEY1_PUB_UNCOMPRESSED)
        address, wif = addrgen.get_addr(uncompressed)
        self.assertEqual(address, KEY1_ADDR_UNCOMPRESSED)
        self.assertEqual(wif, KEY1_WIF_UNCOMPRESSED)

        imported, reencoded = addrgen.get_addr(addrgen.gen_eckey(pkey=KEY1_WIF_COMPRESSED))
        self.assertEqual(imported, KEY1_ADDR_COMPRESSED)
        self.assertEqual(reencoded, KEY1_WIF_COMPRESSED)

    def test_known_address_survives_ripemd160_fallback(self):
        real_new = hashlib.new

        def fake_new(name, data=b"", *args, **kwargs):
            if name == "ripemd160":
                raise ValueError("unsupported hash type ripemd160")
            return real_new(name, data, *args, **kwargs)

        ripemd160_mod._impl = None
        with mock.patch.object(ripemd160_mod.hashlib, "new", fake_new):
            address, _wif = addrgen.get_addr(
                addrgen.gen_eckey(secret=WIKI_SECRET, compressed=True)
            )
        self.assertEqual(address, WIKI_ADDR_COMPRESSED)
        self.assertIs(ripemd160_mod._impl, _ripemd160_pure)

    def test_passphrase_is_iterated_sha256(self):
        phrase = "Satoshi Nakamoto"
        once = hashlib.sha256(phrase.encode("utf-8")).digest()
        self.assertEqual(
            addrgen.get_addr(addrgen.gen_eckey(passphrase=phrase, compressed=True)),
            addrgen.get_addr(addrgen.gen_eckey(secret=once, compressed=True)),
        )
        thrice = phrase.encode("utf-8")
        for _ in range(3):
            thrice = hashlib.sha256(thrice).digest()
        self.assertEqual(
            addrgen.get_addr(addrgen.gen_eckey(passphrase=phrase, rounds=3)),
            addrgen.get_addr(addrgen.gen_eckey(secret=thrice)),
        )

    def test_comment_example_wifs_roundtrip(self):
        for wif in (
            "5K1HkbYffstTZDuV4riUWMbAMkQh57b8798uoy9pXYUDYeUHe7F",
            "L3ATL5R9Exe1ubuAnHVgNgTKZEUKkDvWYAWkLUCyyvzzxRjtgyFe",
        ):
            address, again = addrgen.get_addr(addrgen.gen_eckey(pkey=wif))
            self.assertEqual(again, wif)
            self.assertTrue(address.startswith("1"))

    def test_version_byte_and_checksum_errors(self):
        address, wif = addrgen.get_addr(
            addrgen.gen_eckey(secret=KEY1, compressed=True, version=111),
            version=111,
        )
        self.assertEqual(
            addrgen.base58_check_decode(address, 111),
            addrgen.rhash(KEY1_PUB_COMPRESSED),
        )
        self.assertEqual(addrgen.base58_check_decode(wif, 128 + 111), KEY1 + b"\x01")
        with self.assertRaises(BaseException) as mismatch:
            addrgen.base58_check_decode(address, 0)
        self.assertIn("version", str(mismatch.exception))
        broken = address[:-1] + ("X" if address[-1] != "X" else "Y")
        with self.assertRaises(BaseException) as bad_sum:
            addrgen.base58_check_decode(broken, 111)
        self.assertIn("checksum", str(bad_sum.exception))

    def test_rejects_invalid_secrets(self):
        with self.assertRaises(ValueError):
            addrgen.gen_eckey(secret=b"\x00" * 32)
        with self.assertRaises(ValueError):
            addrgen.gen_eckey(secret=b"\xff" * 32)
        with self.assertRaises(ValueError):
            addrgen.gen_eckey(secret=b"\x01")
        with self.assertRaises(ValueError):
            addrgen.gen_eckey(secret="11" * 32)

    def test_random_keys_are_compressed_on_the_default_path(self):
        first = addrgen.get_addr(addrgen.gen_eckey(compressed=True))
        second = addrgen.get_addr(addrgen.gen_eckey(compressed=True))
        self.assertNotEqual(first, second)
        for address, wif in (first, second):
            payload = addrgen.base58_check_decode(wif, 128)
            self.assertEqual(len(payload), 33)
            self.assertEqual(payload[-1:], b"\x01")
            self.assertEqual(
                addrgen.get_addr(addrgen.gen_eckey(pkey=wif))[0],
                address,
            )

    def test_source_does_not_call_deprecated_openssl(self):
        with open(os.path.join(ROOT, "addrgen.py"), encoding="utf-8") as source_file:
            source = source_file.read()
        for needle in ("EC_KEY_", "i2o_ECPublicKey", "libeay32", "ctypes", "hashlib.new"):
            self.assertNotIn(needle, source)

    def test_command_line_prints_a_valid_pair(self):
        output = subprocess.check_output(
            [sys.executable, "addrgen.py"],
            cwd=ROOT,
            text=True,
        )
        address, wif = ast.literal_eval(output.strip())
        self.assertEqual(addrgen.get_addr(addrgen.gen_eckey(pkey=wif))[0], address)

        alt = subprocess.check_output(
            [sys.executable, "addrgen.py", "--otherversion=111"],
            cwd=ROOT,
            text=True,
        )
        alt_address, alt_wif = ast.literal_eval(alt.strip())
        addrgen.base58_check_decode(alt_address, 111)
        self.assertEqual(
            len(addrgen.base58_check_decode(alt_wif, 128 + 111)),
            33,
        )


if __name__ == "__main__":
    unittest.main()
