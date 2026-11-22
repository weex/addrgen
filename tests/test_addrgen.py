"""Known-answer tests for WIF and mainnet P2PKH.

Public vectors only. None of these keys should hold funds.

Sources
-------
* Bitcoin Wiki, "Wallet import format"
  https://en.bitcoin.it/wiki/Wallet_import_format
  Private key, uncompressed payload, checksum, and WIF. The compressed WIF
  is the same key with the 0x01 suffix defined on that page.
* Bitcoin Wiki, "Technical background of version 1 Bitcoin addresses"
  https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
  Private key, compressed public key, HASH160, and address
  ``1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs``. The uncompressed address
  ``16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM`` is the same example's uncompressed
  form.
* Bitcoin Core ``src/test/key_tests.cpp`` (the four WIF/address pairs and
  ``strAddressBad``) and ``src/test/base58_tests.cpp`` (the hello-world
  checksum pair).
* SEC 2 / secp256k1 generator. Private key 1, its public point, and the
  well-known WIFs and addresses for that scalar.
* Base58 samples used by Bitcoin Core ``base58_encode_decode.json``
  (``61`` -> ``2g``, and the leading-zero payload ``0000ffff`` -> ``11LUv``).

``addrgen.py`` imports on Python 3, but most of the codec and the private-key
checks still follow the Python 2 script. Cases that fail on current master
are marked ``xfail`` instead of changing the script. An XPASS means that
case now matches the vector and the marker can be removed.
"""

from __future__ import annotations

from typing import NamedTuple

import pytest

import addrgen


# Checksum and version failures must be ValueError. BaseException also
# covers KeyboardInterrupt and SystemExit, so it is not a usable error.
XFAIL_BASE58CHECK = (
    "Base58Check still uses the Python 2 hex codec and mixes str with "
    "bytes, so WIF and P2PKH encoding never run"
)
XFAIL_ADDRESS = (
    "KEY.get_secret uses true division for the BIGNUM width and pads with "
    "str, so get_addr crashes before it can return a WIF or P2PKH address"
)
XFAIL_IMPORT = (
    "WIF import decodes through str.decode('hex'), which Python 3 removed, "
    "so the compression flag and address are never checked"
)
XFAIL_CHECKSUM = (
    "checksum and version checks sit behind the Python 2 hex codec and "
    "still raise BaseException instead of ValueError"
)
XFAIL_INVALID_KEY = (
    "out-of-range scalars and malformed WIF payloads are not rejected; "
    "on Python 3 the decoder or get_secret crashes before that check"
)

# secp256k1 order. A private key must satisfy 1 <= scalar < n.
SECP256K1_ORDER = (
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
)

WIKI_WIF_SECRET = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
WIKI_P2PKH_SECRET = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
GENERATOR_SECRET = "00" * 31 + "01"

# Wiki worked example, steps 6 and 7: payload || checksum, then Base58.
WIKI_WIF_RAW = bytes.fromhex(
    "800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D"
)
WIKI_WIF_TEXT = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"

# Wiki address example, stages 4 and 8-9.
WIKI_ADDRESS_PAYLOAD = bytes.fromhex(
    "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8"
)
WIKI_ADDRESS_TEXT = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
WIKI_COMPRESSED_PUBKEY = bytes.fromhex(
    "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
)
WIKI_UNCOMPRESSED_PUBKEY = bytes.fromhex(
    "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    "2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
)
WIKI_HASH160 = bytes.fromhex("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31")

# Public key of the wiki WIF sample, checked against that sample's addresses.
WIKI_WIF_PUBKEY_UNCOMPRESSED = bytes.fromhex(
    "04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c"
    "d85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a"
)
WIKI_WIF_PUBKEY_COMPRESSED = bytes.fromhex(
    "02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c"
)

# secp256k1 generator point, private key 1.
GENERATOR_PUBKEY_UNCOMPRESSED = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
GENERATOR_PUBKEY_COMPRESSED = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)


class KnownKey(NamedTuple):
    name: str
    secret_hex: str
    compressed: bool
    wif: str
    address: str

    @property
    def secret(self) -> bytes:
        return bytes.fromhex(self.secret_hex)

    @property
    def wif_payload(self) -> bytes:
        if self.compressed:
            return self.secret + b"\x01"
        return self.secret


KNOWN_KEYS = [
    KnownKey(
        "wiki-wif-uncompressed",
        WIKI_WIF_SECRET,
        False,
        "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
        "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S",
    ),
    KnownKey(
        "wiki-wif-compressed",
        WIKI_WIF_SECRET,
        True,
        "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617",
        "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK",
    ),
    KnownKey(
        "wiki-p2pkh-uncompressed",
        WIKI_P2PKH_SECRET,
        False,
        "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V",
        "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
    ),
    KnownKey(
        "wiki-p2pkh-compressed",
        WIKI_P2PKH_SECRET,
        True,
        "Kx45GeUBSMPReYQwgXiKhG9FzNXrnCeutJp4yjTd5kKxCitadm3C",
        "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
    ),
    # Bitcoin Core src/test/key_tests.cpp. Each pair is one scalar.
    KnownKey(
        "core-1-uncompressed",
        "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747",
        False,
        "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj",
        "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ",
    ),
    KnownKey(
        "core-1-compressed",
        "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747",
        True,
        "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw",
        "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs",
    ),
    KnownKey(
        "core-2-uncompressed",
        "b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117",
        False,
        "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3",
        "1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ",
    ),
    KnownKey(
        "core-2-compressed",
        "b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117",
        True,
        "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g",
        "1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs",
    ),
    # Private key 1. The high 31 bytes are zero, so the WIF path has to
    # keep the scalar padded to 32 bytes.
    KnownKey(
        "generator-uncompressed",
        GENERATOR_SECRET,
        False,
        "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
        "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
    ),
    KnownKey(
        "generator-compressed",
        GENERATOR_SECRET,
        True,
        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
    ),
]


def _key_id(key: KnownKey) -> str:
    return key.name


# ---------------------------------------------------------------------------
# What already works: hashes, the base58 alphabet, and public-key derivation.
# ---------------------------------------------------------------------------


def test_wiki_wif_double_sha256_checksum():
    """Wiki WIF page, steps 3-5. The checksum bytes themselves are public."""
    extended = bytes.fromhex(
        "800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    )
    assert addrgen.dhash(extended)[:4] == bytes.fromhex("507A5B8D")


def test_wiki_p2pkh_hash160():
    """Wiki address page, stages 1-3, compressed public key."""
    assert addrgen.rhash(WIKI_COMPRESSED_PUBKEY) == WIKI_HASH160


@pytest.mark.parametrize(
    ("hex_payload", "text"),
    [
        ("61", "2g"),
        ("626262", "a3gV"),
        ("636363", "aPEr"),
    ],
)
def test_base58_integer_alphabet(hex_payload, text):
    """Bitcoin Core base58 vectors that have no leading zero bytes."""
    value = int(hex_payload, 16)
    assert addrgen.base58_encode(value) == text
    assert addrgen.base58_decode(text) == value


@pytest.mark.parametrize(
    "text",
    [
        "invalid",
        "bad0IOl",
        "goodbad0IOl",
        "0HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
        "OHueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
        "IHueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
        "lHueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
    ],
)
def test_base58_rejects_excluded_characters(text):
    """0, O, I, and l are not in the Base58 alphabet (Bitcoin Core).

    Both the integer decoder and the WIF decoder reject them. The WIF
    decoder fails on the alphabet before it reaches the hex codec.
    """
    with pytest.raises(ValueError):
        addrgen.base58_decode(text)
    with pytest.raises(ValueError):
        addrgen.base58_check_decode(text, 128)


@pytest.mark.parametrize(
    ("secret_hex", "compressed", "pubkey"),
    [
        (WIKI_WIF_SECRET, False, WIKI_WIF_PUBKEY_UNCOMPRESSED),
        (WIKI_WIF_SECRET, True, WIKI_WIF_PUBKEY_COMPRESSED),
        (WIKI_P2PKH_SECRET, False, WIKI_UNCOMPRESSED_PUBKEY),
        (WIKI_P2PKH_SECRET, True, WIKI_COMPRESSED_PUBKEY),
        (GENERATOR_SECRET, False, GENERATOR_PUBKEY_UNCOMPRESSED),
        (GENERATOR_SECRET, True, GENERATOR_PUBKEY_COMPRESSED),
    ],
)
def test_public_key_for_published_secret(secret_hex, compressed, pubkey):
    """OpenSSL already returns these public keys. WIF encoding does not."""
    key = addrgen.gen_eckey(secret=bytes.fromhex(secret_hex), compressed=compressed)
    assert key.compressed is compressed
    assert key.get_pubkey() == pubkey


@pytest.mark.parametrize("key", KNOWN_KEYS, ids=_key_id)
def test_compression_form_follows_the_flag(key):
    derived = addrgen.gen_eckey(secret=key.secret, compressed=key.compressed)
    pubkey = derived.get_pubkey()
    if key.compressed:
        assert len(pubkey) == 33
        assert pubkey[0] in (2, 3)
    else:
        assert len(pubkey) == 65
        assert pubkey[0] == 4


# ---------------------------------------------------------------------------
# Base58Check. These are the calls that still use the Python 2 hex codec.
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason=XFAIL_BASE58CHECK)
def test_wiki_wif_base58_payload_round_trip():
    assert addrgen.base58_encode_padded(WIKI_WIF_RAW) == WIKI_WIF_TEXT
    assert addrgen.base58_decode_padded(WIKI_WIF_TEXT) == WIKI_WIF_RAW


@pytest.mark.xfail(reason=XFAIL_BASE58CHECK)
def test_wiki_address_base58_payload_round_trip():
    """The leading 0x00 version byte has to survive as a leading '1'."""
    assert addrgen.base58_encode_padded(WIKI_ADDRESS_PAYLOAD) == WIKI_ADDRESS_TEXT
    assert addrgen.base58_decode_padded(WIKI_ADDRESS_TEXT) == WIKI_ADDRESS_PAYLOAD


@pytest.mark.xfail(reason=XFAIL_BASE58CHECK)
@pytest.mark.parametrize(
    ("raw", "text"),
    [
        (b"\x00", "1"),
        (b"\x00\x00", "11"),
        (bytes.fromhex("0000ffff"), "11LUv"),
        (b"\x01\x00", "5R"),
    ],
)
def test_base58_preserves_leading_zero_bytes(raw, text):
    """Bitcoin Core leading-zero vectors. An all-zero payload is ``n`` '1's."""
    assert addrgen.base58_encode_padded(raw) == text
    assert addrgen.base58_decode_padded(text) == raw


@pytest.mark.xfail(reason=XFAIL_BASE58CHECK)
@pytest.mark.parametrize("key", KNOWN_KEYS, ids=_key_id)
def test_wif_base58check_round_trip(key):
    assert addrgen.base58_check_encode(key.wif_payload, 128) == key.wif
    assert addrgen.base58_check_decode(key.wif, 128) == key.wif_payload


@pytest.mark.xfail(reason=XFAIL_BASE58CHECK)
def test_p2pkh_base58check_from_published_hash160():
    assert addrgen.base58_check_encode(WIKI_HASH160, 0) == WIKI_ADDRESS_TEXT
    assert addrgen.base58_check_decode(WIKI_ADDRESS_TEXT, 0) == WIKI_HASH160


@pytest.mark.xfail(reason=XFAIL_BASE58CHECK)
def test_core_base58check_hello_world_vector():
    """Bitcoin Core base58_tests.cpp: ``3vQB7B6MrGQZaxCuFg4oh`` is valid."""
    assert addrgen.base58_check_decode("3vQB7B6MrGQZaxCuFg4oh", 0x68) == b"ello world"
    assert addrgen.base58_check_encode(b"ello world", 0x68) == "3vQB7B6MrGQZaxCuFg4oh"


# ---------------------------------------------------------------------------
# Full address generation and WIF import.
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason=XFAIL_ADDRESS)
@pytest.mark.parametrize("key", KNOWN_KEYS, ids=_key_id)
def test_secret_produces_wif_and_p2pkh(key):
    address, wif = addrgen.get_addr(
        addrgen.gen_eckey(secret=key.secret, compressed=key.compressed)
    )
    assert address == key.address
    assert wif == key.wif


@pytest.mark.xfail(reason=XFAIL_IMPORT)
@pytest.mark.parametrize("key", KNOWN_KEYS, ids=_key_id)
def test_wif_import_round_trip(key):
    imported = addrgen.gen_eckey(pkey=key.wif)
    assert imported.compressed is key.compressed
    address, wif = addrgen.get_addr(imported)
    assert address == key.address
    assert wif == key.wif
    assert imported.get_secret() == key.secret


# ---------------------------------------------------------------------------
# Bad checksums and the wrong version byte.
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason=XFAIL_CHECKSUM)
@pytest.mark.parametrize(
    ("text", "version"),
    [
        # Last character of the wiki WIF flipped. Checksum was 507a5b8d.
        ("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTK", 128),
        # Last character of the wiki uncompressed address flipped.
        ("1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2T", 0),
        # Bitcoin Core: valid sibling is 3vQB7B6MrGQZaxCuFg4oh.
        ("3vQB7B6MrGQZaxCuFg4oi", 0x68),
    ],
)
def test_bad_checksum_raises_valueerror(text, version):
    with pytest.raises(ValueError, match="checksum"):
        addrgen.base58_check_decode(text, version)


@pytest.mark.xfail(reason=XFAIL_CHECKSUM)
def test_valid_wif_is_not_a_p2pkh_address():
    """Checksum matches; the version byte is 0x80, not 0x00."""
    with pytest.raises(ValueError, match="version mismatch"):
        addrgen.base58_check_decode(WIKI_WIF_TEXT, 0)


@pytest.mark.xfail(reason=XFAIL_CHECKSUM)
def test_p2pkh_address_is_not_a_private_key():
    """Bitcoin Core strAddressBad: a real address, passed to DecodeSecret."""
    address = "1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF"
    with pytest.raises(ValueError, match="version mismatch"):
        addrgen.base58_check_decode(address, 128)
    with pytest.raises(ValueError, match="version mismatch"):
        addrgen.gen_eckey(pkey=address)


# ---------------------------------------------------------------------------
# Invalid keys. Checksums are valid unless the case says otherwise; the
# scalar or the WIF shape is what must be rejected.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret_hex",
    [
        "00" * 32,
        SECP256K1_ORDER,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142",
        "FF" * 32,
    ],
    ids=["zero", "curve-order", "above-curve-order", "all-ones"],
)
def test_out_of_range_secret_rejected(secret_hex):
    secret = bytes.fromhex(secret_hex)
    with pytest.raises(ValueError):
        addrgen.get_addr(addrgen.gen_eckey(secret=secret))


@pytest.mark.parametrize(
    "wif",
    [
        # 0x80 || 32 zero bytes. Checksum is valid; the scalar is not.
        "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU",
        # 0x80 || secp256k1 order.
        "5Km2kuu7vtFDPpxywn4u3NLpbr5jKpTB3jsuDU2KYEqetwr388P",
        # 0x80 || order + 1.
        "5Km2kuu7vtFDPpxywn4u3NLpbr5jKpTB3jsuDU2KYEqetyuszSh",
    ],
    ids=["zero", "curve-order", "above-curve-order"],
)
def test_out_of_range_wif_rejected(wif):
    with pytest.raises(ValueError):
        addrgen.get_addr(addrgen.gen_eckey(pkey=wif))


@pytest.mark.parametrize(
    "wif",
    [
        # Wiki sample secret with a trailing 0x00. Early addrgen appended
        # 0x00 for compressed keys; Bitcoin requires 0x01.
        pytest.param(
            "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvHFRKf6",
            id="suffix-0x00",
            marks=pytest.mark.xfail(reason=XFAIL_INVALID_KEY),
        ),
        # Same secret with a trailing 0x02.
        pytest.param(
            "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvWxyf5d",
            id="suffix-0x02",
            marks=pytest.mark.xfail(reason=XFAIL_INVALID_KEY),
        ),
        # 0x80 || the first 31 bytes of the wiki sample secret.
        pytest.param(
            "yPoVP5njSzmEVK4VJGRWWAwqnwCyLPRcMm5XyrKgY1DE64xhu",
            id="31-byte-secret",
        ),
    ],
)
def test_malformed_wif_payload_rejected(wif):
    """Each string is valid Base58Check and still not a WIF."""
    with pytest.raises(ValueError):
        addrgen.get_addr(addrgen.gen_eckey(pkey=wif))
