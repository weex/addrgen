"""reencode() must keep the 32-byte secret when adding the compression suffix.

Public vectors:

* Secret 0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
  from the Bitcoin wiki Wallet Import Format example (and Bitcoin Core's
  historical base58_keys_valid.json).
* Secret 0x01, whose last byte is 0x01 and must not be treated as the
  compression suffix. Same Bitcoin Core base58 key vectors.
"""

import pytest

import addrgen

# Wiki / Bitcoin Core vector. Last secret byte is 0x1d, not a suffix.
WIKI_UNCOMPRESSED = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
WIKI_COMPRESSED = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"

# Private key 1. Uncompressed payload ends in 0x01, which is secret data.
ONE_UNCOMPRESSED = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"
ONE_COMPRESSED = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"

# Same wiki secret with the testnet WIF version (0xef == 128 + 111).
TESTNET_UNCOMPRESSED = "91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2"
TESTNET_COMPRESSED = "cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx"


def test_uncompressed_wiki_vector_keeps_full_secret(capsys):
    secret = addrgen.base58_check_decode(WIKI_UNCOMPRESSED, 128)
    assert len(secret) == 32
    assert secret[-1] == 0x1D
    compressed = addrgen.reencode(WIKI_UNCOMPRESSED)
    assert compressed == WIKI_COMPRESSED
    assert addrgen.base58_check_decode(compressed, 128) == secret + b"\x01"
    assert capsys.readouterr().out == (
        "('1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK', '%s')\n" % WIKI_COMPRESSED
    )


def test_compressed_wiki_vector_round_trips(capsys):
    secret = addrgen.base58_check_decode(WIKI_COMPRESSED, 128)
    assert len(secret) == 33
    assert secret[-1] == 1
    assert addrgen.reencode(WIKI_COMPRESSED) == WIKI_COMPRESSED
    assert capsys.readouterr().out == (
        "('1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK', '%s')\n" % WIKI_COMPRESSED
    )


def test_uncompressed_secret_ending_in_compression_byte(capsys):
    secret = addrgen.base58_check_decode(ONE_UNCOMPRESSED, 128)
    assert len(secret) == 32
    assert secret[-1] == 1
    compressed = addrgen.reencode(ONE_UNCOMPRESSED)
    assert compressed == ONE_COMPRESSED
    assert compressed != ONE_UNCOMPRESSED
    assert addrgen.base58_check_decode(compressed, 128) == secret + b"\x01"
    assert capsys.readouterr().out == (
        "('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', '%s')\n" % ONE_COMPRESSED
    )


def test_compressed_secret_one_round_trips():
    assert addrgen.reencode(ONE_COMPRESSED) == ONE_COMPRESSED


def test_preserves_wif_version(capsys):
    secret = addrgen.base58_check_decode(TESTNET_UNCOMPRESSED, 128 + 111)
    assert len(secret) == 32
    compressed = addrgen.reencode(TESTNET_UNCOMPRESSED, 111)
    assert compressed == TESTNET_COMPRESSED
    assert addrgen.base58_check_decode(compressed, 128 + 111) == secret + b"\x01"
    assert capsys.readouterr().out == (
        "('n1KSZGmQgB8iSZqv6UVhGkCGUbEdw8Lm3Q', '%s')\n" % TESTNET_COMPRESSED
    )
    assert addrgen.reencode(TESTNET_COMPRESSED, 111) == TESTNET_COMPRESSED


def test_rejects_other_payload_lengths_and_bad_suffix():
    payloads = [
        b"\x02" * 31,
        b"\x02" * 34,
        b"\x02" * 30,
        b"\x02" * 32 + b"\x00",
        b"\x02" * 32 + b"\x02",
    ]
    for payload in payloads:
        wif = addrgen.base58_check_encode(payload, 128)
        with pytest.raises(ValueError):
            addrgen.reencode(wif)
