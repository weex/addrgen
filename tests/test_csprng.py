"""New private keys come from the OS CSPRNG, not from the crypto library."""

import pytest

import addrgen


def test_prefers_secrets_token_bytes(monkeypatch):
    calls = []

    def fake(n):
        calls.append(n)
        return b'\x42' * n

    monkeypatch.setattr(addrgen.secrets, 'token_bytes', fake)
    assert addrgen.os_random_bytes(32) == b'\x42' * 32
    assert calls == [32]


def test_falls_back_to_os_urandom(monkeypatch):
    calls = []

    def fake(n):
        calls.append(n)
        return b'\x24' * n

    monkeypatch.setattr(addrgen, 'secrets', None)
    monkeypatch.setattr(addrgen.os, 'urandom', fake)
    assert addrgen.os_random_bytes(32) == b'\x24' * 32
    assert calls == [32]


def test_scalar_bounds():
    n = addrgen.SECP256K1_ORDER
    assert not addrgen.secret_in_range(b'\x00' * 32)
    assert not addrgen.secret_in_range(n.to_bytes(32, 'big'))
    assert not addrgen.secret_in_range(b'\xff' * 32)
    assert not addrgen.secret_in_range(b'\x01' * 31)
    assert addrgen.secret_in_range((1).to_bytes(32, 'big'))
    assert addrgen.secret_in_range((n - 1).to_bytes(32, 'big'))


def test_retries_out_of_range_samples(monkeypatch):
    n = addrgen.SECP256K1_ORDER
    valid = (n - 1).to_bytes(32, 'big')
    samples = [b'\x00' * 32, n.to_bytes(32, 'big'), b'\xff' * 32, valid]

    def fake(nbytes):
        assert nbytes == 32
        return samples.pop(0)

    monkeypatch.setattr(addrgen, 'os_random_bytes', fake)
    assert addrgen.random_secret() == valid
    assert samples == []


def test_short_rng_output_fails(monkeypatch):
    monkeypatch.setattr(addrgen, 'os_random_bytes', lambda n: b'\x11')
    with pytest.raises(RuntimeError, match='expected 32'):
        addrgen.random_secret()


def test_stuck_rng_fails(monkeypatch):
    monkeypatch.setattr(addrgen, 'os_random_bytes', lambda n: b'\x00' * 32)
    with pytest.raises(RuntimeError, match=r'\[1, n-1\]'):
        addrgen.random_secret()


def test_generate_passes_an_os_secret_into_coincurve(monkeypatch):
    seen = []
    real = addrgen.PrivateKey

    def wrapped(secret=None, *args, **kwargs):
        seen.append(secret)
        assert secret is not None
        return real(secret, *args, **kwargs)

    monkeypatch.setattr(addrgen, 'PrivateKey', wrapped)
    key = addrgen.KEY()
    key.generate()
    key.set_compressed(True)
    assert seen == [key.get_secret()]
    assert addrgen.secret_in_range(key.get_secret())
    again = addrgen.KEY()
    again.generate(key.get_secret())
    again.set_compressed(True)
    assert again.get_pubkey() == key.get_pubkey()


def test_caller_supplied_secret_is_not_replaced():
    secret = (1).to_bytes(32, 'big')
    key = addrgen.KEY()
    key.generate(secret)
    assert key.get_secret() == secret


def test_live_rng_is_in_range_and_not_constant():
    samples = [addrgen.random_secret() for _ in range(8)]
    assert len(set(samples)) > 1
    for raw in samples:
        assert addrgen.secret_in_range(raw)
