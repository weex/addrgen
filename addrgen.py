#!/usr/bin/env python
# Joric/bitcoin-dev, june 2012, public domain

import hashlib
import ctypes
import ctypes.util
import sys

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl') or 'libeay32')

class VoidP(ctypes.c_void_p):
    """Opaque pointer that ctypes will not turn into an int.

    A c_void_p restype becomes a Python int. On 64-bit platforms that int
    is truncated to 32 bits when passed into a later call, so every pointer
    OpenSSL returns uses this subclass instead.
    """
    pass


# secp256k1 private keys are 256-bit scalars, serialized big-endian.
SECRET_LEN = 32


def _require_ptr(result, func, args):
    # NULL comes back as None, not 0, when restype is a pointer.
    if not result:
        raise ValueError('%s failed' % func.__name__)
    return result


def _require_success(result, func, args):
    # These OpenSSL calls return 1 on success and 0 on error.
    if result != 1:
        raise ValueError('%s failed' % func.__name__)
    return result


def _require_positive(result, func, args):
    if result <= 0:
        raise ValueError('%s failed' % func.__name__)
    return result


def _bind(name, argtypes, restype, errcheck=None):
    fn = getattr(ssl, name)
    fn.argtypes = argtypes
    fn.restype = restype
    if errcheck is not None:
        fn.errcheck = errcheck


_char_p_p = ctypes.POINTER(ctypes.c_char_p)

_bind('EC_KEY_new_by_curve_name', [ctypes.c_int], VoidP, _require_ptr)
_bind('EC_KEY_free', [VoidP], None)
_bind('EC_KEY_generate_key', [VoidP], ctypes.c_int, _require_success)
_bind('EC_KEY_get0_group', [VoidP], VoidP, _require_ptr)
_bind('EC_KEY_get0_private_key', [VoidP], VoidP, _require_ptr)
_bind('EC_KEY_set_private_key', [VoidP, VoidP], ctypes.c_int, _require_success)
_bind('EC_KEY_set_public_key', [VoidP, VoidP], ctypes.c_int, _require_success)
_bind('EC_KEY_set_conv_form', [VoidP, ctypes.c_int], None)
_bind('BN_bin2bn', [ctypes.c_char_p, ctypes.c_int, VoidP], VoidP, _require_ptr)
_bind('BN_clear_free', [VoidP], None)
_bind('BN_num_bits', [VoidP], ctypes.c_int)
_bind('BN_bn2bin', [VoidP, ctypes.c_char_p], ctypes.c_int)
_bind('BN_CTX_new', [], VoidP, _require_ptr)
_bind('BN_CTX_free', [VoidP], None)
_bind('EC_POINT_new', [VoidP], VoidP, _require_ptr)
_bind('EC_POINT_free', [VoidP], None)
_bind('EC_POINT_mul',
      [VoidP, VoidP, VoidP, VoidP, VoidP, VoidP],
      ctypes.c_int, _require_success)
_bind('i2o_ECPublicKey', [VoidP, _char_p_p], ctypes.c_int, _require_positive)


class KEY:
    def __init__(self):
        NID_secp256k1 = 714
        self.k = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)
        self.compressed = False
        self.POINT_CONVERSION_COMPRESSED = 2
        self.POINT_CONVERSION_UNCOMPRESSED = 4

    def __del__(self):
        k = getattr(self, 'k', None)
        if k and ssl:
            ssl.EC_KEY_free(k)
            self.k = None

    def generate(self, secret=None):
        if secret is not None:
            # Length must be the buffer's real size. A hardcoded 32-byte read
            # overruns a shorter secret and silently truncates a longer one.
            if not isinstance(secret, type(b'')) or len(secret) != SECRET_LEN:
                raise ValueError('secret must be exactly %d bytes' % SECRET_LEN)
            self.prikey = secret
            priv_key = None
            pub_key = None
            ctx = None
            try:
                priv_key = ssl.BN_bin2bn(secret, len(secret), None)
                group = ssl.EC_KEY_get0_group(self.k)
                pub_key = ssl.EC_POINT_new(group)
                ctx = ssl.BN_CTX_new()
                ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
                ssl.EC_KEY_set_private_key(self.k, priv_key)
                ssl.EC_KEY_set_public_key(self.k, pub_key)
            finally:
                # EC_KEY_set_private_key copies the scalar. Wipe the temporary.
                if pub_key:
                    ssl.EC_POINT_free(pub_key)
                if ctx:
                    ssl.BN_CTX_free(ctx)
                if priv_key:
                    ssl.BN_clear_free(priv_key)
        else:
            ssl.EC_KEY_generate_key(self.k)
        return self.k

    def get_pubkey(self):
        size = ssl.i2o_ECPublicKey(self.k, None)
        expect = 33 if self.compressed else 65
        if size != expect:
            raise ValueError('unexpected public key length %s' % size)
        mb = ctypes.create_string_buffer(size)
        # i2o writes through *out and then advances that pointer.
        buf_ptr = ctypes.c_char_p(ctypes.addressof(mb))
        written = ssl.i2o_ECPublicKey(self.k, ctypes.byref(buf_ptr))
        if written != size:
            raise ValueError('i2o_ECPublicKey wrote %s bytes, expected %s' % (written, size))
        return mb.raw

    def get_secret(self):
        bn = ssl.EC_KEY_get0_private_key(self.k)
        nbytes = (ssl.BN_num_bits(bn) + 7) / 8
        mb = ctypes.create_string_buffer(nbytes)
        n = ssl.BN_bn2bin(bn, mb)
        if n != nbytes:
            raise ValueError('BN_bn2bin failed')
        return mb.raw.rjust(SECRET_LEN, chr(0))

    def set_compressed(self, compressed):
        self.compressed = compressed
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        ssl.EC_KEY_set_conv_form(self.k, form)

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(b58_digits[r]))
    return ''.join(l)

def base58_decode(s):
    n = 0
    for ch in s:
        n *= 58
        digit = b58_digits.index(ch)
        n += digit
    return n

def base58_encode_padded(s):
    res = base58_encode(int('0x' + s.encode('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def base58_decode_padded(s):
    pad = 0
    for c in s:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    h = '%x' % base58_decode(s)
    if len(h) % 2:
        h = '0' + h
    res = h.decode('hex')
    return chr(0) * pad + res

def base58_check_encode(s, version=0):
    vs = chr(version) + s
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)

def base58_check_decode(s, version=0):
    k = base58_decode_padded(s)
    v0, data, check0 = k[0], k[1:-4], k[-4:]
    check1 = dhash(v0 + data)[:4]
    if check0 != check1:
        raise BaseException('checksum error')
    if version != ord(v0):
        raise BaseException('version mismatch')
    return data

def gen_eckey(passphrase=None, secret=None, pkey=None, compressed=False, rounds=1, version=0):
    k = KEY()
    if passphrase:
        secret = passphrase.encode('utf8')
        for i in xrange(rounds):
            secret = hashlib.sha256(secret).digest()
    if pkey:
        secret = base58_check_decode(pkey, 128+version)
        compressed = len(secret) == 33
        secret = secret[0:32]
    k.generate(secret)
    k.set_compressed(compressed)
    return k

def get_addr(k,version=0):
    pubkey = k.get_pubkey()
    secret = k.get_secret()
    hash160 = rhash(pubkey)
    addr = base58_check_encode(hash160,version)
    payload = secret
    if k.compressed:
        payload = secret + chr(1)
    pkey = base58_check_encode(payload, 128+version)
    return addr, pkey

def reencode(pkey,version=0):
    payload = base58_check_decode(pkey,128+version)
    secret = payload[:-1]
    payload = secret + chr(1)
    pkey = base58_check_encode(payload, 128+version)
    print(get_addr(gen_eckey(pkey)))

def test(otherversion):
    # random compressed
    print(get_addr(gen_eckey(compressed=True,version=otherversion),version=otherversion))

    # uncomment these to create addresses via a different method
    # random uncompressed
    #print get_addr(gen_eckey())
    # by secret
    #print get_addr(gen_eckey(secret=('%064x' % 0xdeadbabe).decode('hex')))
    # by passphrase
    #print get_addr(gen_eckey(passphrase='Satoshi Nakamoto'))
    # by private key
    #print get_addr(gen_eckey(pkey='5K1HkbYffstTZDuV4riUWMbAMkQh57b8798uoy9pXYUDYeUHe7F'))
    #print get_addr(gen_eckey(pkey='L3ATL5R9Exe1ubuAnHVgNgTKZEUKkDvWYAWkLUCyyvzzxRjtgyFe'))

    # uncomment this to reencode the private keys created by early versions of this script
    #reencode(sys.argv[1])

if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option("--otherversion", dest="otherversion", default=0,
                    help="Generate address with different version number")
    (options, args) = parser.parse_args()
 
    test(int(options.otherversion))
