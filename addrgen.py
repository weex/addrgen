#!/usr/bin/env python
# Joric/bitcoin-dev, june 2012, public domain

import hashlib
import ctypes
import ctypes.util
import sys
import atexit
import weakref

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl') or 'libeay32')

# __del__ can run after libcrypto is gone. The atexit hook is registered after
# the first OpenSSL call so keys are wiped while the library is still loaded.
_libssl_alive = True
_live_keys = weakref.WeakSet()
_release_registered = False

def _release_keys():
    global _libssl_alive
    for key in list(_live_keys):
        try:
            key.free()
        except Exception:
            pass
    _libssl_alive = False

def _ensure_release_hook():
    global _release_registered
    if _release_registered:
        return
    atexit.register(_release_keys)
    _release_registered = True

def check_result (val, func, args):
    if val == 0: raise ValueError 
    else: return ctypes.c_void_p (val)

ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.errcheck = check_result

class VoidP(ctypes.c_void_p) :
    pass

ssl.BN_bin2bn.restype = VoidP
ssl.BN_new.restype = VoidP
ssl.EC_KEY_generate_key.restype = VoidP
ssl.EC_KEY_get0_group.restype = VoidP
ssl.EC_KEY_get0_private_key.restype = VoidP
ssl.BN_CTX_new.restype = VoidP
ssl.EC_POINT_new.restype = VoidP
ssl.BN_clear_free.argtypes = [ctypes.c_void_p]
ssl.BN_clear_free.restype = None

class KEY:
    def __init__(self):
        NID_secp256k1 = 714
        self.k = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)
        self.compressed = False
        self.POINT_CONVERSION_COMPRESSED = 2
        self.POINT_CONVERSION_UNCOMPRESSED = 4
        _live_keys.add(self)
        _ensure_release_hook()

    def free(self):
        # Drop the registration first so atexit will not free this key twice.
        try:
            _live_keys.discard(self)
        except Exception:
            pass
        k = getattr(self, 'k', None)
        self.k = None
        if not k or not _libssl_alive:
            return
        ssl.EC_KEY_free(k)

    def __del__(self):
        # Interpreter shutdown may have already unloaded libcrypto.
        try:
            self.free()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.free()
        return False

    def generate(self, secret=None):
        if secret:
            # EC_KEY_set_private_key copies the scalar. Wipe this temporary.
            priv_key = ssl.BN_bin2bn(secret, 32, ssl.BN_new())
            group = ssl.EC_KEY_get0_group(self.k)
            pub_key = ssl.EC_POINT_new(group)
            ctx = ssl.BN_CTX_new()
            try:
                ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
                ssl.EC_KEY_set_private_key(self.k, priv_key)
                ssl.EC_KEY_set_public_key(self.k, pub_key)
            finally:
                # Wipe the secret before releasing the public point or BN_CTX.
                ssl.BN_clear_free(priv_key)
                ssl.EC_POINT_free(pub_key)
                ssl.BN_CTX_free(ctx)
            return self.k
        else:
            return ssl.EC_KEY_generate_key(self.k)

    def get_pubkey(self):
        size = ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw

    def get_secret(self):
        bn = ssl.EC_KEY_get0_private_key(self.k);
        bytes = (ssl.BN_num_bits(bn) + 7) / 8
        mb = ctypes.create_string_buffer(bytes)
        ssl.BN_bn2bin(bn, mb);
        try:
            # mb.raw is a copy, so wiping mb does not erase the returned secret.
            return mb.raw.rjust(32, chr(0))
        finally:
            ctypes.memset(mb, 0, len(mb))

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
    try:
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
    except Exception:
        k.free()
        raise
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

def warn_private_key_on_tty():
    # A terminal keeps the key in scrollback. A redirect such as "> key.txt"
    # writes that same secret to a file, so mention both when someone is at a TTY.
    try:
        if not sys.stdout.isatty():
            return
    except Exception:
        return
    sys.stderr.write(
        "warning: printing a private key to the terminal. "
        "It may remain in scrollback, and redirecting stdout to a file stores the key on disk.\n"
    )

def reencode(pkey,version=0):
    payload = base58_check_decode(pkey,128+version)
    secret = payload[:-1]
    payload = secret + chr(1)
    pkey = base58_check_encode(payload, 128+version)
    with gen_eckey(pkey) as k:
        result = get_addr(k)
        warn_private_key_on_tty()
        print(result)

def test(otherversion):
    # random compressed
    with gen_eckey(compressed=True, version=otherversion) as k:
        result = get_addr(k, version=otherversion)
        warn_private_key_on_tty()
        print(result)

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
