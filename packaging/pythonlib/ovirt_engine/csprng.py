#
# ovirt-engine -- ovirt engine
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""The random bytes every secret of this product is made from.

Keys, nonces, salts and generated passwords all come from here, out of a
Hash_DRBG over SHA-256 at 256-bit security strength (NIST SP 800-90A, and the
Hash_DRBG of the Korean approved random bit generators). The operating system
generator - getrandom(2), what os.urandom() reads - is not replaced: it is the
entropy the DRBG is seeded and reseeded from, which is the place the standard
gives it.

The DRBG is OpenSSL's own, reached through its EVP_RAND interface, in a
context of its own. Nothing is configured process-wide, so the TLS of this
process and every other program on the host keep the generator they had.

When libcrypto offers no Hash_DRBG - an OpenSSL older than 3.0, a library that
cannot be loaded - the bytes come from os.urandom() instead, as they always
did, and describe() says so. Refusing to produce a key would stop setup and
the encryptor outright; reporting the generator in use leaves that judgment
to the security verification, which checks it.
"""

import ctypes
import ctypes.util
import logging
import os
import threading


MECHANISM = 'Hash_DRBG'
DIGEST = 'SHA256'
STRENGTH = 256

# What every instance of this generator mixes in, so that its output cannot
# be mistaken for any other DRBG's on the same host (SP 800-90A 8.7.1).
PERSONALIZATION = b'ovirt-engine csprng v1'

# A Hash_DRBG answers at most 2^19 bits a request; asking for less keeps the
# loop simple and well inside every implementation's limit.
_MAX_REQUEST = 4096

_OSSL_PARAM_UNSIGNED_INTEGER = 2
_OSSL_PARAM_UTF8_STRING = 4
_OSSL_PARAM_OCTET_STRING = 5
_OSSL_PARAM_UNMODIFIED = ctypes.c_size_t(-1).value

_log = logging.getLogger(__name__)


class _OsslParam(ctypes.Structure):
    _fields_ = [
        ('key', ctypes.c_char_p),
        ('data_type', ctypes.c_uint),
        ('data', ctypes.c_void_p),
        ('data_size', ctypes.c_size_t),
        ('return_size', ctypes.c_size_t),
    ]


class DrbgUnavailable(Exception):
    """libcrypto could not give a Hash_DRBG."""


def _load_libcrypto():
    for name in (ctypes.util.find_library('crypto'), 'libcrypto.so.3'):
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            continue
        if hasattr(lib, 'EVP_RAND_fetch'):
            return lib
    raise DrbgUnavailable('libcrypto with EVP_RAND (OpenSSL 3) not found')


def _bind(lib):
    vp = ctypes.c_void_p
    lib.EVP_RAND_fetch.restype = vp
    lib.EVP_RAND_fetch.argtypes = [vp, ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_RAND_free.restype = None
    lib.EVP_RAND_free.argtypes = [vp]
    lib.EVP_RAND_CTX_new.restype = vp
    lib.EVP_RAND_CTX_new.argtypes = [vp, vp]
    lib.EVP_RAND_CTX_free.restype = None
    lib.EVP_RAND_CTX_free.argtypes = [vp]
    lib.EVP_RAND_enable_locking.restype = ctypes.c_int
    lib.EVP_RAND_enable_locking.argtypes = [vp]
    lib.EVP_RAND_instantiate.restype = ctypes.c_int
    lib.EVP_RAND_instantiate.argtypes = [
        vp, ctypes.c_uint, ctypes.c_int,
        ctypes.c_char_p, ctypes.c_size_t, vp,
    ]
    lib.EVP_RAND_generate.restype = ctypes.c_int
    lib.EVP_RAND_generate.argtypes = [
        vp, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint, ctypes.c_int,
        ctypes.c_char_p, ctypes.c_size_t,
    ]
    lib.EVP_RAND_CTX_set_params.restype = ctypes.c_int
    lib.EVP_RAND_CTX_set_params.argtypes = [vp, vp]
    return lib


def _params(**values):
    """An OSSL_PARAM array, kept alive by the buffers returned beside it.

    A str is a UTF-8 string, bytes an octet string, an int an unsigned int.
    """
    keep = []
    array = (_OsslParam * (len(values) + 1))()
    for index, (key, value) in enumerate(values.items()):
        key_buffer = ctypes.create_string_buffer(key.encode('ascii'))
        if isinstance(value, str):
            data = ctypes.create_string_buffer(value.encode('ascii'))
            kind, size = _OSSL_PARAM_UTF8_STRING, len(value)
        elif isinstance(value, bytes):
            data = ctypes.create_string_buffer(value, len(value))
            kind, size = _OSSL_PARAM_OCTET_STRING, len(value)
        else:
            data = ctypes.c_uint(value)
            kind, size = _OSSL_PARAM_UNSIGNED_INTEGER, ctypes.sizeof(data)
        keep.extend((key_buffer, data))
        array[index] = _OsslParam(
            ctypes.cast(key_buffer, ctypes.c_char_p),
            kind,
            ctypes.cast(ctypes.pointer(data), ctypes.c_void_p),
            size,
            _OSSL_PARAM_UNMODIFIED,
        )
    return array, keep


class HashDrbg(object):
    """One instantiated OpenSSL Hash_DRBG over SHA-256.

    seed_source names the OpenSSL generator it is seeded from: SEED-SRC, the
    operating system, in use; TEST-RAND, which hands back given bytes, only
    in the known-answer test.
    """

    def __init__(self, lib=None, seed_source=b'SEED-SRC', seed_params=None):
        self._lib = lib or _bind(_load_libcrypto())
        self._lock = threading.Lock()
        parent = self._new_context(seed_source, None)
        self._owned_parent = parent
        if seed_params:
            array, keep = _params(**seed_params)
            if self._lib.EVP_RAND_CTX_set_params(parent, array) != 1:
                raise DrbgUnavailable(
                    '%s refused its parameters' % seed_source.decode())
            self._seed_keep = keep
        self._ctx = self._new_context(b'HASH-DRBG', parent)
        params, self._keep = _params(digest=DIGEST)
        if self._lib.EVP_RAND_CTX_set_params(self._ctx, params) != 1:
            raise DrbgUnavailable('Hash_DRBG refused digest %s' % DIGEST)

    def _new_context(self, name, parent):
        rand = self._lib.EVP_RAND_fetch(None, name, None)
        if not rand:
            raise DrbgUnavailable('%s is not available' % name.decode())
        try:
            ctx = self._lib.EVP_RAND_CTX_new(rand, parent)
        finally:
            self._lib.EVP_RAND_free(rand)
        if not ctx:
            raise DrbgUnavailable('cannot create %s' % name.decode())
        # Locked, because this context is shared by every thread that asks.
        self._lib.EVP_RAND_enable_locking(ctx)
        return ctx

    def instantiate(self, personalization=PERSONALIZATION):
        if self._lib.EVP_RAND_instantiate(
                self._owned_parent, STRENGTH, 0, None, 0, None) != 1:
            raise DrbgUnavailable('the seed source cannot instantiate')
        if self._lib.EVP_RAND_instantiate(
                self._ctx, STRENGTH, 0,
                personalization, len(personalization), None) != 1:
            raise DrbgUnavailable('Hash_DRBG cannot instantiate')
        return self

    def generate(self, count, additional_input=None):
        out = ctypes.create_string_buffer(count)
        done = 0
        with self._lock:
            while done < count:
                size = min(_MAX_REQUEST, count - done)
                chunk = ctypes.create_string_buffer(size)
                if self._lib.EVP_RAND_generate(
                        self._ctx, chunk, size, STRENGTH, 0,
                        additional_input,
                        len(additional_input) if additional_input else 0,
                ) != 1:
                    raise DrbgUnavailable('Hash_DRBG generate failed')
                ctypes.memmove(ctypes.byref(out, done), chunk, size)
                done += size
        return out.raw[:count]


_lock = threading.Lock()
_generator = None
_description = None


# The known answer: a Hash_DRBG over SHA-256 instantiated from the entropy
# 00..1f, the nonce 20..2f and the personalization below, asked twice for 64
# bytes, answers this the second time. Worked out from SP 800-90A 10.1.1 by an
# independent implementation of it (packaging/pythonlib/tests), so it checks
# that what libcrypto runs is that mechanism, and not only that it runs.
KAT_ENTROPY = bytes(range(32))
KAT_NONCE = bytes(range(32, 48))
KAT_PERSONALIZATION = b'ovirt-engine csprng kat'
KAT_EXPECTED = bytes.fromhex(
    '3fb87b445496730b696e437d450e042e255ba5aee9c674b90b59f5b6925c2c39'
    '3ef12a671d209e56da7f34cd8d506aaab33b6843f038b30f2aaf4987b22f6939'
)


def known_answer_test(lib=None):
    """Fails unless libcrypto's Hash_DRBG gives the known answer.

    The entropy is fed through TEST-RAND, OpenSSL's generator that hands back
    given bytes, so that the output can be known in advance.
    """
    drbg = HashDrbg(
        lib=lib,
        seed_source=b'TEST-RAND',
        seed_params={
            'test_entropy': KAT_ENTROPY,
            'test_nonce': KAT_NONCE,
            'strength': STRENGTH,
        },
    ).instantiate(KAT_PERSONALIZATION)
    drbg.generate(64)
    if drbg.generate(64) != KAT_EXPECTED:
        raise DrbgUnavailable('Hash_DRBG failed its known-answer test')


def _health_check(drbg):
    """The continuous test of SP 800-90B 4.4 in its simplest form.

    Two consecutive blocks that are equal, or a block of zeros, means the
    generator is broken - better to fall back and say so than to hand out
    keys that are all alike.
    """
    first, second = drbg.generate(32), drbg.generate(32)
    if first == second or first == bytes(32):
        raise DrbgUnavailable('Hash_DRBG failed its health check')


def _instance():
    global _generator, _description
    if _generator is not None or _description is not None:
        return _generator
    with _lock:
        if _generator is None and _description is None:
            try:
                known_answer_test()
                drbg = HashDrbg().instantiate()
                _health_check(drbg)
                _generator = drbg
                _description = '%s,%s,%d (OpenSSL EVP_RAND, seeded by ' \
                    'SEED-SRC, known-answer test passed)' % (
                        MECHANISM, 'SHA-256', STRENGTH)
            except (DrbgUnavailable, OSError, AttributeError) as error:
                _description = 'os.urandom fallback: %s' % error
                _log.warning(
                    'Approved random generator unavailable, using '
                    'os.urandom: %s', error,
                )
    return _generator


def is_approved():
    """Whether the bytes come from the Hash_DRBG rather than the fallback."""
    return _instance() is not None


def describe():
    """The generator in use, in words a log or an audit can record."""
    _instance()
    return _description


def token_bytes(count):
    """count random bytes. The drop-in replacement for os.urandom(count)."""
    if count < 0:
        raise ValueError('negative byte count')
    if count == 0:
        return b''
    generator = _instance()
    if generator is None:
        return os.urandom(count)
    return generator.generate(count)


def randbelow(limit):
    """A uniform integer in [0, limit), by rejection, without modulo bias."""
    if limit <= 0:
        raise ValueError('limit must be positive')
    bits = limit.bit_length()
    size = (bits + 7) // 8
    mask = (1 << bits) - 1
    while True:
        value = int.from_bytes(token_bytes(size), 'big') & mask
        if value < limit:
            return value


def choice(sequence):
    """A uniform pick from a non-empty sequence."""
    if not sequence:
        raise IndexError('cannot choose from an empty sequence')
    return sequence[randbelow(len(sequence))]


class SystemRandom(object):
    """Enough of random.SystemRandom for the callers here, on token_bytes."""

    def choice(self, sequence):
        return choice(sequence)

    def randrange(self, start, stop=None):
        if stop is None:
            start, stop = 0, start
        if stop <= start:
            raise ValueError('empty range')
        return start + randbelow(stop - start)

    def randint(self, low, high):
        return self.randrange(low, high + 1)

    def getrandbits(self, bits):
        return int.from_bytes(token_bytes((bits + 7) // 8), 'big') >> (
            (8 - bits % 8) % 8)

    def shuffle(self, items):
        for index in range(len(items) - 1, 0, -1):
            other = randbelow(index + 1)
            items[index], items[other] = items[other], items[index]

    def sample(self, population, count):
        pool = list(population)
        if count > len(pool):
            raise ValueError('sample larger than population')
        self.shuffle(pool)
        return pool[:count]


# vim: expandtab tabstop=4 shiftwidth=4
