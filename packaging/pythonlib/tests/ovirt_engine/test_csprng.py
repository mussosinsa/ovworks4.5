"""
test_csprng.py - Tests for ovirt_engine/csprng.py

Runs under pytest with the other library tests, and on its own:
    PYTHONPATH=packaging/pythonlib python3 packaging/pythonlib/tests/ovirt_engine/test_csprng.py
"""

import hashlib
import unittest
from unittest import mock

from ovirt_engine import csprng


SEED_BYTES = 55  # seedlen of a Hash_DRBG over SHA-256: 440 bits
MODULUS = 1 << (SEED_BYTES * 8)


def _sha256(data):
    return hashlib.sha256(data).digest()


def _hash_df(data, count):
    out = b''
    counter = 1
    while len(out) < count:
        out += _sha256(bytes([counter]) + (count * 8).to_bytes(4, 'big') + data)
        counter += 1
    return out[:count]


class ReferenceHashDrbg(object):
    """SP 800-90A 10.1.1, written from the standard and nothing else.

    No reseed, no additional input: enough to tell whether what libcrypto runs
    is this mechanism.
    """

    def __init__(self, entropy, nonce, personalization):
        self.v = _hash_df(entropy + nonce + personalization, SEED_BYTES)
        self.c = _hash_df(b'\x00' + self.v, SEED_BYTES)
        self.counter = 1

    def generate(self, count):
        data = int.from_bytes(self.v, 'big')
        out = b''
        while len(out) < count:
            out += _sha256(data.to_bytes(SEED_BYTES, 'big'))
            data = (data + 1) % MODULUS
        h = _sha256(b'\x03' + self.v)
        self.v = (
            (int.from_bytes(self.v, 'big') + int.from_bytes(h, 'big')
             + int.from_bytes(self.c, 'big') + self.counter) % MODULUS
        ).to_bytes(SEED_BYTES, 'big')
        self.counter += 1
        return out[:count]


class CsprngTest(unittest.TestCase):

    def test_the_known_answer_is_what_the_standard_gives(self):
        reference = ReferenceHashDrbg(
            csprng.KAT_ENTROPY, csprng.KAT_NONCE, csprng.KAT_PERSONALIZATION)
        reference.generate(64)
        self.assertEqual(csprng.KAT_EXPECTED, reference.generate(64))

    def test_libcrypto_runs_that_mechanism(self):
        csprng.known_answer_test()

    def test_libcrypto_agrees_with_the_standard_on_other_inputs_too(self):
        entropy = bytes(range(100, 132))
        nonce = bytes(range(200, 216))
        drbg = csprng.HashDrbg(
            seed_source=b'TEST-RAND',
            seed_params={'test_entropy': entropy, 'test_nonce': nonce,
                         'strength': csprng.STRENGTH},
        ).instantiate(b'another')
        reference = ReferenceHashDrbg(entropy, nonce, b'another')
        for size in (1, 32, 100, 4096):
            self.assertEqual(reference.generate(size), drbg.generate(size))
        # A longer request is answered as several of at most 4096 bytes.
        self.assertEqual(
            reference.generate(4096) + reference.generate(904),
            drbg.generate(5000))

    def test_the_bytes_come_from_the_hash_drbg(self):
        self.assertTrue(csprng.is_approved(), csprng.describe())
        self.assertTrue(
            csprng.describe().startswith('Hash_DRBG,SHA-256,256'),
            csprng.describe())
        first = csprng.token_bytes(32)
        self.assertEqual(32, len(first))
        self.assertNotEqual(first, csprng.token_bytes(32))
        self.assertEqual(b'', csprng.token_bytes(0))
        self.assertEqual(10000, len(csprng.token_bytes(10000)))
        with self.assertRaises(ValueError):
            csprng.token_bytes(-1)

    def test_choices_are_uniform_and_within_range(self):
        rand = csprng.SystemRandom()
        letters = 'abc'
        seen = {rand.choice(letters) for _ in range(300)}
        self.assertEqual(set(letters), seen)
        for _ in range(200):
            self.assertTrue(10 <= rand.randint(10, 12) <= 12)
            self.assertTrue(0 <= csprng.randbelow(7) < 7)
        with self.assertRaises(IndexError):
            rand.choice('')

    def test_without_a_drbg_the_bytes_still_come_and_it_says_so(self):
        with mock.patch.object(csprng, '_generator', None), \
                mock.patch.object(csprng, '_description', None), \
                mock.patch.object(
                    csprng, 'known_answer_test',
                    side_effect=csprng.DrbgUnavailable('no EVP_RAND')):
            self.assertFalse(csprng.is_approved())
            self.assertEqual(
                'os.urandom fallback: no EVP_RAND', csprng.describe())
            self.assertEqual(16, len(csprng.token_bytes(16)))


if __name__ == '__main__':
    unittest.main()
