"""Shared helpers for hash algorithm modules."""

import hashlib
import hmac
import zlib


def digest(plaintext, algorithm):
    return hashlib.new(algorithm, plaintext.encode('utf-8')).hexdigest()


def digest_many(plaintext, algorithms):
    data = plaintext.encode('utf-8')
    return [(label, hashlib.new(name, data).hexdigest()) for label, name in algorithms]


def digest_with_length(plaintext, algorithm, length=None):
    data = plaintext.encode('utf-8')
    h = hashlib.new(algorithm, data)
    if length is None:
        return h.hexdigest()
    return h.hexdigest(int(length))


def hmac_digest(plaintext, key='key', algorithm='sha256'):
    return hmac.new(key.encode('utf-8'), plaintext.encode('utf-8'), algorithm).hexdigest()


def crc32_digest(plaintext):
    return format(zlib.crc32(plaintext.encode('utf-8')) & 0xffffffff, '08x')


def adler32_digest(plaintext):
    return format(zlib.adler32(plaintext.encode('utf-8')) & 0xffffffff, '08x')
