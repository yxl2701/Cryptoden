import base64
import binascii
import html
import re
from urllib.parse import quote, unquote


def _format_error(prefix, error):
    return f"{prefix}: {error}"


def _clean_hex(text):
    cleaned = ''.join(text.split()).replace('-', '').replace(':', '')
    if cleaned.lower().startswith('0x'):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError('十六进制长度必须为偶数')
    return cleaned


def encode_hex_with_codec(plaintext, codec):
    try:
        return plaintext.encode(codec).hex().upper()
    except Exception as error:
        return _format_error('编码错误', error)


def decode_hex_with_codec(ciphertext, codec):
    try:
        return bytes.fromhex(_clean_hex(ciphertext)).decode(codec)
    except Exception as error:
        return _format_error('解码错误', error)


def encode_hex_lower_utf8(plaintext):
    try:
        return plaintext.encode('utf-8').hex()
    except Exception as error:
        return _format_error('编码错误', error)


def decode_hex_lower_utf8(ciphertext):
    return decode_hex_with_codec(ciphertext, 'utf-8')


def encode_base64_variant(plaintext, urlsafe=False, strip_padding=False):
    try:
        raw = plaintext.encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)
        text = encoded.decode('ascii')
        return text.rstrip('=') if strip_padding else text
    except Exception as error:
        return _format_error('编码错误', error)


def decode_base64_variant(ciphertext, urlsafe=False):
    try:
        cleaned = ''.join(ciphertext.split())
        padding = (-len(cleaned)) % 4
        cleaned += '=' * padding
        decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
        return decoder(cleaned.encode('ascii')).decode('utf-8')
    except Exception as error:
        return _format_error('解码错误', error)


def encode_ascii85(plaintext):
    try:
        return base64.a85encode(plaintext.encode('utf-8')).decode('ascii')
    except Exception as error:
        return _format_error('编码错误', error)


def decode_ascii85(ciphertext):
    try:
        cleaned = ''.join(ciphertext.split())
        return base64.a85decode(cleaned.encode('ascii')).decode('utf-8')
    except Exception as error:
        return _format_error('解码错误', error)


def encode_text_codec(plaintext, codec):
    try:
        return plaintext.encode(codec).decode('ascii')
    except Exception as error:
        return _format_error('编码错误', error)


def decode_text_codec(ciphertext, codec):
    try:
        return ciphertext.encode('ascii').decode(codec)
    except Exception as error:
        return _format_error('解码错误', error)


def encode_uu(plaintext):
    try:
        raw = plaintext.encode('utf-8')
        lines = []
        for index in range(0, len(raw), 45):
            lines.append(binascii.b2a_uu(raw[index:index + 45]).decode('ascii').rstrip('\n'))
        return '\n'.join(lines)
    except Exception as error:
        return _format_error('编码错误', error)


def decode_uu(ciphertext):
    try:
        chunks = []
        for line in ciphertext.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            chunks.append(binascii.a2b_uu(stripped.encode('ascii')))
        return b''.join(chunks).decode('utf-8')
    except Exception as error:
        return _format_error('解码错误', error)


def encode_html_entities(plaintext, hex_mode=False):
    try:
        if hex_mode:
            return ''.join(f'&#x{ord(char):X};' for char in plaintext)
        return ''.join(f'&#{ord(char)};' for char in plaintext)
    except Exception as error:
        return _format_error('编码错误', error)


def decode_html_entities(ciphertext):
    try:
        return html.unescape(ciphertext)
    except Exception as error:
        return _format_error('解码错误', error)


def encode_url_all(plaintext):
    try:
        return quote(plaintext, safe='')
    except Exception as error:
        return _format_error('编码错误', error)


def decode_url_all(ciphertext):
    try:
        return unquote(ciphertext)
    except Exception as error:
        return _format_error('解码错误', error)


def encode_utf9(plaintext):
    try:
        return ' '.join(format(byte, '09b') for byte in plaintext.encode('utf-8'))
    except Exception as error:
        return _format_error('编码错误', error)


def decode_utf9(ciphertext):
    try:
        cleaned = ciphertext.strip()
        if not cleaned:
            return ''
        groups = cleaned.split() if ' ' in cleaned else [cleaned[index:index + 9] for index in range(0, len(cleaned), 9)]
        if any(len(group) != 9 or re.search(r'[^01]', group) for group in groups):
            raise ValueError('UTF9 数据必须由 9 位二进制组组成')
        raw = bytearray()
        for group in groups:
            value = int(group, 2)
            if value > 255:
                raise ValueError('UTF9 组值超出字节范围')
            raw.append(value)
        return raw.decode('utf-8')
    except Exception as error:
        return _format_error('解码错误', error)


def encode_byte_values(plaintext, base, separator=' '):
    try:
        raw = plaintext.encode('utf-8')
        if base == 2:
            parts = [format(byte, '08b') for byte in raw]
        elif base == 8:
            parts = [format(byte, '03o') for byte in raw]
        elif base == 10:
            parts = [str(byte) for byte in raw]
        else:
            raise ValueError('不支持的进制')
        return separator.join(parts)
    except Exception as error:
        return _format_error('编码错误', error)


def decode_byte_values(ciphertext, base):
    try:
        cleaned = ciphertext.strip()
        if not cleaned:
            return ''
        parts = [part for part in re.split(r'[\s,;]+', cleaned) if part]
        values = bytearray(int(part, base) for part in parts)
        return values.decode('utf-8')
    except Exception as error:
        return _format_error('解码错误', error)
