"""
摩斯密码加密模块
"""

MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.'
}

def encrypt(plaintext, separator='space'):
    result = []
    for char in plaintext.upper():
        if char in MORSE_CODE:
            result.append(MORSE_CODE[char])
        elif char == ' ':
            result.append('/')
        else:
            result.append(char)
    if separator == 'space':
        return ' '.join(result)
    elif separator == 'slash':
        return ' / '.join(result)
    return ''.join(result)


# 构建反向映射
REVERSE_MORSE = {v: k for k, v in MORSE_CODE.items()}

def decrypt(ciphertext):
    words = ciphertext.split('/')
    result = []
    for word in words:
        chars = word.strip().split()
        word_result = []
        for char in chars:
            if char in REVERSE_MORSE:
                word_result.append(REVERSE_MORSE[char])
            else:
                word_result.append('?')
        result.append(''.join(word_result))
    return ' '.join(result)

