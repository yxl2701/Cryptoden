def pairwise_swap_text(text):
    chars = list(text)
    for index in range(0, len(chars) - 1, 2):
        chars[index], chars[index + 1] = chars[index + 1], chars[index]
    return ''.join(chars)


def even_odd_transpose_encrypt(text):
    return text[::2] + text[1::2]


def even_odd_transpose_decrypt(text):
    midpoint = (len(text) + 1) // 2
    even_part = text[:midpoint]
    odd_part = text[midpoint:]
    result = []
    for index in range(midpoint):
        result.append(even_part[index])
        if index < len(odd_part):
            result.append(odd_part[index])
    return ''.join(result)
