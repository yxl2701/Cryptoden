"""
Enigma密码加密模块
=================

【算法介绍】
Enigma密码机是二战期间德军使用的转子密码机。
本模块实现了简化的Enigma I型（3转子）模型。

【加密原理】
1. 3个转子（Rotor），每个转子将字母映射为另一个字母
2. 反射器（Reflector）将信号反射回去
3. 每按一个键，转子转动，改变映射关系
4. 加密和解密过程相同

【示例】
转子: I, II, III
初始位置: A, A, A
明文: HELLO
密文: ...

【参数说明】
- rotors: 转子列表，如 ['I', 'II', 'III']
- positions: 初始位置，如 ['A', 'A', 'A']
- reflector: 反射器，如 'B'
- plugboard: 插线板，如 'AB CD'（表示A-B, C-D互换）
"""

ALGORITHM_NAME = "Enigma密码"
ALGORITHM_DESC = "Enigma密码机，二战德军转子密码机模拟"

# 转子接线（字母映射）
ROTOR_WIRING = {
    'I':    'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
    'II':   'AJDKSIRUXBLHWTMCQGZNPYFVOE',
    'III':  'BDFHJLCPRTXVZNYEIWGAKMUSQO',
    'IV':   'ESOVPZJAYQUIRHXLNFTGKDCMWB',
    'V':    'VZBRGITYUPSDNHLXAWMJQOFECK',
}

# 转子凹口位置（触发下一个转子转动）
ROTOR_NOTCH = {
    'I': 'Q',
    'II': 'E',
    'III': 'V',
    'IV': 'J',
    'V': 'Z',
}

# 反射器接线
REFLECTOR_WIRING = {
    'A': 'EJMZALYXVBWFCRQUONTSPIKHGD',
    'B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
    'C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
}

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


class _EnigmaRotor:
    """Enigma转子"""
    def __init__(self, wiring, notch, position='A'):
        self.wiring = wiring
        self.notch = notch
        self.position = position

    def forward(self, c):
        """正向通过转子"""
        idx = (ALPHABET.index(c) + ALPHABET.index(self.position)) % 26
        mapped = self.wiring[idx]
        return ALPHABET[(ALPHABET.index(mapped) - ALPHABET.index(self.position)) % 26]

    def backward(self, c):
        """反向通过转子"""
        idx = (ALPHABET.index(c) + ALPHABET.index(self.position)) % 26
        mapped_char = ALPHABET[idx]
        wiring_idx = self.wiring.index(mapped_char)
        return ALPHABET[(wiring_idx - ALPHABET.index(self.position)) % 26]

    def step(self):
        """步进转子，返回步进前是否在凹口位置"""
        was_at_notch = self.position == self.notch
        idx = ALPHABET.index(self.position)
        self.position = ALPHABET[(idx + 1) % 26]
        return was_at_notch


def encrypt(plaintext, rotors=None, positions=None, reflector='B', plugboard=''):
    """
    Enigma密码加密/解密

    参数:
        plaintext (str): 明文/密文
        rotors (list): 转子列表
        positions (list): 初始位置
        reflector (str): 反射器类型
        plugboard (str): 插线板设置

    返回:
        str: 结果
    """
    if rotors is None:
        rotors = ['I', 'II', 'III']
    if positions is None:
        positions = ['A', 'A', 'A']

    # 支持字符串参数（CLI传入的是逗号分隔的字符串）
    if isinstance(rotors, str):
        rotors = [r.strip() for r in rotors.replace('，', ',').split(',')]
    if isinstance(positions, str):
        positions = [p.strip() for p in positions.replace('，', ',').split(',')]

    # 初始化转子
    rotor_objs = []
    for r, p in zip(rotors, positions):
        wiring = ROTOR_WIRING.get(r, ROTOR_WIRING['I'])
        notch = ROTOR_NOTCH.get(r, ROTOR_NOTCH['I'])
        rotor_objs.append(_EnigmaRotor(wiring, notch, p))

    # 反射器
    reflector_wiring = REFLECTOR_WIRING.get(reflector, REFLECTOR_WIRING['B'])

    # 插线板映射
    plug_map = {}
    for pair in plugboard.upper().split():
        if len(pair) >= 2:
            a, b = pair[0], pair[1]
            plug_map[a] = b
            plug_map[b] = a

    def _apply_plugboard(c):
        return plug_map.get(c, c)

    plaintext = plaintext.upper().replace(' ', '')
    result = []

    for c in plaintext:
        if c not in ALPHABET:
            result.append(c)
            continue

        # 转子步进
        # 右转子始终步进
        carry = rotor_objs[0].step()
        # 右转子在凹口时，中转子步进
        if carry:
            carry = rotor_objs[1].step()
        # 中转子在凹口时，左转子步进（双步进）
        if carry:
            rotor_objs[2].step()

        # 插线板
        c = _apply_plugboard(c)

        # 正向通过转子
        for rotor in rotor_objs:
            c = rotor.forward(c)

        # 反射器
        idx = ALPHABET.index(c)
        c = reflector_wiring[idx]

        # 反向通过转子
        for rotor in reversed(rotor_objs):
            c = rotor.backward(c)

        # 插线板
        c = _apply_plugboard(c)

        result.append(c)

    return ''.join(result)


# Enigma加密和解密相同
decrypt = encrypt