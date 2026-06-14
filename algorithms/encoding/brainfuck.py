"""
Brainfuck编码模块
=================

【算法介绍】
Brainfuck是一种极小化的图灵完备编程语言，由Urban Müller于1993年创造。
在CTF中常用于编码隐藏信息。

【指令集】
>  指针加一
<  指针减一
+  当前单元加一
-  当前单元减一
.  输出当前单元字符
,  输入到当前单元
[  如果当前单元为0，跳转到对应的]之后
]  如果当前单元非0，跳转到对应的[之前

【示例】
  输入: A
  BF: ++++++[>++++++++++<-]>+++++.
"""

ALGORITHM_NAME = "Brainfuck"
ALGORITHM_DESC = "Brainfuck编程语言，极小化图灵完备语言编码"


def encrypt(plaintext):
    """
    将文本编码为Brainfuck程序

    参数:
        plaintext (str): 明文

    返回:
        str: Brainfuck程序
    """
    result = []
    for c in plaintext:
        n = ord(c)
        # 生成设置当前单元为n的BF代码
        # 优化：使用乘法
        if n <= 10:
            result.append('+' * n + '.')
        elif n <= 20:
            result.append('+' * n + '.')
        else:
            # 使用乘法优化
            factor = int(n ** 0.5)
            remainder = n - factor * factor
            result.append('+' * factor + '[>' + '+' * factor + '<-]>' + '+' * remainder + '.>')

    return ''.join(result)


def decrypt(ciphertext):
    """
    执行Brainfuck程序并获取输出

    参数:
        ciphertext (str): Brainfuck程序

    返回:
        str: 输出结果
    """
    try:
        tape = [0] * 30000
        ptr = 0
        output = []
        i = 0

        while i < len(ciphertext):
            cmd = ciphertext[i]

            if cmd == '>':
                ptr += 1
                if ptr >= len(tape):
                    tape.append(0)
            elif cmd == '<':
                ptr -= 1
                if ptr < 0:
                    ptr = 0
            elif cmd == '+':
                tape[ptr] = (tape[ptr] + 1) % 256
            elif cmd == '-':
                tape[ptr] = (tape[ptr] - 1) % 256
            elif cmd == '.':
                output.append(chr(tape[ptr]))
            elif cmd == ',':
                pass  # 忽略输入
            elif cmd == '[':
                if tape[ptr] == 0:
                    depth = 1
                    while depth > 0:
                        i += 1
                        if ciphertext[i] == '[':
                            depth += 1
                        elif ciphertext[i] == ']':
                            depth -= 1
            elif cmd == ']':
                if tape[ptr] != 0:
                    depth = 1
                    while depth > 0:
                        i -= 1
                        if ciphertext[i] == ']':
                            depth += 1
                        elif ciphertext[i] == '[':
                            depth -= 1

            i += 1

        return ''.join(output)
    except Exception as e:
        return f"执行错误: {str(e)}"