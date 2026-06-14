"""
Common Prime RSA攻击模块
========================

【攻击原理】
当两个不同的RSA模数N1和N2共享一个素因子p时，可以通过计算最大公约数分解两个模数。

数学基础：
- 设 N1 = p * q1，N2 = p * q2
- 则 gcd(N1, N2) = p
- 分解后: q1 = N1 / p，q2 = N2 / p

【攻击条件】
1. 两个RSA模数N1和N2
2. 两个模数共享一个素因子p（可能是由于随机数生成器问题）

【攻击步骤】
1. 计算 p = gcd(N1, N2)
2. 如果 p > 1 且 p < N1, N2，则分解成功
3. 计算 q1 = N1 / p，q2 = N2 / p
4. 如果提供了密文，可以进一步解密

【时间复杂度】
O(log(min(N1, N2)))，使用欧几里得算法

【实际场景】
- 多个RSA密钥使用相同或相近的随机种子
- 弱随机数生成器导致素数重复
- CTF中常见的"共享素因子"题目

【参考文献】
- GCD攻击
- 欧几里得算法
"""

ATTACK_NAME = "Common Prime攻击(sagemath)"
ATTACK_DESC = "当两个RSA模数共享一个素因子时恢复因子（需要SageMath）"
ATTACK_HINT = "适用于两个模数N1和N2共享一个素因子p的情况"

INPUT_FIELDS = [
    {
        'name': 'n1',
        'label': '模数 N1',
        'type': 'text',
        'placeholder': '输入第一个模数N1',
        'default': ''
    },
    {
        'name': 'n2',
        'label': '模数 N2',
        'type': 'text',
        'placeholder': '输入第二个模数N2',
        'default': ''
    },
    {
        'name': 'e1',
        'label': '公钥指数 e1',
        'type': 'text',
        'placeholder': '输入第一个公钥指数e1',
        'default': ''
    },
    {
        'name': 'e2',
        'label': '公钥指数 e2',
        'type': 'text',
        'placeholder': '输入第二个公钥指数e2',
        'default': ''
    },
    {
        'name': 'c1',
        'label': '密文 c1',
        'type': 'text',
        'placeholder': '输入第一个密文c1',
        'default': ''
    },
    {
        'name': 'c2',
        'label': '密文 c2',
        'type': 'text',
        'placeholder': '输入第二个密文c2',
        'default': ''
    }
]

SAGE_CODE = '''
from sage.all import ZZ, gcd

def attack_common_prime(N1, N2, e1, e2, c1, c2):
    """
    Common Prime RSA攻击
    当两个模数共享一个素因子时恢复因子
    """
    try:
        N1 = int(N1)
        N2 = int(N2)
        e1 = int(e1) if e1 else 65537
        e2 = int(e2) if e2 else 65537
        c1 = int(c1) if c1 else 0
        c2 = int(c2) if c2 else 0
        
        p = gcd(N1, N2)
        
        if p == 1:
            return {'success': False, 'error': '两个模数没有公共因子'}
        
        if p == N1 or p == N2:
            return {'success': False, 'error': '一个模数是另一个的倍数'}
        
        q1 = N1 // p
        q2 = N2 // p
        
        phi1 = (p - 1) * (q1 - 1)
        phi2 = (p - 1) * (q2 - 1)
        
        result = {
            'success': True,
            'p': str(p),
            'q1': str(q1),
            'q2': str(q2),
            'text': f"攻击成功!\\n公共因子 p = {p}\\nN1的另一个因子 q1 = {q1}\\nN2的另一个因子 q2 = {q2}"
        }
        
        if c1 and c2:
            try:
                d1 = pow(e1, -1, phi1)
                d2 = pow(e2, -1, phi2)
                
                m1 = pow(c1, d1, N1)
                m2 = pow(c2, d2, N2)
                
                try:
                    plaintext1 = bytes.fromhex(hex(m1)[2:])
                    plaintext2 = bytes.fromhex(hex(m2)[2:])
                    result['m1'] = str(m1)
                    result['m2'] = str(m2)
                    result['plaintext1'] = plaintext1.decode('utf-8', errors='replace')
                    result['plaintext2'] = plaintext2.decode('utf-8', errors='replace')
                    result['text'] += f"\\n明文1: {plaintext1.decode('utf-8', errors='replace')}\\n明文2: {plaintext2.decode('utf-8', errors='replace')}"
                except:
                    result['m1'] = str(m1)
                    result['m2'] = str(m2)
                    result['text'] += f"\\n明文1(十进制): {m1}\\n明文2(十进制): {m2}"
            except:
                pass
        
        return result
        
    except Exception as ex:
        return {'success': False, 'error': str(ex)}

result = attack_common_prime(n1_val, n2_val, e1_val, e2_val, c1_val, c2_val)
print(json.dumps(result))
'''


def attack(n1: str, n2: str, e1: str = "", e2: str = "", c1: str = "", c2: str = "", **kwargs) -> dict:
    """
    执行Common Prime RSA攻击
    
    参数:
        n1: 第一个模数
        n2: 第二个模数
        e1: 第一个公钥指数
        e2: 第二个公钥指数
        c1: 第一个密文
        c2: 第二个密文
        
    返回:
        攻击结果字典
    """
    from core.sage_executor import sage_executor
    
    try:
        n1_val = int(n1, 16) if n1.startswith('0x') or n1.startswith('0X') else int(n1)
        n2_val = int(n2, 16) if n2.startswith('0x') or n2.startswith('0X') else int(n2)
        e1_val = int(e1, 16) if e1.startswith('0x') or e1.startswith('0X') else int(e1) if e1 else 0
        e2_val = int(e2, 16) if e2.startswith('0x') or e2.startswith('0X') else int(e2) if e2 else 0
        c1_val = int(c1, 16) if c1.startswith('0x') or c1.startswith('0X') else int(c1) if c1 else 0
        c2_val = int(c2, 16) if c2.startswith('0x') or c2.startswith('0X') else int(c2) if c2 else 0
    except ValueError as ex:
        return {'success': False, 'text': f'参数解析错误: {str(ex)}'}
    
    if not sage_executor.is_available():
        return {'success': False, 'text': 'SageMath未配置，请在设置中配置SageMath路径'}
    
    code = SAGE_CODE.replace('n1_val', str(n1_val)).replace('n2_val', str(n2_val))
    code = code.replace('e1_val', str(e1_val)).replace('e2_val', str(e2_val))
    code = code.replace('c1_val', str(c1_val)).replace('c2_val', str(c2_val))
    
    success, result = sage_executor.execute_and_parse(code, timeout=60)
    
    if success and isinstance(result, dict):
        if result.get('success'):
            return result
        else:
            return {'success': False, 'text': result.get('error', '攻击失败')}
    else:
        return {'success': False, 'text': result.get('error', '执行失败') if isinstance(result, dict) else '执行失败'}
