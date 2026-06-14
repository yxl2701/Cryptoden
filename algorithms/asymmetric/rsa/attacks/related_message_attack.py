"""
Related Message攻击模块
=======================

【攻击原理】
当两个明文满足线性关系 m2 = a*m1 + b，且使用相同的n和e加密时，
可以使用Franklin-Reiter相关消息攻击恢复明文。

数学基础：
- c1 = m1^e mod n
- c2 = m2^e mod n = (a*m1 + b)^e mod n
- 构造多项式:
  f1(x) = x^e - c1
  f2(x) = (a*x + b)^e - c2
- 两个多项式有公共根 x = m1
- 计算 gcd(f1, f2) 可以得到一次多项式，从而求出m1

【攻击条件】
1. 两个密文使用相同的模数n和公钥e
2. 两个明文满足线性关系 m2 = a*m1 + b
3. 公钥e较小（通常e <= 20，否则计算量太大）

【攻击步骤】
1. 构造多项式 f1(x) = x^e - c1
2. 构造多项式 f2(x) = (a*x + b)^e - c2
3. 计算 g = gcd(f1, f2)
4. 如果g是一次多项式，则 m1 = -g[0]/g[1]

【时间复杂度】
O(e^2 * log^2(n))，取决于多项式GCD的计算

【参考文献】
Franklin, M. & Reiter, M. (1995). "A Linear Protocol Failure for RSA with Public Exponent 2"
"""

ATTACK_NAME = "Related Message攻击(sagemath)"
ATTACK_DESC = "当两个明文满足线性关系m2 = a*m1 + b时恢复明文（需要SageMath）"
ATTACK_HINT = "适用于两个密文使用相同n和e加密，且明文有线性关系"

INPUT_FIELDS = [
    {
        'name': 'n',
        'label': '模数 N',
        'type': 'text',
        'placeholder': '输入模数N',
        'default': ''
    },
    {
        'name': 'e',
        'label': '公钥指数 e',
        'type': 'text',
        'placeholder': '输入公钥指数e',
        'default': ''
    },
    {
        'name': 'c1',
        'label': '密文 c1',
        'type': 'text',
        'placeholder': '输入第一个密文',
        'default': ''
    },
    {
        'name': 'c2',
        'label': '密文 c2',
        'type': 'text',
        'placeholder': '输入第二个密文',
        'default': ''
    },
    {
        'name': 'a',
        'label': '线性系数 a',
        'type': 'text',
        'placeholder': 'm2 = a*m1 + b中的a',
        'default': '1'
    },
    {
        'name': 'b',
        'label': '线性偏移 b',
        'type': 'text',
        'placeholder': 'm2 = a*m1 + b中的b',
        'default': '0'
    }
]

SAGE_CODE = '''
from sage.all import Zmod, ZZ, gcd, PolynomialRing

def attack_related_message(N, e, c1, c2, a, b):
    """
    Related Message攻击
    当m2 = a*m1 + b时恢复明文
    使用Franklin-Reiter相关消息攻击
    """
    try:
        N = int(N)
        e = int(e)
        c1 = int(c1)
        c2 = int(c2)
        a = int(a)
        b = int(b)
        
        if e > 20:
            return {'success': False, 'error': f'e={e}过大，计算量太大，建议e<=20'}
        
        R = PolynomialRing(Zmod(N), 'x')
        x = R.gen()
        
        f1 = x^e - c1
        f2 = (a*x + b)^e - c2
        
        def polynomial_gcd(f, g):
            """多项式GCD"""
            while g != 0:
                f, g = g, f % g
            return f
        
        g = polynomial_gcd(f1, f2)
        
        if g.degree() == 1:
            m = int(-g[0] / g[1])
            
            if pow(m, e, N) == c1:
                m2 = (a * m + b) % N
                
                try:
                    plaintext1 = bytes.fromhex(hex(m)[2:])
                    plaintext2 = bytes.fromhex(hex(m2)[2:])
                    return {
                        'success': True,
                        'm1': str(m),
                        'm2': str(m2),
                        'plaintext1': plaintext1.decode('utf-8', errors='replace'),
                        'plaintext2': plaintext2.decode('utf-8', errors='replace'),
                        'text': f"攻击成功!\\n明文1: {plaintext1.decode('utf-8', errors='replace')}\\n明文2: {plaintext2.decode('utf-8', errors='replace')}"
                    }
                except:
                    return {
                        'success': True,
                        'm1': str(m),
                        'm2': str(m2),
                        'text': f"攻击成功!\\n明文1(十进制): {m}\\n明文2(十进制): {m2}"
                    }
        
        return {'success': False, 'error': 'GCD不是一次多项式，可能明文关系不正确'}
        
    except Exception as ex:
        return {'success': False, 'error': str(ex)}

result = attack_related_message(n_val, e_val, c1_val, c2_val, a_val, b_val)
print(json.dumps(result))
'''


def attack(n: str, e: str, c1: str, c2: str, a: str = "1", b: str = "0", **kwargs) -> dict:
    """
    执行Related Message攻击
    
    参数:
        n: 模数
        e: 公钥指数
        c1: 第一个密文
        c2: 第二个密文
        a: 线性系数
        b: 线性偏移
        
    返回:
        攻击结果字典
    """
    from core.sage_executor import sage_executor
    
    try:
        n_val = int(n, 16) if n.startswith('0x') or n.startswith('0X') else int(n)
        e_val = int(e, 16) if e.startswith('0x') or e.startswith('0X') else int(e)
        c1_val = int(c1, 16) if c1.startswith('0x') or c1.startswith('0X') else int(c1)
        c2_val = int(c2, 16) if c2.startswith('0x') or c2.startswith('0X') else int(c2)
        a_val = int(a, 16) if a.startswith('0x') or a.startswith('0X') else int(a)
        b_val = int(b, 16) if b.startswith('0x') or b.startswith('0X') else int(b)
    except ValueError as ex:
        return {'success': False, 'text': f'参数解析错误: {str(ex)}'}
    
    if not sage_executor.is_available():
        return {'success': False, 'text': 'SageMath未配置，请在设置中配置SageMath路径'}
    
    code = SAGE_CODE.replace('n_val', str(n_val)).replace('e_val', str(e_val))
    code = code.replace('c1_val', str(c1_val)).replace('c2_val', str(c2_val))
    code = code.replace('a_val', str(a_val)).replace('b_val', str(b_val))
    
    success, result = sage_executor.execute_and_parse(code, timeout=120)
    
    if success and isinstance(result, dict):
        if result.get('success'):
            return result
        else:
            return {'success': False, 'text': result.get('error', '攻击失败')}
    else:
        return {'success': False, 'text': result.get('error', '执行失败') if isinstance(result, dict) else '执行失败'}
