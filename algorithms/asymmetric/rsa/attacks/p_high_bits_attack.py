"""
P高位泄露攻击模块
=================

【攻击原理】
当RSA素因子p的高位比特已知时，可以使用Coppersmith方法恢复完整的p。

数学基础：
- 设 p = p_high * 2^k + p_low，其中p_high已知，p_low未知
- 构造多项式 f(x) = p_high * 2^k + x mod N
- 使用Coppersmith方法寻找小根x = p_low

Coppersmith定理：
- 对于模N下的多项式f(x)，如果存在小根|x| < N^(1/deg(f))
- 则可以在多项式时间内找到这个根
- 对于p高位攻击，需要已知约p位数的一半以上比特

【攻击条件】
- 已知p的高位比特（约p位数的一半以上，通常需要55%以上）
- 已知已知比特数
- 需要SageMath环境

【攻击步骤】
1. 计算未知比特数 unknown_bits = p_bits - known_bits
2. 构造多项式 f(x) = p_high * 2^unknown_bits + x
3. 使用small_roots方法寻找小根
4. 验证 p_candidate 是否整除 N

【时间复杂度】
取决于Coppersmith方法的参数设置，通常在几秒到几分钟

【参考文献】
Coppersmith, D. (1996). "Finding a Small Root of a Univariate Modular Equation"
"""

ATTACK_NAME = "P高位泄露攻击(sagemath)"
ATTACK_DESC = "当p的高位已知时使用Coppersmith方法恢复完整p（需要SageMath）"
ATTACK_HINT = "适用于已知p的高位比特的情况，需要已知约p位数的一半以上"

INPUT_FIELDS = [
    {
        'name': 'n',
        'label': '模数 N',
        'type': 'text',
        'placeholder': '输入模数N',
        'default': ''
    },
    {
        'name': 'p_high',
        'label': '已知p的高位',
        'type': 'text',
        'placeholder': '输入已知p的高位值',
        'default': ''
    },
    {
        'name': 'known_bits',
        'label': '已知比特数',
        'type': 'text',
        'placeholder': '已知多少位高位',
        'default': ''
    }
]

SAGE_CODE = '''
def attack_p_high_bits(N, p_high, known_bits):
    """
    P高位泄露攻击
    当p的高位已知时使用Coppersmith方法恢复完整p
    """
    try:
        from sage.all import Zmod, PolynomialRing, ZZ, RR
        
        N = int(N)
        p_high = int(p_high)
        known_bits = int(known_bits)
        
        n_bits = N.bit_length()
        p_bits = (n_bits + 1) // 2
        unknown_bits = p_bits - known_bits
        
        if unknown_bits <= 0:
            p_test = p_high
            if p_test > 1 and N % p_test == 0:
                q = N // p_test
                return {
                    'success': True,
                    'p': str(p_test),
                    'q': str(q),
                    'text': f"攻击成功! p = {p_test}"
                }
            return {'success': False, 'error': 'p_high已经是完整的p，但不是N的因子'}
        
        if known_bits < p_bits * 0.55:
            return {'success': False, 'error': f'已知比特数太少。p约{p_bits}位，建议已知至少{int(p_bits * 0.55)}位，当前已知{known_bits}位'}
        
        p_approx = p_high << unknown_bits
        
        PR = PolynomialRing(Zmod(N), 'x')
        x = PR.gen()
        f = p_approx + x
        
        X = 2 ** unknown_bits
        
        try:
            roots = f.small_roots(X=X, beta=0.5)
            
            for root in roots:
                p_candidate = int(p_approx + root)
                
                if p_candidate > 1 and N % p_candidate == 0:
                    q = N // p_candidate
                    return {
                        'success': True,
                        'p': str(p_candidate),
                        'q': str(q),
                        'text': f"攻击成功! p = {p_candidate}"
                    }
        except Exception as ex:
            pass
        
        search_range = min(1000000, 2 ** min(20, unknown_bits))
        for delta in range(-search_range, search_range + 1):
            p_test = p_approx + delta
            if p_test > 1 and N % p_test == 0:
                q = N // p_test
                return {
                    'success': True,
                    'p': str(p_test),
                    'q': str(q),
                    'text': f"攻击成功! p = {p_test}"
                }
        
        return {'success': False, 'error': f'攻击失败。p约{p_bits}位，已知{known_bits}位，未知{unknown_bits}位。Coppersmith方法未能找到小根，请尝试提供更多已知比特。'}
        
    except Exception as ex:
        return {'success': False, 'error': str(ex)}

result = attack_p_high_bits(n_val, p_high_val, known_bits_val)
import json
print(json.dumps(result))
'''


def attack(n: str, p_high: str, known_bits: str, **kwargs) -> dict:
    """
    执行P高位泄露攻击
    
    参数:
        n: 模数
        p_high: 已知p的高位值
        known_bits: 已知比特数
        
    返回:
        攻击结果字典
    """
    from core.sage_executor import sage_executor
    
    try:
        n_val = int(n, 16) if n.startswith('0x') or n.startswith('0X') else int(n)
        p_high_val = int(p_high, 16) if p_high.startswith('0x') or p_high.startswith('0X') else int(p_high)
        known_bits_val = int(known_bits)
    except ValueError as ex:
        return {'success': False, 'text': f'参数解析错误: {str(ex)}'}
    
    if not sage_executor.is_available():
        return {'success': False, 'text': 'SageMath未配置，请在设置中配置SageMath路径'}
    
    code = SAGE_CODE.replace('n_val', str(n_val)).replace('p_high_val', str(p_high_val))
    code = code.replace('known_bits_val', str(known_bits_val))
    
    success, result = sage_executor.execute_and_parse(code, timeout=180)
    
    if success and isinstance(result, dict):
        if result.get('success'):
            return result
        else:
            return {'success': False, 'text': result.get('error', '攻击失败')}
    else:
        return {'success': False, 'text': result.get('error', '执行失败') if isinstance(result, dict) else '执行失败'}
