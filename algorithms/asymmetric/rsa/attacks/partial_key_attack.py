"""
Partial Key Exposure攻击模块
============================

【攻击原理】
当私钥d的部分比特已知时（如高位或低位泄露），可以使用格基方法恢复完整私钥。

数学基础：
- 由 e*d ≡ 1 (mod φ(n))
- 如果已知d的高位或低位，可以构造格来恢复未知部分
- 使用Coppersmith方法或格基规约

【攻击条件】
1. 已知私钥d的部分比特（高位或低位）
2. 已知比特数量足够（通常需要超过一半）
3. 需要SageMath环境

【攻击步骤】
1. 根据已知部分构造多项式或格
2. 使用small_roots或LLL算法
3. 恢复完整私钥d

【适用场景】
- 侧信道攻击泄露部分私钥比特
- 内存泄露部分私钥
- 硬件故障泄露部分私钥

【参考文献】
Boneh, D., Durfee, G., & Frankel, Y. (1998). "Exposing an RSA Private Key Given a Small Fraction of its Bits"
"""

ATTACK_NAME = "Partial Key Exposure攻击(sagemath)"
ATTACK_DESC = "当私钥d的部分比特已知时恢复完整私钥（需要SageMath）"
ATTACK_HINT = "适用于已知d的高位或低位比特的情况"

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
        'name': 'd_partial',
        'label': '已知d的部分值',
        'type': 'text',
        'placeholder': '输入已知的d部分值',
        'default': ''
    },
    {
        'name': 'known_bits',
        'label': '已知比特数',
        'type': 'text',
        'placeholder': '已知多少位',
        'default': ''
    },
    {
        'name': 'position',
        'label': '已知位置',
        'type': 'choice',
        'choices': ['msb', 'lsb'],
        'choice_labels': ['高位(MSB)', '低位(LSB)'],
        'default': 'msb'
    }
]

SAGE_CODE = '''
from sage.all import ZZ, RR, isqrt

def attack_partial_key(N, e, d_partial, known_bits, position):
    """
    Partial Key Exposure攻击
    当私钥d的部分比特已知时恢复完整私钥
    """
    try:
        N = int(N)
        e = int(e)
        d_partial = int(d_partial)
        known_bits = int(known_bits)
        
        n_bits = N.bit_length()
        
        if known_bits < n_bits // 4:
            return {'success': False, 'error': f'已知比特数太少，至少需要{n_bits // 4}位'}
        
        if position == 'msb':
            d_approx = d_partial << (n_bits - known_bits)
        else:
            d_approx = d_partial
        
        k_approx = (e * d_approx - 1) // N
        
        for k in range(max(1, k_approx - 100), k_approx + 100):
            if k == 0:
                continue
                
            phi_approx = (e * d_approx - 1) // k
            
            if phi_approx <= 0:
                continue
            
            p_plus_q = N - phi_approx + 1
            discriminant = p_plus_q^2 - 4*N
            
            if discriminant >= 0:
                sqrt_disc = isqrt(discriminant)
                if sqrt_disc^2 == discriminant:
                    p = (p_plus_q + sqrt_disc) // 2
                    q = (p_plus_q - sqrt_disc) // 2
                    
                    if p * q == N:
                        phi = (p - 1) * (q - 1)
                        d = pow(e, -1, phi)
                        
                        if pow(pow(2, e, N), d, N) == 2:
                            if position == 'msb':
                                if (d >> (n_bits - known_bits)) == d_partial:
                                    return {
                                        'success': True,
                                        'p': str(p),
                                        'q': str(q),
                                        'd': str(d),
                                        'phi': str(phi),
                                        'text': f"攻击成功!\\n找到因子p和q\\n私钥d = {d}"
                                    }
                            else:
                                if (d & ((1 << known_bits) - 1)) == d_partial:
                                    return {
                                        'success': True,
                                        'p': str(p),
                                        'q': str(q),
                                        'd': str(d),
                                        'phi': str(phi),
                                        'text': f"攻击成功!\\n找到因子p和q\\n私钥d = {d}"
                                    }
        
        return {'success': False, 'error': 'Partial Key Exposure攻击失败，可能已知比特不足或位置不正确'}
        
    except Exception as ex:
        return {'success': False, 'error': str(ex)}

result = attack_partial_key(n_val, e_val, d_partial_val, known_bits_val, position_val)
print(json.dumps(result))
'''


def attack(n: str, e: str, d_partial: str, known_bits: str, position: str = "msb", **kwargs) -> dict:
    """
    执行Partial Key Exposure攻击
    
    参数:
        n: 模数
        e: 公钥指数
        d_partial: 已知的d部分值
        known_bits: 已知比特数
        position: 已知位置(msb/lsb)
        
    返回:
        攻击结果字典
    """
    from core.sage_executor import sage_executor
    
    try:
        n_val = int(n, 16) if n.startswith('0x') or n.startswith('0X') else int(n)
        e_val = int(e, 16) if e.startswith('0x') or e.startswith('0X') else int(e)
        d_partial_val = int(d_partial, 16) if d_partial.startswith('0x') or d_partial.startswith('0X') else int(d_partial)
        known_bits_val = int(known_bits)
    except ValueError as ex:
        return {'success': False, 'text': f'参数解析错误: {str(ex)}'}
    
    if not sage_executor.is_available():
        return {'success': False, 'text': 'SageMath未配置，请在设置中配置SageMath路径'}
    
    code = SAGE_CODE.replace('n_val', str(n_val)).replace('e_val', str(e_val))
    code = code.replace('d_partial_val', str(d_partial_val)).replace('known_bits_val', str(known_bits_val))
    code = code.replace('position_val', f'"{position}"')
    
    success, result = sage_executor.execute_and_parse(code, timeout=120)
    
    if success and isinstance(result, dict):
        if result.get('success'):
            return result
        else:
            return {'success': False, 'text': result.get('error', '攻击失败')}
    else:
        return {'success': False, 'text': result.get('error', '执行失败') if isinstance(result, dict) else '执行失败'}
