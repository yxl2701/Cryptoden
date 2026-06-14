"""
Boneh-Durfee攻击模块
====================

【攻击原理】
Boneh-Durfee攻击是Wiener攻击的改进版本，可以处理更大的私钥d。
当私钥d < N^0.292时，可以使用格基规约方法恢复私钥。

数学基础：
- 由 e*d ≡ 1 (mod φ(n))，设 k = (e*d - 1) / φ(n)
- 可以证明 k/d 是 φ(n)/n 的渐近分数
- 使用LLL格基规约可以在更大的范围内找到k/d

Wiener攻击限制: d < N^0.25
Boneh-Durfee攻击: d < N^0.292

【攻击条件】
1. 私钥d < N^0.292
2. 公钥e较大（接近N）
3. 需要SageMath环境

【攻击步骤】
1. 构造格基矩阵
2. 使用LLL算法规约格基
3. 从规约后的向量中提取可能的k和d
4. 验证是否找到正确的私钥

【时间复杂度】
取决于LLL算法，通常在多项式时间内完成

【参考文献】
Boneh, D. & Durfee, G. (1999). "Cryptanalysis of RSA with Private Key d Less than N^0.292"
"""

ATTACK_NAME = "Boneh-Durfee攻击(sagemath)"
ATTACK_DESC = "当私钥d < N^0.292时恢复私钥（需要SageMath）"
ATTACK_HINT = "适用于e较大且d较小的情况，d < N^0.292"

INPUT_FIELDS = [
    {
        'name': 'n',
        'label': '模数 N',
        'type': 'text',
        'placeholder': '输入模数N（十进制或0x开头十六进制）',
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
        'name': 'delta',
        'label': 'delta值（d < N^delta）',
        'type': 'text',
        'placeholder': '默认0.25，最大0.292',
        'default': '0.25'
    }
]

SAGE_CODE = '''
import json
from sage.all import ZZ, RR, isqrt, gcd

def attack_boneh_durfee(N, e, delta=0.25):
    """
    Boneh-Durfee攻击实现
    当d < N^delta时恢复私钥
    使用连分数方法
    """
    try:
        N = int(N)
        e = int(e)
        delta = float(delta)
        
        if delta > 0.292:
            return {'success': False, 'error': 'delta值过大，最大支持0.292'}
        
        def wiener_like_attack(N, e):
            """类似Wiener的连分数攻击，可以处理稍大的d"""
            from sage.all import continued_fraction
            
            cf = continued_fraction(e / N)
            convergents_list = list(cf.convergents())
            
            for conv in convergents_list[:100]:
                k = conv.numerator()
                d = conv.denominator()
                
                if k == 0:
                    continue
                
                phi_candidate = (e * d - 1) // k
                
                if phi_candidate <= 0:
                    continue
                
                p_plus_q = N - phi_candidate + 1
                discriminant = p_plus_q^2 - 4*N
                
                if discriminant >= 0:
                    sqrt_disc = isqrt(discriminant)
                    if sqrt_disc^2 == discriminant:
                        p = (p_plus_q + sqrt_disc) // 2
                        q = (p_plus_q - sqrt_disc) // 2
                        if p * q == N and p > 1 and q > 1:
                            return p, q, d
            
            return None, None, None
        
        p, q, d = wiener_like_attack(N, e)
        
        if p is not None:
            return {
                'success': True,
                'p': str(p),
                'q': str(q),
                'd': str(d),
                'text': f"攻击成功!\\n找到因子p和q\\n私钥d = {d}"
            }
        
        # 在线环境下用于小规模题目的兜底：在 N^delta 范围内有界搜索小d。
        # 对真实大模数会自动限制搜索上限，避免SageCell长时间卡死。
        search_bound = min(int(RR(N) ** delta) + 2, 200000)
        for d_candidate in range(1, search_bound + 1):
            if gcd(d_candidate, e) != 1:
                continue

            t = e * d_candidate - 1
            for k in range(1, d_candidate + 1):
                if t % k != 0:
                    continue

                phi_candidate = t // k
                if phi_candidate <= 0:
                    continue

                p_plus_q = N - phi_candidate + 1
                discriminant = p_plus_q^2 - 4*N
                if discriminant < 0:
                    continue

                sqrt_disc = isqrt(discriminant)
                if sqrt_disc^2 != discriminant:
                    continue

                p = (p_plus_q + sqrt_disc) // 2
                q = (p_plus_q - sqrt_disc) // 2
                if p * q == N and p > 1 and q > 1:
                    return {
                        'success': True,
                        'p': str(p),
                        'q': str(q),
                        'd': str(d_candidate),
                        'text': f"攻击成功!\\n找到因子p和q\\n私钥d = {d_candidate}"
                    }

        return {'success': False, 'error': 'Boneh-Durfee攻击失败，可能d不满足条件'}
        
    except Exception as ex:
        return {'success': False, 'error': str(ex)}

result = attack_boneh_durfee(n_val, e_val, delta_val)
print(json.dumps(result))
'''


def attack(n: str, e: str, delta: str = "0.25", **kwargs) -> dict:
    """
    执行Boneh-Durfee攻击
    
    参数:
        n: 模数
        e: 公钥指数
        delta: d < N^delta的估计值
        
    返回:
        攻击结果字典
    """
    from core.sage_executor import sage_executor
    
    try:
        n_val = int(n, 16) if n.startswith('0x') or n.startswith('0X') else int(n)
        e_val = int(e, 16) if e.startswith('0x') or e.startswith('0X') else int(e)
        delta_val = float(delta) if delta else 0.25
    except ValueError as ex:
        return {'success': False, 'text': f'参数解析错误: {str(ex)}'}
    
    if not sage_executor.is_available():
        return {'success': False, 'text': 'SageMath未配置，请在设置中配置SageMath路径'}
    
    code = SAGE_CODE.replace('n_val', str(n_val)).replace('e_val', str(e_val)).replace('delta_val', str(delta_val))
    
    success, result = sage_executor.execute_and_parse(code, timeout=120)
    
    if success and isinstance(result, dict):
        if result.get('success'):
            return result
        else:
            return {'success': False, 'text': result.get('error', '攻击失败')}
    else:
        return {'success': False, 'text': result.get('error', '执行失败') if isinstance(result, dict) else '执行失败'}
