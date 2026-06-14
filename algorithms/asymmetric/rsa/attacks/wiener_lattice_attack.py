"""
Wiener Lattice攻击模块
======================

【攻击原理】
Wiener Lattice攻击是使用格基规约方法实现的Wiener攻击变体。
当私钥d < N^0.25时，可以通过构造格并使用LLL算法恢复私钥。

数学基础：
- 由 e*d - k*φ(n) = 1
- 构造格来寻找满足条件的小向量
- 使用LLL格基规约算法找到短向量

【攻击条件】
1. 私钥d < N^0.25
2. 公钥e较大
3. 需要SageMath环境

【攻击步骤】
1. 构造格基矩阵
2. 使用LLL算法规约
3. 从短向量中提取k和d
4. 验证私钥正确性

【与标准Wiener攻击的区别】
- 标准Wiener攻击使用连分数展开
- Lattice攻击使用格基规约
- 两者在相同条件下有效，但实现方式不同

【参考文献】
- 格基密码分析
- LLL算法
"""

ATTACK_NAME = "Wiener Lattice攻击(sagemath)"
ATTACK_DESC = "使用格基方法恢复小私钥d（需要SageMath）"
ATTACK_HINT = "适用于d < N^0.25的情况，使用LLL格基规约"

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
    }
]

SAGE_CODE = '''
from sage.all import ZZ, matrix, isqrt, continued_fraction

def attack_wiener_lattice(N, e):
    """
    Wiener Lattice攻击
    使用格基方法恢复小私钥d
    """
    try:
        N = int(N)
        e = int(e)
        
        s = isqrt(N)
        L = matrix(ZZ, [[e, s], [N, 0]])
        
        L_reduced = L.LLL()
        
        for row in L_reduced:
            d_candidate = abs(row[1] // s)
            
            if d_candidate > 0:
                k = abs(row[0] - e * d_candidate) // N
                
                if k > 0:
                    phi_candidate = (e * d_candidate - 1) // k
                    
                    if phi_candidate > 0:
                        p_plus_q = N - phi_candidate + 1
                        discriminant = p_plus_q^2 - 4*N
                        
                        if discriminant >= 0:
                            sqrt_disc = isqrt(discriminant)
                            if sqrt_disc^2 == discriminant:
                                p = (p_plus_q + sqrt_disc) // 2
                                q = (p_plus_q - sqrt_disc) // 2
                                
                                if p * q == N:
                                    if pow(pow(2, e, N), d_candidate, N) == 2:
                                        return {
                                            'success': True,
                                            'p': str(p),
                                            'q': str(q),
                                            'd': str(d_candidate),
                                            'phi': str(phi_candidate),
                                            'text': f"攻击成功!\\n找到因子p和q\\n私钥d = {d_candidate}"
                                        }

        # 标准Wiener连分数兜底。上面的2维格构造对部分有效样例不稳定，
        # 连分数验证能覆盖经典 d < N^0.25 场景。
        cf = continued_fraction(ZZ(e) / ZZ(N))
        for conv in cf.convergents():
            k = ZZ(conv.numerator())
            d_candidate = ZZ(conv.denominator())

            if k == 0 or d_candidate <= 0:
                continue

            if (e * d_candidate - 1) % k != 0:
                continue

            phi_candidate = (e * d_candidate - 1) // k
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
            if p * q == N and pow(pow(2, e, N), d_candidate, N) == 2:
                return {
                    'success': True,
                    'p': str(p),
                    'q': str(q),
                    'd': str(d_candidate),
                    'phi': str(phi_candidate),
                    'text': f"攻击成功!\\n找到因子p和q\\n私钥d = {d_candidate}"
                }
        
        return {'success': False, 'error': 'Wiener Lattice攻击失败，可能d不满足条件'}
        
    except Exception as ex:
        return {'success': False, 'error': str(ex)}

result = attack_wiener_lattice(n_val, e_val)
print(json.dumps(result))
'''


def attack(n: str, e: str, **kwargs) -> dict:
    """
    执行Wiener Lattice攻击
    
    参数:
        n: 模数
        e: 公钥指数
        
    返回:
        攻击结果字典
    """
    from core.sage_executor import sage_executor
    
    try:
        n_val = int(n, 16) if n.startswith('0x') or n.startswith('0X') else int(n)
        e_val = int(e, 16) if e.startswith('0x') or e.startswith('0X') else int(e)
    except ValueError as ex:
        return {'success': False, 'text': f'参数解析错误: {str(ex)}'}
    
    if not sage_executor.is_available():
        return {'success': False, 'text': 'SageMath未配置，请在设置中配置SageMath路径'}
    
    code = SAGE_CODE.replace('n_val', str(n_val)).replace('e_val', str(e_val))
    
    success, result = sage_executor.execute_and_parse(code, timeout=60)
    
    if success and isinstance(result, dict):
        if result.get('success'):
            return result
        else:
            return {'success': False, 'text': result.get('error', '攻击失败')}
    else:
        return {'success': False, 'text': result.get('error', '执行失败') if isinstance(result, dict) else '执行失败'}
