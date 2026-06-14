"""
Hastad广播攻击模块
==================

【攻击原理】
当同一明文m使用相同的小公钥指数e加密多次，发送给不同的接收者时，
可以使用中国剩余定理(CRT)恢复明文。

数学基础：
- 设有e组密文: c_i = m^e mod n_i
- 如果所有n_i两两互质，由中国剩余定理:
  存在唯一的 C 满足 C ≡ c_i (mod n_i)
- 且 C = m^e (因为 m^e < n_1 * n_2 * ... * n_e)
- 因此 m = C^(1/e)

【攻击条件】
1. 同一明文m使用相同的小e加密
2. 至少有e组不同的密文
3. 所有模数n_i两两互质
4. m^e < n_1 * n_2 * ... * n_e

【攻击步骤】
1. 收集至少e组 (n_i, c_i)
2. 验证所有n_i两两互质
3. 使用CRT计算 C ≡ c_i (mod n_i)
4. 计算 m = C^(1/e) (整数e次根)

【时间复杂度】
O(e * log(N))，其中N是模数的乘积

【参考文献】
Hastad, J. (1988). "Solving Simultaneous Modular Equations of Low Degree"
"""

ATTACK_NAME = "Hastad广播攻击(sagemath)"
ATTACK_DESC = "当同一明文使用相同小指数e加密多次时恢复明文（需要SageMath）"
ATTACK_HINT = "适用于同一明文用相同e加密多次发送给不同接收者，需要至少e组密文"

INPUT_FIELDS = [
    {
        'name': 'e',
        'label': '公钥指数 e',
        'type': 'text',
        'placeholder': '输入公钥指数e（小整数）',
        'default': '3'
    },
    {
        'name': 'n_list',
        'label': '模数列表N（逗号分隔）',
        'type': 'text',
        'placeholder': '输入多个模数N，用逗号分隔',
        'default': ''
    },
    {
        'name': 'c_list',
        'label': '密文列表c（逗号分隔）',
        'type': 'text',
        'placeholder': '输入对应的密文c，用逗号分隔',
        'default': ''
    }
]

SAGE_CODE = '''
from sage.all import ZZ, CRT_list

def attack_hastad(e, n_list, c_list):
    """
    Hastad广播攻击
    当同一明文使用相同小指数e加密多次时恢复明文
    """
    try:
        e = int(e)
        n_list = [int(n) for n in n_list]
        c_list = [int(c) for c in c_list]
        
        if len(n_list) != len(c_list):
            return {'success': False, 'error': '模数和密文数量不匹配'}
        
        if len(n_list) < e:
            return {'success': False, 'error': f'需要至少{e}组密文'}
        
        n_list = n_list[:e]
        c_list = c_list[:e]
        
        for i in range(len(n_list)):
            for j in range(i + 1, len(n_list)):
                if ZZ(n_list[i]).gcd(n_list[j]) != 1:
                    return {'success': False, 'error': f'模数n{i}和n{j}不互质'}
        
        N = 1
        for n in n_list:
            N *= n
        
        c = CRT_list(c_list, n_list)
        
        root_result = ZZ(c).nth_root(e, truncate_mode=True)
        if isinstance(root_result, tuple):
            m = root_result[0]
        else:
            m = root_result
        
        m_int = int(m)
        
        for i in range(len(n_list)):
            if pow(m_int, e, n_list[i]) == c_list[i]:
                try:
                    plaintext = bytes.fromhex(hex(m_int)[2:])
                    return {
                        'success': True,
                        'm': str(m_int),
                        'plaintext': plaintext.decode('utf-8', errors='replace'),
                        'text': f"攻击成功!\\n明文(十进制): {m_int}\\n明文(文本): {plaintext.decode('utf-8', errors='replace')}"
                    }
                except:
                    return {
                        'success': True,
                        'm': str(m_int),
                        'text': f"攻击成功!\\n明文(十进制): {m_int}"
                    }
        
        return {'success': False, 'error': '开方结果验证失败'}
        
    except Exception as ex:
        return {'success': False, 'error': str(ex)}

result = attack_hastad(e_val, n_list_val, c_list_val)
print(json.dumps(result))
'''


def attack(e: str, n_list: str, c_list: str, **kwargs) -> dict:
    """
    执行Hastad广播攻击
    
    参数:
        e: 公钥指数
        n_list: 模数列表（逗号分隔）
        c_list: 密文列表（逗号分隔）
        
    返回:
        攻击结果字典
    """
    from core.sage_executor import sage_executor
    
    try:
        e_val = int(e, 16) if e.startswith('0x') or e.startswith('0X') else int(e)
        
        n_vals = []
        for n in n_list.split(','):
            n = n.strip()
            if n:
                n_vals.append(int(n, 16) if n.startswith('0x') or n.startswith('0X') else int(n))
        
        c_vals = []
        for c in c_list.split(','):
            c = c.strip()
            if c:
                c_vals.append(int(c, 16) if c.startswith('0x') or c.startswith('0X') else int(c))
    except ValueError as ex:
        return {'success': False, 'text': f'参数解析错误: {str(ex)}'}
    
    if not n_vals or not c_vals:
        return {'success': False, 'text': '请输入模数和密文列表'}
    
    if not sage_executor.is_available():
        return {'success': False, 'text': 'SageMath未配置，请在设置中配置SageMath路径'}
    
    code = SAGE_CODE.replace('e_val', str(e_val))
    code = code.replace('n_list_val', str(n_vals))
    code = code.replace('c_list_val', str(c_vals))
    
    success, result = sage_executor.execute_and_parse(code, timeout=120)
    
    if success and isinstance(result, dict):
        if result.get('success'):
            return result
        else:
            return {'success': False, 'text': result.get('error', '攻击失败')}
    else:
        return {'success': False, 'text': result.get('error', '执行失败') if isinstance(result, dict) else '执行失败'}
