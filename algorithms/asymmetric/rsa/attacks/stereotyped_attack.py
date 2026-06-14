"""
Stereotyped Message攻击模块
===========================

【攻击原理】
当明文的部分内容已知时（如已知明文格式、前缀或后缀），
可以使用Coppersmith方法恢复完整的明文。

数学基础：
- 设 m = known_part + unknown_part
- 构造多项式 f(x) = (known_part + x)^e - c
- 使用Coppersmith方法寻找小根x = unknown_part

【攻击条件】
1. 已知明文的部分内容
2. 公钥e较小（通常e <= 17效果较好）
3. 未知部分相对较小
4. 需要SageMath环境

【攻击步骤】
1. 根据已知部分构造多项式
2. 使用small_roots方法寻找小根
3. 恢复完整明文

【适用场景】
- 已知明文格式（如"flag{...}"）
- 已知明文前缀或后缀
- 已知部分填充内容

【参考文献】
Coppersmith, D. (1996). "Finding a Small Root of a Univariate Modular Equation"
"""

ATTACK_NAME = "Stereotyped Message攻击(sagemath)"
ATTACK_DESC = "当明文部分已知时恢复完整明文（需要SageMath）"
ATTACK_HINT = "适用于已知明文部分比特的情况，e较小效果更好"

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
        'placeholder': '输入公钥指数e（小指数效果更好）',
        'default': ''
    },
    {
        'name': 'c',
        'label': '密文 c',
        'type': 'text',
        'placeholder': '输入密文c',
        'default': ''
    },
    {
        'name': 'known_part',
        'label': '已知明文部分',
        'type': 'text',
        'placeholder': '已知部分，用?表示未知位',
        'default': ''
    }
]

SAGE_CODE = '''
from sage.all import Zmod, ZZ

def attack_stereotyped(N, e, c, known_part):
    """
    Stereotyped Message攻击
    当明文部分已知时使用Coppersmith方法恢复完整明文
    """
    try:
        N = int(N)
        e = int(e)
        c = int(c)
        
        if '?' not in known_part:
            return {'success': False, 'error': '已知部分需要包含?表示未知位'}
        
        unknown_count = known_part.count('?')
        if unknown_count > 100:
            return {'success': False, 'error': f'未知位过多({unknown_count})，计算量过大'}
        
        x = Zmod(N)['x'].gen()
        
        known_prefix = ''
        known_suffix = ''
        
        q_pos = known_part.find('?')
        if q_pos > 0:
            known_prefix = known_part[:q_pos]
        last_q = known_part.rfind('?')
        if last_q < len(known_part) - 1:
            known_suffix = known_part[last_q + 1:]
        
        prefix_val = int(known_prefix, 16) if known_prefix else 0
        suffix_val = int(known_suffix, 16) if known_suffix else 0
        
        shift = len(known_suffix) * 4 if known_suffix else 0
        
        f = (prefix_val * (16 ** (unknown_count + len(known_suffix))) + x * (16 ** shift) + suffix_val) ** e - c
        
        X = 16 ** unknown_count
        
        from sage.all import small_roots
        
        try:
            roots = f.small_roots(X=X, beta=0.5)
            
            for root in roots:
                m = int(prefix_val * (16 ** (unknown_count + len(known_suffix))) + int(root) * (16 ** shift) + suffix_val)
                
                if pow(m, e, N) == c:
                    try:
                        plaintext = bytes.fromhex(hex(m)[2:])
                        return {
                            'success': True,
                            'm': str(m),
                            'plaintext': plaintext.decode('utf-8', errors='replace'),
                            'text': f"攻击成功!\\n明文(十进制): {m}\\n明文(文本): {plaintext.decode('utf-8', errors='replace')}"
                        }
                    except:
                        return {
                            'success': True,
                            'm': str(m),
                            'text': f"攻击成功!\\n明文(十进制): {m}"
                        }
        except Exception as ex:
            pass
        
        return {'success': False, 'error': '未能找到小根，可能未知位过多或e过大'}
        
    except Exception as ex:
        return {'success': False, 'error': str(ex)}

result = attack_stereotyped(n_val, e_val, c_val, known_part_val)
print(json.dumps(result))
'''


def attack(n: str, e: str, c: str, known_part: str = "", **kwargs) -> dict:
    """
    执行Stereotyped Message攻击
    
    参数:
        n: 模数
        e: 公钥指数
        c: 密文
        known_part: 已知明文部分，用?表示未知
        
    返回:
        攻击结果字典
    """
    from core.sage_executor import sage_executor
    
    try:
        n_val = int(n, 16) if n.startswith('0x') or n.startswith('0X') else int(n)
        e_val = int(e, 16) if e.startswith('0x') or e.startswith('0X') else int(e)
        c_val = int(c, 16) if c.startswith('0x') or c.startswith('0X') else int(c)
    except ValueError as ex:
        return {'success': False, 'text': f'参数解析错误: {str(ex)}'}
    
    if not known_part:
        return {'success': False, 'text': '请输入已知明文部分'}
    
    if not sage_executor.is_available():
        return {'success': False, 'text': 'SageMath未配置，请在设置中配置SageMath路径'}
    
    code = SAGE_CODE.replace('n_val', str(n_val)).replace('e_val', str(e_val))
    code = code.replace('c_val', str(c_val)).replace('known_part_val', f'"{known_part}"')
    
    success, result = sage_executor.execute_and_parse(code, timeout=120)
    
    if success and isinstance(result, dict):
        if result.get('success'):
            return result
        else:
            return {'success': False, 'text': result.get('error', '攻击失败')}
    else:
        return {'success': False, 'text': result.get('error', '执行失败') if isinstance(result, dict) else '执行失败'}
