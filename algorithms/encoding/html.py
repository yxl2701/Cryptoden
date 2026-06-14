"""
HTML实体编码模块
================

【编码原理】
HTML实体编码将特殊字符转换为HTML实体名称或编号，
用于在HTML文档中安全显示特殊字符。

转换规则:
  & → &amp;    (防止被解析为HTML实体)
  < → &lt;     (防止被解析为标签起始)
  > → &gt;     (防止被解析为标签结束)
  " → &quot;   (防止属性值提前结束)
  ' → &#x27;   (防止属性值提前结束)

【应用场景】
1. 防止XSS攻击
2. 在HTML中显示代码片段
3. 处理用户输入的安全显示

【示例】
  输入: <script>alert('xss')</script>
  编码: &lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;
"""

import html


def encrypt(plaintext):
    """
    HTML实体编码
    
    将字符串中的HTML特殊字符转换为对应的实体名称，
    确保文本在HTML中安全显示。
    
    参数:
        plaintext (str): 要编码的原始文本
    
    返回:
        str: HTML实体编码后的文本
    
    示例:
        >>> encrypt("<test>")
        '&lt;test&gt;'
    """
    return html.escape(plaintext)


def decrypt(ciphertext):
    """
    HTML实体解码
    
    将HTML实体名称/编号还原为原始字符。
    
    参数:
        ciphertext (str): HTML实体编码的文本
    
    返回:
        str: 解码后的原始文本
    
    示例:
        >>> decrypt("&lt;test&gt;")
        '<test>'
    """
    try:
        return html.unescape(ciphertext)
    except Exception as e:
        return f"解码错误: {str(e)}"

