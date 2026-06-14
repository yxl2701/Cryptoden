"""
Cryptoden CLI - 命令行加解密工具
=================================
用法:
  python cli.py [全局选项] <命令> [参数...]

全局选项:
  -i, --input FILE      从文件读取输入
  -o, --output FILE     输出到文件
  --json                以 JSON 格式输出
  --batch               批量模式（逐行处理）
  --interactive         交互式 Shell

命令:
  list                  列出所有可用算法
  encrypt <算法名> [参数=值...] [文本]  加密
  decrypt <算法名> [参数=值...] [文本]  解密
  rsa [攻击名] [参数=值...]             RSA 攻击
  ecc [攻击名] [参数=值...]             ECC 攻击
  lcg [攻击名] [参数=值...]             LCG 攻击
  try-all [文本]                       尝试所有解密方法
  recursive [文本]                     递归解密（自动尝试多层解密链）

默认行为（无命令）: 等同于 try-all，一键解密

示例:
  python cli.py "U0VGQ1RGe3Rlc3R9"              # 默认一键解密
  python cli.py encrypt caesar shift=3 "hello"
  python cli.py -i cipher.txt -o plain.txt decrypt base64
  python cli.py --json -i input.txt              # 默认一键解密，JSON 输出
  python cli.py --batch -i lines.txt             # 批量一键解密
  python cli.py --interactive                    # 交互式 Shell
  python cli.py recursive "U0VGQ1RGe3Rlc3R9"       # 递归解密
  type cipher.txt | python cli.py decrypt base64
"""

import sys
import json
import argparse
from pathlib import Path

from cryptoden import __version__


def setup_path():
    project_root = Path(__file__).parent.resolve()
    root_str = str(project_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return project_root


def load_crypto_loader():
    """加载算法加载器"""
    from core.crypto_loader import CryptoLoader
    loader = CryptoLoader(Path(__file__).parent.resolve())
    loader.load_all_modules()
    return loader


# ── 全局 I/O 辅助 ──────────────────────────────────────────────

def resolve_input_text(args, raw_text: str = "") -> str:
    """按优先级获取输入文本: 命令行 > -i 文件 > stdin"""
    if raw_text:
        return raw_text
    if args.input_file:
        try:
            raw = Path(args.input_file).read_bytes()
            # 尝试常见编码，优先使用带 BOM 检测的编码
            for enc in ('utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be', 'gbk', 'latin-1'):
                try:
                    return raw.decode(enc).strip().lstrip('\ufeff')
                except (UnicodeDecodeError, UnicodeError):
                    continue
            # 最后尝试 utf-8
            return raw.decode('utf-8').strip().lstrip('\ufeff')
        except Exception as e:
            print(f"错误: 读取文件失败 {args.input_file}: {e}", file=sys.stderr)
            sys.exit(1)
    if not sys.stdin.isatty():
        return sys.stdin.read().strip().lstrip('\ufeff')
    return ""





def emit_output(args, content, is_json=False):
    """输出结果，支持 -o 文件写入"""
    if is_json:
        output = json.dumps(content, ensure_ascii=False, indent=2)
    else:
        output = str(content)

    if args.output_file:
        try:
            Path(args.output_file).write_text(output, encoding="utf-8")
        except Exception as e:
            print(f"错误: 写入文件失败 {args.output_file}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output)


# ── 参数解析 ────────────────────────────────────────────────────

def _parse_kv_args(raw_args):
    """解析 key=value 参数，自动转换数值类型

    规则：
    - 形如 key=value 且 value 不含 = 的视为参数
    - `--` 之后的所有内容当作文本（不再解析参数）
    - 其余当作文本拼接
    """
    params = {}
    text_parts = []
    in_text = False
    for a in raw_args:
        if in_text:
            text_parts.append(a)
            continue
        if a == '--':
            in_text = True
            continue
        if '=' in a and a.count('=') == 1 and not a.startswith('='):
            k, v = a.split('=', 1)
            k, v = k.strip(), v.strip()
            # value 为空时不视为参数（避免 base64 末尾 = 被误解析）
            if v and k.isidentifier():
                try:
                    if '.' in v:
                        params[k] = float(v)
                    else:
                        params[k] = int(v)
                except ValueError:
                    params[k] = v
                continue
        text_parts.append(a)
    return params, ' '.join(text_parts)


def _fuzzy_find_algo(loader, algo_input, mode):
    """模糊匹配算法名，支持短名和中英文"""
    names = loader.get_all_algo_names(mode)

    # 1. 精确匹配
    if algo_input in names:
        return algo_input

    algo_lower = algo_input.lower()

    # 2. 不区分大小写精确匹配
    for name in names:
        if name.lower() == algo_lower:
            return name

    # 3. 去掉中文后缀后精确匹配（如 "caesar" → "caesar凯撒密码"）
    for name in names:
        name_clean = _clean_algo_name(name)
        if name_clean == algo_lower:
            return name

    # 4. 包含匹配
    matches = [n for n in names if algo_lower in n.lower()]
    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        print(f"找到多个匹配: {', '.join(matches)}", file=sys.stderr)
        return matches[0]

    return None


def _clean_algo_name(name: str) -> str:
    """去掉算法名中的中文后缀，如 'caesar凯撒密码' → 'caesar'"""
    cleaned = name
    # 去掉括号内容
    if '(' in cleaned:
        cleaned = cleaned.split('(')[0]
    # 去掉中文字符
    import re
    cleaned = re.sub(r'[\u4e00-\u9fff]+', '', cleaned)
    return cleaned.strip().lower()


def _fuzzy_find_attack(loader, attack_input):
    """模糊匹配攻击名"""
    names = loader.get_attack_names()

    # 1. 精确匹配
    if attack_input in names:
        return attack_input

    inp_lower = attack_input.lower()

    # 2. 不区分大小写精确匹配
    for name in names:
        if name.lower() == inp_lower:
            return name

    # 3. 去掉括号/中文后缀后精确匹配
    clean_matches = []
    for name in names:
        name_clean = _clean_algo_name(name)
        if name_clean == inp_lower:
            clean_matches.append(name)
    if clean_matches:
        # 多个匹配时选原始名最短的（最可能是精确目标）
        clean_matches.sort(key=len)
        return clean_matches[0]

    # 4. 子串匹配
    matches = [n for n in names if inp_lower in n.lower()]
    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        # 有多个匹配时，优先选更短的（更可能是精确目标）
        matches.sort(key=len)
        return matches[0]

    return None


def _is_error_result(result_str: str) -> bool:
    """判断解密结果是否为错误信息"""
    if not result_str:
        return True
    error_indicators = ('错误:', '解码失败', '解码错误', '失败:', '???', '?')
    stripped = result_str.strip()
    return any(stripped.startswith(ind) for ind in error_indicators) or stripped in ('', '?')


# ── 子命令实现 ──────────────────────────────────────────────────

def cmd_list(args):
    """列出所有可用算法"""
    loader = load_crypto_loader()

    encrypt_names = loader.get_all_algo_names('encrypt')
    decrypt_names = loader.get_all_algo_names('decrypt')

    lines = []
    lines.append(f"加密模块 ({len(encrypt_names)}):")
    for name in sorted(encrypt_names):
        info = loader.get_module_info(name, 'encrypt')
        cat = info.get('category', '?') if info else '?'
        lines.append(f"  {name:30s} [{cat}]")

    lines.append("")
    lines.append(f"解密模块 ({len(decrypt_names)}):")
    for name in sorted(decrypt_names):
        info = loader.get_module_info(name, 'decrypt')
        cat = info.get('category', '?') if info else '?'
        lines.append(f"  {name:30s} [{cat}]")

    lines.append("")
    lines.append("RSA 攻击:")
    from algorithms.asymmetric.rsa.attacks.loader import RSALoader
    rsa_loader = RSALoader(Path(__file__).parent / "algorithms" / "asymmetric" / "rsa" / "attacks")
    for name in rsa_loader.get_attack_names():
        lines.append(f"  {name}")

    lines.append("")
    lines.append("ECC 攻击:")
    from algorithms.asymmetric.ecc.attacks.loader import ECCLoader
    ecc_loader = ECCLoader(Path(__file__).parent / "algorithms" / "asymmetric" / "ecc" / "attacks")
    for name in ecc_loader.get_attack_names():
        lines.append(f"  {name}")

    lines.append("")
    lines.append("LCG 攻击:")
    from algorithms.asymmetric.lcg.attacks.loader import LCGLoader
    lcg_loader = LCGLoader(Path(__file__).parent / "algorithms" / "asymmetric" / "lcg" / "attacks")
    for name in lcg_loader.get_attack_names():
        lines.append(f"  {name}")

    emit_output(args, "\n".join(lines))


def cmd_encrypt(args):
    """执行加密"""
    if not args.algo:
        print("错误: 请指定算法名", file=sys.stderr)
        print("用法: python cli.py encrypt <算法名> [参数=值...] [文本]", file=sys.stderr)
        print("提示: 用 python cli.py list 查看所有算法", file=sys.stderr)
        return 1

    loader = load_crypto_loader()
    params, text = _parse_kv_args(args.params)
    text = resolve_input_text(args, text)

    if not text:
        print("错误: 请提供要加密的文本", file=sys.stderr)
        return 1

    algo_name = _fuzzy_find_algo(loader, args.algo, 'encrypt')
    if not algo_name:
        print(f"错误: 未找到算法 '{args.algo}'", file=sys.stderr)
        print("提示: 用 python cli.py list 查看所有算法", file=sys.stderr)
        return 1

    try:
        if args.batch:
            results = []
            for line in text.splitlines():
                if not line.strip():
                    continue
                r = loader.execute_encrypt(algo_name, line.strip(), **params)
                results.append({"input": line.strip(), "result": r})
            if args.json:
                emit_output(args, results, is_json=True)
            else:
                for item in results:
                    print(f"[{item['input']}] → {item['result']}")
        else:
            result = loader.execute_encrypt(algo_name, text, **params)
            if result is not None:
                if args.json:
                    emit_output(args, {"algo": algo_name, "input": text, "result": result}, is_json=True)
                else:
                    emit_output(args, result)
            else:
                print(f"错误: 算法 '{algo_name}' 加密失败", file=sys.stderr)
                return 1
    except Exception as e:
        print(f"加密失败: {e}", file=sys.stderr)
        return 1


def cmd_decrypt(args):
    """执行解密"""
    if not args.algo:
        print("错误: 请指定算法名", file=sys.stderr)
        print("用法: python cli.py decrypt <算法名> [参数=值...] [文本]", file=sys.stderr)
        print("提示: 用 python cli.py list 查看所有算法", file=sys.stderr)
        return 1

    loader = load_crypto_loader()
    params, text = _parse_kv_args(args.params)
    text = resolve_input_text(args, text)

    if not text:
        print("错误: 请提供要解密的文本", file=sys.stderr)
        return 1

    algo_name = _fuzzy_find_algo(loader, args.algo, 'decrypt')
    if not algo_name:
        print(f"错误: 未找到算法 '{args.algo}'", file=sys.stderr)
        print("提示: 用 python cli.py list 查看所有算法", file=sys.stderr)
        return 1

    try:
        if args.batch:
            results = []
            for line in text.splitlines():
                if not line.strip():
                    continue
                r = loader.execute_decrypt(algo_name, line.strip(), **params)
                results.append({"input": line.strip(), "result": r})
            if args.json:
                emit_output(args, results, is_json=True)
            else:
                for item in results:
                    print(f"[{item['input']}] → {item['result']}")
        else:
            result = loader.execute_decrypt(algo_name, text, **params)
            if result is not None:
                if args.json:
                    emit_output(args, {"algo": algo_name, "input": text, "result": result}, is_json=True)
                else:
                    emit_output(args, result)
            else:
                print(f"错误: 算法 '{algo_name}' 解密失败", file=sys.stderr)
                return 1
    except Exception as e:
        print(f"解密失败: {e}", file=sys.stderr)
        return 1


def _run_attack(attack_type, args):
    """通用攻击执行（RSA/ECC/LCG）"""
    loader_map = {
        'rsa': ('algorithms.asymmetric.rsa.attacks.loader', 'RSALoader'),
        'ecc': ('algorithms.asymmetric.ecc.attacks.loader', 'ECCLoader'),
        'lcg': ('algorithms.asymmetric.lcg.attacks.loader', 'LCGLoader'),
    }
    mod_path, cls_name = loader_map[attack_type]
    import importlib
    mod = importlib.import_module(mod_path)
    loader_cls = getattr(mod, cls_name)

    attacks_dir = Path(__file__).parent / "algorithms" / "asymmetric" / attack_type / "attacks"
    loader = loader_cls(attacks_dir)

    if not args.attack:
        lines = [f"可用 {attack_type.upper()} 攻击:"]
        for name in loader.get_attack_names():
            info = loader.get_attack_info(name)
            fields = [f['name'] for f in info.get('input_fields', [])]
            lines.append(f"  {name:30s} 参数: {', '.join(fields)}")
        emit_output(args, "\n".join(lines))
        return 0

    attack_name = _fuzzy_find_attack(loader, args.attack)
    if not attack_name:
        print(f"错误: 未知攻击 '{args.attack}'", file=sys.stderr)
        print(f"提示: 用 python cli.py {attack_type} 查看所有攻击", file=sys.stderr)
        return 1

    info = loader.get_attack_info(attack_name)
    raw_params, _ = _parse_kv_args(args.params)
    # 攻击模块参数都当作字符串处理
    params = {k: str(v) for k, v in raw_params.items()}

    required = [f['name'] for f in info.get('input_fields', []) if f.get('required')]
    missing = [r for r in required if r not in params]
    if missing:
        print(f"错误: 缺少必需参数: {', '.join(missing)}", file=sys.stderr)
        return 1

    try:
        attack_mod = info['module']
        if not hasattr(attack_mod, 'attack'):
            print("错误: 攻击模块没有 attack 函数", file=sys.stderr)
            return 1
        result = attack_mod.attack(**params)
        if args.json:
            emit_output(args, result if isinstance(result, dict) else {"result": str(result)}, is_json=True)
        else:
            if isinstance(result, dict):
                if result.get('success'):
                    print(result.get('text', '攻击成功'))
                else:
                    print(f"攻击失败: {result.get('text', '未知错误')}")
            else:
                print(result)
    except Exception as e:
        print(f"攻击执行失败: {e}", file=sys.stderr)
        return 1


def cmd_rsa(args):
    return _run_attack('rsa', args)


def cmd_ecc(args):
    return _run_attack('ecc', args)


def cmd_lcg(args):
    return _run_attack('lcg', args)


def cmd_recursive(args):
    """递归解密"""
    from de_recursion import recursive_decrypt, format_recursive_result, parse_patterns

    text = ' '.join(args.params) if args.params else ''
    text = resolve_input_text(args, text)

    if not text:
        print("错误: 请提供要解密的文本", file=sys.stderr)
        return 1

    # 解析模式参数
    patterns = parse_patterns(args.pattern) if args.pattern else None

    try:
        result = recursive_decrypt(
            text,
            max_depth=args.max_depth,
            patterns=patterns,
            match_all=args.match_all,
        )
    except Exception as e:
        print(f"递归解密失败: {e}", file=sys.stderr)
        return 1

    if args.json:
        emit_output(args, result, is_json=True)
    else:
        output = format_recursive_result(
            result,
            show_all=args.chain,
            brief=args.brief,
        )
        emit_output(args, output)

    return 0


def cmd_try_all(args):
    """尝试所有解密方法"""
    loader = load_crypto_loader()

    text = ' '.join(args.params) if args.params else ''
    text = resolve_input_text(args, text)

    if not text:
        print("错误: 请提供要解密的文本", file=sys.stderr)
        return 1

    if args.batch:
        all_results = []
        for line in text.splitlines():
            if not line.strip():
                continue
            results = loader.try_decrypt_all(line.strip())
            all_results.append({"input": line.strip(), "results": [
                {"name": r["name"], "result": r["result"]} for r in results
            ]})
        if args.json:
            emit_output(args, all_results, is_json=True)
        else:
            for item in all_results:
                print(f"[{item['input']}]")
                if item["results"]:
                    for r in item["results"]:
                        print(f"  {r['name']}: {str(r['result'])[:200]}")
                else:
                    print("  (无结果)")
                print()
        return 0

    results = loader.try_decrypt_all(text)

    if args.json:
        output = {
            "input": text,
            "count": len(results),
            "results": [
                {
                    "name": r["name"],
                    "result": r["result"],
                    "is_brute": bool(r.get("is_brute")),
                    "params": r.get("params", ""),
                    "score": r.get("score", 0),
                }
                for r in results
            ]
        }
        emit_output(args, output, is_json=True)
        return 0

    if not results:
        emit_output(args, "所有解密方法均未返回有效结果")
        return 0

    # 过滤掉明显是错误信息的结果
    valid_results = [r for r in results if not _is_error_result(str(r['result']))]
    error_count = len(results) - len(valid_results)

    lines = []
    if valid_results:
        lines.append(f"找到 {len(valid_results)} 个可能的解密结果:\n")
        for r in valid_results:
            result_str = str(r['result'])
            suffix = f" / {r['params']}" if r.get('params') else ""
            label = f"{r['name']} - 爆破结果{suffix}" if r.get('is_brute') else r['name']
            lines.append(f"[{label}]")
            lines.append(f"  {result_str[:200]}")
            if len(result_str) > 200:
                lines.append(f"  ... (共 {len(result_str)} 字符)")
            lines.append("")

    if error_count > 0:
        lines.append(f"（另有 {error_count} 个算法因缺少参数未能执行，加 --json 可查看全部）")

    emit_output(args, "\n".join(lines))


def cmd_interactive(args):
    """交互式 Shell"""
    loader = load_crypto_loader()
    print("Cryptoden 交互式 Shell (输入 help 查看帮助, exit 退出)")
    print()

    while True:
        try:
            raw = input("cryptoden> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break

        line = raw.strip().strip('\r').lstrip('\ufeff')
        if not line:
            continue

        if line in ('exit', 'quit', 'q'):
            break

        if line == 'help':
            print("可用命令:")
            print("  list                       列出所有算法")
            print("  enc <algo> [k=v...] <text>  加密")
            print("  dec <algo> [k=v...] <text>  解密")
            print("  try-all <text>              一键解密")
            print("  recursive <text>            递归解密")
            print("  rsa [attack] [k=v...]       RSA 攻击")
            print("  ecc [attack] [k=v...]       ECC 攻击")
            print("  lcg [attack] [k=v...]       LCG 攻击")
            print("  help                       显示帮助")
            print("  exit/quit                   退出")
            print()
            continue

        parts = line.split()
        cmd = parts[0]
        rest = parts[1:]

        try:
            if cmd == 'list':
                cmd_list(args)
            elif cmd in ('enc', 'encrypt'):
                if not rest:
                    print("用法: enc <算法名> [k=v...] <文本>")
                    continue
                algo = _fuzzy_find_algo(loader, rest[0], 'encrypt') or rest[0]
                p, t = _parse_kv_args(rest[1:])
                if not t:
                    t = input("文本: ").strip()
                if t:
                    result = loader.execute_encrypt(algo, t, **p)
                    print(result if result is not None else "加密失败")
            elif cmd in ('dec', 'decrypt'):
                if not rest:
                    print("用法: dec <算法名> [k=v...] <文本>")
                    continue
                algo = _fuzzy_find_algo(loader, rest[0], 'decrypt') or rest[0]
                p, t = _parse_kv_args(rest[1:])
                if not t:
                    t = input("文本: ").strip()
                if t:
                    result = loader.execute_decrypt(algo, t, **p)
                    print(result if result is not None else "解密失败")
            elif cmd == 'try-all':
                t = ' '.join(rest)
                if not t:
                    t = input("文本: ").strip()
                if t:
                    results = loader.try_decrypt_all(t)
                    if results:
                        for r in results:
                            if not _is_error_result(str(r['result'])):
                                print(f"[{r['name']}] {str(r['result'])[:200]}")
                    else:
                        print("无结果")
            elif cmd == 'recursive':
                t = ' '.join(rest)
                if not t:
                    t = input("文本: ").strip()
                if t:
                    from de_recursion import recursive_decrypt, format_recursive_result
                    try:
                        result = recursive_decrypt(t)
                        print(format_recursive_result(result, show_all=False, brief=False))
                    except Exception as e:
                        print(f"错误: {e}")
            elif cmd in ('rsa', 'ecc', 'lcg'):
                sub_args = argparse.Namespace(
                    attack=rest[0] if rest else None,
                    params=rest[1:] if len(rest) > 1 else [],
                    json=False, input_file=None, output_file=None,
                    batch=False, interactive=False,
                )
                globals()[f'cmd_{cmd}'](sub_args)
            else:
                print(f"未知命令: {cmd}，输入 help 查看帮助")
        except Exception as e:
            print(f"错误: {e}")

    return 0


# ── 主入口 ──────────────────────────────────────────────────────

def build_parser():
    """构建参数解析器
    
    全局选项只放在主解析器中。子命令后的全局选项通过
    _reorder_global_flags 在解析前移到子命令前。
    """
    parser = argparse.ArgumentParser(
        description="Cryptoden - CTF 加解密命令行工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
示例:
  python cli.py list
  python cli.py encrypt caesar shift=3 "hello world"
  python cli.py -i cipher.txt -o plain.txt decrypt base64
  python cli.py rsa wiener n=123456789 e=65537 c=987654321
  python cli.py --json -i input.txt              # 默认一键解密，JSON 输出
  python cli.py --batch -i lines.txt             # 批量一键解密
  python cli.py --interactive                    # 交互式 Shell
  python cli.py recursive "U0VGQ1RGe3Rlc3R9"       # 递归解密
  type cipher.txt | python cli.py decrypt base64
        """,
    )

    # 全局选项（放在子命令前，供默认模式使用）
    parser.add_argument('-i', '--input', dest='input_file', metavar='FILE',
                        help='从文件读取输入')
    parser.add_argument('-o', '--output', dest='output_file', metavar='FILE',
                        help='输出到文件')
    parser.add_argument('--json', action='store_true',
                        help='以 JSON 格式输出')
    parser.add_argument('--batch', action='store_true',
                        help='批量模式（逐行处理输入）')
    parser.add_argument('--interactive', action='store_true',
                        help='交互式 Shell')
    parser.add_argument('--version', action='store_true',
                        help='显示版本号')

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # list
    subparsers.add_parser('list', help='列出所有可用算法')

    # encrypt
    p_enc = subparsers.add_parser('encrypt', help='加密')
    p_enc.add_argument('algo', nargs='?', help='算法名')
    p_enc.add_argument('params', nargs='*', help='参数 (key=value) 和文本')

    # decrypt
    p_dec = subparsers.add_parser('decrypt', help='解密')
    p_dec.add_argument('algo', nargs='?', help='算法名')
    p_dec.add_argument('params', nargs='*', help='参数 (key=value) 和文本')

    # rsa
    p_rsa = subparsers.add_parser('rsa', help='RSA 攻击')
    p_rsa.add_argument('attack', nargs='?', help='攻击名')
    p_rsa.add_argument('params', nargs='*', help='参数 (key=value)')

    # ecc
    p_ecc = subparsers.add_parser('ecc', help='ECC 攻击')
    p_ecc.add_argument('attack', nargs='?', help='攻击名')
    p_ecc.add_argument('params', nargs='*', help='参数 (key=value)')

    # lcg
    p_lcg = subparsers.add_parser('lcg', help='LCG 攻击')
    p_lcg.add_argument('attack', nargs='?', help='攻击名')
    p_lcg.add_argument('params', nargs='*', help='参数 (key=value)')

    # try-all
    p_try = subparsers.add_parser('try-all', help='尝试所有解密方法')
    p_try.add_argument('params', nargs='*', help='要解密的文本')

    # recursive
    p_rec = subparsers.add_parser('recursive', help='递归解密（自动尝试多层解密链）')
    p_rec.add_argument('params', nargs='*', help='要解密的文本')
    p_rec.add_argument('-d', '--max-depth', '--depth', type=int, default=None,
                       dest='max_depth',
                       help='最大递归深度（默认读取 config.json）')
    p_rec.add_argument('-p', '--pattern', action='append', default=[],
                       help='匹配模式（支持空格/逗号分隔多个，如 -p "flag,ctf,key"）')
    p_rec.add_argument('--match-all', action='store_true',
                       help='所有模式都要匹配（默认任一匹配即可）')
    p_rec.add_argument('--chain', action='store_true',
                       help='显示完整解密路径')
    p_rec.add_argument('--brief', action='store_true',
                       help='紧凑输出模式（仅显示最佳结果）')

    return parser


def _parse_global_flags(argv):
    """只解析全局选项，不碰子命令"""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument('-i', '--input', dest='input_file', default=None)
    p.add_argument('-o', '--output', dest='output_file', default=None)
    p.add_argument('--json', action='store_true', default=False)
    p.add_argument('--batch', action='store_true', default=False)
    p.add_argument('--interactive', action='store_true', default=False)
    p.add_argument('--version', action='store_true', default=False)
    return p.parse_known_args(argv)


def _reorder_global_flags(argv):
    """将子命令后的全局选项移到子命令前
    
    例如: ['encrypt', '--json', 'caesar'] → ['--json', 'encrypt', 'caesar']
    这样 argparse 可以正确解析全局选项。
    """
    known_commands = {'list', 'encrypt', 'decrypt', 'rsa', 'ecc', 'lcg', 'try-all', 'recursive'}
    value_flags = {'-i', '--input', '-o', '--output'}
    bool_flags = {'--json', '--batch', '--interactive'}
    global_flags = value_flags | bool_flags

    # 找到第一个子命令的位置
    cmd_idx = None
    for i, arg in enumerate(argv):
        if arg in known_commands:
            cmd_idx = i
            break

    if cmd_idx is None:
        return argv

    # 收集子命令后的全局选项
    before_cmd = argv[:cmd_idx + 1]  # 包含子命令
    after_cmd = []
    moved_flags = []
    i = cmd_idx + 1

    while i < len(argv):
        arg = argv[i]
        if arg in value_flags:
            # 带值的选项：移动 flag 和它的值
            moved_flags.append(arg)
            if i + 1 < len(argv) and not argv[i + 1].startswith('-'):
                moved_flags.append(argv[i + 1])
                i += 2
            else:
                i += 1
        elif arg in bool_flags:
            moved_flags.append(arg)
            i += 1
        else:
            after_cmd.append(arg)
            i += 1

    return moved_flags + before_cmd + after_cmd


def main():
    setup_path()

    known_commands = {'list', 'encrypt', 'decrypt', 'rsa', 'ecc', 'lcg', 'try-all', 'recursive'}
    if '--version' in sys.argv[1:]:
        print(f"Cryptoden {__version__}")
        return 0
    has_command = any(arg in known_commands for arg in sys.argv[1:] if not arg.startswith('-'))

    if not has_command:
        # 无子命令 → 默认 try-all（一键解密）
        flags, remaining = _parse_global_flags(sys.argv[1:])
        if flags.interactive:
            return cmd_interactive(flags)
        text_parts = [a for a in remaining if not a.startswith('-')]
        text = ' '.join(text_parts) if text_parts else ''
        # 命令行无文本、无文件时，尝试读 stdin
        if not text and not flags.input_file:
            if not sys.stdin.isatty():
                text = sys.stdin.read().strip().lstrip('\ufeff')
            if not text:
                build_parser().print_help()
                return 0
        args = argparse.Namespace(
            params=[text] if text else [],
            input_file=flags.input_file,
            output_file=flags.output_file,
            json=flags.json,
            batch=flags.batch,
            interactive=False,
        )
        return cmd_try_all(args)

    # 重新排序 argv：将子命令后的全局选项移到前面
    reordered_argv = _reorder_global_flags(sys.argv[1:])

    parser = build_parser()
    args = parser.parse_args(reordered_argv)

    if args.interactive:
        return cmd_interactive(args)

    commands = {
        'list': cmd_list,
        'encrypt': cmd_encrypt,
        'decrypt': cmd_decrypt,
        'rsa': cmd_rsa,
        'ecc': cmd_ecc,
        'lcg': cmd_lcg,
        'try-all': cmd_try_all,
        'recursive': cmd_recursive,
    }

    return commands[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
