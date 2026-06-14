# Cryptoden 使用手册

## 简介

Cryptoden 是一个面向 CTF 密码学题目的加解密工具，支持 GUI 和 CLI。它可以处理常见古典密码、编码/解码、哈希、对称密码、非对称密码，并提供一键解密、递归解密、AI 分析和若干攻击辅助功能。

## 免责声明与许可

- 本项目采用 MIT License 开源发布，具体条款见 `LICENSE`。
- 本工具面向 CTF 练习、密码学学习、安全教育和授权分析场景。
- 使用本工具造成的任何损失、风险、法律责任、数据损坏、服务中断、账号限制、竞赛处罚或其他后果，均与开发者本人无关。
- 使用者应自行确认行为符合法律法规、平台规则、竞赛规则和授权边界。

## 安装与启动

环境要求：

- Python 3.8+
- 依赖见 `requirements.txt`
- 部分 SageMath 攻击需要额外配置 SageMath，支持本机、WSL 和网页端 SageCell

安装依赖：

```bash
pip install -r requirements.txt
```

如果使用 `pip install .`，会安装核心依赖并注册 `cryptoden`、`cryptoden-gui` 两个入口；但 SageCell 在线执行的浏览器兜底能力依赖 `playwright`、`selenium`，更推荐完整安装 `requirements.txt`。

启动图形界面：

```bash
python main.py
```

查看命令行帮助：

```bash
python cli.py --help
```

## GUI 使用

主界面默认包含基础面板和常用算法选项卡：

- `加解密`：用于常规文本加密、解密和转换。
- `AI工作台`：用于调用已配置的 AI 服务分析密文、对话或运行受限 Agent。
- `RSA`：RSA 加密、解密和攻击辅助。
- `AES`：对称密码专用界面，默认选择 AES。

其他算法选项卡默认隐藏。需要显示 `ECC`、`LCG`、`DES`、`3DES`、`Blowfish`、`RC4`、`ChaCha20`、`Twofish`、`Fernet` 或 `XOR` 时，打开 `设置 -> 首选项 -> 算法选项卡` 勾选并应用。

常规流程：

1. 在菜单栏选择 `加密` 或 `解密` 下的算法。
2. 在输入框粘贴或输入待处理内容。
3. 按算法要求填写参数。参数来自算法函数签名，会自动生成。
4. 查看输出框结果。
5. 需要保存时使用 `文件 -> 保存结果...`。

常用菜单：

- `文件`：打开文件、保存结果、刷新算法列表、重启程序、退出。
- `编辑`：撤销、重做、粘贴、清空全部。
- `加密/解密`：按分类选择古典密码、编码/解码、哈希等通用算法。
- `对称密码`：打开 AES/DES/3DES/Blowfish/RC4 等专用界面，不在 `加密/解密` 菜单中重复出现。
- `非对称密码`：打开 RSA、ECC、LCG 专用界面和攻击辅助，不在 `加密/解密` 菜单中重复出现。
- `转换`：大小写转换、格式清理、进制转换、文本反转。
- `设置`：首选项、AI 配置、自动复制、自动交换、算法选项卡、解密记录；常用首选项会自动保存到 `config.json`。
- `帮助`：快捷键参考、可搜索算法列表、关于。

### 输出区功能

- `匹配`：输入 `flag;ctf;key` 这类关键字，输出内容会自动高亮匹配项。
- `快捷`：点击常用标签快速增删匹配关键字。
- `搜索`：在输出内容内搜索任意文本，并用“上一个/下一个”跳转。
- 一键解密结果会优先显示命中关键字、疑似 `flag{...}` 或可读性更高的内容。

### 复制与剪贴板

- 文本框中的复制操作按纯文本处理，适合直接粘贴到脚本、终端或题目平台。
- Windows 下如果其他程序短暂占用剪贴板，可能看到 `OleSetClipboard` 或 `qt.qpa.mime` 日志；通常不影响加解密结果，可稍后再次复制。

### 帮助菜单

- `快捷键参考`：只展示常用快捷键，避免大段文本干扰。
- `算法列表`：以独立窗口展示，可切换加密/解密、按分类筛选、按名称搜索。
- `关于`：展示版本号和主要功能概览。

## CLI 使用

列出全部算法和攻击模块：

```bash
python cli.py list
python cli.py --version
```

加密/解密：

```bash
python cli.py encrypt base64 "hello"
python cli.py decrypt base64 "aGVsbG8="
python cli.py encrypt caesar shift=3 "hello"
python cli.py decrypt caesar shift=3 "khoor"
```

一键解密和递归解密：

```bash
python cli.py try-all "U0VGQ1RGe3Rlc3R9"
python cli.py recursive "U0VGQ1RGe3Rlc3R9"
python cli.py try-all "khoor zruog"
python cli.py recursive --brief -p hello "khoor zruog"
```

文件输入输出：

```bash
python cli.py -i cipher.txt -o result.txt decrypt base64
```

JSON 输出和批量模式：

```bash
python cli.py --json try-all "khoor zruog"
python cli.py --batch -i lines.txt try-all
```

交互模式：

```bash
python cli.py --interactive
```

攻击模块列表：

```bash
python cli.py rsa
python cli.py ecc
python cli.py lcg
```

## 支持的主要算法

当前实际加载结果：119 个加密模块、97 个解密模块、22 个 RSA 攻击、11 个 ECC 攻击、1 个 LCG 攻击。

算法分类：

- 古典密码：凯撒、维吉尼亚、栅栏、仿射、培根、Enigma、Playfair、Hill、ADFGVX、四方密码、路线密码等。
- 编码/解码：Base32、Base58、Base62、Base64、Base85、Base91、Hex、URL、HTML、Unicode、Morse、Brainfuck、Quoted-Printable、与佛论禅、社会主义核心价值观编码等。
- 哈希/校验：MD5、SHA1、SHA2、SHA3、SHAKE、BLAKE2、RIPEMD160、HMAC、CRC32、Adler32、批量哈希。
- 对称密码：AES、DES、3DES、Blowfish、ChaCha20、Fernet、RC4、Twofish、XOR。
- 非对称密码：RSA、ECC、ECC ECDSA 签名/验签。
- 攻击辅助：RSA 多种分解、低指数、广播、共模、Wiener、Boneh-Durfee、部分密钥泄露等；ECC 参数恢复、ECDSA Nonce 重用；LCG 参数恢复。

## 一键解密与递归解密说明

- 一键解密适合无需复杂上下文的编码、解码、古典密码等，会同时尝试普通 `decrypt()` 和 `decrypt_all()` 爆破结果。
- 一键解密会把小密钥空间爆破结果逐条显示。例如凯撒密文 `khoor zruog` 会显示 `caesar凯撒密码 - 爆破结果 / shift=3` 和结果 `hello world`。
- 一键解密结果会按匹配关键词、flag/ctf 格式、英文可读词、可读性和结果长度排序，优先显示更可能正确的内容。
- CLI 的 `try-all --json` 会输出 `is_brute`、`params` 和 `score` 字段，可用于脚本筛选爆破结果。
- GUI 和 CLI 的一键解密使用同一套核心逻辑，常见情况下结果顺序一致。
- 递归解密会继续尝试多层解密链，适合多层嵌套编码/古典密码。
- 递归解密会自动识别结果特征并优先推进更可能的下一层解密。支持的特征包括：
  - 编码层：`Hex候选`、`Base32候选`、`Base58候选`、`Base64候选`、`URL编码候选`
  - 古典层：`Morse候选`、`ROT候选`、`ROT47候选`
  - 通用层：`flag格式`、`花括号文本`、`字母数字候选`、`高可读文本`、`关键词`
- Base64/Base32 候选在标记前会实际验证解码结果是否为可打印 UTF-8，避免误判。
- 凯撒、仿射、栅栏等实现了 `decrypt_all()` 的小密钥空间算法会自动参与一键解密和递归解密，不再只使用默认密钥。
- 递归解密会在路径中显示爆破参数，例如 `caesar凯撒密码(shift=3)`，方便复现正确解法。
- 如果密文是普通字母和空格组成的古典密码，可用 `-p` 指定期望关键词提高命中率，例如 `python cli.py recursive --brief -p hello "khoor zruog"`。
- 相同 ROT 算法连续重复 3 次以上自动剪枝，避免死循环。
- GUI 和 CLI 使用同一套递归核心，常见情况下结果和解密路径一致。
- 递归解密设置位于 `设置 -> 首选项 -> 常规 -> 递归解密`，可调整最大递归轮数、线程数、任务数、最大显示结果数，以及是否启用小密钥空间爆破。
- GUI 默认只显示特征值较高的有限结果，避免大量候选导致界面卡顿；最大显示条数可调整，但上限为 1000。
- 哈希不可逆，通常不会提供解密。
- AES/RSA/ECC 等现代密码需要明确密钥、参数或攻击条件，不适合作为通用自动解密。

CLI 示例：

```bash
python cli.py recursive "U0VGQ1RGe3Rlc3R9"
python cli.py recursive --brief "GYZDKOBUIU3EMNRSGZCTONBWHA3DENBYG4YDMOBVHAZTENBWG43DMMZUHA3TANRWGYZDKOBUIU3EMNRSGZCTGMBTIQ======"
python cli.py recursive -d 5 -p "flag,ctf" --chain "密文"
python cli.py recursive --brief -p hello "khoor zruog"
```

一键解密 JSON 示例字段：

```json
{
  "name": "caesar凯撒密码",
  "result": "hello world",
  "is_brute": true,
  "params": "shift=3",
  "score": 175
}
```

## AI 工作台

AI 工作台包括 `对话模式` 和 `Agent模式`。使用前需要配置 API：

1. 打开 `设置 -> AI配置...`。
2. 填写 API 地址和 Key。
3. 点击刷新获取实时模型列表，或在模型框中手动输入模型名。
4. 保存后在 `AI工作台` 选项卡使用。

AI 配置文件位于 `config/ai_config.json`。请勿公开真实 API Key。

对话模式：

- 可输入密文、题目描述或代码片段，让模型辅助识别编码、解释算法或给出解题思路。
- AI 输出只作为辅助参考，最终结果仍应通过本地算法或脚本验证。

Agent模式：

- 用于分析当前项目代码，例如梳理模块职责、查找调用关系、总结潜在问题。
- Agent 受本地权限策略和 MCP 工具层限制，当前默认是 `command` 模式。
- 内置 MCP 工具可列目录、读文件、搜索文本、写文件、网络搜索和执行命令。
- 文件读取和搜索只允许工作空间内的非敏感路径；API Key、`.env`、凭据文件、权限配置和项目外路径会被拒绝。
- 写文件、网络搜索、执行命令或调用外部 MCP 工具时，界面会显示请求，用户可以选择允许一次或拒绝。
- 命令执行仍受白名单和危险命令拦截限制。
- 高级用户可编辑 `agent/agent_config.json` 的 `mcp_servers` 和 `enabled_mcp_tools` 添加自己的 stdio MCP 工具。

## SageMath 攻击配置

部分 RSA 攻击名称中带有 `(sagemath)`，这些攻击需要 SageMath 执行环境。打开 `设置 -> 首选项 -> SageMath` 后可选择三种方式：

- `本机安装`：适合已经安装 SageMath 的用户，填写 `sage` 或 `sage.exe` 可执行文件路径。
- `WSL`：适合 Windows 用户在 WSL 中安装 SageMath，填写发行版名称和 Sage 路径。
- `网页端 SageCell`：使用 `https://sagecell.sagemath.org/` 在线运行，适合本机没有 SageMath 的情况。

选择 `网页端 SageCell` 后，点击 `测试连接`。成功时会提示 `SageCell连接成功!`。

在线运行说明：

- 程序会先尝试 SageCell 服务接口。
- 如果服务接口不可用，会自动使用无头浏览器打开网页执行。
- 当前备用方案包括 Playwright 和 Selenium Manager，不需要手动放置 `chromedriver.exe`。
- 复杂攻击可能需要等待较长时间，网络异常或 SageCell 服务异常时可能失败。

已验证在线运行可以执行 SageMath 多项式、有限域、矩阵运算，以及共享素因子、Hastad 广播、p 高位泄露、Wiener 类小私钥等攻击样例。

## 快捷键

| 快捷键 | 功能 |
| --- | --- |
| Ctrl+O | 打开文件 |
| Ctrl+Shift+S | 保存结果 |
| F5 | 刷新算法列表 |
| Ctrl+R | 重启程序 |
| Ctrl+Q | 退出 |
| Ctrl+Z | 撤销 |
| Ctrl+Y | 重做 |
| Ctrl+V | 粘贴 |
| Ctrl+Delete | 清空全部 |
| Ctrl+U | 转为大写 |
| Ctrl+L | 转为小写 |

## 常见问题

### 找不到算法

先运行 `python cli.py list` 或在 GUI 中点击 `文件 -> 刷新算法列表`。新增算法文件必须放在 `algorithms/<分类>/` 下，并实现 `encrypt()` 或 `decrypt()`。

### 参数不知道怎么填

GUI 会根据函数签名自动生成参数输入框。CLI 使用 `key=value` 形式传参，例如 `shift=3`。

### SageMath 攻击无法运行

带 `(sagemath)` 标记的攻击需要配置 SageMath 环境。推荐先在 `设置 -> 首选项 -> SageMath` 中选择 `网页端 SageCell` 并点击 `测试连接`。

如果在线方式失败，请检查网络连接、SageCell 服务状态，以及是否已安装 `playwright`/`selenium` 依赖。Playwright 首次使用可能需要执行 `python -m playwright install chromium`。

### AI 无响应

检查 `config/ai_config.json` 或 GUI AI 配置中的 API 地址、模型、Key 和网络连接。

在 `设置 -> 首选项` 中点击“确定”或“应用”不会强制要求 API Key；只有点击 AI 配置页中的“测试连接”时才会校验 API Key 和模型名。

### 移动项目目录后还能使用吗

可以。项目内配置、算法、图标和日志都按项目目录相对定位，移动整个目录后通常无需修改。

需要重新确认的只有外部环境配置，例如 SageMath 本机路径、WSL 中的 Sage 路径、AI API 地址和 API Key。

### Agent 请求被拒绝

Agent 受 `agent/agent_config.json`、本地安全策略和 MCP 工具开关限制。读取敏感文件、访问项目外路径、修改权限配置，或执行不在白名单中的命令/危险命令都会被拒绝，这是预期行为。

如果自定义 MCP 工具不可用，请检查：

- `mcp_servers` 中的 `command` 和 `args` 是否能在当前工作空间启动。
- 工具名是否按 `服务名.工具名` 写入 `enabled_mcp_tools`。
- 工具的 `allowed_args`、`required_args` 是否与模型请求参数一致。
- 外部 MCP 是否从 stdin 接收 JSON-RPC `tools/call` 请求，并向 stdout 输出 JSON-RPC 结果。

### 程序崩溃后如何排查

未处理异常会写入 `logs/cryptoden.log`。如果 GUI 弹出错误提示，可根据日志内容定位问题。
