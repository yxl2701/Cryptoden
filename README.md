# Cryptoden - CTF 密码学 AI 加解密工具

Cryptoden 是一个面向 CTF 密码学题目的 Python 工具箱，提供图形界面和命令行两种使用方式。

项目支持常见古典密码、编码/解码、哈希、对称密码、非对称密码，以及 RSA/ECC/LCG 攻击辅助模块，并内置 AI 分析与对话能力。

当前项目采用 `algorithms/` 目录作为统一算法入口，程序会动态扫描算法文件，并根据 `encrypt()`、`decrypt()`、`decrypt_all()` 等函数自动加载能力。GUI 参数面板和 CLI 参数也会根据函数签名自动识别，不再要求每个算法手动维护 `PARAMS`。

项目采用**AI 辅助开发**，部分代码和功能采用 AI 生成并通过现有自动化测试验证；复杂攻击模块仍建议使用者结合题目环境自行复核结果。

项目以 MIT License 开源发布，欢迎使用者自行二次开发、提交 Issue 或贡献改进。

## 免责声明与许可

- 本项目采用 MIT License 开源发布，详见 `LICENSE`。
- 本工具面向 CTF 练习、密码学学习、安全教育和授权分析场景。
- 使用本工具造成的任何损失、风险、法律责任、数据损坏、服务中断、账号限制、竞赛处罚或其他后果，均与开发者本人无关。
- 使用者应自行确认行为符合法律法规、平台规则、竞赛规则和授权边界。

## 当前状态

根据 `python cli.py list` 的实际输出，当前可用模块如下：

| 类型 | 数量 |
| --- | ---: |
| 加密模块 | 119 |
| 解密模块 | 97 |
| RSA 攻击 | 22 |
| ECC 攻击 | 11 |
| LCG 攻击 | 1 |

主要分类：

- 古典密码：凯撒、维吉尼亚、栅栏、仿射、培根、Enigma、Bifid、Trifid、ADFGVX、四方密码等。
- 编码/解码：Base32、Base58、Base62、Base64、Base85、Base91、Hex、URL、HTML、Unicode、Morse、Brainfuck、Quoted-Printable、与佛论禅、社会主义核心价值观编码等。
- 哈希/校验：MD5、SHA1、SHA2、SHA3、SHAKE、BLAKE2、RIPEMD160、HMAC、CRC32、Adler32、批量哈希。哈希模块通常只支持加密/摘要计算。
- 对称密码：AES、DES、3DES、Blowfish、ChaCha20、Fernet、RC4、Twofish、XOR。
- 非对称密码：RSA、ECC、ECC ECDSA 签名/验签，以及 RSA/ECC/LCG 攻击辅助。
- AI 功能：AI 分析、AI 对话、API 配置。
- 辅助功能：一键解密、递归解密、输出搜索、关键字高亮、进制转换、文本大小写/格式处理、历史撤销/重做、解密记录。
- 易用性：帮助菜单中的算法列表支持搜索和分类筛选；首选项中的自动化、字体、颜色设置会持久化到 `config.json`。
- 稳定性：未处理异常会写入 `logs/cryptoden.log`，便于排查崩溃原因。

## 项目总览与复盘

项目定位：

- 面向 CTF 密码学和常见加解密任务，提供 GUI、CLI、AI 辅助和攻击模块入口。
- 普通算法采用动态加载架构，减少新增算法时对主界面和 CLI 的侵入式修改。
- RSA/ECC/LCG/AES 等复杂功能保留专用界面，避免把大量参数硬塞进通用面板。

当前复盘：

- 已统一算法目录和加载方式，通用算法扩展成本较低。
- 主界面算法选项卡已改为配置驱动，默认只显示 `RSA` 和 `AES`，其他选项卡由用户自行启用。
- AI 工作台已拆分为普通对话和受限 Agent 模式，Agent 通过本地策略和 MCP 工具层限制文件、命令、网络和敏感配置访问。
- Windows 剪贴板富文本 MIME 报错已通过纯文本复制处理规避。
- SageMath 支持本机、WSL 和 SageCell 在线执行，但复杂攻击仍受网络、环境和参数规模影响。
- 项目路径均以源码根目录为基准解析，避免依赖开发者机器上的绝对目录；SageMath 可执行文件、WSL 路径、API 地址等外部环境配置除外。
- 默认 AI 配置不包含真实 API Key 或聊天历史；发布前仍应清理日志、缓存、构建产物和本地解密记录。

## 可迁移性说明

- 从任意目录启动 `python main.py`、`python cli.py ...` 或打包后的程序时，项目内部资源会按源码根目录或打包资源目录定位。
- `config.json`、`algorithm_tabs_config.json`、`sagemath_config.json`、`config/ai_config.json` 使用相对项目位置保存，移动整个项目目录后无需修改项目内路径。
- `logs/`、`__pycache__/`、`.pytest_cache/`、`build/`、`dist/`、`config/decrypt_records.json` 属于运行时或构建产物，可通过 `python cleanup.py --apply` 清理。
- `sagemath_config.json` 中的 `local_path`、`wsl_path` 和 AI 配置中的 `api_base` 描述外部环境，不应写成项目内路径；迁移到新机器后可在 GUI 设置中重新配置。
- 发布或共享源码前，不要把个人 API Key、聊天历史、日志或解密记录作为项目配置分发。

## 环境要求

- Python 3.8+
- Windows/Linux/macOS 理论可运行，当前仓库包含 Windows 打包脚本。
- 依赖见 `requirements.txt`。
- 部分带 `(sagemath)` 标记的攻击需要配置 SageMath。支持本机、WSL 和 SageCell 网页端在线运行。

## 安装

```bash
pip install -r requirements.txt
```

也可以按包方式安装：

```bash
pip install .
```

`pip install .` 会安装核心运行依赖并注册命令入口；若需要 SageCell 在线执行的浏览器兜底能力，仍建议优先使用 `pip install -r requirements.txt`，以确保 `playwright`、`selenium` 等可选依赖一并安装。

安装后会注册两个入口：

```bash
cryptoden --help
cryptoden-gui
```

## 快速开始

启动 GUI：

```bash
python main.py
```

使用 CLI：

```bash
python cli.py list
python cli.py --version
python cli.py encrypt base64 "hello"
python cli.py decrypt base64 "aGVsbG8="
python cli.py try-all "U0VGQ1RGe3Rlc3R9"
python cli.py try-all "khoor zruog"
python cli.py recursive "U0VGQ1RGe3Rlc3R9"
python cli.py recursive --brief -p hello "khoor zruog"
```

CLI 支持文件输入、文件输出、JSON 输出、批量模式和交互模式：

```bash
python cli.py -i cipher.txt -o result.txt decrypt base64
python cli.py --json try-all "khoor zruog"
python cli.py --batch -i lines.txt try-all
python cli.py --interactive
```

现代/攻击模块示例：

```bash
python cli.py rsa
python cli.py ecc
python cli.py lcg
```

## GUI 功能

主窗口默认显示基础面板和常用算法选项卡：

- `加解密`：选择算法、输入文本、设置参数、查看结果。
- `AI工作台`：配置并调用 AI 接口分析密文、对话或运行受限 Agent。
- `RSA`：RSA 加密、解密和攻击辅助。
- `AES`：对称密码专用界面，默认定位到 AES。

其他对称/非对称算法选项卡默认不显示，可在 `设置 -> 首选项 -> 算法选项卡` 中勾选启用。可显示的算法选项卡清单位于 `algorithm_tabs_config.json`，用户勾选状态保存到 `config.json` 的 `enabled_algorithm_tabs`。

菜单功能：

- `文件`：打开文件、保存结果、刷新算法列表、重启、退出。
- `编辑`：撤销、重做、粘贴、清空全部。
- `加密/解密`：按分类列出古典密码、编码/解码、哈希等通用算法；对称/非对称算法不在此处重复显示。
- `对称密码`：打开 AES/DES/3DES/Blowfish/RC4 等专用界面。
- `非对称密码`：打开 RSA、ECC、LCG 专用界面和攻击辅助。
- `转换`：大小写转换、去空白、去换行、进制转换、反转文本。
- `设置`：首选项、AI 配置、自动复制结果、自动交换、解密记录。
- `帮助`：快捷键、可搜索算法列表、关于。

## 一键解密与递归解密

- 一键解密会尝试当前可直接调用的 `decrypt()`，并自动调用 `decrypt_all()` 的爆破候选，适合编码、古典密码等轻量场景。
- 一键解密会把 `decrypt_all()` 的小密钥空间爆破结果逐条展开，不再把整块爆破文本混在一个结果里。
- 一键解密结果会按关键字命中、flag/ctf 格式、英文可读词、可读字符比例和结果长度评分排序，高可信且更易读的结果优先显示。
- 对凯撒、仿射、栅栏等返回参数化爆破结果的算法，CLI/GUI 会显示参数，例如 `caesar凯撒密码 - 爆破结果 / shift=3`。
- `try-all --json` 会返回 `name`、`result`、`is_brute`、`params`、`score`，方便脚本读取爆破参数和排序分数。
- GUI 和 CLI 的一键解密复用同一套 `CryptoLoader.try_decrypt_all()` 核心逻辑，避免结果不一致。
- 递归解密会尝试多层解密链，并使用匹配规则和结果特征筛选结果，适合多层嵌套编码/古典密码。
- GUI 递归解密复用 CLI 同一套核心逻辑，结果、路径和速度保持一致。
- 递归解密会自动识别结果特征并优先推进更可能的下一步解码链。支持的特征包括：
  - 编码层：`Hex候选`、`Base32候选`、`Base58候选`、`Base64候选`、`URL编码候选`
  - 古典层：`Morse候选`、`ROT候选`、`ROT47候选`
  - 通用层：`flag格式`、`花括号文本`、`字母数字候选`、`高可读文本`、`关键词`
- Base64/Base32 候选在标记前会实际验证解码结果是否为可打印 UTF-8，避免误判。
- ROT/古典层候选自带优先级排序，ROT 与 ROT47 不互相冲突时各自独立探索。
- 对实现了 `decrypt_all()` 的小密钥空间算法，一键解密和递归解密都会自动使用爆破结果，例如凯撒偏移爆破。
- 递归解密会把爆破参数写入解密路径，例如 `caesar凯撒密码(shift=3)`，便于复现。
- 字母和空格组成的短文本会作为 ROT/凯撒候选参与递归解密，例如 `khoor zruog` 可以通过 `-p hello` 命中 `hello world`。
- 递归解密使用多层缓存（特征缓存、解密候选缓存、算法小写索引）减少重复计算。
- 对称密码（AES/DES/Blowfish 等）作为末位兜底层，防止它们在无特征时抢占预算。
- 相同 ROT 算法连续重复 3 次以上自动剪枝，避免死循环。
- 递归解密参数保存在 `config.json` 的 `recursive_decrypt`，包括最大深度、总尝试次数、每层保留候选数、GUI 最大显示条数等。
- 哈希、复杂现代密码和需要人工参数/攻击上下文的算法通常不适合自动一键解密。

## 输出搜索与匹配

- 输出区支持关键字匹配，高亮 `flag`、`ctf`、`key` 等自定义关键字。
- 一键解密的多段结果中，命中关键字或高可信的结果会置顶。
- 输出区提供独立搜索框，支持结果计数和上一个/下一个跳转。

## 剪贴板说明

- GUI 内文本框复制默认按纯文本处理，避免 Windows/Qt 偶发写入富文本剪贴板 MIME 时出现 `OleSetClipboard` 日志。
- 如果系统剪贴板被其他程序占用，复制可能短暂失败，但不会影响加解密计算结果。

## 项目结构

```text
new/
├── main.py                    # GUI 入口
├── cli.py                     # CLI 入口
├── __main__.py                # python -m 入口，转到 CLI
├── setup.py                   # Python 包配置
├── pyproject.toml             # 构建后端配置
├── requirements.txt           # 运行依赖
├── cryptoden_icon.png         # 应用图标
├── build.bat                  # Windows PyInstaller 打包脚本
├── Cryptoden.spec             # PyInstaller 配置
├── config.json                # 界面/程序配置
├── algorithm_tabs_config.json # 主界面算法选项卡定义和默认显示状态
├── algorithms/                # 统一算法目录
│   ├── classical/             # 古典密码
│   ├── encoding/              # 编码/解码
│   ├── hash/                  # 哈希
│   ├── symmetric/             # 对称密码
│   ├── asymmetric/            # RSA/ECC/LCG 与攻击模块
│   └── other/                 # 其他扩展算法
├── core/                      # 核心加载、常量、SageMath 配置与执行
├── gui/                       # PyQt5 图形界面
├── utils/                     # AI、历史记录、递归解密等工具
├── config/                    # AI 配置和解密记录
└── tests/                     # 测试用例，仅用于源码开发和回归验证
```

`tests/` 不是程序运行必需目录，打包和安装时不会作为运行功能入口使用；但它用于 `pytest` 回归验证，建议源码仓库保留。若只分发最终可执行文件或安装包，可不包含测试目录。

## 添加新算法

在 `algorithms/<分类>/` 下新增 `.py` 文件，并按需实现函数：

```python
ALGORITHM_NAME = "示例算法"
ALGORITHM_DESC = "算法说明"

def encrypt(plaintext, key="default"):
    return plaintext

def decrypt(ciphertext, key="default"):
    return ciphertext

def decrypt_all(ciphertext):
    return []
```

说明：

- `ALGORITHM_NAME` 和 `ALGORITHM_DESC` 可选，不写时默认使用文件名。
- 第一个文本参数可命名为 `plaintext`、`ciphertext`、`cryptotext`、`text`、`input_text`、`message`、`msg`、`input` 或 `data`。
- 除文本参数外的其他参数会被 GUI/CLI 作为算法参数处理。
- 新增文件后可在 GUI 中点击 `文件 -> 刷新算法列表`，或重启程序。
- 小密钥空间算法建议实现 `decrypt_all(ciphertext)`。一键解密会逐条展开返回内容，递归解密会读取这些爆破候选，并把参数写入解密路径。
- 推荐的爆破输出格式为每行一个候选，例如 `偏移量  3: hello world`、`shift 3: hello world` 或 `a=1,b=3: hello world`。冒号前的文本会作为参数说明显示。

## AI 工作台

AI 工作台包含两个模式：

- `对话模式`：使用已配置的模型进行密文分析、题目解释和普通对话。
- `Agent模式`：在受限权限策略下辅助分析当前项目代码。

AI 配置文件位于 `config/ai_config.json`，也可以在 GUI 中通过 `设置 -> AI配置...` 修改。请不要把真实 API Key 提交到公共仓库。

AI 配置中的模型列表会通过当前 API 地址实时获取；获取失败时保留手动输入能力，不再依赖固定模型清单。

Agent 权限配置位于 `agent/agent_config.json`。当前默认权限模式为 `command`，Agent 通过 MCP 工具层访问能力：

- 内置 MCP 工具包括 `list_files`、`read_file`、`search_text`、`write_file`、`web_search` 和 `run_command`。
- `read_file`、`list_files`、`search_text` 只能访问工作空间内的非敏感路径。
- `write_file`、`web_search`、外部 MCP 工具默认需要用户在 GUI 中确认一次。
- `run_command` 仍受命令白名单、危险命令拦截和用户确认控制。
- 用户可在 `mcp_servers` 中添加 stdio MCP 服务，并将 `服务名.工具名` 加入 `enabled_mcp_tools` 后使用。
- Agent 仍不能读取敏感配置全文，也不能修改权限配置、AI Key 或项目外文件。

自定义 MCP 配置示例见 `agent/README.md`。

## SageMath 配置

带 `(sagemath)` 标记的 RSA 攻击会通过 `core/sage_executor.py` 执行 SageMath 代码。可在 GUI 中打开 `设置 -> 首选项 -> SageMath` 配置运行方式。

支持三种方式：

- `本机安装`：填写本机 `sage` 或 `sage.exe` 路径。
- `WSL`：填写 WSL 发行版和 WSL 内的 SageMath 路径，例如 `/usr/bin/sage`。
- `网页端 SageCell`：使用 `https://sagecell.sagemath.org/` 在线运行，无需本机安装 SageMath。

测试连接时可能会卡顿一下（实测网页端连接大概10秒以内），这是正常情况，测试结束后会弹出测试结果提示。

网页端在线运行流程：

- 优先请求 SageCell `/service` 接口。
- 若接口不可用，例如返回 `HTTP 520`，自动使用 Playwright 无头 Chromium 打开 SageCell 页面执行。
- 若 Playwright 不可用，再使用 Selenium Manager 无头 Chrome 作为备用方案。

首次在新环境使用 Playwright 时，可能需要安装浏览器内核：

```bash
python -m playwright install chromium
```

当前已验证在线运行可执行普通 Sage 代码、有限域、多项式、矩阵、RSA 小指数/广播/共享素因子、p 高位泄露、Wiener 类小私钥攻击等模块。在线环境受网络和 SageCell 服务状态影响，复杂大整数攻击仍可能超时。

## 测试

```bash
pytest
```

测试目录为 `tests/`。它用于确认核心加解密、编码容错、哈希输出、RSA 基础能力和部分攻击模块没有被改坏。清理缓存时可以删除 `tests/__pycache__/`，不要删除 `tests/test_core.py`，否则后续无法进行自动回归验证。

基础可用性检查：

```bash
python cli.py list
python cli.py --version
python cli.py encrypt base64 "hello"
python cli.py decrypt base64 "aGVsbG8="
```

## 清理生成文件

项目提供安全清理脚本，用于删除缓存、日志、构建产物和本地解密记录等可再生成文件。清理规则位于 `cleanup_config.json`。

默认只预览，不删除任何文件：

```bash
python cleanup.py
```

确认列表无误后再执行删除：

```bash
python cleanup.py --apply
```

脚本只会删除配置中列出的目标，不用于删除源码、文档或测试文件。

## 打包

Windows 下可运行：

```bat
build.bat
```

或手动执行：

```bash
python -m PyInstaller --clean --noconfirm Cryptoden.spec
```

输出目录：`dist/Cryptoden/Cryptoden.exe`。

## 相关文档

- `USER_MANUAL.md`：面向使用者的操作说明。
- `DEVELOPMENT_MANUAL.md`：面向开发者的扩展和维护说明。
- `CONTRIBUTING.md`：贡献指南和本地验证命令。
- `SECURITY.md`：安全问题报告和敏感数据处理说明。
- `CHANGELOG.md`：版本变更记录。

`USER_MANUAL.md` 详细说明 GUI 菜单、CLI 命令、AI 配置、快捷键、常见问题和典型使用流程。普通用户优先阅读该文档。

`DEVELOPMENT_MANUAL.md` 详细说明当前 `algorithms/` 动态加载架构、普通算法和攻击模块扩展规则、GUI/CLI 开发要点、SageMath 支持、测试验证和打包维护方式。开发者和维护者优先阅读该文档。

## 发布前检查

发布源码、打包可执行文件或对外分发前，应完成以下检查：

- 运行 `pytest`，确认测试通过。
- 运行 `python cli.py list`，确认算法和攻击模块能正常加载。
- 如修改 SageMath 支持，至少用 `sage_type=online` 验证一段 Sage 代码或一个 `(sagemath)` 攻击模块能返回结果。
- 运行 `python cli.py --version`，确认版本号正常输出。
- 运行 `python cli.py encrypt base64 "hello"` 和 `python cli.py decrypt base64 "aGVsbG8="`，确认 CLI 基础链路正常。
- 打开 GUI，确认 `帮助 -> 算法列表` 可搜索、分类筛选正常。
- 打开 GUI，确认 `加密/解密` 菜单不重复展示对称密码和非对称密码分类。
- 确认 `LICENSE`、`README.md`、`USER_MANUAL.md` 的 MIT 许可和免责声明表述一致。
- 确认 `config/ai_config.json` 不包含真实 API Key。
- 确认项目内资源引用使用相对项目位置，不包含开发者机器目录。
- 确认 `config/decrypt_records.json` 为空或不包含用户数据。
- 不随源码发布 `build/`、`dist/`、`*.egg-info/`、`.pytest_cache/`、`__pycache__/`、`*.pyc`、`logs/`。

构建源码包/轮子：

```bash
python -m pip install --upgrade build
python -m build
```

构建 Windows 可执行文件：

```bat
build.bat
```

构建产物会生成到 `dist/`，无需保存在源码仓库中。
