# Cryptoden 开发手册

## 开源说明

- 本项目采用 MIT License 开源发布，允许使用、复制、修改、分发和再许可；具体条款见 `LICENSE`。
- 本工具面向 CTF 练习、密码学学习、安全教育和授权分析场景。
- 使用本工具造成的任何损失、风险、法律责任、数据损坏、服务中断、账号限制、竞赛处罚或其他后果，均与开发者本人无关。

## 项目复盘

- 核心算法通过 `core/crypto_loader.py` 动态扫描 `algorithms/`，GUI 和 CLI 共享同一加载入口。
- 通用加解密逻辑集中在 `CryptoPanel`，新增普通算法通常只需要添加算法文件。
- 复杂现代密码、ECC ECDSA 签名/验签和攻击辅助通过专用界面或专用算法模块实现，主界面选项卡由 `algorithm_tabs_config.json` 配置。
- AI 工作台将普通对话和受限 Agent 分离，Agent 访问能力由 `agent/` 下的配置、策略和工具层控制。
- SageMath 攻击支持本机、WSL 和在线 SageCell，但应保留超时、失败提示和可验证样例。
- GUI 剪贴板复制统一使用纯文本处理，避免 Qt/Windows 富文本 MIME 剪贴板问题。

## 当前架构

Cryptoden 当前使用 `algorithms/` 作为统一算法目录，由 `core.crypto_loader.CryptoLoader` 动态扫描和加载。GUI 与 CLI 共用同一套加载逻辑。

```text
new/
├── main.py                    # GUI 入口
├── cli.py                     # CLI 入口
├── __main__.py                # python -m 入口
├── setup.py                   # 包配置和 console_scripts
├── pyproject.toml             # 构建后端配置
├── requirements.txt           # 运行依赖
├── cryptoden_icon.png         # 应用图标
├── build.bat                  # Windows 打包脚本
├── Cryptoden.spec             # PyInstaller 配置
├── algorithms/                # 算法目录
│   ├── classical/             # 古典密码
│   ├── encoding/              # 编码/解码
│   ├── hash/                  # 哈希
│   ├── symmetric/             # 对称密码
│   ├── asymmetric/            # RSA/ECC/LCG 与攻击模块
│   └── other/                 # 其他算法
├── core/                      # 核心模块
├── gui/                       # PyQt5 界面
├── utils/                     # 工具模块
├── config/                    # AI 配置、解密记录
└── tests/                     # 测试，仅用于源码开发和回归验证
```

当前实现以 `algorithms/`、`gui/`、`utils/` 为准。

## 核心模块

`core/`：

- `crypto_loader.py`：动态加载 `algorithms/` 下的算法，提供统一的加密、解密和一键解密接口。
- `constants.py`：算法分类中文名、分类描述和菜单顺序。
- `sage_executor.py`：SageMath 执行支持，包含本机、WSL、SageCell 服务接口和无头浏览器在线执行兜底。
- `sagemath_config.py`：SageMath 配置管理，保存本机路径、WSL 路径和 SageCell 在线地址。

`gui/`：

- `main_window.py`：主窗口、菜单栏、选项卡和全局操作。
- `crypto_panel.py`：加解密主面板，负责算法选择、参数输入和结果显示。
- `ai_panel.py`、`ai_dialog.py`、`ai_config_dialog.py`：AI 分析、对话和配置。
- `rsa_dialog.py`、`ecc_dialog.py`、`lcg_dialog.py`：非对称和攻击专用界面。
- `symmetric_dialog.py`：对称密码专用界面。
- `base_converter.py`：进制转换。
- `settings_dialog.py`：首选项设置。

`utils/`：

- `ai_assistant.py`：AI 调用封装。
- `ai_auto_analyze.py`：自动识别和 AI 辅助分析。
- `logging_config.py`：全局日志和未处理异常记录。
- `recursive_config.py`：递归解密共享配置默认值和 `config.json` 读取。
- `recursive_features.py`：递归解密结果特征识别和特征评分。
- `recursive_decryptor.py`：GUI 递归解密异步包装、解密记录和兼容回退逻辑。
- `history.py`：撤销/重做历史管理。

## 算法加载规则

`CryptoLoader` 会扫描 `algorithms/` 的一级分类目录，并加载其中的 `.py` 文件。对于子目录，例如 `algorithms/asymmetric/rsa/`，会加载该子目录下的直接 `.py` 文件，但跳过 `attacks` 和 `__pycache__`。

加载判断：

- 存在 `encrypt()` 时加入加密模块。
- 存在 `decrypt()` 时加入解密模块。
- `ALGORITHM_NAME` 可选，未设置时使用文件名。
- `ALGORITHM_DESC` 可选，用于 GUI 状态提示。
- `PARAMS` 兼容保留，但当前 GUI/CLI 主要依赖函数签名自动识别参数。

文本参数映射支持以下名称：

- `plaintext`
- `ciphertext`
- `cryptotext`
- `text`
- `input_text`
- `message`
- `msg`
- `input`
- `data`

## 添加普通算法

在合适分类下新增 `.py` 文件，例如 `algorithms/classical/example.py`：

```python
ALGORITHM_NAME = "Example"
ALGORITHM_DESC = "示例算法"

def encrypt(plaintext, shift=3):
    return plaintext

def decrypt(ciphertext, shift=3):
    return ciphertext
```

要求：

- 返回值应为字符串，或能被界面/CLI 清晰展示的值。
- 不要在算法函数中直接读写 GUI 状态。
- 参数尽量使用简单类型默认值，例如 `int`、`str`、`bool`。
- 哈希类算法通常只实现 `encrypt()`。
- 新算法可通过 `python cli.py list` 验证是否加载。

## 添加攻击模块

RSA/ECC/LCG 攻击位于：

- `algorithms/asymmetric/rsa/attacks/`
- `algorithms/asymmetric/ecc/attacks/`
- `algorithms/asymmetric/lcg/attacks/`

攻击模块由对应目录的 `loader.py` 加载。新增攻击前先参考同目录现有文件的字段约定、返回格式和 GUI 调用方式。

ECC ECDSA 签名/验签由 `algorithms/asymmetric/ecc/ecc.py` 中的 `sign()`、`verify()` 提供核心实现，并通过 `algorithms/asymmetric/ecc/ecc_sign.py` 暴露为通用算法 `ECC ECDSA Sign/Verify`。

通用建议：

- 明确输入字段名称和类型。
- 对 SageMath 依赖进行清晰标注。
- 失败时返回明确错误信息，不要静默失败。
- 大整数运算注意超时和异常处理。

## CLI 开发要点

入口：`cli.py`。

主要命令：

- `list`：列出算法和攻击模块。
- `encrypt <算法名> [参数=值...] [文本]`：执行加密。
- `decrypt <算法名> [参数=值...] [文本]`：执行解密。
- `try-all [文本]`：一键解密，调用 `CryptoLoader.try_decrypt_all()`。
- `recursive [文本]`：递归解密。
- `rsa/ecc/lcg [攻击名] [参数=值...]`：攻击模块。

CLI 支持：

- `-i/--input` 文件输入。
- `-o/--output` 文件输出。
- `--json` JSON 输出。
- `--batch` 逐行批量处理。
- `--interactive` 交互 Shell。
- `--version` 显示版本号。

算法名匹配支持精确匹配、大小写忽略、去中文后缀匹配和子串匹配。

一键解密核心位于 `core/crypto_loader.py` 的 `try_decrypt_all()`，CLI 和 GUI 都应复用该入口。它会：

- 依次尝试每个解密模块的 `decrypt()`。
- 自动调用 `decrypt_all()`，逐行解析小密钥空间爆破候选，并标记为爆破结果。
- 从 `decrypt_all()` 输出中提取参数说明，例如 `shift=3`、`a=1,b=3` 或 `栅栏数 3`。
- 过滤错误结果、去重，并按关键词命中、flag/ctf 格式、英文可读词、可读性和结果长度排序。
- 支持通过 GUI 输出匹配关键词或 CLI 默认关键词影响排序。
- CLI JSON 输出应保留 `is_brute`、`params` 和 `score`，避免程序化调用丢失爆破上下文。

`decrypt_all()` 推荐每行输出一个候选：

```text
偏移量  3: hello world
shift 3: hello world
a=1,b=3: hello world
```

冒号前的文本会作为参数说明显示；冒号后的文本会作为候选明文单独评分和排序。

递归解密核心位于 `de_recursion.py`，GUI 通过 `utils.recursive_decryptor.AsyncRecursiveDecryptor` 异步调用同一核心，避免 CLI/GUI 结果不一致。核心会：

- 按 `config.json -> recursive_decrypt` 读取最大深度、总尝试次数和每层候选保留数量。
- 使用 `utils.recursive_features` 识别结果特征，包括编码层（`Hex候选`、`Base64候选`、`Base58候选`、`Base32候选`、`URL编码候选`）、古典层（`Morse候选`、`ROT候选`、`ROT47候选`）和通用层（`flag格式`、`花括号文本`、`字母数字候选`、`高可读文本`、`关键词`）。
- Base64/Base32 候选在标记前会实际验证解码结果是否为可打印 UTF-8，避免误判。
- 对具备 `decrypt_all()` 的算法自动展开爆破候选，并把参数记录到解密链。
- 字母和空格组成的短文本会纳入 ROT/凯撒候选，便于处理 `khoor zruog` 这类古典密码输入。
- 关键词匹配分为两层：`flag` 子串匹配允许中间层命中后继续深入；`ctf`、`key`、`password`、`secret` 保持边界匹配减少假阳性。
- 相同 ROT 算法连续重复 3 次以上自动剪枝，防止死循环和 ROT 探测分支爆炸。
- visited 集合按深度追踪：同一密文在更浅层已探索过则跳过，但允许更深层（更短路径）覆盖探索。
- 对称密码（AES/DES 等）归入末位兜底层，仅在编码层和古典层均无候选时才尝试，减少无效分支。
- 严格编码特征（如 Hex 候选）不符合时限制回退候选数为 5，避免全量古典密码分支爆炸。
- 最佳结果优先选短链（同等关键词命中时路径更短、变换更少），而非一味追求更深层。
- 对同一候选文本，带爆破参数的路径优先保留，便于显示 `caesar凯撒密码(shift=3)` 这类可复现路径。
- 算法排序按提示强弱分桶，避免 `url` 和 `rot` 等不同线索在同层互相争抢预算。

维护递归逻辑时，应优先修改 `de_recursion.py` 和 `utils/recursive_features.py`，不要在 GUI 中复制搜索策略。

## GUI 开发要点

GUI 使用 PyQt5。

主窗口职责：

- 创建菜单栏、状态栏和选项卡。
- 将算法菜单动作转发给 `CryptoPanel`。
- 打开专用对话框，并按配置将常用专用界面嵌入主界面选项卡。
- 读取和保存 `config.json` 中的 GUI 首选项。

算法选项卡配置：

- `algorithm_tabs_config.json` 定义可嵌入主界面的算法选项卡，包括名称、分类、描述、类型、默认启用状态，以及对称密码的初始算法。
- `gui/algorithm_tabs.py` 负责读取该配置，并提供内置默认值兜底。
- `config.json` 的 `enabled_algorithm_tabs` 保存用户实际勾选状态；默认只显示 `RSA` 和 `AES`，其他选项卡由用户在设置中启用。
- 新增可嵌入的专用界面时，优先更新 `algorithm_tabs_config.json`；只有出现新的界面类型时才需要修改 `main_window.py` 的创建分支。

菜单约定：

- `加密/解密` 菜单只展示通用算法分类，例如古典密码、编码/解码、哈希等。
- `symmetric` 和 `asymmetric` 分类不在 `加密/解密` 中重复显示，应通过单独的 `对称密码`、`非对称密码` 菜单进入。
- `帮助 -> 算法列表` 使用可搜索对话框，不再用长文本弹窗。

加解密面板职责：

- 加载算法。
- 根据函数签名生成参数控件。
- 执行加密、解密、一键解密和递归解密；一键解密应委托 `CryptoLoader.try_decrypt_all()`。
- 管理输入输出、历史记录和解密记录。
- 管理输出关键字高亮、输出搜索和一键解密结果评分排序。

开发注意：

- 不要在主窗口或 GUI 面板中复制算法执行逻辑，优先复用 `CryptoPanel` 和 `CryptoLoader`。
- 新菜单动作应保持快捷键不冲突。
- 长耗时操作应避免阻塞主线程。
- GUI 递归解密应只做异步包装和结果展示，搜索策略应复用 `de_recursion.py`。
- 嵌入 `QDialog` 到主选项卡时，应设置父控件和 `Qt.Widget` 窗口标志，并显式 `show()`。
- GUI 文本框复制应使用 `gui/clipboard_utils.py` 的纯文本复制处理，避免直接调用 `QApplication.clipboard().setText(...)` 分散在各处。

## AI 与 Agent

默认配置文件：`config/ai_config.json`。

AI 工作台结构：

- `gui/ai_workspace_panel.py`：承载 `对话模式` 和 `Agent模式`。
- `gui/ai_panel.py`：普通 AI 对话和密文分析。
- `gui/agent_panel.py`：受限 Agent 交互界面。
- `utils/ai_assistant.py`：AI 配置和客户端封装。
- `agent/config.py`：Agent 配置归一化，包含权限、MCP 工具开关和外部 MCP 服务声明。
- `agent/policy.py`：本地安全策略，统一处理路径、命令、网络和外部 MCP 权限。
- `agent/mcp.py`：轻量 MCP 工具注册和 stdio MCP 调用适配。
- `agent/tools.py`：运行时工具门面，所有工具执行必须经过策略检查。
- `agent/runtime.py`：模型工具调用循环，按 MCP 工具 schema 校验请求。

开发注意：

- 不要提交真实 API Key。
- 读取配置时应容错处理空值、缺失字段和网络错误。
- AI 分析结果只作为辅助，不应替代确定性的算法执行结果。
- 模型列表应通过接口实时获取；网络失败时保留手动输入，不应依赖固定死的模型清单。
- Agent 当前默认权限模式为 `command`，内置 MCP 工具支持列目录、读文件、搜索文本、写文件、网络搜索和命令执行。
- Agent 不能读取 `agent/agent_config.json` 全文，不能修改权限配置、安全核心实现或 AI Key 配置。
- Agent 工具请求必须经过 `AgentPolicy`，路径必须归一化并限制在工作空间内。
- 写文件、网络搜索、命令执行和外部 MCP 调用应默认需要用户确认；命令还必须经过白名单和危险命令拦截。
- 外部 MCP 当前按 stdio JSON-RPC `tools/call` 调用，工具名格式为 `服务名.工具名`，并由 `enabled_mcp_tools` 显式启用。
- 新增 MCP 工具时，应同步定义工具 schema、目标提取、策略检查和测试，不允许绕过 `AgentTools.execute()` 直接执行。
- GUI 只展示 Agent 权限摘要和单次请求，不应把敏感配置全文传给模型。

## 日志与配置

- GUI 启动时安装全局异常钩子，未处理异常写入 `logs/cryptoden.log`。
- `logs/` 属于运行时产物，已加入 `.gitignore`，不应随源码发布。
- `config.json` 保存 GUI 首选项，例如自动复制、自动交换、字体和颜色。
- `algorithm_tabs_config.json` 保存主界面算法选项卡定义；用户启用状态仍写入 `config.json`。

## SageMath

项目包含 `core/sage_executor.py` 和 `core/sagemath_config.py` 用于 SageMath 相关攻击。

配置文件为 `sagemath_config.json`，主要字段：

- `sage_type`：`local`、`wsl` 或 `online`。
- `local_path`：本机 SageMath 可执行文件路径。
- `wsl_distro`：WSL 发行版名称。
- `wsl_path`：WSL 内 SageMath 路径。
- `online_url`：SageCell 地址，默认 `https://sagecell.sagemath.org/`。

执行策略：

- `local`：通过子进程执行本机 SageMath。
- `wsl`：通过 `wsl -d <distro> -- <sage> -c <code>` 执行。
- `online`：先调用 SageCell `/service` 接口；接口失败后使用 Playwright 无头 Chromium 操作 SageCell 页面；Playwright 失败后使用 Selenium Manager 作为第二备用方案。

无头浏览器页面执行约定：

- 输入代码通过页面中的 `#cell .CodeMirror` 实例写入，不直接操作 CodeMirror 的隐藏 span。
- 执行按钮 XPath 为 `//*[@id="cell"]/div[1]/button`。
- Selenium 备用方案优先读取输出 XPath `//*[@id="cell"]/div[3]/div[1]/div/div[2]/pre`。
- 不依赖仓库内固定版本 `chromedriver.exe`；Selenium Manager 会自动匹配本机 Chrome 驱动。

已在线验证的能力包括基础 Sage 表达式、`GF` 有限域、`PolynomialRing`、矩阵行列式、CRT、`inverse_mod`、`small_roots`，以及多个真实 RSA `(sagemath)` 攻击模块。

开发注意：

- 普通算法不要强依赖 SageMath。
- 需要 SageMath 的攻击应在名称或描述中标注。
- 调用失败时提示用户配置解释器。
- 在线 SageCell 受网络和服务状态影响，攻击模块应保留超时、异常和失败原因返回。
- 嵌入到 `SAGE_CODE` 三引号字符串中的换行文本要使用 `\\n`，避免生成 Sage 代码时破坏字符串字面量。
- 大规模格攻击或 Coppersmith 攻击应控制参数和超时，不应让 GUI 长时间无反馈。

## 测试与验证

`tests/` 目录不是运行程序必需目录，但它是维护项目稳定性的必要源码目录。新增算法、修复 GUI/CLI 行为或调整打包配置后，应保留并运行测试。发布最终可执行文件或 wheel 时可以不包含测试目录，但源码仓库建议保留。

运行测试：

```bash
pytest
```

基础验证：

```bash
python cli.py list
python cli.py --version
python cli.py encrypt base64 "hello"
python cli.py decrypt base64 "aGVsbG8="
python cli.py try-all "khoor zruog"
python cli.py recursive --brief -p hello "khoor zruog"
```

一键解密和递归解密调整后，应重点验证：

- `python cli.py try-all "khoor zruog"` 前排包含 `hello world` 和 `shift=3`。
- `python cli.py try-all --json "khoor zruog"` 中凯撒爆破结果包含 `is_brute: true`、`params: "shift=3"`。
- `python cli.py recursive --brief -p hello "khoor zruog"` 输出路径 `caesar凯撒密码(shift=3)`。
- `python -m pytest tests/test_core.py -k "one_click or recursive"` 通过。

SageMath 在线验证建议：

- 在 GUI 中选择 `网页端 SageCell` 并点击 `测试连接`。
- 用 `SageExecutor` 执行 `print(2 + 3)`，应返回 `5`。
- 至少选择一个 `(sagemath)` 攻击模块跑小规模可验证样例，例如共享素因子、Hastad 广播、p 高位泄露或 Wiener 小私钥样例。

新增算法至少验证：

- `python cli.py list` 能看到算法。
- GUI 中 `文件 -> 刷新算法列表` 后能看到算法。
- 加密/解密函数对正常输入返回预期结果。
- 参数缺失、类型错误或非法输入时有清晰错误信息。

清理项目时只应删除 `tests/__pycache__/` 等缓存，不应删除 `tests/test_core.py`。

## 打包

Windows：

```bat
build.bat
```

手动打包：

```bash
python -m PyInstaller --clean --noconfirm Cryptoden.spec
```

`Cryptoden.spec` 会收集 `algorithms`、`core`、`gui`、`utils` 子模块，并打包 `algorithms/`、必要配置文件和 `config.json`。

打包时应同时包含 `algorithm_tabs_config.json`，否则程序会退回到 `gui/algorithm_tabs.py` 中的内置默认选项卡定义。

## 路径与迁移规则

项目内路径应遵循以下规则：

- 以 `Path(__file__).resolve().parent` 或调用方传入的 `base_path` 推导项目根目录，不依赖当前工作目录。
- 配置、图标、算法目录、日志目录、测试夹具等项目资源使用相对项目位置拼接，例如 `base_path / "config.json"`。
- 配置文件中保存项目内路径时优先保存相对路径，例如 `agent/agent_config.json`、`config/ai_config.json`。
- 不在源码、配置或文档示例中写入开发者机器目录。
- 外部程序路径允许由用户配置，例如 SageMath 本机可执行文件或 WSL 中的 `/usr/bin/sage`，但不能作为项目资源路径使用。

迁移验证建议：

- 将项目目录移动或复制到另一个位置后运行 `python cli.py list`。
- 运行 `python cli.py encrypt base64 "hello"` 和 `python cli.py decrypt base64 "aGVsbG8="`。
- 启动 `python main.py`，检查图标、设置、算法选项卡和日志写入是否正常。
- 发布前运行 `python cleanup.py --apply`，并确认 `config/ai_config.json` 不包含真实 API Key 或聊天历史。

## 依赖

运行依赖：

- `PyQt5>=5.15.0`
- `pycryptodome>=3.15.0`
- `requests>=2.28.0`
- `cryptography>=42.0.0`
- `numpy>=1.26.0`
- `markdown>=3.5.0`
- `pycryptodomex>=3.20.0`

可选依赖：

- `playwright>=1.40.0`
- `selenium>=4.20.0`

说明：`requirements.txt` 包含完整运行依赖与 SageCell 在线执行备用依赖；`setup.py` 的 `install_requires` 当前只覆盖核心依赖。

打包依赖：

- `pyinstaller`

## 文档维护

更新功能时同步检查：

- `README.md`：项目总览、安装、结构、快速开始。
- `USER_MANUAL.md`：用户操作流程、CLI/GUI 示例、常见问题。
- `DEVELOPMENT_MANUAL.md`：架构、扩展规则、开发验证。
