#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP 插件静态安全扫描器 (基于论文 "Do Not Mention This to the User" 的方法论)
=======================================================================
三层流水线中的 T2 静态分析实现: 以论文 Table 9 的 14 种攻击模式 + MCP 特有补充
作为统一检测正则, 对已获取到本地的仓库代码做逐文件逐行扫描。

命中仅代表"候选", 需结合语义审查判定意图 (verdict: benign/suspicious/malicious)。

用法:
  python mcp_plugin_scanner.py --repo-dir <dir> --repo <full_name> --out <out.json>
       [--language X] [--size-kb N] [--stars N] [--fetch-method M]
  python mcp_plugin_scanner.py --manifest <shard.csv> --cache-root <root> --out-dir <dir>

严重性沿用论文: CRITICAL(E2/PE3/SC2/SC3) > HIGH(E1/P1/P2/P3/SC1) > MEDIUM(E3/E4/P4/PE2) > LOW(PE1)
只做静态读取, 绝不执行被检代码。
"""

import argparse      # 命令行参数解析
import csv           # CSV 批量清单读取
import json          # JSON 结果序列化
import os            # 目录遍历
import re            # 正则匹配
import sys           # 系统退出码
from pathlib import Path  # 跨平台路径处理

# ---------------- 文件过滤 ----------------
# 扫描时需要跳过的目录（避免依赖/构建产物/文档带来海量噪音命中）
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build",
    ".next", ".nuxt", ".cache", "vendor", ".tox", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".idea", ".vscode", "target", "bin", "obj", ".turbo", ".nx",
    "coverage", ".yarn", ".pnpm-store", ".svelte-kit", ".dart_tool", ".gradle",
    ".hg", ".svn", ".mvn", "third_party", "ThirdParty", "libs", "assets", "fonts",
    "testdata", ".github", ".circleci", ".clinerules", "docs", "images", "img",
}
# docs/images 等目录里也可能藏 README 或 .md 的 P1/P2 指令, 但为避免噪音, 默认跳过纯文档目录;
# 保留 README* 的扫描: 通过下面的 SKIP_DIRS_WITH_README 处理
# 说明: SKIP_DIRS_ALL 去掉了 "docs"，使 docs 目录本身参与扫描（README 等可能在 docs 下）
SKIP_DIRS_ALL = SKIP_DIRS - {"docs"}  # docs 本身参与扫描, 但不再深挖子目录噪音由扩展名控制

# 参与扫描的文件扩展名（覆盖主流代码/脚本/配置/文档）
SCAN_EXTS = {
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs",
    ".sh", ".bash", ".zsh", ".ps1", ".rb", ".java", ".cs", ".c", ".cpp", ".cc",
    ".h", ".hpp", ".zig", ".md", ".markdown", ".json", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".txt", ".html", ".htm", ".sql", ".lua", ".php", ".swift",
    ".kt", ".dockerfile", ".pl", ".r", ".env", ".mcp", ".gradle", ".mustache",
}
# 无标准扩展名但需要扫描的特殊文件名
SPECIAL_FILES = {
    "dockerfile", "makefile", "cmakelists.txt", "requirements.txt", "setup.py",
    "setup.cfg", "pyproject.toml", "package.json", "package-lock.json",
    "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "pipfile", "gemfile", "podfile",
    ".env.example", ".env.sample", "readme", "readme.md", "readme.markdown",
    "skill.md", "skills.md", "agent.md", "agents.md",
}
BINARY_BYTES = b"\x00"  # 二进制文件检测用字节

# ---------------- 攻击模式 (论文 Table 9 的 14 模式 + MCP 补充) ----------------
# 每条: (id, label, severity, regex, flags)
# severity: CRITICAL/HIGH/MEDIUM/LOW
# flags: None 表示不附加 re 标志; re.I 忽略大小写; re.M 多行模式; re.S 使 . 匹配换行
PATTERNS = [
    # ---------- E1 外传: 检测代码向非本机端点发送数据的网络请求 ----------
    # 匹配 Python 常见 HTTP 客户端的 post/put/patch/get 调用，排除 localhost/127.0.0.1/0.0.0.0
    ("E1", "外传:HTTP客户端请求非本地端点",
     "HIGH",
     r"(?:requests|urllib(?:\.request)?|urllib3|httpx|aiohttp|urlopen|botocore|http\.client)\.\s*(?:post|put|patch|get)\s*\([^)]*https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0))",
     re.I),
    # 匹配 JS fetch/got 等对非本地端点的请求
    ("E1", "外传:JS fetch 请求非本地端点",
     "HIGH",
     r"\b(?:fetch|got|undici|superagent|node-fetch)\s*\(\s*[`'\"][^`'\"]*https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0))[^`'\"]*[`'\"]",
     re.I),
    # 匹配 JS axios 的 post/put/patch/get 调用
    ("E1", "外传:JS axios 请求非本地端点",
     "HIGH",
     r"\baxios\s*\.\s*(?:post|put|patch|get)\s*\([^)]*https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0))",
     re.I),

    # ---------- E2 凭据收集: 从环境变量读取凭据类变量 ----------
    # Python: os.environ / os.getenv 读取含 api_key/secret/token 等关键字的变量
    ("E2", "凭据收集:环境变量读取凭据",
     "CRITICAL",
     r"(?:os\.environ|os\.getenv|os\.environ\.get|environ\.get|getenv)\s*(?:\[|\(|\.)?\s*[\"'][^\"']*(?:api[_-]?key|secret|token|password|passwd|credential|auth)[^\"']*[\"']",
     re.I),
    # JS/Node: process.env 读取含凭据关键字的变量
    ("E2", "凭据收集:process.env 读取凭据",
     "CRITICAL",
     r"process\.env\s*\.\s*[A-Za-z0-9_]*(?:api[_-]?key|secret|token|password|passwd|credential|auth)[A-Za-z0-9_]*",
     re.I),

    # ---------- E3 文件枚举: 枚举敏感目录/密钥文件 ----------
    ("E3", "文件枚举:枚举敏感路径",
     "MEDIUM",
     r"(?:glob|iglob|listdir|scandir|os\.walk|\.rglob|readdir|readDir|walk)\s*\([^)]*(?:\.ssh|\.aws|\.gnupg|id_rsa|\.pem|keyring|\.git-credentials|\.netrc|\.pgpass|credentials\.json)",
     re.I),

    # ---------- E4 网络侦察 ----------
    # 端口/主机探测类调用
    ("E4", "网络侦察:端口/主机探测",
     "MEDIUM",
     r"(?:socket\.connect(?:_ex)?|gethostbyname|gethostbyaddr|portscan|synscan|masscan|nmap|connect_ex)\s*\(",
     re.I),

    # ---------- P1 指令覆盖 (prompt injection / jailbreak) ----------
    # 英文: 忽略/覆盖先前或系统指令
    ("P1", "指令覆盖:忽略先前指令(EN)",
     "HIGH",
     r"(?:ignore|disregard|overwrite|forget|override|skip)\s+(?:all\s+)?(?:the\s+)?(?:previous|above|prior|system|user|earlier|initial)\s+(?:instructions?|prompts?|rules?|safety|guidelines?|messages?|content)",
     re.I),
    # 英文: 忽略一切先前内容
    ("P1", "指令覆盖:忽略一切(EN)",
     "HIGH",
     r"(?:ignore|disregard)\s+(?:everything|anything|all|any)\s+(?:above|before|previously|you\s+were\s+told|that\s+came\s+before)",
     re.I),
    # 英文: 不遵守先前/系统指令
    ("P1", "指令覆盖:不遵守指令(EN)",
     "HIGH",
     r"(?:do\s+not\s+(?:follow|obey|respect|listen\s+to))\s+(?:the\s+)?(?:previous|above|system|user|prior)\s+(?:instructions?|rules?|safety|guidelines?)",
     re.I),
    # 中文: 忽略/无视/不遵守之前指令
    ("P1", "指令覆盖:中文忽略/无视指令",
     "HIGH",
     r"(?:忽略|无视|不必理会|不用管|不用理会).{0,24}(?:之前|上面|以上|系统|安全|指令|规则|要求|设定|提示)|不要遵守.{0,16}(?:之前|上面|以上|安全|指令|规则|要求)|(?:无需|不必)遵守.{0,16}(?:指令|规则|安全|系统要求)",
     None),

    # ---------- P2 隐藏指令 ----------
    # HTML 注释内藏指令（多行，由 scan_file 特殊处理，此处正则用于标记存在性）
    ("P2", "隐藏指令:HTML注释内指令",
     "HIGH",
     r"<!--(.*?)-->",
     re.S),
    # 不可见 Unicode 字符（零宽空格/连接符/间隔符/BOM）
    ("P2", "隐藏指令:不可见Unicode字符",
     "HIGH",
     r"[\u200b\u200c\u200d\u2060\ufeff]",
     None),
    # Markdown 隐藏注释（[//]:#(...) 语法）
    ("P2", "隐藏指令:Markdown隐藏注释",
     "HIGH",
     r"\[\s*//\s*\]\s*:\s*#\s*\([^)]*\)",
     None),

    # ---------- P3 代码执行+外泄: exec/eval 接触网络 ----------
    # Python: exec/eval/compile 参数中涉及网络库或 URL
    ("P3", "代码执行与外泄:exec/eval 接触网络",
     "HIGH",
     r"(?:exec|eval|compile|execfile)\s*\([^)]*(?:requests|urllib|urlopen|http[s]?://|socket|subprocess|urlretrieve|fetch|axios)",
     re.I),
    # JS: eval/new Function 接触网络相关
    ("P3", "代码执行与外泄:JS eval 接触网络",
     "HIGH",
     r"(?:eval|new\s+Function)\s*\([^)]*(?:fetch|axios|http[s]?://|require|XMLHttpRequest|WebSocket|process)",
     re.I),

    # ---------- P4 行为操纵: 绝对化指令/禁止询问 ----------
    # 英文: always/never/do not 等强指令 + 动作词组合
    ("P4", "行为操纵:绝对化行为指令(EN)",
     "MEDIUM",
     r"(?i)\b(?:always|never|must|do not|don't|never ask|do not ask|do not mention|never mention|without asking|no need to ask)\b[^\n]{0,110}\b(?:execute|run|perform|question|permission|mention|ask|confirm|inform|tell|reveal|disclose|notify)\b",
     None),
    # 中文: 不要/无需询问、静默执行等
    ("P4", "行为操纵:中文静默/禁止询问",
     "MEDIUM",
     r"(?:不要|无需|不必|禁止)(?:问|提及|询问|告诉|确认|征求|提示|告知)|必须(?:执行|运行|静默|直接)|静默(?:执行|运行|处理)|无条件(?:执行|运行)|(?:执行|运行).{0,8}(?:不要|无需|禁止)(?:问|询问|确认|征求)",
     None),

    # ---------- PE1 过度权限: 配置中可疑权限声明（需语义判定） ----------
    ("PE1", "过度权限:配置中可疑权限声明",
     "LOW",
     r"(?i)(?:permissions?|scopes?)\s*[:=]\s*\[?[\"'][^\"']*(?:\*|admin|write|all|delete|manage|root|bypass)[^\"']*[\"']\]?",
     None),

    # ---------- PE2 提权: sudo/chmod/chown 等特权操作 ----------
    ("PE2", "提权:特权操作",
     "MEDIUM",
     r"\b(?:sudo|chown|runas)\s+[^;\n]{0,40}|chmod\s+[0-7]{3,4}\s+[^;\n]{0,40}|os\.setuid\s*\(|os\.seteuid\s*\(|setuid\s*\(|setgid\s*\(|UseShellExecute\s*=|requireAdministrator|requestAdministrator",
     re.I),

    # ---------- PE3 凭据文件访问: 读取敏感文件 ----------
    # 匹配文件读取调用 + 敏感路径关键字
    ("PE3", "凭据文件访问:读取敏感文件",
     "CRITICAL",
     r"(?:open|open_text|read_text|readlines?|read\s*\(|pathlib\.Path|Path\s*\(|fs\.readFile|readFileSync|File\.ReadAllText|File\.ReadAllLines|Get-Content|readline)\s*[^)\n]{0,80}(?:\.ssh|\.aws|credentials|\.env|id_rsa|keyring|\.npmrc|\.netrc|\.git-credentials|\.pgpass)",
     re.I),

    # ---------- SC1 命令注入/命令执行 ----------
    # Python: subprocess/os.system/os.popen/shell=True
    ("SC1", "命令注入:Python 命令执行",
     "HIGH",
     r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(|os\.system\s*\(|os\.popen\s*\(|pty\.spawn\s*\(|shell\s*=\s*True",
     None),
    # JS: child_process 命令执行
    ("SC1", "命令注入:JS child_process",
     "HIGH",
     r"child_process\.(?:exec|execSync|spawn|spawnSync|fork)\s*\(|\bexecSync\s*\(|\bspawn\s*\(",
     None),
    # Go/Java/C#: 命令执行 API
    ("SC1", "命令注入:Go/Java/C# 命令执行",
     "HIGH",
     r"exec\.Command\s*\(|syscall\.Exec\s*\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(|Process\.Start\s*\(|os/exec",
     None),

    # ---------- SC2 远程脚本执行 ----------
    # curl/wget 管道到 shell（curl|sh 模式）
    ("SC2", "远程脚本执行:curl/wget 管道到 shell",
     "CRITICAL",
     r"(?:curl|wget|Invoke-WebRequest|iwr|powershell)\s+[^\n|;]{0,90}\s*\|?\s*(?:ba)?sh\b|curl\s+[^\n|]*\|\s*(?:ba)?sh\b",
     re.I),
    # PowerShell iex/Invoke-Expression 执行远程内容
    ("SC2", "远程脚本执行:iex/Invoke-Expression",
     "CRITICAL",
     r"Invoke-Expression\s*\(|iex\s*\([^)]*(?:https?://|Invoke-WebRequest|curl|wget)",
     re.I),
    # 动态导入远程 URL（import https://... / require https://...）
    ("SC2", "远程脚本执行:动态导入远程URL",
     "CRITICAL",
     r"(?:import|require|importlib\.import_module|__import__)\s*\(?\s*[\"'](?:https?://|//)[^\"']*[\"']",
     re.I),
    # exec/eval 拉取远程内容执行
    ("SC2", "远程脚本执行:exec/eval 拉取远程内容",
     "CRITICAL",
     r"(?:exec|eval|compile)\s*\([^)]*(?:urlopen|requests\.get|urllib\.request|https?://|read\(\)|\.content)",
     re.I),

    # ---------- SC3 混淆: 编码解码后执行 ----------
    # base64 解码后 exec/eval
    ("SC3", "混淆:base64解码后执行",
     "CRITICAL",
     r"(?:base64\.b64decode|b64decode|base64\.decodebytes|decodebytes|base64\.b85decode|b85decode|base64\.standard_b64decode)\s*\([^)]*\)[^;\n]{0,90}\b(?:exec|eval)\b",
     re.I),
    # marshal/pickle/yaml 反序列化执行
    ("SC3", "混淆:marshal/pickle 反序列化",
     "CRITICAL",
     r"(?:marshal\.loads|pickle\.loads|cPickle\.loads|shelve\.open|yaml\.load\s*\(\s*[^)]*(?:yaml\.LoadUnsafe|Loader\s*=\s*[^)]*Unsafe))",
     re.I),
    # hex/编码解码后执行
    ("SC3", "混淆:hex/编码解码后执行",
     "CRITICAL",
     r"(?:exec|eval)\s*\(\s*(?:bytes\.fromhex|\.fromhex|unhexlify|codecs\.decode|\.decode\s*\(\s*[\"']base64|bytes\.decode|base64\.b64decode|b64decode)",
     re.I),
    # JS atob/Buffer 解码后 eval/Function
    ("SC3", "混淆:JS atob/Buffer 解码后执行",
     "CRITICAL",
     r"(?:atob|Buffer\.from)\s*\([^)]*\)[^;\n]{0,90}\b(?:eval|Function)\b",
     re.I),

    # ---------- MCP 特有补充 ----------
    # M1 反向 shell: 网络连接后重定向描述符或 /dev/tcp 等
    ("M1", "反向shell:网络连接后重定向描述符",
     "CRITICAL",
     r"(?:socket\.connect|connect_ex)\s*\([^)]*\)[^;\n]{0,160}(?:dup2|os\.dup2|/bin/(?:ba)?sh\b)|/dev/tcp/[0-9a-zA-Z./]+/[0-9]{1,5}|(?:ba)?sh\s+-i\s+[^;\n]{0,60}>&\s*/dev/tcp",
     re.I),
    # M1 反向 shell: 已知远控工具/命令标记
    ("M1", "反向shell:已知远控工具标记",
     "CRITICAL",
     r"(?:Invoke-PowerShellTcp|PowerCat|nishang|nc\s+-[a-z]*e\s+|netcat\s+-[a-z]*e\s+|bash\s+-i\s+[^;\n]{0,40}(?:/dev/tcp|>/dev/tcp))",
     re.I),
    # M2 隐藏 BCC: 邮件密送外部地址
    ("M2", "隐藏BCC:邮件密送外部地址",
     "MEDIUM",
     r"(?i)bcc\s*[:=]\s*[\"'][^\"']*@(?![a-z0-9.-]*localhost)[^\"']*[\"']",
     None),
    # M3 硬编码凭据: 疑似密钥/令牌（sk-/ghp_/AKIA 等）
    ("M3", "硬编码凭据:疑似密钥/令牌",
     "CRITICAL",
     r"\b(?:sk-[A-Za-z0-9]{16,}|sk_live_[A-Za-z0-9]{16,}|pk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|sk-ant-[A-Za-z0-9_-]{20,})\b",
     None),
    # M3 硬编码凭据: 配置赋值
    ("M3", "硬编码凭据:配置赋值",
     "CRITICAL",
     r"(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
     re.I),
    # M4 可疑依赖: 安装钩子脚本（postinstall/preinstall/prepare）
    ("M4", "可疑依赖:安装钩子脚本",
     "MEDIUM",
     r"\"(?:postinstall|preinstall|prepare)\"\s*:\s*\"[^\"]*\"",
     None),
    # M4 可疑依赖: 远程/内联依赖来源（URL 指向 tgz/zip/git）
    ("M4", "可疑依赖:远程/内联依赖来源",
     "MEDIUM",
     r"[\"'][^\"']*(?:https?|git\+https?)://[^\"']*\.(?:tgz|zip|tar\.gz)[\"']|[\"'](?:git\+https?|ssh://)[^\"']*[\"']",
     re.I),
    # M4 可疑依赖: requirements 中直连 URL
    ("M4", "可疑依赖:requirements 直连 URL",
     "MEDIUM",
     r"^(?:https?|git\+https?)://[^\s]+",
     re.M),

    # ============================================================
    # M5-M9: MCP 协议层专属投毒检测（正则候选层，需语义/结构审查）
    # 设计原则: 先锚定 MCP 特有结构 (description/name/配置/schema),
    # 再在结构内找投毒 payload 词表 (复用 P1/P4 集合)。
    # ============================================================

    # M5 工具描述投毒: description 内嵌 prompt injection (MCP 最核心攻击面)
    ("M5", "MCP描述投毒:tool description 内嵌指令",
     "HIGH",
     r"(?:\"description\"\s*:\s*|description\s*[:=]|desc\s*[:=]|@mcp\.tool|@server\.tool|\.tool\(\s*[\"'])"
     r"[^\"'\n]{0,240}"
     r"(?:ignore|disregard|overwrite|forget|do\s+not\s+(?:ask|mention|tell|confirm)|"
     r"never\s+ask|without\s+asking|update\s+the\s+mcp\s+config\s+yourself|"
     r"append\s+&groups|忽略|无视|不必理会|不要遵守|无需询问|静默执行|不要问|不要告诉|未经.{0,8}(?:同意|许可))",
     re.I | re.X),

    # M6 工具名仿冒/同形: 注册名含零宽字符 或 覆盖内置可信工具
    ("M6", "MCP工具名仿冒:同形/零宽字符或覆盖内置工具",
     "HIGH",
     r"(?:\"name\"\s*:\s*[\"']|\.tool\(\s*[\"']|@(?:mcp|server)\.tool\(\s*[\"']|register_tool\(\s*[\"'])"
     r"[^\"']{0,60}"
     r"(?:read_file|web_search|write_file|execute|shell|code_runner|[\u200b-\u200f\u2060-\u206f])",
     re.I | re.X),

    # M7 客户端配置投毒: mcpServers 的 command 指向可执行载荷 / env 注入凭据
    ("M7", "MCP配置投毒:mcpServers command/env 恶意",
     "CRITICAL",
     r"(?:\"mcpServers\"|\"command\"\s*:|\"cmd\"\s*:|\"env\"\s*:)"
     r"[^\n]{0,260}"
     r"(?:curl|wget|python\s+-c|python\s+-m\s+http|node\s+-e|bash\s+-c|sh\s+-c|powershell|"
     r"Invoke-|/tmp/|/dev/shm/|base64|--decode|rm\s+-rf|chmod\s+777|nohup)",
     re.I | re.X),

    # M8 参数 schema 投毒: inputSchema 的 default/enum 硬编码恶意值或诱导参数
    ("M8", "MCP schema投毒:inputSchema 恶意 default/enum",
     "MEDIUM",
     r"(?:\"inputSchema\"|\"default\"\s*:|\"enum\"\s*:|\"description\"\s*:)"
     r"[^\n]{0,200}"
     r"(?:ignore|exec\(|eval\(|os\.system|curl\s+\S+\s*\||--eval|--command|--shell|"
     r"下载.{0,20}执行|.{0,10}(?:bash|sh)\s*-c)",
     re.I | re.X),

    # M9 资源/提示词投毒: @resource / @prompt 描述内嵌指令
    ("M9", "MCP资源投毒:resource/prompt 描述内嵌指令",
     "HIGH",
     r"(?:@(?:resource|prompt|read_resource)|\"resources?\"\s*:|\"prompts?\"\s*:|"
     r"read_resource|resource\s*[:=])"
     r"[^\n]{0,240}"
     r"(?:ignore|do\s+not\s+(?:ask|mention|tell)|never\s+ask|without\s+asking|"
     r"忽略|无视|不要问|不要告诉|无需询问|静默执行)",
     re.I | re.X),
]

# 配置类扩展名(用于 M3 严重性动态调整)
CONFIG_EXTS = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"}


def severity_for(pat, path):
    """按文件类型对部分模式做严重性微调(M3 在配置文件中更可疑)。"""
    sev = pat[2]  # 模式默认严重性
    # M3: 若命中文件是配置文件（含密钥配置赋值更可疑）→ CRITICAL
    if pat[0] == "M3" and Path(path).suffix.lower() in CONFIG_EXTS:
        return "CRITICAL"
    # M3: 普通代码文件中的硬编码凭据 → MEDIUM（需语义判定是否为测试夹具）
    if pat[0] == "M3":
        return "MEDIUM"
    return sev  # 其余模式返回默认严重性


def scan_mcp_config(path: Path) -> list:
    """JSON 解析 MCP 客户端配置文件 (.mcp.json / claude_desktop_config.json / mcpServers 等),
    检查 command/env/args 是否存在投毒迹象。
    返回命中列表(可直接并入 scanner 的 hits 格式)。
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return []

    hits = []
    servers = data.get("mcpServers", data) if isinstance(data, dict) else {}
    if not isinstance(servers, dict):
        return hits

    SUSPICIOUS_CMD_KEYWORDS = (
        "curl", "wget", "python -c", "python -m http", "node -e",
        "bash -c", "sh -c", "powershell", "Invoke-",
        "/tmp/", "/dev/shm/", "base64", "--decode",
        "rm -rf", "chmod 777", "nohup",
    )

    for name, conf in servers.items():
        if not isinstance(conf, dict):
            continue
        cmd = str(conf.get("command", "")).lower()
        args_list = conf.get("args", [])
        args = " ".join(str(a) for a in args_list) if isinstance(args_list, list) else str(args_list)
        env = conf.get("env") or {}

        # ---- command/args 指向可疑可执行 ----
        for bad in SUSPICIOUS_CMD_KEYWORDS:
            if bad in cmd or bad in args.lower():
                hits.append({
                    "pattern_id": "M7",
                    "label": "MCP配置投毒:mcpServers command/args 可疑",
                    "severity": "CRITICAL",
                    "file": str(path),
                    "line": 0,
                    "evidence": f"mcpServers[{name}].command={conf.get('command')} args={args[:200]}",
                })
                break  # 同一 server 只记一条

        # ---- env 注入凭据类变量 ----
        if isinstance(env, dict):
            for k, v in env.items():
                if re.search(r"(?i)(api[_-]?key|secret|token|password|credential)", str(k)):
                    hits.append({
                        "pattern_id": "M7",
                        "label": "MCP配置投毒:env 凭据注入",
                        "severity": "CRITICAL",
                        "file": str(path),
                        "line": 0,
                        "evidence": f"mcpServers[{name}].env.{k}=***",
                    })
                    break  # 同一 server 只记一条凭据注入

    return hits


# 需要额外调用 scan_mcp_config 的配置文件名（正则扫描之外的结构化解析）
MCP_CONFIG_FILENAMES = {
    ".mcp.json",
    "claude_desktop_config.json",
    "mcp.json",
    "mcpServers.json",
    "mcp_config.json",
}


def is_scannable(path: Path) -> bool:
    """判断文件是否应参与扫描。

    - 文件名以 readme 开头，或是 SPECIAL_FILES 中的特殊文件 → 扫描
    - 否则看扩展名是否在 SCAN_EXTS 中
    """
    name = path.name.lower()
    if name.startswith("readme") or name in {f.lower() for f in SPECIAL_FILES}:
        return True
    return path.suffix.lower() in SCAN_EXTS


def should_skip_dir(name: str) -> bool:
    """判断目录是否应被跳过（忽略大小写）。"""
    return name.lower() in SKIP_DIRS_ALL


def scan_file(path: Path):
    """扫描单个文件, 返回 hits 列表。

    流程：读字节 → 过滤超大/二进制/伪装文本 → 解码 → 特殊处理 P2 多行注释与
    不可见 Unicode → 逐行匹配其余 PATTERNS → eval 高密度检测 → 去重。
    """
    try:
        raw = path.read_bytes()  # 读取文件原始字节
    except (OSError, PermissionError):
        return []  # 无法读取（权限/占用）→ 无命中
    if len(raw) > 8 * 1024 * 1024:  # 跳过超大文件(如巨型 json)
        return []
    if BINARY_BYTES in raw[:8192]:  # 前 8KB 含空字节 → 判定为二进制
        return []
    try:
        # utf-8-sig 剥离 BOM, 避免 BOM 被误判为不可见 Unicode
        text = raw.decode("utf-8-sig", errors="replace")
    except Exception:
        return []
    # 二进制伪装检测：大量替换符（U+FFFD）说明不是真正文本
    if "\ufffd" in text[:4096] and len([c for c in text[:4096] if c == "\ufffd"]) > 50:
        return []

    lines = text.splitlines()  # 按行切分
    hits = []  # 命中结果列表
    rel = str(path)  # 相对路径（用于记录 file 字段）

    # ---- P2 特殊处理：HTML 注释(多行)、Markdown 隐藏注释、不可见 Unicode ----
    html_hits = []
    # 匹配所有 HTML 注释 <!-- ... -->
    for m in re.finditer(r"<!--(.*?)-->", text, re.S):
        inner = m.group(1)
        # 仅当注释内部包含指令性关键词时才记作命中（避免海量普通注释噪音）
        if re.search(r"(?i)(ignore|never|always|must|do not|don't|execute|run|instruction|secret|hidden|tell|mention|forget)|忽略|不要|必须|隐藏|执行|指令|之前", inner):
            line_no = text.count("\n", 0, m.start()) + 1  # 计算行号
            snippet = inner.strip().replace("\n", " ")[:220]  # 取前 220 字符做证据
            html_hits.append(("P2", "隐藏指令:HTML注释内指令", "HIGH", line_no, snippet))
    # 匹配 Markdown 隐藏注释 [//]:#(...)
    for m in re.finditer(r"\[\s*//\s*\]\s*:\s*#\s*\(([^)]*)\)", text):
        line_no = text.count("\n", 0, m.start()) + 1
        html_hits.append(("P2", "隐藏指令:Markdown隐藏注释", "HIGH", line_no, m.group(1)[:220]))
    # 匹配不可见 Unicode 字符（每个文件只记一次，避免爆炸）
    for m in re.finditer(r"[\u200b\u200c\u200d\u2060\ufeff]", text):
        line_no = text.count("\n", 0, m.start()) + 1
        html_hits.append(("P2", "隐藏指令:不可见Unicode字符", "HIGH", line_no,
                          repr(text[m.start() - 30:m.start() + 30])))
        break  # 每文件记一次即可
    # 将 P2 特殊命中并入 hits
    for pid, label, sev, ln, ev in html_hits:
        hits.append({"pattern_id": pid, "label": label, "severity": sev,
                     "file": rel, "line": ln, "evidence": ev})

    # ---- 逐行匹配其余模式 ----
    for idx, line in enumerate(lines, start=1):
        if len(line) > 2000:  # 超长行截断，避免正则回溯过慢
            line = line[:2000]
        for pid, label, sev, regex, flags in PATTERNS:
            if pid == "P2":  # P2 已在上面处理，跳过
                continue
            try:
                if flags is not None:
                    m = re.search(regex, line, flags)  # 带标志匹配
                else:
                    m = re.search(regex, line)  # 无标志匹配
            except re.error:  # 正则本身异常则跳过该模式
                continue
            if m:
                sev = severity_for((pid, label, sev, regex, flags), path)  # 动态严重性
                hits.append({
                    "pattern_id": pid, "label": label, "severity": sev,
                    "file": rel, "line": idx,
                    "evidence": line.strip()[:260],  # 命中行作为证据
                })
                # 不 break: 同一行可能同时命中多个不同模式(如 subprocess+curl|sh), 全量记录后统一去重

    # ---- eval 高密度检测（SC3 补充） ----
    eval_count = len(re.findall(r"\beval\s*\(", text))  # 统计文件中 eval( 出现次数
    if eval_count >= 5:  # ≥5 次视为高混淆密度候选
        first = next((i for i, l in enumerate(lines, 1) if re.search(r"\beval\s*\(", l)), 1)
        hits.append({"pattern_id": "SC3", "label": "混淆:eval高密度使用",
                     "severity": "MEDIUM", "file": rel, "line": first,
                     "evidence": "eval() 出现 %d 次 (>=5), 高混淆密度候选" % eval_count})

    # ---- 去重: 同文件同行同 pattern 只留一条 ----
    seen = set()
    uniq = []
    for h in hits:
        key = (h["pattern_id"], h["file"], h["line"])  # 唯一键：模式+文件+行
        if key in seen:
            continue
        seen.add(key)
        uniq.append(h)
    return uniq


def scan_repo(repo_dir: Path):
    """遍历仓库目录, 返回 (files_scanned, hits)。

    os.walk 逐目录遍历，跳过 should_skip_dir 判定的目录，
    仅对 is_scannable 的文件调用 scan_file；对 MCP 配置文件额外调 scan_mcp_config。
    """
    files_scanned = 0  # 已扫描文件计数
    all_hits = []  # 汇总命中
    if not repo_dir.exists():  # 目录不存在 → 无可扫描
        return 0, []
    for root, dirs, files in os.walk(str(repo_dir)):
        # 原地过滤需要跳过的子目录（影响后续递归）
        dirs[:] = [d for d in dirs if not should_skip_dir(d)]
        for f in files:
            p = Path(root) / f
            if not is_scannable(p):  # 扩展名/文件名不在扫描范围则跳过
                continue
            files_scanned += 1
            try:
                all_hits.extend(scan_file(p))  # 扫描并追加命中
            except Exception:
                continue  # 单文件异常不影响整体
            # MCP 客户端配置文件: 额外做结构化 JSON 解析 (M7 检测增强)
            if f.lower() in MCP_CONFIG_FILENAMES:
                try:
                    all_hits.extend(scan_mcp_config(p))
                except Exception:
                    continue
    return files_scanned, all_hits


def main():
    # 命令行参数定义
    ap = argparse.ArgumentParser(description="MCP 插件静态扫描器")
    # 单仓库模式参数
    ap.add_argument("--repo-dir", help="单个仓库代码目录")
    ap.add_argument("--repo", help="仓库 full_name")
    ap.add_argument("--out", help="输出 JSON 路径")
    ap.add_argument("--language", default="")
    ap.add_argument("--size-kb", type=int, default=0)
    ap.add_argument("--stars", type=int, default=0)
    ap.add_argument("--fetch-method", default="")
    # 批量模式参数
    ap.add_argument("--manifest", help="批量模式: shard CSV")
    ap.add_argument("--cache-root", help="批量模式: 缓存根目录")
    ap.add_argument("--out-dir", help="批量模式: 输出目录")
    args = ap.parse_args()

    if args.manifest:  # ---------- 批量模式（--manifest） ----------
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)  # 确保输出目录存在
        results = []
        # 读取 shard CSV
        with open(args.manifest, "r", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        for r in rows:
            full = r["full_name"]  # 仓库 full_name
            cache = Path(r["cache_dir"])  # 该仓库的缓存目录
            # 缓存不存在或为空 → 无法扫描，标记 not_scanned
            if not cache.exists() or not any(cache.iterdir()):
                res = {
                    "repo": full, "language": r["language"], "size_kb": int(r["size_kb"]),
                    "stars": int(r["stars"]), "fetch_method": r["fetch_method"],
                    "fetch_ok": False, "files_scanned": 0, "hits": [],
                    "verdict": "not_scanned", "confidence": 0, "reason": "代码获取失败/目录为空",
                    "shadow_features": [],
                }
                results.append(res)
                # 写单仓库 JSON（owner/repo → owner__repo.json）
                out = out_dir / (full.replace("/", "__") + ".json")
                out.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
                continue
            # 正常扫描该仓库
            files_scanned, hits = scan_repo(cache)
            res = {
                "repo": full, "language": r["language"], "size_kb": int(r["size_kb"]),
                "stars": int(r["stars"]), "fetch_method": r["fetch_method"],
                "fetch_ok": True, "files_scanned": files_scanned, "hits": hits,
                "verdict": "pending", "confidence": 0, "reason": "",
                "shadow_features": [],
            }
            results.append(res)
            out = out_dir / (full.replace("/", "__") + ".json")
            out.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
            # 打印该仓库命中统计（按严重性汇总）
            sev = {}
            for h in hits:
                sev[h["severity"]] = sev.get(h["severity"], 0) + 1
            print("[%s] files=%d hits=%d %s" % (full, files_scanned, len(hits),
                                                json.dumps(sev, ensure_ascii=False)))
        # 写本分片汇总 JSON
        summary = out_dir / ("_shard_summary_" + Path(args.manifest).stem + ".json")
        summary.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print("batch done: %d repos -> %s" % (len(results), out_dir))
        return

    # ---------- 单仓库模式 ----------
    repo_dir = Path(args.repo_dir)
    files_scanned, hits = scan_repo(repo_dir)
    res = {
        "repo": args.repo, "language": args.language, "size_kb": args.size_kb,
        "stars": args.stars, "fetch_method": args.fetch_method,
        "fetch_ok": repo_dir.exists() and any(repo_dir.iterdir()),
        "files_scanned": files_scanned, "hits": hits,
        "verdict": "pending", "confidence": 0, "reason": "", "shadow_features": [],
    }
    if args.out:  # 指定输出文件则写入
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False, indent=2))  # 打印结果


if __name__ == "__main__":
    main()  # 程序入口
