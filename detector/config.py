#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 配置中心
=====================
**唯一事实来源（single source of truth）**：所有路径 / 阈值 / 端点 / 凭据默认值都写在这里。

约定
----
* 本文件只做「纯配置定义」，不 import 项目内任何模块（因此可独立运行自检）。
* 其它模块**不要**自己拼路径、不要重复定义跳过目录/扩展名/阈值，
  统一 `from detector.deps import ...` 取用（deps 会读本文件）。
* 路径解析优先级：环境变量 > 项目内默认目录。换机器无需改代码。

自检::

    python detector/config.py
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径配置
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent  # detector/ 的上级 = 项目根


def _env(key: str, default: str) -> str:
    """读取环境变量（自动去空白/引号），缺省返回默认值。"""
    val = os.environ.get(key, "")
    return val.strip().strip('"') if val.strip() else default


def _resolve_dir(env_var: str, default_rel: str) -> Path:
    """解析数据目录：环境变量 > 项目内默认目录（相对项目根）。"""
    env_val = _env(env_var, "")
    if env_val:
        return Path(env_val).expanduser()
    return PROJECT_ROOT / default_rel


# 仓库代码根（其下为 <owner>_<repo> 文件夹；含完整代码或被检源码）
LARGE_REPO_SOURCE = _resolve_dir("MPV_LARGE_REPO_SOURCE", "mcp插件")

# 插件元数据目录（其下为 <owner>_<repo>/info.json）
MEDIUM_REPO_META = _resolve_dir("MPV_MEDIUM_REPO_META", "mcp插件")

# 产物根目录（扫描结果 / 生成的语义文档 / 报告）
OUTPUT_DIR = _resolve_dir("MPV_OUTPUT_DIR", "output")

# 单仓库扫描结果 JSON 目录（<owner>__<repo>.json）
SCAN_OUTPUT_DIR = OUTPUT_DIR / "scan_results"

# 扫描汇总 CSV（所有模块共用同一列口径，见 SCAN_SUMMARY_FIELDS）
SCAN_SUMMARY_CSV = OUTPUT_DIR / "scan_summary.csv"

# 代码获取缓存根（tarball / tree+raw 落盘位置）
CACHE_ROOT = _resolve_dir("MPV_CACHE_ROOT", "output/cache")

# 沙箱运行的临时工作目录（strace / tcpdump / 蜜罐文件）
SANDBOX_WORK_DIR = OUTPUT_DIR / "sandbox_work"

# ---------------------------------------------------------------------------
# 静态扫描口径（扫描 / 代码获取 / 语义文档 三处共用，避免各写一套）
# ---------------------------------------------------------------------------
STATIC_CONFIG = {
    # 遍历时跳过的目录（统一小写比较；静态扫描额外允许 docs/ 参与扫描）
    "SKIP_DIRS": {
        ".git", ".hg", ".svn", ".github", ".circleci", ".clinerules",
        "node_modules", "__pycache__", ".venv", "venv", "env",
        "dist", "build", ".next", ".nuxt", ".svelte-kit", ".cache",
        "vendor", "third_party", "libs", "assets", "fonts", "images", "img",
        "target", "bin", "obj", ".gradle", ".dart_tool", ".mvn",
        ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        ".turbo", ".nx", "coverage", ".yarn", ".pnpm-store",
        "testdata", ".idea", ".vscode",
    },
    # 语义文档生成额外跳过（测试/示例/文档目录不代表插件真实能力）
    "DOC_SKIP_DIRS": {"tests", "test", "__tests__", "docs", "doc",
                      "examples", "example", "scripts"},
    # 参与扫描的文件扩展名（主流代码/脚本/配置/文档）
    "SCAN_EXTS": {
        ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
        ".go", ".rs", ".sh", ".bash", ".zsh", ".ps1", ".rb", ".java", ".cs",
        ".c", ".cpp", ".cc", ".h", ".hpp", ".zig", ".md", ".markdown",
        ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".txt",
        ".html", ".htm", ".sql", ".lua", ".php", ".swift", ".kt", ".pl",
        ".r", ".gradle", ".mustache", ".dockerfile", ".env", ".mcp",
    },
    # 无标准扩展名但需要扫描/保留的特殊文件名
    "SPECIAL_FILES": {
        "dockerfile", "makefile", "cmakelists.txt", "requirements.txt",
        "setup.py", "setup.cfg", "pyproject.toml", "package.json",
        "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock",
        "pipfile", "gemfile", "podfile", ".env.example", ".env.sample",
        "readme", "readme.md", "readme.markdown",
        "skill.md", "skills.md", "agent.md", "agents.md",
    },
    # 纯源码扩展名（代码获取 / AST 硬事实 / 语义文档只用这些）
    "CODE_EXTS": {
        ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
        ".go", ".rs", ".java", ".cs", ".php", ".rb", ".kt", ".swift",
    },
    # 单文件大小上限（超过则跳过，避免巨型 lockfile / 二进制爆炸）
    "MAX_FILE_SIZE_BYTES": 8 * 1024 * 1024,  # 8MB
    # 单行最大长度（截断，避免正则回溯过慢）
    "MAX_LINE_LENGTH": 2000,
    # eval 高密度阈值（单文件 eval 次数）
    "EVAL_DENSITY_THRESHOLD": 5,
    # 语义文档 / 关键文件抽取：每仓库最多文件数与单文件最大字符数
    "MAX_FILES_PER_REPO": 8,
    "MAX_FILE_CHARS": 8000,
    # README 读取上限
    "MAX_README_CHARS": 10000,
}

# ---------------------------------------------------------------------------
# 本地 LLM 服务（默认 Ollama）
# ---------------------------------------------------------------------------
OLLAMA_HOST = _env("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_API_BASE = f"{OLLAMA_HOST}/v1"
# 默认模型名（各模块可用各自环境变量覆盖）
DEFAULT_MODEL = _env("MPV_MODEL", "qwen3-coder:30b")

# ---------------------------------------------------------------------------
# 语义对齐率检测配置
# ---------------------------------------------------------------------------
ALIGN_CONFIG = {
    # LLM 后端
    "backend": _env("ALIGN_BACKEND", "openai"),
    "api_base": _env("ALIGN_API_BASE", OLLAMA_API_BASE),
    "api_key": _env("ALIGN_API_KEY", ""),
    "model": _env("ALIGN_MODEL", DEFAULT_MODEL),
    # 对齐率判定阈值（align_rate 与 sandbox_rules 共用，改这里即全链路生效）
    "CONFLICT_RATE_THRESHOLD_SUSPICIOUS": 0.3,  # 矛盾率 >= 30% → suspicious 候选
    "CONFLICT_RATE_THRESHOLD_HIGH": 0.6,       # 矛盾率 >= 60% → malicious 候选
    # DANGER 信号判定：安全矛盾率阈值 / 冲突条数阈值
    "DANGER_SEC_CONFLICT_RATE": 0.3,
    "DANGER_CONFLICT_COUNT": 3,
}

# ---------------------------------------------------------------------------
# 综合判定阈值（静态扫描命中 + 语义对齐信号 → LOW / REVIEW / HIGH_RISK_REVIEW）
# ---------------------------------------------------------------------------
VERDICT_CONFIG = {
    "CRIT_TIER_HIGH": 10,   # CRITICAL 命中数 >= 10 → 高
    "HIGH_TIER_HIGH": 50,   # HIGH 命中数 >= 50     → 高
    "CRIT_TIER_MED": 1,     # CRITICAL 命中数 >= 1  → 中
    "HIGH_TIER_MED": 5,     # HIGH 命中数 >= 5      → 中
}

# ---------------------------------------------------------------------------
# 沙箱配置
# ---------------------------------------------------------------------------
SANDBOX_CONFIG = {
    # ---- 镜像 ----
    "docker_image": "mpv-sandbox:latest",
    "base_image": "ubuntu:22.04",
    # ---- 资源限制 ----
    "memory_limit_mb": 2048,
    "cpu_limit": 2.0,
    "pids_limit": 256,
    "timeout_seconds": 60,
    # ---- 网络隔离策略 ----
    # 注意: 生产沙箱不能用 --network=none —— 那样恶意插件无法外传，
    # 蜜罐泄露与未声明端点连接都观测不到。改为"受监控出口网络":
    # 目标容器接入自定义 bridge, 另起 tcpdump sidecar 以
    # --network=container:<target> 旁路抓包, 并解析 DNS(53) 建立 IP->域名 映射。
    "network_mode": "bridge",
    "network_name": "mpv-sandbox-net",
    "capture_dns": True,
    # ---- 文件系统与权限 ----
    "read_only_rootfs": True,
    "tmpfs": ["/tmp:rw,size=64m,exec"],
    "cap_drop": ["ALL"],
    "cap_add": ["SYS_PTRACE"],          # strace 采集 execve/openat/connect 需要
    # ---- 行为采集 ----
    "strace_syscalls": ["execve", "openat", "connect", "sendto"],
    "strace_output": "/tmp/mpv_strace.log",
    "net_output": "/tmp/mpv_net.pcap",
    # 容器内插件代码挂载点
    "repo_mount": "/app",
    # openat 噪声前缀: 运行时/系统库加载不应算作"文件访问行为"
    "open_noise_prefixes": [
        "/usr/", "/lib/", "/lib64/", "/proc/", "/sys/", "/etc/ld.so",
        "/etc/nsswitch.conf", "/etc/localtime", "/etc/hosts",
        "/etc/resolv.conf", "/etc/gai.conf", "/etc/ssl/", "/etc/ca-certificates/",
        "/dev/null", "/dev/urandom", "/dev/random", "/dev/tty", "/dev/pts",
        "/app/node_modules/", "/app/venv/", "/app/.venv/", "/app/dist/",
    ],
    # 敏感路径模式: 命中即视为高危文件访问（含上报"试图读取"）
    "sensitive_path_patterns": [
        r"\.ssh/", r"\.aws/", r"\.env$", r"id_rsa", r"id_ed25519",
        r"credential", r"/etc/passwd", r"/etc/shadow", r"\.git-credentials",
        r"\.netrc", r"\.docker/config\.json", r"honeypot",
    ],
    # 蜜罐落地文件: 目标若读取即命中高危信号
    "honeypot_files": {
        "/tmp/honeypot_ssh_key_never_exist":
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "honeypot_decoy_do_not_use_b3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n"
            "-----END OPENSSH PRIVATE KEY-----\n",
        "/tmp/honeypot_credentials.json":
            '{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",'
            ' "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}\n',
    },
    # MCP 工具激活: 通过 stdio 发送 JSON-RPC(initialize/tools/list/tools/call),
    # 否则插件只启动不干活, 休眠触发型恶意行为无法被观测
    "probe": {
        "enabled": True,
        "initialize_timeout": 10,
        "tool_call_timeout": 15,
        "max_tools": 12,
    },
    # 蜜罐凭据（被检代码若外传这些则必然恶意）
    "honeypot": {
        "api_key": "honeypot_fake_key_do_not_use_sk_1234567890abcdef",
        "ssh_private_key": "/tmp/honeypot_ssh_key_never_exist",
        "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    },
    # 需要提交人工审核中心的触发条件
    "auto_trigger_review": [
        "蜜罐凭据外传",
        "未声明的网络端点连接",
        "未声明的命令执行",
        "未声明的敏感文件读取",
    ],
}

# ---------------------------------------------------------------------------
# LLM 语义文档生成配置
# ---------------------------------------------------------------------------
DOC_GEN_CONFIG = {
    "backend": _env("DOC_BACKEND", "openai"),
    "api_base": _env("DOC_API_BASE", OLLAMA_API_BASE),
    "api_key": _env("DOC_API_KEY", ""),
    "model": _env("DOC_MODEL", DEFAULT_MODEL),
    "temperature": 0.3,
    "max_tokens": 4096,
    "timeout": 600,
}

# ---------------------------------------------------------------------------
# GitHub / HTTP 配置
# ---------------------------------------------------------------------------
GITHUB_CONFIG = {
    "api_url": "https://api.github.com",
    "codeload_url": "https://codeload.github.com",
    "api_version": "2022-11-28",
    "user_agent": "MPV-Detector/2.0",
    "token": _env("GITHUB_TOKEN", ""),
    "timeout": 30,
    "max_retries": 3,
    "retry_delay": 5,
}

# ---------------------------------------------------------------------------
# 代码获取（fetcher）配置
# ---------------------------------------------------------------------------
FETCH_CONFIG = {
    "method": _env("MPV_FETCH_METHOD", "auto"),  # auto / tarball / tree
    "workers": 8,
    # 单仓库硬超时（秒）：codeload 偶发挂死，必须有上限
    "hard_timeout": 180,
    "chunk_size": 64 * 1024,
}

# ---------------------------------------------------------------------------
# 扫描汇总 CSV 的统一列口径（summary 写、run_flow 读，两边都从这里取）
# ---------------------------------------------------------------------------
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SCAN_SUMMARY_FIELDS = [
    "repo", "verdict", "files_scanned", "hits",
    *SEVERITIES,
    "top_severity", "fetch_method", "confidence", "reason",
]

# ---------------------------------------------------------------------------
# 合并为全局 CONFIG（只读视图，供需要整份配置的场景使用）
# ---------------------------------------------------------------------------
CONFIG = {
    "project_root": str(PROJECT_ROOT),
    "large_repo_source": str(LARGE_REPO_SOURCE),
    "medium_repo_meta": str(MEDIUM_REPO_META),
    "output_dir": str(OUTPUT_DIR),
    "scan_output_dir": str(SCAN_OUTPUT_DIR),
    "scan_summary_csv": str(SCAN_SUMMARY_CSV),
    "cache_root": str(CACHE_ROOT),
    "sandbox_work_dir": str(SANDBOX_WORK_DIR),
    "static": STATIC_CONFIG,
    "align": ALIGN_CONFIG,
    "verdict": VERDICT_CONFIG,
    "sandbox": SANDBOX_CONFIG,
    "doc_gen": DOC_GEN_CONFIG,
    "github": GITHUB_CONFIG,
    "fetch": FETCH_CONFIG,
    "scan_summary_fields": SCAN_SUMMARY_FIELDS,
    "severities": SEVERITIES,
    "paths": {
        "project_root": str(PROJECT_ROOT),
        "data": str(LARGE_REPO_SOURCE),
        "output": str(OUTPUT_DIR),
        "scan_results": str(SCAN_OUTPUT_DIR),
        "scan_summary": str(SCAN_SUMMARY_CSV),
        "cache": str(CACHE_ROOT),
        "sandbox_work": str(SANDBOX_WORK_DIR),
    },
}

if __name__ == "__main__":
    # 自检：打印所有配置（Path / set 转成可序列化结构）
    import json

    def _jsonable(obj):
        """把 set/Path 等转成 JSON 可序列化的结构。"""
        if isinstance(obj, (set, frozenset)):
            return sorted(str(x) for x in obj)
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, dict):
            return {k: _jsonable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_jsonable(x) for x in obj]
        return obj

    print(json.dumps(_jsonable(CONFIG), indent=2, ensure_ascii=False))
