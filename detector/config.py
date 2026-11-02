#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 配置中心
=====================
**唯一事实来源（single source of truth）**：所有路径 / 阈值 / 端点 / 模型权重地址
都在这里组装。实际取值优先级从高到低：

1. 环境变量（``MPV_*`` / ``OLLAMA_HOST`` / ``GITHUB_TOKEN`` 等）
2. 项目根 ``config.yaml``（本机路径、模型权重地址、阈值，每人一份，已 gitignore）
3. 本文件内置默认值（与 ``config.yaml.example`` 一致，保证新 clone 即可跑）

约定
----
* 本文件只做「纯配置组装」，不 import 项目内任何模块（可独立运行自检）。
* 其它模块**不要**自己拼路径、不要重复定义跳过目录/扩展名/阈值，
  统一 ``from detector.deps import ...`` 取用（deps 会读本文件）。
* YAML 里的相对路径一律相对项目根解析；绝对路径原样使用。
* 修改本机路径 / 换模型 / 调阈值：改 ``config.yaml``，不要改本文件。

自检::

    python detector/config.py        # 打印最终生效配置
    python detector/config.py --example   # 重新生成 config.yaml.example
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict

import yaml

# ---------------------------------------------------------------------------
# 项目根
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent  # detector/ 的上级 = 项目根
CONFIG_FILE = PROJECT_ROOT / "config.yaml"
CONFIG_EXAMPLE = PROJECT_ROOT / "config.yaml.example"


# ---------------------------------------------------------------------------
# 内置默认值（与 config.yaml.example 保持一致；YAML 只写想覆盖的项即可）
# ---------------------------------------------------------------------------
_DEFAULTS: Dict[str, Any] = {
    "paths": {
        # 被检代码根：其下为 <owner>_<repo> 文件夹（本机为 dateset/，1391 个 clone 仓库）
        "repo_root": "dateset",
        # 插件元数据目录（其下为 <owner>_<repo>/info.json）
        "medium_repo_meta": "mcp插件",
        # 产物根目录
        "output_dir": "output",
        # 单仓库扫描结果 JSON 目录
        "scan_results": "output/scan_results",
        # 扫描汇总 CSV
        "scan_summary": "output/scan_summary.csv",
        # 代码获取缓存根
        "cache_root": "output/cache",
        # 沙箱运行的临时工作目录
        "sandbox_work": "output/sandbox_work",
        # 语义分析目标清单（每行一个 owner_repo；flow 默认读它）
        "targets_list": "output/targets.txt",
        # LLM 语义文档输出目录（docgen / flow 共用）
        "gen_docs": "output/gen_docs",
        # HTML 可视化报告输出路径（run / report-html 共用）
        "report_html": "output/report.html",
    },
    "models": {
        # 基座模型权重目录（本地 safetensors，约 5.9GB）
        "base_model": "mcp_doc_finetune/models/Qwen2.5-3B-Instruct",
        # 正式 LoRA adapter（v2 为最新）
        "adapter": "mcp_doc_finetune/adapter_mcp_doc_v2",
        # 冒烟测试用 adapter
        "adapter_smoke": "mcp_doc_finetune/adapter_smoke",
    },
    "datasets": {
        "real": "mcp_doc_finetune/dataset_real.jsonl",
        "real_v2": "mcp_doc_finetune/dataset_real_v2.jsonl",
        "smoke": "mcp_doc_finetune/dataset_smoke.jsonl",
    },
    "manifests": {
        "scan": "output/scan_manifest.csv",
        "shard1": "output/shard1.csv",
    },
    "llm": {
        "ollama_host": "http://localhost:11434",
        "default_model": "qwen3-coder:30b",
    },
    # 静态扫描口径（扫描 / 代码获取 / 语义文档 三处共用）
    "static": {
        "SKIP_DIRS": [
            ".git", ".hg", ".svn", ".github", ".circleci", ".clinerules",
            "node_modules", "__pycache__", ".venv", "venv", "env",
            "dist", "build", ".next", ".nuxt", ".svelte-kit", ".cache",
            "vendor", "third_party", "libs", "assets", "fonts", "images", "img",
            "target", "bin", "obj", ".gradle", ".dart_tool", ".mvn",
            ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache",
            ".turbo", ".nx", "coverage", ".yarn", ".pnpm-store",
            "testdata", ".idea", ".vscode",
        ],
        "DOC_SKIP_DIRS": ["tests", "test", "__tests__", "docs", "doc",
                          "examples", "example", "scripts"],
        "SCAN_EXTS": [
            ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
            ".go", ".rs", ".sh", ".bash", ".zsh", ".ps1", ".rb", ".java", ".cs",
            ".c", ".cpp", ".cc", ".h", ".hpp", ".zig", ".md", ".markdown",
            ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".txt",
            ".html", ".htm", ".sql", ".lua", ".php", ".swift", ".kt", ".pl",
            ".r", ".gradle", ".mustache", ".dockerfile", ".env", ".mcp",
        ],
        "SPECIAL_FILES": [
            "dockerfile", "makefile", "cmakelists.txt", "requirements.txt",
            "setup.py", "setup.cfg", "pyproject.toml", "package.json",
            "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock",
            "pipfile", "gemfile", "podfile", ".env.example", ".env.sample",
            "readme", "readme.md", "readme.markdown",
            "skill.md", "skills.md", "agent.md", "agents.md",
        ],
        "CODE_EXTS": [
            ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
            ".go", ".rs", ".java", ".cs", ".php", ".rb", ".kt", ".swift",
        ],
        "MAX_FILE_SIZE_BYTES": 8 * 1024 * 1024,
        "MAX_LINE_LENGTH": 2000,
        "EVAL_DENSITY_THRESHOLD": 5,
        "MAX_FILES_PER_REPO": 8,
        "MAX_FILE_CHARS": 8000,
        "MAX_README_CHARS": 10000,
    },
    # 语义对齐率检测配置
    "align": {
        "backend": "openai",
        "api_base": "",   # 空字符串 → 用 llm.ollama_host/v1
        "api_key": "",
        "model": "",      # 空字符串 → 用 llm.default_model
        "CONFLICT_RATE_THRESHOLD_SUSPICIOUS": 0.3,
        "CONFLICT_RATE_THRESHOLD_HIGH": 0.6,
        "DANGER_SEC_CONFLICT_RATE": 0.3,
        "DANGER_CONFLICT_COUNT": 3,
    },
    # 综合判定阈值
    "verdict": {
        "CRIT_TIER_HIGH": 10,
        "HIGH_TIER_HIGH": 50,
        "CRIT_TIER_MED": 1,
        "HIGH_TIER_MED": 5,
    },
    # 沙箱配置
    "sandbox": {
        "docker_image": "mpv-sandbox:latest",
        "base_image": "ubuntu:22.04",
        "memory_limit_mb": 2048,
        "cpu_limit": 2.0,
        "pids_limit": 256,
        "timeout_seconds": 60,
        "network_mode": "bridge",
        "network_name": "mpv-sandbox-net",
        "capture_dns": True,
        "read_only_rootfs": True,
        "tmpfs": ["/tmp:rw,size=64m,exec"],
        "cap_drop": ["ALL"],
        "cap_add": ["SYS_PTRACE"],
        "strace_syscalls": ["execve", "openat", "connect", "sendto"],
        "strace_output": "/tmp/mpv_strace.log",
        "net_output": "/tmp/mpv_net.pcap",
        "repo_mount": "/app",
        "open_noise_prefixes": [
            "/usr/", "/lib/", "/lib64/", "/proc/", "/sys/", "/etc/ld.so",
            "/etc/nsswitch.conf", "/etc/localtime", "/etc/hosts",
            "/etc/resolv.conf", "/etc/gai.conf", "/etc/ssl/", "/etc/ca-certificates/",
            "/dev/null", "/dev/urandom", "/dev/random", "/dev/tty", "/dev/pts",
            "/app/node_modules/", "/app/venv/", "/app/.venv/", "/app/dist/",
        ],
        "sensitive_path_patterns": [
            r"\.ssh/", r"\.aws/", r"\.env$", r"id_rsa", r"id_ed25519",
            r"credential", r"/etc/passwd", r"/etc/shadow", r"\.git-credentials",
            r"\.netrc", r"\.docker/config\.json", r"honeypot",
        ],
        "honeypot_files": {
            "/tmp/honeypot_ssh_key_never_exist":
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "honeypot_decoy_do_not_use_b3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n"
                "-----END OPENSSH PRIVATE KEY-----\n",
            "/tmp/honeypot_credentials.json":
                '{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",'
                ' "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}\n',
        },
        "probe": {
            "enabled": True,
            "initialize_timeout": 10,
            "tool_call_timeout": 15,
            "max_tools": 12,
        },
        "honeypot": {
            "api_key": "honeypot_fake_key_do_not_use_sk_1234567890abcdef",
            "ssh_private_key": "/tmp/honeypot_ssh_key_never_exist",
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        "auto_trigger_review": [
            "蜜罐凭据外传",
            "未声明的网络端点连接",
            "未声明的命令执行",
            "未声明的敏感文件读取",
        ],
    },
    # LLM 语义文档生成
    "doc_gen": {
        "backend": "openai",
        "api_base": "",
        "api_key": "",
        "model": "",
        "temperature": 0.3,
        "max_tokens": 4096,
        "timeout": 600,
    },
    "github": {
        "api_url": "https://api.github.com",
        "codeload_url": "https://codeload.github.com",
        "api_version": "2022-11-28",
        "user_agent": "MPV-Detector/2.0",
        "token": "",
        "timeout": 30,
        "max_retries": 3,
        "retry_delay": 5,
    },
    "fetch": {
        "method": "auto",
        "workers": 8,
        "hard_timeout": 180,
        "chunk_size": 64 * 1024,
    },
}


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def _env(key: str, default: str = "") -> str:
    """读取环境变量（自动去空白/引号），缺省返回空串。"""
    val = os.environ.get(key, "")
    return val.strip().strip('"') if val.strip() else default


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """递归合并：override 的 dict 字段深合并，其它字段直接覆盖。"""
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _load_yaml() -> Dict[str, Any]:
    """读 config.yaml（不存在返回 {}）。"""
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return {}
        return data
    except Exception as e:
        print(f"[config] 警告: 读取 {CONFIG_FILE.name} 失败，使用内置默认: {e}", flush=True)
        return {}


def _resolve_path(p: str) -> Path:
    """相对路径相对项目根解析，绝对路径原样。"""
    path = Path(p).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


# ---------------------------------------------------------------------------
# 组装最终配置
# ---------------------------------------------------------------------------
_user_cfg = _load_yaml()
CFG: Dict[str, Any] = _deep_merge(_DEFAULTS, _user_cfg)

# ---- 环境变量覆盖（优先级最高）----
_paths = CFG["paths"]
if v := _env("MPV_LARGE_REPO_SOURCE"):
    _paths["repo_root"] = v
if v := _env("MPV_MEDIUM_REPO_META"):
    _paths["medium_repo_meta"] = v
if v := _env("MPV_OUTPUT_DIR"):
    _paths["output_dir"] = v
if v := _env("MPV_CACHE_ROOT"):
    _paths["cache_root"] = v
if v := _env("OLLAMA_HOST"):
    CFG["llm"]["ollama_host"] = v
if v := _env("MPV_MODEL"):
    CFG["llm"]["default_model"] = v
if v := _env("ALIGN_API_BASE"):
    CFG["align"]["api_base"] = v
if v := _env("ALIGN_API_KEY"):
    CFG["align"]["api_key"] = v
if v := _env("ALIGN_MODEL"):
    CFG["align"]["model"] = v
if v := _env("ALIGN_BACKEND"):
    CFG["align"]["backend"] = v
if v := _env("DOC_API_BASE"):
    CFG["doc_gen"]["api_base"] = v
if v := _env("DOC_API_KEY"):
    CFG["doc_gen"]["api_key"] = v
if v := _env("DOC_MODEL"):
    CFG["doc_gen"]["model"] = v
if v := _env("DOC_BACKEND"):
    CFG["doc_gen"]["backend"] = v
if v := _env("GITHUB_TOKEN"):
    CFG["github"]["token"] = v
if v := _env("MPV_FETCH_METHOD"):
    CFG["fetch"]["method"] = v

# ---- 构建 Path 常量 ----
LARGE_REPO_SOURCE = _resolve_path(_paths["repo_root"])
MEDIUM_REPO_META = _resolve_path(_paths["medium_repo_meta"])
OUTPUT_DIR = _resolve_path(_paths["output_dir"])
SCAN_OUTPUT_DIR = _resolve_path(_paths["scan_results"])
SCAN_SUMMARY_CSV = _resolve_path(_paths["scan_summary"])
CACHE_ROOT = _resolve_path(_paths["cache_root"])
SANDBOX_WORK_DIR = _resolve_path(_paths["sandbox_work"])
TARGETS_FILE = _resolve_path(_paths["targets_list"])
GEN_DOCS_DIR = _resolve_path(_paths["gen_docs"])
REPORT_HTML = _resolve_path(_paths["report_html"])

MODEL_BASE_DIR = _resolve_path(CFG["models"]["base_model"])
MODEL_ADAPTER_DIR = _resolve_path(CFG["models"]["adapter"])
MODEL_ADAPTER_SMOKE_DIR = _resolve_path(CFG["models"]["adapter_smoke"])

DATASET_REAL = _resolve_path(CFG["datasets"]["real"])
DATASET_REAL_V2 = _resolve_path(CFG["datasets"]["real_v2"])
DATASET_SMOKE = _resolve_path(CFG["datasets"]["smoke"])

MANIFEST_SCAN = _resolve_path(CFG["manifests"]["scan"])
MANIFEST_SHARD1 = _resolve_path(CFG["manifests"]["shard1"])

# ---- LLM 端点 ----
OLLAMA_HOST = CFG["llm"]["ollama_host"]
OLLAMA_API_BASE = f"{OLLAMA_HOST.rstrip('/')}/v1"
DEFAULT_MODEL = CFG["llm"]["default_model"]

# ---- 扫描口径：list → frozenset ----
_static = CFG["static"]
STATIC_CONFIG = {
    "SKIP_DIRS": frozenset(_static["SKIP_DIRS"]),
    "DOC_SKIP_DIRS": frozenset(_static["DOC_SKIP_DIRS"]),
    "SCAN_EXTS": frozenset(_static["SCAN_EXTS"]),
    "SPECIAL_FILES": frozenset(_static["SPECIAL_FILES"]),
    "CODE_EXTS": frozenset(_static["CODE_EXTS"]),
    "MAX_FILE_SIZE_BYTES": _static["MAX_FILE_SIZE_BYTES"],
    "MAX_LINE_LENGTH": _static["MAX_LINE_LENGTH"],
    "EVAL_DENSITY_THRESHOLD": _static["EVAL_DENSITY_THRESHOLD"],
    "MAX_FILES_PER_REPO": _static["MAX_FILES_PER_REPO"],
    "MAX_FILE_CHARS": _static["MAX_FILE_CHARS"],
    "MAX_README_CHARS": _static["MAX_README_CHARS"],
}

# ---- 对齐率配置（空值回退到 llm 默认）----
_align = CFG["align"]
ALIGN_CONFIG = {
    "backend": _align["backend"],
    "api_base": _align["api_base"] or OLLAMA_API_BASE,
    "api_key": _align["api_key"],
    "model": _align["model"] or DEFAULT_MODEL,
    "CONFLICT_RATE_THRESHOLD_SUSPICIOUS": _align["CONFLICT_RATE_THRESHOLD_SUSPICIOUS"],
    "CONFLICT_RATE_THRESHOLD_HIGH": _align["CONFLICT_RATE_THRESHOLD_HIGH"],
    "DANGER_SEC_CONFLICT_RATE": _align["DANGER_SEC_CONFLICT_RATE"],
    "DANGER_CONFLICT_COUNT": _align["DANGER_CONFLICT_COUNT"],
}

VERDICT_CONFIG = dict(CFG["verdict"])
SANDBOX_CONFIG = CFG["sandbox"]  # dict 直接透传（含嵌套 dict）

_doc = CFG["doc_gen"]
DOC_GEN_CONFIG = {
    "backend": _doc["backend"],
    "api_base": _doc["api_base"] or OLLAMA_API_BASE,
    "api_key": _doc["api_key"],
    "model": _doc["model"] or DEFAULT_MODEL,
    "temperature": _doc["temperature"],
    "max_tokens": _doc["max_tokens"],
    "timeout": _doc["timeout"],
}

GITHUB_CONFIG = dict(CFG["github"])
FETCH_CONFIG = dict(CFG["fetch"])

# ---- 扫描汇总列口径 ----
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SCAN_SUMMARY_FIELDS = [
    "repo", "verdict", "files_scanned", "hits",
    *SEVERITIES,
    "top_severity", "fetch_method", "confidence", "reason",
]


def _yamlable(obj: Any) -> Any:
    """把 frozenset/Path 等转成 YAML 可序列化结构。"""
    if isinstance(obj, (frozenset, set)):
        return sorted(str(x) for x in obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {k: _yamlable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_yamlable(x) for x in obj]
    return obj


def write_example() -> Path:
    """把内置默认值写成 config.yaml.example（不覆盖用户本地 config.yaml）。"""
    with open(CONFIG_EXAMPLE, "w", encoding="utf-8") as f:
        f.write(
            "# config.yaml.example —— MPV-Detector 本机配置模板\n"
            "# 用法：复制本文件为 config.yaml，按本机路径修改。\n"
            "# config.yaml 已在 .gitignore 中，不会提交。\n"
            "# 路径写相对路径时相对项目根；环境变量 MPV_* 优先级最高。\n"
            "# YAML 里只写想覆盖的项，未列出的段用内置默认。\n\n"
        )
        yaml.safe_dump(_yamlable(_DEFAULTS), f, allow_unicode=True, sort_keys=False,
                       default_flow_style=False)
    return CONFIG_EXAMPLE


# 合并为全局 CONFIG（只读视图，供需要整份配置的场景使用）
CONFIG = {
    "project_root": str(PROJECT_ROOT),
    "large_repo_source": str(LARGE_REPO_SOURCE),
    "medium_repo_meta": str(MEDIUM_REPO_META),
    "output_dir": str(OUTPUT_DIR),
    "scan_output_dir": str(SCAN_OUTPUT_DIR),
    "scan_summary_csv": str(SCAN_SUMMARY_CSV),
    "cache_root": str(CACHE_ROOT),
    "sandbox_work_dir": str(SANDBOX_WORK_DIR),
    "model_base_dir": str(MODEL_BASE_DIR),
    "model_adapter_dir": str(MODEL_ADAPTER_DIR),
    "model_adapter_smoke_dir": str(MODEL_ADAPTER_SMOKE_DIR),
    "dataset_real": str(DATASET_REAL),
    "dataset_real_v2": str(DATASET_REAL_V2),
    "dataset_smoke": str(DATASET_SMOKE),
    "manifest_scan": str(MANIFEST_SCAN),
    "manifest_shard1": str(MANIFEST_SHARD1),
    "static": _yamlable(STATIC_CONFIG),
    "align": ALIGN_CONFIG,
    "verdict": VERDICT_CONFIG,
    "sandbox": SANDBOX_CONFIG,
    "doc_gen": DOC_GEN_CONFIG,
    "github": GITHUB_CONFIG,
    "fetch": FETCH_CONFIG,
    "scan_summary_fields": SCAN_SUMMARY_FIELDS,
    "severities": list(SEVERITIES),
    "paths": {
        "project_root": str(PROJECT_ROOT),
        "data": str(LARGE_REPO_SOURCE),
        "output": str(OUTPUT_DIR),
        "scan_results": str(SCAN_OUTPUT_DIR),
        "scan_summary": str(SCAN_SUMMARY_CSV),
        "cache": str(CACHE_ROOT),
        "sandbox_work": str(SANDBOX_WORK_DIR),
        "targets": str(TARGETS_FILE),
        "gen_docs": str(GEN_DOCS_DIR),
        "report_html": str(REPORT_HTML),
    },
}


if __name__ == "__main__":
    import json
    import sys

    if "--example" in sys.argv:
        p = write_example()
        print(f"已生成: {p}")
        sys.exit(0)

    print(f"[config] config.yaml = {CONFIG_FILE} (exists={CONFIG_FILE.exists()})")
    print(json.dumps(CONFIG, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# 启动时路径存在性检查（WARNING，不中断；新机器 clone 后跑一下即可知道哪条没配）
# ---------------------------------------------------------------------------
def _check_paths() -> None:
    """关键路径不存在时打印 WARNING；模型/数据集/清单可能本就按需准备，不视为错误。"""
    checks = [
        ("被检代码根", LARGE_REPO_SOURCE, False),
        ("插件元数据", MEDIUM_REPO_META, True),   # 可选目录
        ("基座模型权重", MODEL_BASE_DIR, True),
        ("LoRA adapter (v2)", MODEL_ADAPTER_DIR, True),
        ("LoRA adapter (smoke)", MODEL_ADAPTER_SMOKE_DIR, True),
        ("训练数据集 real", DATASET_REAL, True),
        ("训练数据集 real_v2", DATASET_REAL_V2, True),
        ("训练数据集 smoke", DATASET_SMOKE, True),
        ("扫描清单 scan", MANIFEST_SCAN, True),
        ("分片清单 shard1", MANIFEST_SHARD1, True),
    ]
    for label, path, optional in checks:
        if not path.exists():
            tag = "可选" if optional else "必需"
            print(f"[config][warn] {label} 不存在 ({tag}): {path}", file=sys.stderr)


_check_paths()
