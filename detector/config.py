#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 统一配置中心
========================
集中管理数据源路径、检测阈值、LLM 配置、沙箱参数等。
所有模块通过 from config import CONFIG 访问，避免硬编码。
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径配置（相对本项目根目录解析）
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent  # 项目根（detector/ 的上级，数据目录所在）


def _resolve_dir(env_var: str, default_rel: str, legacy: str = "") -> Path:
    """解析数据目录，优先级：环境变量 > 项目内默认 > 历史遗留绝对路径。

    这样换机器/换盘后无需改代码：设置环境变量即可，默认落在项目内。
    """
    env_val = os.environ.get(env_var, "").strip().strip('"')
    if env_val:
        return Path(env_val)
    candidate = PROJECT_ROOT / default_rel
    if candidate.is_dir():
        return candidate
    if legacy and Path(legacy).is_dir():
        return Path(legacy)
    return candidate


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


# 仓库数据源（其下为 <owner>_<repo> 文件夹）
#   大型仓库：完整仓库代码；中型仓库：info.json 元数据（+ 代码待补拉）
#   默认均取项目内 mcp插件/，可用环境变量覆盖：
#     MPV_LARGE_REPO_SOURCE / MPV_MEDIUM_REPO_META
LARGE_REPO_SOURCE = _resolve_dir("MPV_LARGE_REPO_SOURCE", "mcp插件", r"D:\mcp插件")
MEDIUM_REPO_META = _resolve_dir("MPV_MEDIUM_REPO_META", "mcp插件")

# 输出根目录（可用 MPV_OUTPUT_DIR 覆盖）
OUTPUT_DIR = _resolve_dir("MPV_OUTPUT_DIR", "output")

# 扫描结果输出目录
SCAN_OUTPUT_DIR = OUTPUT_DIR / "scan_results"

# 扫描汇总 CSV
SCAN_SUMMARY_CSV = OUTPUT_DIR / "scan_summary.csv"

# ---------------------------------------------------------------------------
# 静态检测配置
# ---------------------------------------------------------------------------
STATIC_CONFIG = {
    "SKIP_DIRS": {
        ".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist",
        "build", ".next", ".nuxt", ".cache", "vendor", "target", "bin", "obj",
        ".turbo", ".nx", "coverage", ".yarn", ".pnpm-store", "third_party",
        ".idea", ".vscode", ".github", ".circleci",
    },
    "SCAN_EXTS": {
        ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs",
        ".sh", ".bash", ".zsh", ".ps1", ".rb", ".java", ".cs", ".c", ".cpp",
        ".h", ".hpp", ".zig", ".md", ".markdown", ".json", ".yaml", ".yml",
        ".toml", ".ini", ".cfg", ".txt", ".html", ".htm", ".sql", ".lua",
        ".php", ".swift", ".kt", ".dockerfile", ".mcp", ".env",
    },
    "SPECIAL_FILES": {
        "dockerfile", "makefile", "requirements.txt", "setup.py",
        "pyproject.toml", "package.json", "package-lock.json",
        "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "readme", "readme.md",
        "skill.md", "agent.md",
    },
    # 单文件大小上限（超过则跳过，避免巨型 lockfile 爆炸）
    "MAX_FILE_SIZE_BYTES": 8 * 1024 * 1024,  # 8MB
    # 单文件最大行数（截断，避免正则回溯过慢）
    "MAX_LINE_LENGTH": 2000,
    # eval 高密度阈值（单文件 eval 次数）
    "EVAL_DENSITY_THRESHOLD": 5,
}

# ---------------------------------------------------------------------------
# 本地 LLM 服务（默认 Ollama）
# ---------------------------------------------------------------------------
OLLAMA_HOST = _env("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_API_BASE = f"{OLLAMA_HOST}/v1"
# 默认模型名（各模块可用各自环境变量覆盖）
DEFAULT_MODEL = _env("MPV_MODEL", "qwen3-coder:30b")

# ---------------------------------------------------------------------------
# 对齐率检测配置
# ---------------------------------------------------------------------------
ALIGN_CONFIG = {
    # LLM 后端
    "backend": os.environ.get("ALIGN_BACKEND", "openai"),
    "api_base": _env("ALIGN_API_BASE", OLLAMA_API_BASE),
    "api_key": os.environ.get("ALIGN_API_KEY", ""),
    "model": _env("ALIGN_MODEL", DEFAULT_MODEL),
    # LLM 生成的说明文档最大文件数/单文件字符数
    "MAX_FILES_PER_REPO": 8,
    "MAX_FILE_CHARS": 8000,
    # 对齐率判定阈值
    "CONFLICT_RATE_THRESHOLD_SUSPICIOUS": 0.3,  # 矛盾率 >= 30% → suspicious 候选
    "CONFLICT_RATE_THRESHOLD_HIGH": 0.6,       # 矛盾率 >= 60% → malicious 候选
}

# ---------------------------------------------------------------------------
# 沙箱配置
# ---------------------------------------------------------------------------
SANDBOX_CONFIG = {
    # ---- 镜像（由 sandbox/Dockerfile 构建） ----
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
    # -- openat 噪声前缀: 运行时/系统库加载不应算作"文件访问行为"
    "open_noise_prefixes": [
        "/usr/", "/lib/", "/lib64/", "/proc/", "/sys/", "/etc/ld.so",
        "/etc/nsswitch.conf", "/etc/localtime", "/etc/hosts",
        "/etc/resolv.conf", "/etc/gai.conf", "/etc/ssl/", "/etc/ca-certificates/",
        "/dev/null", "/dev/urandom", "/dev/random", "/dev/tty", "/dev/pts",
        "/app/node_modules/", "/app/venv/", "/app/.venv/", "/app/dist/",
    ],
    # -- 敏感路径模式: 命中即视为高危文件访问（含上报"试图读取"）
    "sensitive_path_patterns": [
        r"\.ssh/", r"\.aws/", r"\.env$", r"id_rsa", r"id_ed25519",
        r"credential", r"/etc/passwd", r"/etc/shadow", r"\.git-credentials",
        r"\.netrc", r"\.docker/config\.json", r"honeypot",
    ],
    # -- 蜜罐落地文件: 目标若读取即命中高危信号
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
    #      否则插件只启动不干活, 休眠触发型恶意行为无法被观测 ----
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
# LLM 说明文档生成配置（code_to_doc）
# ---------------------------------------------------------------------------
DOC_GEN_CONFIG = {
    "backend": _env("DOC_BACKEND", "openai"),
    "api_base": _env("DOC_API_BASE", OLLAMA_API_BASE),
    "api_key": _env("DOC_API_KEY", ""),
    "model": _env("DOC_MODEL", DEFAULT_MODEL),
    "temperature": 0.3,
    "max_tokens": 4096,
}

# ---------------------------------------------------------------------------
# GitHub API 配置
# ---------------------------------------------------------------------------
GITHUB_CONFIG = {
    "api_url": "https://api.github.com",
    "api_version": "2022-11-28",
    "user_agent": "MPV-Detector/2.0",
    "token": os.environ.get("GITHUB_TOKEN", ""),
    "timeout": 30,
    "max_retries": 3,
    "retry_delay": 5,
}

# ---------------------------------------------------------------------------
# 合并为全局 CONFIG
# ---------------------------------------------------------------------------
CONFIG = {
    "project_root": str(PROJECT_ROOT),
    "large_repo_source": str(LARGE_REPO_SOURCE),
    "medium_repo_meta": str(MEDIUM_REPO_META),
    "scan_output_dir": str(SCAN_OUTPUT_DIR),
    "scan_summary_csv": str(SCAN_SUMMARY_CSV),
    "static": STATIC_CONFIG,
    "align": ALIGN_CONFIG,
    "sandbox": SANDBOX_CONFIG,
    "doc_gen": DOC_GEN_CONFIG,
    "github": GITHUB_CONFIG,
}

if __name__ == "__main__":
    # 自检：打印所有配置
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
