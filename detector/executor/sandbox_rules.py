#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 沙箱拦截规则生成器
================================
从静态检测结果（对齐率模块的 facts/claims/judgments）和 LLM 生成的说明文档中，
提取"插件声明允许的行为边界"，转化为沙箱可执行的拦截规则。

核心思路:
  静态阶段(align_rate.py)产出的 facts 是硬事实、claims 是声明。本模块把两者合并成:
    - allowlist: 明确声明允许的行为（网络域名白名单、文件路径白名单、命令白名单）
    - blocklist: 一律拦截的恶意模式（蜜罐外传、curl|sh、base64+exec 等）
    - violation_actions: 触发拦截/送审的阈值与条件
  
  这些规则直接喂给 behavior_monitor.py 做运行时拦截。

用法:
  python sandbox_rules.py --repo-dir mcp插件\\某仓库
  python sandbox_rules.py --repo-dir mcp插件\\某仓库 --align-json align_result.json
  python sandbox_rules.py --repo-dir mcp插件\\某仓库 --output rules.json
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# 确保能 import config 与 align_rate（config 在 detector/，align_rate 在 analyzer/）
_HERE = Path(__file__).resolve().parent                       # detector/executor
sys.path.insert(0, str(_HERE.parent))                         # detector/ → import config
sys.path.insert(0, str(_HERE.parent / "analyzer"))            # analyzer/ → import align_rate

# ---------------------------------------------------------------------------
# 1. 默认恶意模式黑名单（universal blocklist，所有插件通吃）
# ---------------------------------------------------------------------------
UNIVERSAL_BLOCK_PATTERNS = [
    # 反向 shell
    r"nc\s+-[a-z]*e\b", r"netcat\s+-[a-z]*e\b", r"/dev/tcp/", r"bash\s+-i\s+>&",
    r"Invoke-PowerShellTcp", r"PowerCat",
    # 远程脚本执行
    r"curl\s+[^\s]+\s*\|\s*(?:ba)?sh", r"wget\s+[^\s]+\s*\|\s*(?:ba)?sh",
    r"Invoke-WebRequest\s+[^\s]+\|\s*iex", r"\|\s*powershell",
    # 混淆执行
    r"base64\s*\(\s*--decode", r"b64decode\s*\(.*\)\s*\n?\s*(?:exec|eval)",
    r"marshal\.loads\s*\(.*\).*(?:exec|eval)",
    # 提权/擦除
    r"chmod\s+777", r"rm\s+-rf\s+/", r"sudo\s+.*(?:cat|chmod|chown)",
]

# 蜜罐凭据指纹（与 config.SANDBOX_CONFIG['honeypot'] 单一来源，避免注入与检测漂移）
def _load_honeypot_indicators() -> List[str]:
    """从 config 的 honeypot 配置派生检测指纹; 导入失败则回退内置默认值。"""
    fallback = [
        "honeypot_fake_key_do_not_use",
        "/tmp/honeypot_ssh_key_never_exist",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ]
    try:
        from config import CONFIG
        vals = [str(v) for v in CONFIG["sandbox"]["honeypot"].values()
                if str(v).strip()]
        return vals or fallback
    except Exception:
        return fallback


HONEYPOT_INDICATORS = _load_honeypot_indicators()

# ---------------------------------------------------------------------------
# 2. 规则生成核心
# ---------------------------------------------------------------------------

def generate_rules(repo_dir: Path,
                   align_result: Optional[Dict] = None,
                   llm_doc: Optional[str] = None) -> Dict[str, Any]:
    """从仓库 + 对齐率结果 + 可选 LLM 文档生成完整拦截规则。"""

    repo_name = repo_dir.name

    # ---- 2a. 先跑对齐率（如果没传入） ----
    if align_result is None:
        try:
            from align_rate import compute_alignment
            align_result = compute_alignment(repo_dir)
        except Exception as e:
            print(f"[警告] 无法运行 align_rate: {e}", file=sys.stderr)
            align_result = {
                "repo": repo_name,
                "facts": {k: [] for k in ["file_access", "network", "subprocess",
                                           "credential", "obfuscation"]},
                "claims": [],
                "claim_judgments": [],
                "alignment_rate": 1.0,
                "conflict_rate": 0.0,
                "security_conflict_rate": 0.0,
                "verdict_signal": "UNKNOWN",
                "_judgment_counts": {"support": 0, "conflict": 0},
            }

    facts = align_result.get("facts", {})

    # ---- 2b. 从 facts 提取 allowlist ----
    allowlist = extract_allowlist(facts, repo_dir)

    # ---- 2c. 通用 blocklist ----
    blocklist = {
        "dangerous_patterns": UNIVERSAL_BLOCK_PATTERNS[:],
        "honeypot_indicators": HONEYPOT_INDICATORS[:],
    }

    # ---- 2d. violation_actions ----
    security_conflict_rate = align_result.get("security_conflict_rate", 0.0)
    verdict_signal = align_result.get("verdict_signal", "UNKNOWN")

    violation_actions = {
        # 矛盾率阈值
        "conflict_rate_threshold": 0.3,
        "conflict_rate_high": 0.6,
        # 直接 block 的行为类别
        "auto_block_categories": ["credential", "obfuscation"],
        # 送人工审核但不 block
        "review_categories": ["subprocess", "file_access"],
        # 蜜罐保护（一旦外传立即判定 malicious 并终止运行）
        "honeypot_protected": True,
    }

    # 如果对齐率模块已经判了 DANGER，规则直接进入"严格模式"
    if verdict_signal == "DANGER" or security_conflict_rate >= 0.3:
        violation_actions["conflict_rate_threshold"] = 0.1  # 收紧阈值
        violation_actions["auto_block_categories"].append("network")  # 网络也 block
        allowlist["network_endpoints"] = []  # 清空 allowlist，全部拦截

    # ---- 2e. 规则元数据 ----
    rules = {
        "repo": repo_name,
        "version": "2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "facts_count": sum(len(v) for v in facts.values()),
            "claim_count": align_result.get("_claim_count", 0),
            "alignment_rate": align_result.get("alignment_rate", 1.0),
            "security_conflict_rate": security_conflict_rate,
            "verdict_signal": verdict_signal,
        },
        "allowlist": allowlist,
        "blocklist": blocklist,
        "violation_actions": violation_actions,
    }

    return rules


def extract_allowlist(facts: Dict[str, List[str]], repo_dir: Path) -> Dict[str, List[str]]:
    """从硬事实中提取"允许行为白名单"。

    覆盖 Python / JS / Go / Rust 四类事实字符串格式（align_rate.py 产出）。
    """

    network_endpoints = set()
    file_paths = set()
    commands = set()
    env_vars = set()

    # ---- 网络端点（各语言事实串里的 URL 字面量） ----
    for fact in facts.get("network", []):
        urls = re.findall(r"https?://([a-zA-Z0-9\-._]+)", fact)
        for domain in urls:
            if domain not in ("localhost", "127.0.0.1", "0.0.0.0"):
                network_endpoints.add(domain)
    # 若存在网络硬事实但未能提取出具体域名，保守放行 "*" 并交人工审核
    if facts.get("network") and not network_endpoints:
        network_endpoints.add("*")

    # ---- 文件路径 ----
    FILE_PATH_PATTERNS = [
        # Python (AST 事实串为 repr 形式: open['/x', 'r'])
        r"\bopen\s*[\(\[]\s*[\"']([^\"']+)",
        r"read_(?:text|bytes)\s*[\(\[]\s*[\"']([^\"']+)",
        r"os\.(?:ReadFile|Open|WriteFile|Write)\s*\(\s*[\"`]([^\"`]+)",          # Go
        r"ioutil\.(?:ReadFile|WriteFile)\s*\(\s*[\"`]([^\"`]+)",                 # Go (旧)
        r"(?:std::)?fs::(?:read|read_to_string|read_dir|File)\s*\(\s*[\"']([^\"']+)",  # Rust
        r"File::open\s*\(\s*[\"']([^\"']+)",                                     # Rust
        r"fs\.read(?:File|FileSync|dir|dirSync)\s*\(\s*[\"']([^\"']+)",           # JS
    ]
    for fact in facts.get("file_access", []):
        for pat in FILE_PATH_PATTERNS:
            for hit in re.findall(pat, fact):
                val = hit if isinstance(hit, str) else next((x for x in hit if x), "")
                if val:
                    file_paths.add(val)
    if not file_paths and facts.get("file_access"):
        file_paths.add("*")

    # ---- 命令 ----
    CMD_PATTERNS = [
        r"subprocess\.\w+\s*[\(\[]\s*[\"']([^\"',]+)",           # Python (repr: ['ls', ...])
        r"os\.system\s*[\(\[]\s*[\"']([^\"']+)",                  # Python
        r"os\.popen\s*[\(\[]\s*[\"']([^\"']+)",                   # Python
        r"exec\.Command(?:Context)?\s*\(\s*(?:[A-Za-z_][\w.]*\s*,\s*)?[\"`]([^\"`]+)",  # Go
        r"Command::new\s*\(\s*[\"']([^\"']+)",                    # Rust
        r"(?:execSync|exec|spawn)(?:Sync)?\s*\(\s*[\"']([^\"']+)", # JS
    ]
    for fact in facts.get("subprocess", []):
        for pat in CMD_PATTERNS:
            for hit in re.findall(pat, fact):
                val = hit if isinstance(hit, str) else next((x for x in hit if x), "")
                token = val.split()[0] if val.strip() else ""
                if token:
                    commands.add(token)

    # ---- env 变量 ----
    ENV_PATTERNS = [
        r"os\.(?:getenv|environ\.get)\s*[\(\[]\s*[\"'](\w+)",     # Python
        r"os\.environ\s*\[\s*[\"'](\w+)",                         # Python
        r"process\.env\s*\.\s*(\w+)",                             # JS
        r"process\.env\s*\[\s*[\"'](\w+)",                        # JS
        r"os\.(?:Getenv|LookupEnv)\s*\(\s*[\"`](\w+)",            # Go
        r"(?:std::)?env::var(?:_os)?\s*\(\s*[\"'](\w+)",          # Rust
    ]
    for fact in facts.get("credential", []):
        for pat in ENV_PATTERNS:
            for hit in re.findall(pat, fact, re.I):
                val = hit if isinstance(hit, str) else next((x for x in hit if x), "")
                if val:
                    env_vars.add(val)

    return {
        "network_endpoints": sorted(network_endpoints),
        "file_paths": sorted(file_paths),
        "commands": sorted(commands),
        "env_vars": sorted(env_vars),
    }


# ---------------------------------------------------------------------------
# 3. CLI 入口
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="MPV-Detector 沙箱规则生成器")
    ap.add_argument("--repo-dir", required=True, help="仓库目录")
    ap.add_argument("--align-json", default="", help="已有的对齐率结果 JSON (可选，不传则自动计算)")
    ap.add_argument("--output", default="", help="规则输出 JSON 路径 (可选)")
    ap.add_argument("--brief", action="store_true", help="只输出摘要")
    args = ap.parse_args()

    repo_dir = Path(args.repo_dir)
    if not repo_dir.exists():
        print(f"[错误] 仓库目录不存在: {repo_dir}")
        sys.exit(1)

    align_result = None
    if args.align_json:
        rp = Path(args.align_json)
        if rp.exists():
            align_result = json.loads(rp.read_text(encoding="utf-8"))

    rules = generate_rules(repo_dir, align_result)

    if args.brief:
        src = rules["source"]
        al = rules["allowlist"]
        va = rules["violation_actions"]
        print(f"repo              = {rules['repo']}")
        print(f"verdict_signal    = {src['verdict_signal']}")
        print(f"alignment_rate    = {src['alignment_rate']}")
        print(f"sec_conflict_rate = {src['security_conflict_rate']}")
        print(f"facts             = {src['facts_count']}")
        print(f"allowlist:")
        print(f"  network_endpoints = {al['network_endpoints'][:8]}")
        print(f"  file_paths         = {al['file_paths'][:8]}")
        print(f"  commands           = {al['commands'][:8]}")
        print(f"  env_vars           = {al['env_vars'][:8]}")
        print(f"violation_actions:")
        print(f"  auto_block_categories = {va['auto_block_categories']}")
        print(f"  review_categories     = {va['review_categories']}")
        print(f"  honeypot_protected    = {va['honeypot_protected']}")
    else:
        print(json.dumps(rules, ensure_ascii=False, indent=2))

    if args.output:
        Path(args.output).write_text(
            json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n已写入: {args.output}")


if __name__ == "__main__":
    main()
