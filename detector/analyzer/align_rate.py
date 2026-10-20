#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 语义对齐率检测模块
================================
把"声明的功能"（README/description）与"代码的实际行为"（AST 硬事实 + LLM 生成文档）
做逐声明比对，输出对齐率与矛盾率。矛盾率是投毒的核心信号之一。

设计原则:
  1. 以硬事实为主（确定性，绝不幻觉），LLM 文档为辅（可选增强）
     - Python: ast.NodeVisitor 真 AST 解析
     - JS/TS/Go/Rust: 正则硬事实（本机无 Go/Rust 工具链，故与 JS 同走正则）
  2. 对齐判定分三档: support / conflict / unknown
  3. 安全相关声明的矛盾率优先: 文件访问/网络/子进程/凭据/混淆
  4. 输出可直接送沙箱规则生成器（声明的允许行为清单）

用法:
  python align_rate.py --repo-dir mcp插件\\某仓库
  python align_rate.py --repo-dir mcp插件\\某仓库 --doc path\\to\\generated_doc.md
  python align_rate.py --repo-dir mcp插件\\某仓库 --readme path\\to\\README.md
"""

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 1. AST 硬事实收集（Python）
# ---------------------------------------------------------------------------

# 敏感行为关键词库（英文/中文混合，用于声明和代码双侧匹配）
SECURITY_KEYWORDS = {
    "file_access": [
        r"(?i)(文件|读取|写入|目录|read.*file|write.*file|access.*file|filesystem)",
    ],
    "network": [
        r"(?i)(网络|外传|上传|下载|发送|同步|上报|telemetry|upload|download|sync|report|http|fetch)",
    ],
    "subprocess": [
        r"(?i)(命令|执行|shell|运行|execute|command|run.*cmd|powershell|bash|sh)",
    ],
    "credential": [
        r"(?i)(凭据|密钥|token|password|key|secret|credential|api[_-]?key)",
    ],
    "obfuscation": [
        r"(?i)(混淆|解码|解密|base64|decode|eval|exec|marshal|pickle)",
    ],
}


class AstFactCollector(ast.NodeVisitor):
    """遍历 Python 代码，收集安全相关硬事实（确定性，不执行代码）。"""

    NETWORK_CALLS = {
        "requests.get", "requests.post", "requests.put", "requests.patch",
        "requests.delete", "requests.request",
        "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
        "httpx.AsyncClient.get", "httpx.AsyncClient.post",
        "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
        "urllib.request.urlopen", "socket.connect", "socket.create_connection",
    }
    SUBPROC_CALLS = {
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "os.system", "os.popen", "commands.getoutput",
    }
    ENV_CALLS = {"os.getenv", "os.environ.get", "os.environ"}
    FILE_CALLS = {"open", "read", "read_text", "read_bytes", "Path.read_text",
                  "Path.read_bytes", "Path.exists", "Path.is_file"}
    EVAL_CALLS = {"eval", "exec", "execfile", "compile", "importlib.import_module"}
    OBFUSCATE_CALLS = {
        "base64.b64decode", "base64.b64encode", "marshal.loads",
        "pickle.loads", "binascii.unhexlify",
    }

    def __init__(self):
        self.facts = {k: [] for k in SECURITY_KEYWORDS}
        self._seen = set()

    def _call_name(self, node) -> str:
        func = node.func
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        return ".".join(reversed(parts))

    def _add(self, category: str, value: str):
        value = value.strip()
        if not value or value in self._seen:
            return
        self._seen.add(value)
        if len(self.facts[category]) < 100:
            self.facts[category].append(value)

    def visit_Call(self, node: ast.Call):
        name = self._call_name(node)
        str_args = [a.value for a in node.args
                    if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        str_repr = str(str_args)[:200]

        if name in self.NETWORK_CALLS:
            self._add("network", f"{name}{str_repr}")
        if name in self.SUBPROC_CALLS:
            self._add("subprocess", f"{name}{str_repr}")
        if name in self.ENV_CALLS:
            self._add("credential", f"{name}{str_repr}")
        if name in self.EVAL_CALLS:
            self._add("obfuscation", f"{name}{str_repr}")
        if name in self.OBFUSCATE_CALLS:
            self._add("obfuscation", f"{name}{str_repr}")

        # 通用文件读取调用
        if name in self.FILE_CALLS or name.endswith(".read") or name.endswith(".open"):
            sensitive = any(re.search(r"(?i)(\.ssh|\.aws|\.env|id_rsa|credential)", a)
                            for a in str_args)
            if sensitive or name in self.FILE_CALLS:
                self._add("file_access", f"{name}{str_repr}")

        self.generic_visit(node)


def extract_python_facts(repo_dir: Path) -> Dict[str, List[str]]:
    """扫描仓库所有 .py 文件，收集 AST 硬事实。"""
    collector = AstFactCollector()
    for root, dirs, files in os.walk(str(repo_dir)):
        dirs[:] = [d for d in dirs if d not in
                   {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build"}]
        for f in files:
            if f.endswith(".py"):
                try:
                    tree = ast.parse((Path(root) / f).read_text(
                        encoding="utf-8-sig", errors="replace"))
                    collector.visit(tree)
                except (SyntaxError, OSError):
                    continue
    return collector.facts


# ---------------------------------------------------------------------------
# 2. 多语言正则硬事实收集（Python AST 覆盖不到时的补充）
# ---------------------------------------------------------------------------
# 说明: 本机未安装 Go/Rust 工具链，无法用编译器 AST 解析，因此 Go/Rust 与
# JS/TS 一样走"正则硬事实"通道。所有语言共用同一套五类事实口径，
# 由 _extract_regex_facts() 统一遍历，保证与 compute_alignment 的合并逻辑一致。

JS_FACT_PATTERNS = {
    "network": [
        r"\b(?:fetch|axios\.|https?\.request|https?\.get|https?\.post|undici)\b",
        # 带 URL 字面量: 便于 allowlist 提取真实域名
        r"(?:fetch|axios\.\w+|https?\.(?:get|post|request))\s*\(\s*[\"'`](https?://[^\"'`\s]+)",
    ],
    "subprocess": [
        r"\bchild_process\b|\bexecSync\b|\bspawn\b|\bexec\s*\(",
        r"(?:execSync|exec|spawn)(?:Sync)?\s*\(\s*[\"'][^\"']+",   # 带参: 便于提取命令
    ],
    "credential": [
        r"process\.env\s*\.\s*[A-Za-z0-9_]*(?:key|secret|token|password|credential)",
        r"process\.env\s*\[\s*[\"'](\w+)",
    ],
    "obfuscation": [
        r"\b(?:eval|new\s+Function|atob)\b|\bBuffer\.from\s*\([^)]*base64",
    ],
    "file_access": [
        r"\bfs\.read(File|FileSync|dir|dirSync)\b",
        r"fs\.read(?:File|FileSync|dir|dirSync)\s*\(\s*[\"'][^\"']+",  # 带参
    ],
}

# Go 硬事实（正则；本机无 Go 工具链）
GO_FACT_PATTERNS = {
    "network": [
        r"\bhttp\.(?:Get|Post|NewRequest|Client|DefaultClient)\b",
        r"\bnet\.Dial\b|\bnet/http\b",
        # 带 URL 字面量: 便于 allowlist 提取真实域名
        r"http\.(?:Get|Post|NewRequest)\s*\(\s*\"(https?://[^\"]+)",
    ],
    "subprocess": [
        r"\bexec\.Command(?:Context)?\b|\bos/exec\b",
        r"exec\.Command(?:Context)?\s*\(\s*(?:[A-Za-z_][\w.]*\s*,\s*)?[\"`][^\"`]+",  # 带参
    ],
    "credential": [
        r"\bos\.(?:Getenv|LookupEnv)\b",
        r"os\.(?:Getenv|LookupEnv)\s*\(\s*[\"`][^\"`]+",   # 带参: 便于提取 env 名
    ],
    "obfuscation": [
        r"\bbase64\.(?:StdEncoding|URLEncoding)\b|\bencoding/base64\b",
        r"\bgob\.NewDecoder\b",
    ],
    "file_access": [
        r"\bos\.(?:ReadFile|Open|WriteFile|Write|Remove)\b",
        r"\bioutil\.(?:ReadFile|WriteFile)\b",
        r"os\.(?:ReadFile|Open|WriteFile|Write)\s*\(\s*[\"`][^\"`]+",  # 带参: 便于提取路径
    ],
}

# Rust 硬事实（正则；本机无 Rust 工具链）
RUST_FACT_PATTERNS = {
    "network": [
        r"\breqwest::\w+|\bhyper::\w+|\bureq::\w+",
        r"\bTcpStream::connect\b|\bstd::net::TcpStream\b",
        # 带 URL 字面量: 便于 allowlist 提取真实域名
        r"(?:reqwest|ureq)::(?:get|post)\s*\(\s*\"(https?://[^\"]+)",
    ],
    "subprocess": [
        r"\bstd::process::Command\b|\bprocess::Command\b|\bCommand::new\b",
        r"Command::new\s*\(\s*[\"'][^\"']+",   # 带参: 便于提取命令
    ],
    "credential": [
        r"\bstd::env::var\w*|\benv::var\w*",
        r"(?:std::)?env::var(?:_os)?\s*\(\s*[\"'][^\"']+",  # 带参
    ],
    "obfuscation": [
        r"\bbase64::(?:decode|Engine|engine)\b",
    ],
    "file_access": [
        r"\bstd::fs::(?:read|read_to_string|read_dir|File)\b",
        r"\bfs::(?:read|read_to_string|read_dir)\b|\bFile::open\b",
        r"(?:std::)?fs::(?:read|read_to_string|read_dir|File)\s*\(\s*[\"'][^\"']+",  # 带参
        r"File::open\s*\(\s*[\"'][^\"']+",     # 带参
    ],
}

# 语言 -> (模式表, 扩展名, 额外跳过目录)
REGEX_LANGUAGES = {
    "js": (JS_FACT_PATTERNS,
           (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"),
           {".git", "node_modules", "dist", "build", ".next", ".nuxt", "coverage"}),
    "go": (GO_FACT_PATTERNS,
           (".go",),
           {".git", "vendor", "bin", "testdata"}),
    "rust": (RUST_FACT_PATTERNS,
             (".rs",),
             {".git", "target", "vendor"}),
}

# 语言 -> 源文件扩展名（用于语言探测）
LANG_EXT_MAP = {
    "python": (".py",),
    "js": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"),
    "go": (".go",),
    "rust": (".rs",),
}


def _extract_regex_facts(repo_dir: Path, patterns: Dict[str, List[str]],
                         extensions: Tuple[str, ...],
                         skip_dirs: set) -> Dict[str, List[str]]:
    """通用正则硬事实收集器: 遍历指定扩展名的文件, 按 category 累积后统一去重。"""
    facts = {k: [] for k in patterns}
    for root, dirs, files in os.walk(str(repo_dir)):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if not f.endswith(extensions):
                continue
            p = Path(root) / f
            try:
                text = p.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue
            for category, pats in patterns.items():
                for pat in pats:
                    for m in re.finditer(pat, text, re.I):
                        facts[category].append(f"{p.name}: {m.group(0)[:120]}")
    # 全局去重 + 上限
    for category in facts:
        facts[category] = sorted(set(facts[category]))[:100]
    return facts


def extract_js_facts(repo_dir: Path) -> Dict[str, List[str]]:
    """扫描 .js/.ts/.mjs/.cjs/.jsx/.tsx 文件，用正则收集安全事实。"""
    pats, exts, skip = REGEX_LANGUAGES["js"]
    return _extract_regex_facts(repo_dir, pats, exts, skip)


def extract_go_facts(repo_dir: Path) -> Dict[str, List[str]]:
    """扫描 .go 文件，用正则收集安全事实（本机无 Go 工具链，故走正则）。"""
    pats, exts, skip = REGEX_LANGUAGES["go"]
    return _extract_regex_facts(repo_dir, pats, exts, skip)


def extract_rust_facts(repo_dir: Path) -> Dict[str, List[str]]:
    """扫描 .rs 文件，用正则收集安全事实（本机无 Rust 工具链，故走正则）。"""
    pats, exts, skip = REGEX_LANGUAGES["rust"]
    return _extract_regex_facts(repo_dir, pats, exts, skip)


def detect_languages(repo_dir: Path) -> List[str]:
    """探测仓库包含哪些语言的源文件（用于报告与覆盖率统计）。"""
    found = set()
    ignore = {".git", "node_modules", "venv", ".venv", "dist", "build",
              "target", "vendor", ".next", "__pycache__", "bin", "obj"}
    for root, dirs, files in os.walk(str(repo_dir)):
        dirs[:] = [d for d in dirs if d not in ignore]
        for f in files:
            for lang, exts in LANG_EXT_MAP.items():
                if f.endswith(exts):
                    found.add(lang)
                    break
    return sorted(found)


# ---------------------------------------------------------------------------
# 3. 原子声明提取（从 README/description）
# ---------------------------------------------------------------------------

def extract_claims(text: str) -> List[Dict]:
    """把声明文档拆成原子声明，每条标注类别和原文片段。

    返回: [{"category": str, "claim": str, "evidence": str}]
    """
    if not text:
        return []
    claims = []

    lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if len(line) < 6 or len(line) > 500:
            continue
        # 跳过纯标点/链接/代码块标记
        if re.match(r"^[\s\-*#>!\]\[|]+$", line):
            continue

        for category, patterns in SECURITY_KEYWORDS.items():
            for pat in patterns:
                if re.search(pat, line):
                    claims.append({
                        "category": category,
                        "claim": line[:300],
                        "evidence": line[:300],
                    })
                    break  # 一行只归为一个类别
    return claims


def extract_readme(repo_dir: Path) -> Optional[str]:
    """尝试从仓库提取 README 内容。"""
    candidates = list(repo_dir.glob("README*")) + list(repo_dir.glob("readme*"))
    for c in candidates:
        if c.is_file():
            try:
                return c.read_text(encoding="utf-8-sig", errors="replace")[:10000]
            except OSError:
                continue
    return None


# ---------------------------------------------------------------------------
# 4. 对齐判定引擎
# ---------------------------------------------------------------------------

def compute_alignment(repo_dir: Path,
                      readme_text: Optional[str] = None) -> Dict[str, Any]:
    """核心函数: 计算声明 vs 实际行为的对齐率。

    返回:
    {
        "repo": str,
        "facts": {category: [fact_str, ...]},  # 合并的 AST+正则硬事实
        "claims": [{"category","claim","evidence"}],
        "claim_judgments": [{"category","claim","judgment","reason"}],  # judgment=support/conflict/unknown
        "alignment_rate": float,     # 支持 / (支持+冲突)，无判定时=1.0
        "conflict_rate": float,      # 冲突 / (支持+冲突)
        "security_conflict_rate": float,  # 仅安全相关声明的矛盾率
        "has_hard_facts": bool,      # 是否有硬事实（网络/子进程/凭据/混淆）
        "verdict_signal": str,       # 投毒信号: CLEAN/WARN/DANGER
    }
    """
    repo_name = repo_dir.name

    # ---- Step 0: 探测语言构成（便于报告与后续覆盖率统计） ----
    languages = detect_languages(repo_dir)

    # ---- Step 1: 收集实际行为硬事实（Python AST + JS/Go/Rust 正则） ----
    py_facts = extract_python_facts(repo_dir)
    js_facts = extract_js_facts(repo_dir)
    go_facts = extract_go_facts(repo_dir)
    rust_facts = extract_rust_facts(repo_dir)
    regex_facts = {k: [] for k in SECURITY_KEYWORDS}
    for lang_facts in (js_facts, go_facts, rust_facts):
        for cat, vals in lang_facts.items():
            regex_facts[cat].extend(vals)
    # 合并（去重 + 上限），保持与五类事实口径一致
    facts = {}
    for cat in SECURITY_KEYWORDS:
        facts[cat] = sorted(set(py_facts.get(cat, []) + regex_facts.get(cat, [])))[:200]

    has_hard_facts = any(facts.values())

    # ---- Step 2: 提取声明 ----
    if readme_text is None:
        readme_text = extract_readme(repo_dir) or ""
    claims = extract_claims(readme_text)

    # ---- Step 3: 对齐判定 ----
    judgments = []
    support_count = 0
    conflict_count = 0
    security_support = 0
    security_conflict = 0
    security_categories = {"file_access", "network", "subprocess", "credential", "obfuscation"}

    # 收集声明中提到但代码里完全没有硬事实的类别
    claimed_categories = set(c["category"] for c in claims)

    for cat in SECURITY_KEYWORDS:
        claim_count = sum(1 for c in claims if c["category"] == cat)
        fact_count = len(facts.get(cat, []))

        if claim_count == 0 and fact_count == 0:
            continue  # 双方都没提，不算

        if fact_count > 0 and claim_count == 0:
            # === 关键投毒信号: 代码里有安全敏感行为，但声明里完全没提 ===
            # 对每个硬事实都产出 conflict judgment
            for fact in facts[cat][:5]:  # 取前5条，避免爆炸
                judgments.append({
                    "category": cat,
                    "claim": f"[shadow] 代码未声明但存在: {fact[:100]}",
                    "judgment": "conflict",
                    "reason": f"代码存在 {cat} 类行为 ({fact_count}处) 但 README 未声明",
                })
                conflict_count += 1
                if cat in security_categories:
                    security_conflict += 1
            continue

        if claim_count > 0 and fact_count == 0:
            # 声明有提到但代码找不到对应硬事实 —— 可能是良性（功能未用敏感API）也可能是文档夸大
            # 标记为 unknown，不直接算 conflict
            for c in claims:
                if c["category"] == cat:
                    judgments.append({
                        "category": cat,
                        "claim": c["claim"],
                        "judgment": "unknown",
                        "reason": f"声明 {cat} 行为，代码中未找到对应硬事实",
                    })
            continue

        # 双方都有 —— 互相印证，判 support
        for c in claims:
            if c["category"] == cat:
                judgments.append({
                    "category": cat,
                    "claim": c["claim"],
                    "judgment": "support",
                    "reason": f"声明 {cat}，代码中有 {fact_count} 处硬事实支撑",
                })
                support_count += 1
                if cat in security_categories:
                    security_support += 1

    # ---- Step 4: 计算比率 ----
    total_judged = support_count + conflict_count
    alignment_rate = support_count / total_judged if total_judged > 0 else 1.0
    conflict_rate = conflict_count / total_judged if total_judged > 0 else 0.0

    sec_total = security_support + security_conflict
    security_conflict_rate = (security_conflict / sec_total
                              if sec_total > 0 else 0.0)

    # ---- Step 5: 投毒信号判定 ----
    verdict_signal = "CLEAN"
    if conflict_count > 0:
        verdict_signal = "WARN"
    if security_conflict_rate >= 0.3 or conflict_count >= 3:
        verdict_signal = "DANGER"

    return {
        "repo": repo_name,
        "facts": facts,
        "claims": claims,
        "claim_judgments": judgments,
        "alignment_rate": round(alignment_rate, 3),
        "conflict_rate": round(conflict_rate, 3),
        "security_conflict_rate": round(security_conflict_rate, 3),
        "has_hard_facts": has_hard_facts,
        "verdict_signal": verdict_signal,
        "_languages": languages,
        "_claim_count": len(claims),
        "_judgment_counts": {
            "support": support_count, "conflict": conflict_count,
        },
    }


# ---------------------------------------------------------------------------
# 5. CLI 入口
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="MPV-Detector 语义对齐率检测")
    ap.add_argument("--repo-dir", required=True, help="仓库目录")
    ap.add_argument("--readme", default="", help="声明文档路径 (可选)")
    ap.add_argument("--output", default="", help="输出 JSON 路径 (可选)")
    ap.add_argument("--brief", action="store_true", help="只输出摘要")
    args = ap.parse_args()

    repo_dir = Path(args.repo_dir)
    if not repo_dir.exists():
        print(f"[错误] 仓库目录不存在: {repo_dir}")
        sys.exit(1)

    readme_text = None
    if args.readme:
        rp = Path(args.readme)
        if rp.exists():
            readme_text = rp.read_text(encoding="utf-8-sig", errors="replace")

    result = compute_alignment(repo_dir, readme_text)

    if args.brief:
        print(f"repo           = {result['repo']}")
        print(f"signal         = {result['verdict_signal']}")
        print(f"alignment_rate = {result['alignment_rate']}")
        print(f"conflict_rate  = {result['conflict_rate']}")
        print(f"sec_conflict   = {result['security_conflict_rate']}")
        print(f"hard_facts     = {result['has_hard_facts']}")
        print(f"languages      = {result.get('_languages', [])}")
        for cat, facts in result["facts"].items():
            if facts:
                print(f"  {cat}: {len(facts)} facts")
        print(f"judgments      = support:{result['_judgment_counts']['support']} "
              f"conflict:{result['_judgment_counts']['conflict']} "
              f"unknown:{len(result['claim_judgments']) - result['_judgment_counts']['support'] - result['_judgment_counts']['conflict']}")
        # 列出所有 conflict
        conflicts = [j for j in result["claim_judgments"] if j["judgment"] == "conflict"]
        for c in conflicts[:10]:
            print(f"  ⚠ conflict[{c['category']}]: {c['claim'][:120]}")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))

    if args.output:
        Path(args.output).write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n已写入: {args.output}")


if __name__ == "__main__":
    main()
