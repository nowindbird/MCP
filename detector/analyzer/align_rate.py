#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 语义对齐率检测模块
================================
把"声明的功能"（README / description）与"代码的实际行为"（AST 硬事实 + LLM 生成文档）
做逐声明比对，输出对齐率与矛盾率。矛盾率是投毒的核心信号之一。

设计原则:
  1. 以硬事实为主（确定性，绝不幻觉），LLM 文档为辅（可选增强）
     - Python: ast.NodeVisitor 真 AST 解析
     - JS/TS/Go/Rust: 正则硬事实（本机无 Go/Rust 工具链，故与 JS 同走正则）
  2. 对齐判定分三档: support / conflict / unknown
  3. 安全相关声明的矛盾率优先: 文件访问/网络/子进程/凭据/混淆
  4. 输出可直接送沙箱规则生成器（声明的允许行为清单）

阈值统一来自 ``detector.config.ALIGN_CONFIG``，遍历口径来自 ``detector.deps``，
因此本模块与 sandbox_rules / scanner 对"什么算危险行为"始终一致。

用法::

    python -m detector.cli align --repo-dir dateset/<owner>_<repo>
    python -m detector.cli align --repo-dir <repo> --doc generated_doc.md --brief
"""

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from detector.deps import (
    ALIGN_CONFIG,
    SKIP_DIRS,
    detect_languages as _detect_languages,
    ensure_utf8_stdio,
    iter_repo_files,
    read_readme,
    read_text,
    write_json,
)

# ---------------------------------------------------------------------------
# 1. 事实/声明共用的类别与关键词库
# ---------------------------------------------------------------------------
FACT_CATEGORIES = ("file_access", "network", "subprocess", "credential", "obfuscation")
SECURITY_CATEGORIES = set(FACT_CATEGORIES)

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

# 预编译关键词正则（模块加载时一次，避免每条声明重复编译）
COMPILED_KEYWORDS = {
    cat: [re.compile(p) for p in pats]
    for cat, pats in SECURITY_KEYWORDS.items()
}


def _empty_facts() -> Dict[str, List[str]]:
    """空事实表（五类口径固定，避免各处 key 不一致）。"""
    return {k: [] for k in FACT_CATEGORIES}


# ---------------------------------------------------------------------------
# 2. AST 硬事实收集（Python）
# ---------------------------------------------------------------------------
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
    SENSITIVE_PATH_RE = re.compile(r"(?i)(\.ssh|\.aws|\.env|id_rsa|credential)")

    def __init__(self):
        self.facts = _empty_facts()
        self._seen: set = set()

    def _call_name(self, node) -> str:
        """把调用节点还原成 ``a.b.c`` 形式的点分名。"""
        func = node.func
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        return ".".join(reversed(parts))

    def _add(self, category: str, value: str) -> None:
        value = value.strip()
        if not value or value in self._seen or len(self.facts[category]) >= 100:
            return
        self._seen.add(value)
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
        if name in self.EVAL_CALLS or name in self.OBFUSCATE_CALLS:
            self._add("obfuscation", f"{name}{str_repr}")

        # 通用文件读取调用（命中敏感路径或本身就是文件 API 才记录）
        if name in self.FILE_CALLS or name.endswith((".read", ".open")):
            sensitive = any(self.SENSITIVE_PATH_RE.search(a) for a in str_args)
            if sensitive or name in self.FILE_CALLS:
                self._add("file_access", f"{name}{str_repr}")

        self.generic_visit(node)


# 各语言事实抽取时跳过的目录：从全局 SKIP_DIRS（config）派生的历史子集。
# 用「交集」保证口径永远与 config 一致，增删只需改 config 的 SKIP_DIRS。
PY_SKIP_DIRS = set(SKIP_DIRS) & {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build"}
JS_SKIP_DIRS = set(SKIP_DIRS) & {".git", "node_modules", "dist", "build", ".next", ".nuxt", "coverage"}
GO_SKIP_DIRS = set(SKIP_DIRS) & {".git", "vendor", "bin", "testdata"}
RUST_SKIP_DIRS = set(SKIP_DIRS) & {".git", "target", "vendor"}
LANG_SKIP_DIRS = set(SKIP_DIRS) & {".git", "node_modules", "venv", ".venv", "dist", "build",
                                    "target", "vendor", ".next", "__pycache__", "bin", "obj"}


def extract_python_facts(repo_dir: Path) -> Dict[str, List[str]]:
    """扫描仓库所有 .py 文件，收集 AST 硬事实。"""
    collector = AstFactCollector()
    for p in iter_repo_files(repo_dir, exts=(".py",), skip_dirs=PY_SKIP_DIRS):
        try:
            tree = ast.parse(read_text(p) or "")
        except (SyntaxError, ValueError, OSError):
            continue
        try:
            collector.visit(tree)
        except RecursionError:  # 极端嵌套文件不拖垮整仓分析
            continue
    return collector.facts


# ---------------------------------------------------------------------------
# 3. 多语言正则硬事实收集（Python AST 覆盖不到时的补充）
# ---------------------------------------------------------------------------
# 说明: 本机未安装 Go/Rust 工具链，无法用编译器 AST 解析，因此 Go/Rust 与
# JS/TS 一样走"正则硬事实"通道。所有语言共用同一套五类事实口径，
# 由 _extract_regex_facts() 统一遍历，保证与 compute_alignment 的合并逻辑一致。

JS_FACT_PATTERNS = {
    "network": [
        r"\b(?:fetch|axios\.|https?\.request|https?\.get|https?\.post|undici)\b",
        r"(?:fetch|axios\.\w+|https?\.(?:get|post|request))\s*\(\s*[\"'`](https?://[^\"'`\s]+)",
    ],
    "subprocess": [
        r"\bchild_process\b|\bexecSync\b|\bspawn\b|\bexec\s*\(",
        r"(?:execSync|exec|spawn)(?:Sync)?\s*\(\s*[\"'][^\"']+",
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
        r"fs\.read(?:File|FileSync|dir|dirSync)\s*\(\s*[\"'][^\"']+",
    ],
}

GO_FACT_PATTERNS = {
    "network": [
        r"\bhttp\.(?:Get|Post|NewRequest|Client|DefaultClient)\b",
        r"\bnet\.Dial\b|\bnet/http\b",
        r"http\.(?:Get|Post|NewRequest)\s*\(\s*\"(https?://[^\"]+)",
    ],
    "subprocess": [
        r"\bexec\.Command(?:Context)?\b|\bos/exec\b",
        r"exec\.Command(?:Context)?\s*\(\s*(?:[A-Za-z_][\w.]*\s*,\s*)?[\"`][^\"`]+",
    ],
    "credential": [
        r"\bos\.(?:Getenv|LookupEnv)\b",
        r"os\.(?:Getenv|LookupEnv)\s*\(\s*[\"`][^\"`]+",
    ],
    "obfuscation": [
        r"\bbase64\.(?:StdEncoding|URLEncoding)\b|\bencoding/base64\b",
        r"\bgob\.NewDecoder\b",
    ],
    "file_access": [
        r"\bos\.(?:ReadFile|Open|WriteFile|Write|Remove)\b",
        r"\bioutil\.(?:ReadFile|WriteFile)\b",
        r"os\.(?:ReadFile|Open|WriteFile|Write)\s*\(\s*[\"`][^\"`]+",
    ],
}

RUST_FACT_PATTERNS = {
    "network": [
        r"\breqwest::\w+|\bhyper::\w+|\bureq::\w+",
        r"\bTcpStream::connect\b|\bstd::net::TcpStream\b",
        r"(?:reqwest|ureq)::(?:get|post)\s*\(\s*\"(https?://[^\"]+)",
    ],
    "subprocess": [
        r"\bstd::process::Command\b|\bprocess::Command\b|\bCommand::new\b",
        r"Command::new\s*\(\s*[\"'][^\"']+",
    ],
    "credential": [
        r"\bstd::env::var\w*|\benv::var\w*",
        r"(?:std::)?env::var(?:_os)?\s*\(\s*[\"'][^\"']+",
    ],
    "obfuscation": [
        r"\bbase64::(?:decode|Engine|engine)\b",
    ],
    "file_access": [
        r"\bstd::fs::(?:read|read_to_string|read_dir|File)\b",
        r"\bfs::(?:read|read_to_string|read_dir)\b|\bFile::open\b",
        r"(?:std::)?fs::(?:read|read_to_string|read_dir|File)\s*\(\s*[\"'][^\"']+",
        r"File::open\s*\(\s*[\"'][^\"']+",
    ],
}

# 语言 → (模式表, 源码扩展名, 跳过目录)
REGEX_LANGUAGES = {
    "js": (JS_FACT_PATTERNS, (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"), JS_SKIP_DIRS),
    "go": (GO_FACT_PATTERNS, (".go",), GO_SKIP_DIRS),
    "rust": (RUST_FACT_PATTERNS, (".rs",), RUST_SKIP_DIRS),
}


def _extract_regex_facts(repo_dir: Path, patterns: Dict[str, List[str]],
                         extensions: Tuple[str, ...],
                         skip_dirs: set) -> Dict[str, List[str]]:
    """通用正则硬事实收集器：遍历指定扩展名文件，按 category 累积后统一去重。"""
    facts = {k: [] for k in patterns}
    for p in iter_repo_files(repo_dir, exts=extensions, skip_dirs=skip_dirs):
        text = read_text(p)
        if not text:
            continue
        for category, pats in patterns.items():
            for pat in pats:
                for m in re.finditer(pat, text, re.I):
                    facts[category].append(f"{p.name}: {m.group(0)[:120]}")
    for category in facts:
        facts[category] = sorted(set(facts[category]))[:100]
    return facts


def extract_js_facts(repo_dir: Path) -> Dict[str, List[str]]:
    pats, exts, skip = REGEX_LANGUAGES["js"]
    return _extract_regex_facts(repo_dir, pats, exts, skip)


def extract_go_facts(repo_dir: Path) -> Dict[str, List[str]]:
    pats, exts, skip = REGEX_LANGUAGES["go"]
    return _extract_regex_facts(repo_dir, pats, exts, skip)


def extract_rust_facts(repo_dir: Path) -> Dict[str, List[str]]:
    pats, exts, skip = REGEX_LANGUAGES["rust"]
    return _extract_regex_facts(repo_dir, pats, exts, skip)


def detect_languages(repo_dir: Path) -> List[str]:
    """探测仓库语言构成（转调 deps，保持接口向后兼容）。"""
    return _detect_languages(repo_dir, skip_dirs=LANG_SKIP_DIRS)


# ---------------------------------------------------------------------------
# 4. 原子声明提取（从 README / 生成的说明文档）
# ---------------------------------------------------------------------------
_SKIP_LINE_RE = re.compile(r"^[\s\-*#>!\]\[|]+$")


def extract_claims(text: str) -> List[Dict]:
    """把声明文档拆成原子声明，每条标注类别和原文片段。

    一行命中多个类别时**每个类别各记一条**（如 ``curl ... | sh`` 同时是网络外传
    与命令执行，两边都应参与对齐判定）。

    返回: [{"category": str, "claim": str, "evidence": str}]
    """
    if not text:
        return []
    claims = []
    for line in text.splitlines():
        line = line.strip()
        if len(line) < 6 or len(line) > 500:  # 过短/过长都不是有效声明
            continue
        if _SKIP_LINE_RE.match(line):  # 纯标点/链接/代码块标记
            continue
        for category, patterns in COMPILED_KEYWORDS.items():
            if any(pat.search(line) for pat in patterns):
                claims.append({"category": category, "claim": line[:300],
                               "evidence": line[:300]})
    return claims


# ---------------------------------------------------------------------------
# 5. 对齐判定引擎
# ---------------------------------------------------------------------------
def compute_alignment(repo_dir: Path,
                      readme_text: Optional[str] = None) -> Dict[str, Any]:
    """核心函数：计算声明 vs 实际行为的对齐率。

    返回::

        {
          "repo", "facts", "claims", "claim_judgments",
          "alignment_rate",           # 支持 / (支持+冲突)，无判定时 1.0
          "conflict_rate",            # 冲突 / (支持+冲突)
          "security_conflict_rate",   # 仅安全相关声明的矛盾率
          "has_hard_facts",           # 是否存在网络/子进程/凭据/混淆硬事实
          "verdict_signal",           # CLEAN / WARN / DANGER
          "_languages", "_claim_count", "_judgment_counts"
        }
    """
    repo_dir = Path(repo_dir)
    repo_name = repo_dir.name

    # ---- Step 0: 语言构成 ----
    languages = detect_languages(repo_dir)

    # ---- Step 1: 实际行为硬事实（Python AST + JS/Go/Rust 正则）----
    py_facts = extract_python_facts(repo_dir)
    regex_facts = _empty_facts()
    for lang_facts in (extract_js_facts(repo_dir), extract_go_facts(repo_dir),
                       extract_rust_facts(repo_dir)):
        for cat, vals in lang_facts.items():
            regex_facts[cat].extend(vals)
    facts = {cat: sorted(set(py_facts.get(cat, []) + regex_facts.get(cat, [])))[:200]
             for cat in FACT_CATEGORIES}
    has_hard_facts = any(facts.values())

    # ---- Step 2: 声明提取 ----
    if readme_text is None:
        readme_text = read_readme(repo_dir) or ""
    claims = extract_claims(readme_text)

    # ---- Step 3: 对齐判定 ----
    judgments: List[Dict] = []
    support_count = conflict_count = 0
    security_support = security_conflict = 0

    for cat in FACT_CATEGORIES:
        claim_count = sum(1 for c in claims if c["category"] == cat)
        fact_count = len(facts[cat])

        if claim_count == 0 and fact_count == 0:
            continue  # 双方都没提，不算

        if fact_count > 0 and claim_count == 0:
            # === 关键投毒信号: 代码里有安全敏感行为，但声明里完全没提 ===
            for fact in facts[cat][:5]:  # 取前 5 条，避免爆炸
                judgments.append({
                    "category": cat,
                    "claim": f"[shadow] 代码未声明但存在: {fact[:100]}",
                    "judgment": "conflict",
                    "reason": f"代码存在 {cat} 类行为 ({fact_count}处) 但 README 未声明",
                })
                conflict_count += 1
                if cat in SECURITY_CATEGORIES:
                    security_conflict += 1
            continue

        if claim_count > 0 and fact_count == 0:
            # 声明提到但代码找不到对应硬事实 → unknown（可能良性，也可能文档夸大）
            for c in claims:
                if c["category"] == cat:
                    judgments.append({
                        "category": cat, "claim": c["claim"], "judgment": "unknown",
                        "reason": f"声明 {cat} 行为，代码中未找到对应硬事实",
                    })
            continue

        # 双方都有 → 互相印证
        for c in claims:
            if c["category"] == cat:
                judgments.append({
                    "category": cat, "claim": c["claim"], "judgment": "support",
                    "reason": f"声明 {cat}，代码中有 {fact_count} 处硬事实支撑",
                })
                support_count += 1
                if cat in SECURITY_CATEGORIES:
                    security_support += 1

    # ---- Step 4: 计算比率 ----
    total_judged = support_count + conflict_count
    alignment_rate = support_count / total_judged if total_judged else 1.0
    conflict_rate = conflict_count / total_judged if total_judged else 0.0
    sec_total = security_support + security_conflict
    security_conflict_rate = security_conflict / sec_total if sec_total else 0.0

    # ---- Step 5: 投毒信号判定（阈值集中于 config.ALIGN_CONFIG）----
    verdict_signal = "CLEAN"
    if conflict_count > 0:
        verdict_signal = "WARN"
    if (security_conflict_rate >= ALIGN_CONFIG["DANGER_SEC_CONFLICT_RATE"]
            or conflict_count >= ALIGN_CONFIG["DANGER_CONFLICT_COUNT"]):
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
        "_judgment_counts": {"support": support_count, "conflict": conflict_count},
    }


# ---------------------------------------------------------------------------
# 6. CLI 入口
# ---------------------------------------------------------------------------
def main() -> int:
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description="MPV-Detector 语义对齐率检测")
    ap.add_argument("--repo-dir", required=True, help="仓库目录")
    ap.add_argument("--readme", default="", help="声明文档路径（默认自动找 README）")
    ap.add_argument("--output", default="", help="输出 JSON 路径")
    ap.add_argument("--brief", action="store_true", help="只输出摘要")
    args = ap.parse_args()

    repo_dir = Path(args.repo_dir)
    if not repo_dir.exists():
        print(f"[错误] 仓库目录不存在: {repo_dir}")
        return 1

    readme_text = None
    if args.readme:
        rp = Path(args.readme)
        if rp.exists():
            readme_text = read_text(rp) or ""

    result = compute_alignment(repo_dir, readme_text)

    if args.brief:
        counts = result["_judgment_counts"]
        unknown = len(result["claim_judgments"]) - counts["support"] - counts["conflict"]
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
        print(f"judgments      = support:{counts['support']} "
              f"conflict:{counts['conflict']} unknown:{unknown}")
        for c in [j for j in result["claim_judgments"] if j["judgment"] == "conflict"][:10]:
            print(f"  ⚠ conflict[{c['category']}]: {c['claim'][:120]}")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))

    if args.output:
        write_json(args.output, result)
        print(f"\n已写入: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
