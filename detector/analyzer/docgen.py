#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP 插件代码 → 语义说明文档 批量生成脚本
==========================================
生成 MCP 插件的语义说明文档（供后续对齐率 / 投毒复核使用）。

两种代码来源：
  1. GitHub 模式（默认）：读取 mcp插件/ 下的插件元数据，通过 GitHub API 拉取关键代码文件。
  2. 本地代码模式（--local-root + --repo-list）：从本地完整仓库目录
     （默认项目内 mcp插件/<owner>_<repo>，可用 MPV_LARGE_REPO_SOURCE 覆盖）
     直接读取代码与 README，绕开 GitHub 限流，无需 token。

LLM 后端：OpenAI 兼容接口（默认本地 Ollama qwen3-coder:30b），也支持 Claude / GPT。

使用方式：
    # 1. 本地 Ollama + 本地代码清单模式（推荐，无需 token）
    python docgen.py --local-root mcp插件 --repo-list targets.txt --out-dir output/gen_docs_800

    # 2. 本地 Ollama + 桌面元数据清单（走 GitHub API）
    python docgen.py

    # 3. 使用 OpenAI / 兼容 API
    python docgen.py --api-base https://api.openai.com/v1 --api-key sk-xxx --model gpt-4o

    # 4. 指定处理前 N 个插件（调试用）
    python docgen.py --limit 5

    # 5. 强制重新生成（覆盖已有文档）
    python docgen.py --force

依赖：requests
    pip install requests
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    print("[错误] 缺少依赖 requests，请先执行: pip install requests")
    sys.exit(1)


# 路径配置（项目根 = detector/analyzer 上两级）
BASE_DIR = str(Path(__file__).resolve().parent.parent.parent)
PLUGIN_DIR = os.path.join(BASE_DIR, "mcp插件")
INDEX_FILE = os.path.join(PLUGIN_DIR, "插件路径清单.json")

# 复用 detector/config.py 的统一配置；本文件也支持单独运行，故用 try 兜底
try:
    sys.path.insert(0, os.path.join(BASE_DIR, "detector"))
    from config import OLLAMA_API_BASE, DEFAULT_MODEL  # type: ignore
except Exception:  # pragma: no cover - 独立运行时不依赖 detector 包
    OLLAMA_API_BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434") + "/v1"
    DEFAULT_MODEL = os.environ.get("MPV_MODEL", "qwen3-coder:30b")

GITHUB_API = "https://api.github.com"
TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 5

# MCP 相关文件关键词（用于从仓库文件树中筛选关键代码）
MCP_FILE_KEYWORDS = [
    "mcp", "server", "tool", "tools", "handler", "index", "main",
    "app", "cli", "__init__", "manifest", "config",
]
# 优先抓取的文件扩展名
CODE_EXTENSIONS = {".py", ".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".go", ".rs",
                   ".java", ".cs", ".php", ".rb"}
# 单个仓库最多抓取的代码文件数
MAX_FILES_PER_REPO = 8
# 单个文件最大字符数（超出截断）
MAX_FILE_CHARS = 8000
# 单文件大小上限（本地模式跳过超大文件）
MAX_FILE_BYTES = 8 * 1024 * 1024
# 本地模式跳过的目录（不含隐藏目录前缀 "._"）
SKIP_DIR_NAMES = {
    "node_modules", ".git", ".venv", "venv", "env", "dist", "build", "__pycache__",
    ".next", ".nuxt", ".cache", "vendor", "target", "bin", "obj", ".turbo", ".nx",
    "coverage", ".yarn", ".pnpm-store", "third_party", ".idea", ".vscode", ".github",
    ".circleci", "tests", "test", "docs", "doc", "examples", "example", "assets",
}


# ---------------------------------------------------------------------------
# GitHub API 封装
# ---------------------------------------------------------------------------
class GitHubFetcher:
    """GitHub REST API 封装：文件树 / 文件内容 / README 抓取，带速率限制与重试。"""

    def __init__(self, token: Optional[str] = None):
        # 复用 Session 保持连接与头信息
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "MCP-Code2Doc/1.0",
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"  # Bearer 鉴权
        # 速率限制状态（由响应头回填）
        self.rate_remaining = None
        self.rate_reset = None

    def _request(self, url: str, params: Optional[Dict] = None,
                 headers: Optional[Dict] = None) -> Optional[Any]:
        """带重试和速率限制的 GET 请求；返回 JSON / 文本 / None。"""
        for attempt in range(MAX_RETRIES):
            try:
                resp = self.session.get(url, params=params, headers=headers, timeout=TIMEOUT)
                # 回填速率限制状态
                self.rate_remaining = int(resp.headers.get("X-RateLimit-Remaining", 0))
                self.rate_reset = int(resp.headers.get("X-RateLimit-Reset", 0))

                if resp.status_code == 200:
                    # 按 Content-Type 决定返回 JSON 还是纯文本
                    return resp.json() if "application/json" in resp.headers.get("Content-Type", "") else resp.text
                if resp.status_code == 403 and self.rate_remaining == 0:  # 配额耗尽
                    wait = max(self.rate_reset - int(time.time()), 0) + 5
                    print(f"  [速率限制] 等待 {wait:.0f}s...")
                    time.sleep(wait)
                    continue
                if resp.status_code in (422, 502, 503):  # 临时性错误
                    time.sleep(RETRY_DELAY)
                    continue
                if resp.status_code == 404:  # 资源不存在
                    return None
                print(f"  [GitHub HTTP {resp.status_code}] {url}")
                return None
            except requests.RequestException as e:
                print(f"  [请求异常] {e}")
                time.sleep(RETRY_DELAY)
        return None  # 重试耗尽

    def get_repo_tree(self, owner: str, repo: str, branch: str = "HEAD") -> List[Dict]:
        """获取仓库文件树（递归，branch 默认 HEAD）。"""
        url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}"
        data = self._request(url, params={"recursive": "1"})
        if not data:
            return []
        return data.get("tree", [])  # 返回 tree 节点列表

    def get_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        """获取文件原始内容；二进制文件（返回 JSON base64）时解码。"""
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
        data = self._request(url, headers={"Accept": "application/vnd.github.raw"})
        if isinstance(data, str):  # raw 纯文本
            return data
        # 若返回 JSON（大文件/二进制走 base64 编码），解码
        if isinstance(data, dict) and data.get("content"):
            import base64
            try:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None
        return None

    def get_readme(self, owner: str, repo: str) -> Optional[str]:
        """获取 README 原始内容（纯文本）。"""
        url = f"{GITHUB_API}/repos/{owner}/{repo}/readme"
        return self._request(url, headers={"Accept": "application/vnd.github.raw"})


def select_key_files(tree: List[Dict]) -> List[str]:
    """从文件树中筛选 MCP 相关的关键代码文件（按相关性打分取前 N 个）。"""
    candidates = []
    for item in tree:
        if item.get("type") != "blob":  # 只处理文件
            continue
        path = item.get("path", "")
        lower = path.lower()

        # 跳过测试/依赖/构建产物目录
        if any(skip in lower for skip in ["/test", "/tests", "/__tests__", "/node_modules/",
                                           "/dist/", "/build/", "/.git", "/vendor/", "/target/"]):
            continue
        # 跳过锁文件/清单/文档/压缩文件等非源码
        if lower.endswith((".min.js", ".min.css", ".map", ".lock", ".toml", ".yaml", ".yml",
                            ".json", ".md", ".txt", ".cfg", ".ini")):
            continue

        ext = os.path.splitext(path)[1].lower()
        if ext not in CODE_EXTENSIONS:  # 只保留代码扩展名
            continue

        # 按"文件名/路径是否含 MCP 关键词"打分
        basename = os.path.basename(lower)
        score = 0
        for kw in MCP_FILE_KEYWORDS:
            if kw in basename:  # 文件名命中权重更高
                score += 3
            if kw in lower:     # 路径命中权重较低
                score += 1
        if "/" not in path:     # 根目录文件加分
            score += 2
        depth = path.count("/")  # 路径越浅越重要
        score += max(0, 5 - depth)

        if score > 0:  # 有相关性的才进入候选
            candidates.append((score, path))

    candidates.sort(key=lambda x: -x[0])  # 按分数降序
    return [p for _, p in candidates[:MAX_FILES_PER_REPO]]  # 取前 MAX_FILES_PER_REPO 个


# ---------------------------------------------------------------------------
# 本地代码读取（替代 GitHub API，避免限流）
# ---------------------------------------------------------------------------
def read_local_code_files(repo_root: str) -> List[Dict]:
    """从本地完整仓库目录读取 MCP 关键代码文件。

    返回 [{path, content}, ...]：递归遍历，跳过常见大目录，按相关性打分取前 N 个。
    """
    if not os.path.isdir(repo_root):
        return []

    candidates: List[tuple] = []  # (score, rel_path, abs_path)
    for dirpath, dirnames, filenames in os.walk(repo_root):
        # 原地裁剪：跳过隐藏目录与常见大目录，避免遍历巨型依赖
        dirnames[:] = [d for d in dirnames
                       if d.lower() not in SKIP_DIR_NAMES and not d.startswith(".")]
        rel_dir = os.path.relpath(dirpath, repo_root)
        for fn in filenames:
            rel_path = fn if rel_dir == "." else os.path.join(rel_dir, fn)
            lower = rel_path.lower().replace("\\", "/")

            ext = os.path.splitext(fn)[1].lower()
            if ext not in CODE_EXTENSIONS:  # 只保留代码扩展名
                continue
            # 跳过压缩/锁文件等非源码
            if lower.endswith((".min.js", ".min.css", ".map", ".lock")):
                continue

            abs_path = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(abs_path) > MAX_FILE_BYTES:  # 超大文件跳过
                    continue
            except OSError:
                continue

            # 按"文件名/路径是否含 MCP 关键词"打分
            basename = fn.lower()
            score = 0
            for kw in MCP_FILE_KEYWORDS:
                if kw in basename:
                    score += 3
                if kw in lower:
                    score += 1
            depth = lower.count("/")
            score += max(0, 5 - depth)  # 路径越浅越重要

            if score > 0:
                candidates.append((score, rel_path, abs_path))

    candidates.sort(key=lambda x: -x[0])  # 按分数降序
    code_files: List[Dict] = []
    for score, rel_path, abs_path in candidates[:MAX_FILES_PER_REPO]:
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        if content and len(content.strip()) > 50:
            code_files.append({"path": rel_path, "content": content})
    return code_files


def read_local_readme(repo_root: str) -> Optional[str]:
    """从本地仓库目录读取 README（区分大小写试探常见命名）。"""
    for name in ("README.md", "readme.md", "README", "Readme.md", "Readme", "readme"):
        p = os.path.join(repo_root, name)
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except OSError:
                return None
    return None


# ---------------------------------------------------------------------------
# LLM 封装
# ---------------------------------------------------------------------------
class LLMClient:
    def __init__(self, backend: str = "openai", api_base: str = "",
                 api_key: str = "", model: str = ""):
        self.backend = backend
        self.api_base = api_base
        self.api_key = api_key
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        if self.backend == "anthropic":
            return self._call_anthropic(system_prompt, user_prompt)
        else:
            return self._call_openai(system_prompt, user_prompt)

    def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.api_base.rstrip('/')}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 4096,
        }
        for attempt in range(MAX_RETRIES):
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=600)
                if resp.status_code == 200:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
                print(f"  [LLM HTTP {resp.status_code}] {resp.text[:200]}")
                time.sleep(RETRY_DELAY)
            except requests.RequestException as e:
                print(f"  [LLM 请求异常] {e}")
                time.sleep(RETRY_DELAY)
        return ""

    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.api_base.rstrip('/')}/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "max_tokens": 4096,
            "temperature": 0.3,
        }
        for attempt in range(MAX_RETRIES):
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=600)
                if resp.status_code == 200:
                    data = resp.json()
                    return "".join(b.get("text", "") for b in data.get("content", []))
                print(f"  [Anthropic HTTP {resp.status_code}] {resp.text[:200]}")
                time.sleep(RETRY_DELAY)
            except requests.RequestException as e:
                print(f"  [LLM 请求异常] {e}")
                time.sleep(RETRY_DELAY)
        return ""


# ---------------------------------------------------------------------------
# 提示词
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """你是一位专业的 MCP（Model Context Protocol）安全分析专家。
你的任务是根据 MCP 服务器/插件的代码，生成一份准确、客观的语义说明文档。
要求：
1. 只基于代码中实际存在的逻辑生成描述，不得编造代码中没有的功能
2. 重点关注：工具名称、工具功能、输入参数、返回值、副作用、权限要求、网络请求、文件操作、命令执行
3. 特别标注任何可能存在安全风险的行为（如执行系统命令、读写任意文件、发起网络请求、调用外部 API）
4. 输出结构清晰，使用 Markdown 格式
5. 如果代码中存在与 README/描述不一致的地方，在"潜在不一致"部分指出
"""

def build_user_prompt(repo_info: Dict, code_files: List[Dict], readme: Optional[str]) -> str:
    parts = []
    parts.append(f"# 仓库信息\n")
    parts.append(f"- 名称: {repo_info.get('full_name', '')}")
    parts.append(f"- 描述: {repo_info.get('description', '')}")
    parts.append(f"- 语言: {repo_info.get('language', '')}")
    parts.append(f"- Star: {repo_info.get('stars', 0)}")
    parts.append(f"- 主页: {repo_info.get('html_url', '')}\n")

    if readme:
        readme_truncated = readme[:3000]
        parts.append(f"# README（前3000字符）\n```\n{readme_truncated}\n```\n")

    parts.append("# 关键代码文件\n")
    for cf in code_files:
        content = cf["content"][:MAX_FILE_CHARS]
        parts.append(f"## 文件: {cf['path']}\n```\n{content}\n```\n")

    parts.append("""
# 任务
请根据以上代码，生成该 MCP 插件的语义说明文档，严格按以下结构输出：

## 1. 插件概述
（一句话描述插件的核心功能）

## 2. 暴露的工具列表
对每个工具，列出：
- **工具名称**: 
- **功能描述**: 
- **输入参数**: （参数名、类型、是否必填、含义）
- **返回值**: 
- **副作用**: （是否修改文件、执行命令、发起网络请求等）
- **安全风险**: （低/中/高，及原因）

## 3. 权限与外部依赖
（需要哪些 API key、访问哪些外部服务、执行哪些系统命令）

## 4. 潜在不一致
（代码实现与 README/描述可能存在差异的地方，如无则写"未发现"）

## 5. 投毒风险评估
（从工具描述与实现对齐的角度，评估该插件是否容易被投毒，以及投毒可能的注入点）
""")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def load_targets_from_file(repo_list_path: str) -> List[Dict]:
    """读取清单文件（每行一个 owner_repo），构造本地目标列表。"""
    targets = []
    with open(repo_list_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append({"full_name": line, "owner_repo": line})
    return targets


def main():
    parser = argparse.ArgumentParser(
        description="MCP 插件代码转语义说明文档批量生成器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--backend", choices=["openai", "anthropic"], default="openai",
                        help="LLM 后端类型（默认: openai，兼容 Ollama）")
    parser.add_argument("--api-base", default=OLLAMA_API_BASE,
                        help=f"API 地址（默认: {OLLAMA_API_BASE}，可用 OLLAMA_HOST 覆盖）")
    parser.add_argument("--api-key", default=os.environ.get("LLM_API_KEY", ""),
                        help="API Key（也可通过环境变量 LLM_API_KEY 设置）")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"模型名称（默认: {DEFAULT_MODEL}，需先 ollama pull）")
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""),
                        help="GitHub Token（提高速率限制，也可通过环境变量 GITHUB_TOKEN 设置）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只处理前 N 个插件（0=全部，默认: 0）")
    parser.add_argument("--force", action="store_true",
                        help="强制重新生成，覆盖已有文档")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="每个插件处理后的等待秒数（默认: 1.0）")
    # ---- 本地代码模式参数 ----
    parser.add_argument("--local-root", default=PLUGIN_DIR,
                        help="本地完整仓库根目录（默认项目内 mcp插件/），其下为 <owner>_<repo> 文件夹")
    parser.add_argument("--repo-list", default="",
                        help="仓库清单文件（每行一个 owner_repo），配合 --local-root 使用")
    parser.add_argument("--out-dir", default="",
                        help="文档输出目录（本地模式默认 output/gen_docs_800/<owner_repo>/generated_doc.md）")
    args = parser.parse_args()

    # ---- 确定运行模式 ----
    local_mode = bool(args.local_root and args.repo_list)
    out_dir = args.out_dir
    if local_mode:
        if not out_dir:
            out_dir = os.path.join(BASE_DIR, "output", "gen_docs_800")
        os.makedirs(out_dir, exist_ok=True)
        plugins = load_targets_from_file(args.repo_list)
        if args.limit > 0:
            plugins = plugins[:args.limit]
        print(f"[本地代码模式] root={args.local_root} 清单={args.repo_list} 目标={len(plugins)} 输出={out_dir}")
    else:
        # 加载插件清单（GitHub 模式）
        if not os.path.exists(INDEX_FILE):
            print(f"[错误] 找不到插件清单: {INDEX_FILE}")
            sys.exit(1)
        with open(INDEX_FILE, "r", encoding="utf-8") as f:
            index_data = json.load(f)
        plugins = index_data.get("plugins", [])
        if args.limit > 0:
            plugins = plugins[:args.limit]

    print("=" * 60)
    print("MCP 代码转语义文档 批量生成")
    print("=" * 60)
    print(f"  后端:     {args.backend}")
    print(f"  API:      {args.api_base}")
    print(f"  模型:     {args.model}")
    print(f"  插件数:   {len(plugins)}")
    print(f"  强制覆盖: {'是' if args.force else '否'}")
    print("=" * 60)

    gh = GitHubFetcher(token=args.github_token or None)
    llm = LLMClient(
        backend=args.backend,
        api_base=args.api_base,
        api_key=args.api_key,
        model=args.model,
    )

    success = 0
    skipped = 0
    failed = 0
    results = []  # 记录每个目标的成败

    for idx, plugin in enumerate(plugins, 1):
        full_name = plugin["full_name"]

        # ---- 确定代码来源与文档输出路径 ----
        if local_mode:
            repo_root = os.path.join(args.local_root, plugin["owner_repo"])
            doc_path = os.path.join(out_dir, plugin["owner_repo"], "generated_doc.md")
        else:
            storage_path = plugin["storage_path"]
            repo_root = storage_path  # 本地模式下不使用
            doc_path = os.path.join(storage_path, "generated_doc.md")

        print(f"\n[{idx}/{len(plugins)}] {full_name}")

        # 跳过已生成
        if os.path.exists(doc_path) and not args.force:
            print(f"  -> 已存在 generated_doc.md，跳过")
            skipped += 1
            results.append({"full_name": full_name, "status": "skipped", "doc": doc_path})
            continue

        if local_mode:
            if not os.path.isdir(repo_root):
                print(f"  [警告] 本地仓库不存在，跳过: {repo_root}")
                failed += 1
                results.append({"full_name": full_name, "status": "no_local_code", "doc": ""})
                continue

            # 读取本地元数据（如存在 info.json）
            repo_info = {"full_name": full_name, "description": "", "language": "", "stars": 0, "html_url": ""}
            info_path = os.path.join(repo_root, "info.json")
            if os.path.exists(info_path):
                try:
                    with open(info_path, "r", encoding="utf-8") as f:
                        info = json.load(f)
                    repo_info.update({
                        "full_name": info.get("full_name", full_name),
                        "description": info.get("description", ""),
                        "language": info.get("language", ""),
                        "stars": info.get("stars", 0),
                        "html_url": info.get("html_url", ""),
                    })
                except Exception:
                    pass

            # 本地读代码
            code_files = read_local_code_files(repo_root)
            print(f"  -> 本地读取到 {len(code_files)} 个关键代码文件")
            if not code_files:
                print(f"  [警告] 未在本地找到代码文件，跳过")
                failed += 1
                results.append({"full_name": full_name, "status": "no_code", "doc": ""})
                continue
            for cf in code_files:
                print(f"     + {cf['path']} ({len(cf['content'])} 字符)")

            # 本地读 README
            readme = read_local_readme(repo_root)
            if readme:
                print(f"  -> README: {len(readme)} 字符")
        else:
            # ---- GitHub 模式（原逻辑） ----
            info_path = os.path.join(plugin["storage_path"], "info.json")
            if not os.path.exists(info_path):
                print(f"  [警告] 找不到 info.json，跳过")
                failed += 1
                results.append({"full_name": full_name, "status": "no_info", "doc": ""})
                continue
            with open(info_path, "r", encoding="utf-8") as f:
                repo_info = json.load(f)

            owner = repo_info.get("owner", "")
            repo = repo_info.get("name", "")
            if not owner or not repo:
                print(f"  [警告] 缺少 owner/repo，跳过")
                failed += 1
                results.append({"full_name": full_name, "status": "no_owner_repo", "doc": ""})
                continue

            print(f"  -> 拉取文件树...")
            tree = gh.get_repo_tree(owner, repo)
            if not tree:
                print(f"  [警告] 获取文件树失败，跳过")
                failed += 1
                results.append({"full_name": full_name, "status": "no_tree", "doc": ""})
                continue

            key_files = select_key_files(tree)
            print(f"  -> 筛选出 {len(key_files)} 个关键代码文件")

            code_files = []
            for fp in key_files:
                content = gh.get_file_content(owner, repo, fp)
                if content and len(content.strip()) > 50:
                    code_files.append({"path": fp, "content": content})
                    print(f"     + {fp} ({len(content)} 字符)")
                time.sleep(0.3)

            if not code_files:
                print(f"  [警告] 未获取到代码文件，跳过")
                failed += 1
                results.append({"full_name": full_name, "status": "no_code", "doc": ""})
                continue

            readme = gh.get_readme(owner, repo)
            if readme:
                print(f"  -> README: {len(readme)} 字符")

        # ---- 调用 LLM 生成文档 ----
        print(f"  -> 调用 {args.model} 生成文档...")
        user_prompt = build_user_prompt(repo_info, code_files, readme)
        doc = llm.generate(SYSTEM_PROMPT, user_prompt)

        if not doc:
            print(f"  [错误] 文档生成失败")
            failed += 1
            results.append({"full_name": full_name, "status": "gen_failed", "doc": doc_path})
            continue

        # 保存文档
        os.makedirs(os.path.dirname(doc_path), exist_ok=True)
        with open(doc_path, "w", encoding="utf-8") as f:
            f.write(f"<!-- 由 docgen.py 自动生成 -->\n")
            f.write(f"<!-- 仓库: {full_name} -->\n")
            f.write(f"<!-- 模型: {args.model} -->\n")
            f.write(f"<!-- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')} -->\n\n")
            f.write(doc)

        print(f"  -> 已保存: {doc_path} ({len(doc)} 字符)")
        success += 1
        results.append({"full_name": full_name, "status": "ok", "doc": doc_path})
        time.sleep(args.delay)

    # 汇总
    print(f"\n{'=' * 60}")
    print(f"完成！成功: {success}，跳过: {skipped}，失败: {failed}")
    print(f"{'=' * 60}")

    # 写结果清单
    if local_mode:
        result_csv = os.path.join(out_dir, "docgen_results.csv")
        with open(result_csv, "w", encoding="utf-8") as f:
            f.write("full_name,status,doc_path\n")
            for r in results:
                f.write(f"{r['full_name']},{r['status']},{r['doc']}\n")
        print(f"结果清单: {result_csv}")


if __name__ == "__main__":
    main()
