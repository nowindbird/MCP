#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP 插件代码 → 语义说明文档 批量生成
======================================
生成 MCP 插件的语义说明文档（供后续对齐率 / 投毒复核使用）。

两种代码来源：
  1. 本地代码模式（--local-root + --repo-list）：从本地完整仓库目录
     （默认项目内 mcp插件/<owner>_<repo>，可用 MPV_LARGE_REPO_SOURCE 覆盖）
     直接读取代码与 README，绕开 GitHub 限流，无需 token。
  2. GitHub 模式（默认）：读取 mcp插件/ 下的插件元数据，通过 GitHub API 拉取关键代码文件。

LLM 后端：OpenAI 兼容接口（默认本地 Ollama qwen3-coder:30b），也支持 Claude / GPT。
GitHub / LLM 客户端、文件遍历与 IO 全部来自 ``detector.deps``（本模块不再自带一套）。

用法::

    # 本地 Ollama + 本地代码清单模式（推荐，无需 token）
    python -m detector.cli docgen --local-root mcp插件 --repo-list targets.txt --out-dir output/gen_docs

    # 本地 Ollama + 插件元数据清单（走 GitHub API）
    python -m detector.cli docgen

    # 使用 OpenAI / 兼容 API
    python -m detector.cli docgen --api-base https://api.openai.com/v1 --api-key sk-xxx --model gpt-4o
"""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from detector.deps import (
    CODE_EXTS,
    DOC_GEN_CONFIG,
    METADATA_DIR,
    OUTPUT_DIR,
    STATIC_CONFIG,
    GitHubClient,
    LLMClient,
    MissingDependency,
    ensure_utf8_stdio,
    iter_repo_files,
    load_targets,
    read_json,
    read_readme,
    read_text,
    write_csv,
)

# MCP 相关文件关键词（用于从仓库文件树中筛选关键代码）
MCP_FILE_KEYWORDS = [
    "mcp", "server", "tool", "tools", "handler", "index", "main",
    "app", "cli", "__init__", "manifest", "config",
]
MAX_FILES_PER_REPO = STATIC_CONFIG["MAX_FILES_PER_REPO"]
MAX_FILE_CHARS = STATIC_CONFIG["MAX_FILE_CHARS"]
# 本地模式跳过：依赖/构建产物 + 测试/示例/文档（不代表插件真实能力）
LOCAL_SKIP_DIRS = set(STATIC_CONFIG["SKIP_DIRS"]) | set(STATIC_CONFIG["DOC_SKIP_DIRS"])

# 插件元数据清单（owner_repo + storage_path）
INDEX_FILE = METADATA_DIR / "插件路径清单.json"


# ---------------------------------------------------------------------------
# 关键文件筛选（GitHub 文件树 / 本地目录共用同一套打分规则）
# ---------------------------------------------------------------------------
def _score_path(path: str) -> int:
    """按"文件名/路径是否含 MCP 关键词"打分：文件名权重更高，路径越浅越重要。"""
    lower = path.lower().replace("\\", "/")
    basename = lower.rsplit("/", 1)[-1]
    score = 0
    for kw in MCP_FILE_KEYWORDS:
        if kw in basename:
            score += 3
        if kw in lower:
            score += 1
    if "/" not in lower:  # 根目录文件加分
        score += 2
    score += max(0, 5 - lower.count("/"))
    return score


def select_key_files(tree: List[Dict]) -> List[str]:
    """从 GitHub 文件树中筛选 MCP 相关关键代码文件（按相关性取前 N 个）。"""
    candidates = []
    for item in tree:
        if item.get("type") != "blob":  # 只处理文件
            continue
        path = item.get("path", "")
        lower = path.lower()
        # 跳过测试/依赖/构建产物
        if any(part in lower for part in ("/test", "/tests", "/__tests__", "/node_modules/",
                                          "/dist/", "/build/", "/.git", "/vendor/",
                                          "/target/")):
            continue
        # 跳过锁文件/清单/文档/压缩文件等非源码
        if lower.endswith((".min.js", ".min.css", ".map", ".lock", ".toml", ".yaml",
                           ".yml", ".json", ".md", ".txt", ".cfg", ".ini")):
            continue
        if os.path.splitext(path)[1].lower() not in CODE_EXTS:
            continue
        score = _score_path(path)
        if score > 0:
            candidates.append((score, path))
    candidates.sort(key=lambda x: -x[0])
    return [p for _, p in candidates[:MAX_FILES_PER_REPO]]


def read_local_code_files(repo_root: Path | str) -> List[Dict[str, str]]:
    """从本地仓库目录读取 MCP 关键代码文件（打分取前 N 个）。"""
    candidates = []
    for p in iter_repo_files(repo_root, exts=CODE_EXTS, skip_dirs=LOCAL_SKIP_DIRS):
        rel = p.relative_to(repo_root).as_posix()
        if rel.lower().endswith((".min.js", ".min.css", ".map", ".lock")):
            continue
        score = _score_path(rel)
        if score > 0:
            candidates.append((score, rel, p))
    candidates.sort(key=lambda x: -x[0])

    code_files: List[Dict[str, str]] = []
    for _score, rel, p in candidates[:MAX_FILES_PER_REPO]:
        content = read_text(p)
        if content and len(content.strip()) > 50:
            code_files.append({"path": rel, "content": content})
    return code_files


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

TASK_PROMPT = """
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
"""


def build_user_prompt(repo_info: Dict, code_files: List[Dict], readme: Optional[str]) -> str:
    """拼装用户提示词：仓库信息 + README 摘要 + 关键代码。"""
    parts = [
        "# 仓库信息",
        f"- 名称: {repo_info.get('full_name', '')}",
        f"- 描述: {repo_info.get('description', '')}",
        f"- 语言: {repo_info.get('language', '')}",
        f"- Star: {repo_info.get('stars', 0)}",
        f"- 主页: {repo_info.get('html_url', '')}\n",
    ]
    if readme:
        parts.append(f"# README（前3000字符）\n```\n{readme[:3000]}\n```\n")
    parts.append("# 关键代码文件")
    for cf in code_files:
        parts.append(f"## 文件: {cf['path']}\n```\n{cf['content'][:MAX_FILE_CHARS]}\n```\n")
    parts.append(TASK_PROMPT)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def _load_plugin_index() -> List[Dict[str, Any]]:
    """读取插件路径清单（GitHub 模式用）。"""
    data = read_json(INDEX_FILE, default={}) or {}
    return data.get("plugins", []) if isinstance(data, dict) else []


def _topic_from_info(info: Dict[str, Any], full_name: str) -> Dict[str, Any]:
    """把 info.json 归一化为提示词需要的仓库信息。"""
    return {
        "full_name": info.get("full_name", full_name),
        "description": info.get("description", ""),
        "language": info.get("language", ""),
        "stars": info.get("stars", 0),
        "html_url": info.get("html_url", ""),
    }


def main() -> int:
    ensure_utf8_stdio()
    parser = argparse.ArgumentParser(
        description="MCP 插件代码转语义说明文档批量生成器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--backend", choices=["openai", "anthropic"],
                        default=DOC_GEN_CONFIG["backend"], help="LLM 后端类型")
    parser.add_argument("--api-base", default=DOC_GEN_CONFIG["api_base"],
                        help=f"API 地址（默认 {DOC_GEN_CONFIG['api_base']}）")
    parser.add_argument("--api-key", default=DOC_GEN_CONFIG["api_key"],
                        help="API Key（也可用 DOC_API_KEY 环境变量）")
    parser.add_argument("--model", default=DOC_GEN_CONFIG["model"],
                        help=f"模型名称（默认 {DOC_GEN_CONFIG['model']}）")
    parser.add_argument("--github-token", default="",
                        help="GitHub Token（也可用 GITHUB_TOKEN 环境变量）")
    parser.add_argument("--limit", type=int, default=0, help="只处理前 N 个插件（0=全部）")
    parser.add_argument("--force", action="store_true", help="强制重新生成（覆盖已有文档）")
    parser.add_argument("--delay", type=float, default=1.0, help="每个插件处理后的等待秒数")
    # ---- 本地代码模式 ----
    parser.add_argument("--local-root", default=str(METADATA_DIR),
                        help="本地完整仓库根目录（其下为 <owner>_<repo> 文件夹）")
    parser.add_argument("--repo-list", default="",
                        help="仓库清单文件（每行一个 owner_repo），配合 --local-root 使用")
    parser.add_argument("--out-dir", default="",
                        help=f"文档输出目录（默认 {OUTPUT_DIR / 'gen_docs'}）")
    args = parser.parse_args()

    # ---- 运行模式 ----
    local_mode = bool(args.repo_list)
    if local_mode:
        out_dir = Path(args.out_dir) if args.out_dir else OUTPUT_DIR / "gen_docs"
        out_dir.mkdir(parents=True, exist_ok=True)
        targets = load_targets(args.repo_list)
        plugins = [{"full_name": t, "owner_repo": t} for t in targets]
        if args.limit > 0:
            plugins = plugins[:args.limit]
        print(f"[本地代码模式] root={args.local_root} 清单={args.repo_list} "
              f"目标={len(plugins)} 输出={out_dir}")
    else:
        plugins = _load_plugin_index()
        if not plugins:
            print(f"[错误] 找不到插件清单或清单为空: {INDEX_FILE}")
            return 1
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

    try:
        llm = LLMClient(backend=args.backend, api_base=args.api_base,
                        api_key=args.api_key, model=args.model)
        gh = None if local_mode else GitHubClient(token=args.github_token or None)
    except MissingDependency as e:
        print(f"[错误] {e}")
        return 1

    success = skipped = failed = 0
    results: List[Dict[str, str]] = []

    for idx, plugin in enumerate(plugins, 1):
        full_name = plugin["full_name"]

        # ---- 代码来源与文档输出路径 ----
        if local_mode:
            repo_root = Path(args.local_root) / plugin["owner_repo"]
            doc_path = out_dir / plugin["owner_repo"] / "generated_doc.md"
        else:
            repo_root = Path(plugin["storage_path"])
            doc_path = repo_root / "generated_doc.md"

        print(f"\n[{idx}/{len(plugins)}] {full_name}")

        if doc_path.exists() and not args.force:
            print("  -> 已存在 generated_doc.md，跳过")
            skipped += 1
            results.append({"full_name": full_name, "status": "skipped",
                            "doc_path": str(doc_path)})
            continue

        # ---- 取代码 + README + 元数据 ----
        if local_mode:
            if not repo_root.is_dir():
                print(f"  [警告] 本地仓库不存在，跳过: {repo_root}")
                failed += 1
                results.append({"full_name": full_name, "status": "no_local_code",
                                "doc_path": ""})
                continue
            repo_info = _topic_from_info(read_json(repo_root / "info.json", default={}), full_name)
            code_files = read_local_code_files(repo_root)
            print(f"  -> 本地读取到 {len(code_files)} 个关键代码文件")
            if not code_files:
                print("  [警告] 未在本地找到代码文件，跳过")
                failed += 1
                results.append({"full_name": full_name, "status": "no_code", "doc_path": ""})
                continue
            for cf in code_files:
                print(f"     + {cf['path']} ({len(cf['content'])} 字符)")
            readme = read_readme(repo_root)
            if readme:
                print(f"  -> README: {len(readme)} 字符")
        else:
            info = read_json(repo_root / "info.json", default=None)
            if not isinstance(info, dict):
                print("  [警告] 找不到 info.json，跳过")
                failed += 1
                results.append({"full_name": full_name, "status": "no_info", "doc_path": ""})
                continue
            repo_info = _topic_from_info(info, full_name)
            owner, repo = info.get("owner", ""), info.get("name", "")
            if not owner or not repo:
                print("  [警告] 缺少 owner/repo，跳过")
                failed += 1
                results.append({"full_name": full_name, "status": "no_owner_repo",
                                "doc_path": ""})
                continue

            print("  -> 拉取文件树...")
            tree = gh.repo_tree(owner, repo)
            if not tree:
                print("  [警告] 获取文件树失败，跳过")
                failed += 1
                results.append({"full_name": full_name, "status": "no_tree", "doc_path": ""})
                continue

            key_files = select_key_files(tree)
            print(f"  -> 筛选出 {len(key_files)} 个关键代码文件")
            code_files = []
            for fp in key_files:
                content = gh.file_content(owner, repo, fp)
                if content and len(content.strip()) > 50:
                    code_files.append({"path": fp, "content": content})
                    print(f"     + {fp} ({len(content)} 字符)")
                time.sleep(0.3)
            if not code_files:
                print("  [警告] 未获取到代码文件，跳过")
                failed += 1
                results.append({"full_name": full_name, "status": "no_code", "doc_path": ""})
                continue
            readme = gh.readme(owner, repo)
            if readme:
                print(f"  -> README: {len(readme)} 字符")

        # ---- 调用 LLM 生成文档 ----
        print(f"  -> 调用 {args.model} 生成文档...")
        doc = llm.chat(SYSTEM_PROMPT, build_user_prompt(repo_info, code_files, readme))
        if not doc:
            print("  [错误] 文档生成失败")
            failed += 1
            results.append({"full_name": full_name, "status": "gen_failed",
                            "doc_path": str(doc_path)})
            continue

        # ---- 保存 ----
        doc_path.parent.mkdir(parents=True, exist_ok=True)
        doc_path.write_text(
            f"<!-- 由 docgen 自动生成 -->\n"
            f"<!-- 仓库: {full_name} -->\n"
            f"<!-- 模型: {args.model} -->\n"
            f"<!-- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')} -->\n\n{doc}",
            encoding="utf-8",
        )
        print(f"  -> 已保存: {doc_path} ({len(doc)} 字符)")
        success += 1
        results.append({"full_name": full_name, "status": "ok", "doc_path": str(doc_path)})
        time.sleep(args.delay)

    print(f"\n{'=' * 60}")
    print(f"完成！成功: {success}，跳过: {skipped}，失败: {failed}")
    print(f"{'=' * 60}")

    if local_mode:
        result_csv = write_csv(out_dir / "docgen_results.csv", results,
                               ["full_name", "status", "doc_path"])
        print(f"结果清单: {result_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
