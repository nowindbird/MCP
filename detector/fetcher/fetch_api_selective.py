#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_selective fetcher: 对平台级大仓库，通过 GitHub REST tree + raw 仅拉取 MCP 攻击面相关文件。

适用场景：仓库过大（PostHog 7GB 等）无法整仓克隆时，按"MCP 相关文件/README/清单/入口脚本"
规则精选文件落盘，供静态扫描器使用。只覆盖 MCP 相关子集，不等同于全仓审查。
"""
import json, os, sys, time, re, urllib.request, urllib.error, http.client
from pathlib import Path
import tempfile

# 缓存根目录（%TEMP%\mcp_scan_cache，动态获取，可移植）
CACHE_ROOT = Path(tempfile.gettempdir()) / "mcp_scan_cache"

# 待拉取仓库列表：(full_name, 默认分支, 缓存目录)
REPOS = [
    ("googleapis/mcp-toolbox", "main", str(CACHE_ROOT / "googleapis_mcp-toolbox")),
    ("ruvnet/ruflo", "main", str(CACHE_ROOT / "ruvnet_ruflo")),
    ("reactive-resume/reactive-resume", "main", str(CACHE_ROOT / "reactive-resume_reactive-resume")),
    ("budtmo/docker-android", "master", str(CACHE_ROOT / "budtmo_docker-android")),
    ("bytedance/UI-TARS-desktop", "main", str(CACHE_ROOT / "bytedance_UI-TARS-desktop")),
    ("t8y2/dbx", "main", str(CACHE_ROOT / "t8y2_dbx")),
]

UA = {"User-Agent": "mcp-scan-shard4", "Accept": "application/vnd.github+json"}  # 请求头
ENTRY_NAMES = {"server.py", "mcp_server.py", "main.py", "cli.py", "index.ts", "index.js"}  # 入口脚本名
ROOT_KEY_FILES = {"package.json", "pyproject.toml", "setup.py", "setup.cfg", "cargo.toml", "go.mod",
                  ".env.example", "dockerfile", ".mcp.json"}  # 根级关键清单文件
KEY_DIRS = ("packages/", "src/", "mcp/", "server/", "servers/", "tools/", "agent/", "lib/", "core/")  # 关键目录前缀


def http_get(url, binary=False, retries=3):
    """发起 GET 请求，带速率限制退避与重试。

    - 403/429（速率受限）：按 20*(i+1) 秒递增等待后重试
    - IncompleteRead：大文件/大树响应被截断时，抢救已到达的部分字节
    - 其他异常：等待 3 秒后重试
    返回 bytes（binary=True）或解码后的 str；失败返回 None。
    """
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
                return data if binary else data.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):  # 速率限制
                wait = 20 * (i + 1)
                print(f"  rate limited {e.code}, sleep {wait}s")
                time.sleep(wait)
                continue
            print(f"  HTTP {e.code} for {url}")
            return None
        except http.client.IncompleteRead as e:
            # 大 tree 常被截断；抢救已到达的字节
            partial = getattr(e, "partial", b"")
            if partial:
                print(f"  IncompleteRead salvaged {len(partial)} bytes")
                return partial if binary else partial.decode("utf-8", errors="replace")
            time.sleep(3)
        except Exception as e:
            print(f"  err {e} for {url}")
            time.sleep(3)
    return None


def fetch_tree(full, branch):
    """获取仓库递归文件树，返回 blob 文件的 path 列表。

    优先严格 JSON 解析；tree 被截断时用正则从部分 JSON 中抢救 path 字段。
    """
    url = f"https://api.github.com/repos/{full}/git/trees/{branch}?recursive=1"
    txt = http_get(url)
    if not txt:
        return None
    paths = []
    try:
        j = json.loads(txt)  # 严格 JSON 解析
        if j.get("truncated"):
            print("  WARN: tree truncated by GitHub")
        paths = [t["path"] for t in j.get("tree", []) if t.get("type") == "blob"]  # 只取文件
    except Exception:
        # 从部分 JSON 中用正则抢救 path
        paths = re.findall(r'"path"\s*:\s*"([^"]+)"', txt)
        print(f"  parsed tree via regex, {len(paths)} paths")
    return paths


def select(paths):
    """从文件树中筛选出 MCP 攻击面相关文件，并做数量上限控制。"""
    chosen = []
    chosen_set = set()
    def add(p):  # 去重添加
        if p not in chosen_set:
            chosen_set.add(p); chosen.append(p)
    for p in paths:
        pl = p.lower()
        base = pl.rsplit("/", 1)[-1]  # 文件名
        # 1) 路径含 "mcp" 的文件全部保留
        if "mcp" in pl:
            add(p); continue
        # 2) README 文档
        if base.startswith("readme"):
            add(p); continue
        # 3) 关键清单文件（任意深度）
        if base in ("package.json", "pyproject.toml", "setup.py", "setup.cfg", "cargo.toml", "go.mod"):
            add(p); continue
        if base.startswith("requirements") and base.endswith(".txt"):  # requirements.txt
            add(p); continue
        if base.endswith(".mcp.json") or base == ".env.example":  # MCP 配置 / 环境变量样例
            add(p); continue
        if base.startswith("skill") and base.endswith(".md"):  # skill 文档
            add(p); continue
        if base == "dockerfile" or base.endswith("/dockerfile"):  # Dockerfile
            add(p); continue
        # 4) 入口脚本：位于根目录或关键目录下
        if base in ENTRY_NAMES:
            if "/" not in p or any(pl.startswith(d) for d in KEY_DIRS):
                add(p); continue
    # 数量上限：最多 150 个文件，优先保留含 mcp 的文件
    if len(chosen) > 150:
        mcp = [p for p in chosen if "mcp" in p.lower()]
        rest = [p for p in chosen if p not in mcp]
        chosen = mcp + rest
        chosen = chosen[:150]
    return chosen


def main():
    summary = {}  # 各仓库拉取结果汇总
    for full, branch, cache in REPOS:
        print(f"=== {full} ===")
        os.makedirs(cache, exist_ok=True)  # 创建缓存目录
        paths = fetch_tree(full, branch)
        time.sleep(1)
        if not paths:  # 文件树获取失败
            print("  TREE FETCH FAILED")
            summary[full] = (0, 0, "tree_failed")
            continue
        chosen = select(paths)  # 筛选关键文件
        print(f"  tree files={len(paths)} chosen={len(chosen)}")
        ok = 0; fail = 0
        for p in chosen:  # 逐个下载 raw 内容
            url = f"https://raw.githubusercontent.com/{full}/{branch}/{p}"
            data = http_get(url, binary=True)
            if data is None:
                fail += 1; continue
            dest = Path(cache) / p  # 落盘路径（保持相对目录结构）
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                dest.write_bytes(data)
                ok += 1
            except Exception as e:
                print(f"  write err {p}: {e}")
                fail += 1
            time.sleep(0.15)  # 礼貌延迟，避免次级限流
        summary[full] = (ok, fail, "ok")
        print(f"  downloaded ok={ok} fail={fail}")
    print("=== SUMMARY ===")
    for k, v in summary.items():
        print(k, v)


if __name__ == "__main__":
    main()  # 程序入口
