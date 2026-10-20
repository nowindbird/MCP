#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unified tree+raw fetcher for the 19 'clone' repos (git/codeload stalled).
Download all scannable source files via raw.githubusercontent."""
import os, re, time, json, tarfile, io, urllib.request, urllib.error, http.client
from pathlib import Path
import tempfile

# 缓存根目录（%TEMP%\mcp_scan_cache，动态获取，可移植）
CACHE_ROOT = Path(tempfile.gettempdir()) / "mcp_scan_cache"

# 待拉取仓库列表：(full_name, 默认分支, 缓存目录)
# 来源：原 "clone" 分组 19 个仓库（git 协议/codeload 曾卡死，改走 tree+raw）
REPOS = [
  ("rocketride-org/rocketride-server", "develop", str(CACHE_ROOT / "rocketride-org_rocketride-server")),
  ("headroomlabs-ai/headroom", "main", str(CACHE_ROOT / "headroomlabs-ai_headroom")),
  ("AstrBotDevs/AstrBot", "master", str(CACHE_ROOT / "AstrBotDevs_AstrBot")),
  ("creativetimofficial/ui", "main", str(CACHE_ROOT / "creativetimofficial_ui")),
  ("assafelovic/gpt-researcher", "main", str(CACHE_ROOT / "assafelovic_gpt-researcher")),
  ("upstash/context7", "master", str(CACHE_ROOT / "upstash_context7")),
  ("yamadashy/repomix", "main", str(CACHE_ROOT / "yamadashy_repomix")),
  ("lastmile-ai/mcp-agent", "main", str(CACHE_ROOT / "lastmile-ai_mcp-agent")),
  ("nowork-studio/notfair-plugin", "main", str(CACHE_ROOT / "nowork-studio_notfair-plugin")),
  ("zhayujie/CowAgent", "master", str(CACHE_ROOT / "zhayujie_CowAgent")),
  ("cheshire-cat-ai/core", "main", str(CACHE_ROOT / "cheshire-cat-ai_core")),
  ("oraios/serena", "main", str(CACHE_ROOT / "oraios_serena")),
  ("54yyyu/zotero-mcp", "main", str(CACHE_ROOT / "54yyyu_zotero-mcp")),
  ("modelcontextprotocol/csharp-sdk", "main", str(CACHE_ROOT / "modelcontextprotocol_csharp-sdk")),
  ("snyk/agent-scan", "main", str(CACHE_ROOT / "snyk_agent-scan")),
  ("jacob-bd/gemini-notebook-mcp-cli", "main", str(CACHE_ROOT / "jacob-bd_gemini-notebook-mcp-cli")),
  ("mobile-next/mobile-mcp", "main", str(CACHE_ROOT / "mobile-next_mobile-mcp")),
  ("duty1g/x64dbg-mcp-server", "main", str(CACHE_ROOT / "duty1g_x64dbg-mcp-server")),
  ("tadata-org/fastapi_mcp", "main", str(CACHE_ROOT / "tadata-org_fastapi_mcp")),
]

UA = {"User-Agent": "mcp-scan-shard4"}  # 请求头
# 参与扫描的文件扩展名
SCAN_EXTS = {".py",".pyi",".js",".mjs",".cjs",".ts",".tsx",".jsx",".go",".rs",".sh",".bash",".ps1",
 ".rb",".java",".cs",".c",".cpp",".cc",".h",".hpp",".zig",".md",".markdown",".json",".yaml",".yml",
 ".toml",".ini",".cfg",".txt",".html",".htm",".sql",".lua",".php",".swift",".kt",".pl",".env"}
# 需要跳过的目录（任意层级的路径段）
SKIP_DIR_PARTS = {".git","node_modules","__pycache__",".venv","venv","dist","build",".next",".cache",
 "vendor","testdata",".github","docs","images","img","assets","fonts","coverage",".turbo",".gradle"}
# 无标准扩展名但需要保留的特殊文件
SPECIAL = {"dockerfile","makefile",".env.example",".mcp.json"}


def http_get(url, binary=True, retries=3):
    """GET 请求，带速率限制退避、404 处理与 IncompleteRead 抢救。

    默认返回原始 bytes；403/429 按 15*(i+1) 秒退避；404 返回 None。
    """
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=45) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:  # 文件不存在
                return None
            if e.code in (403,429):  # 速率限制
                time.sleep(15*(i+1)); continue
            return None
        except http.client.IncompleteRead as e:  # 响应截断，抢救部分字节
            p = getattr(e, "partial", b"")
            if p: return p
            time.sleep(3)
        except Exception:
            time.sleep(2*(i+1))
    return None


def fetch_tree(full, branch):
    """获取仓库递归文件树，返回文件 path 列表（JSON 解析失败用正则兜底）。"""
    url = f"https://api.github.com/repos/{full}/git/trees/{branch}?recursive=1"
    data = http_get(url)
    if not data: return []
    txt = data.decode("utf-8", errors="replace")
    paths = []
    try:
        j = json.loads(txt)
        paths = [t["path"] for t in j.get("tree",[]) if t.get("type")=="blob"]
    except Exception:
        # 正则配对 "path":"X" 与 "type":"blob"
        for m in re.finditer(r'"path"\s*:\s*"([^"]+)"[^}]*?"type"\s*:\s*"blob"', txt):
            paths.append(m.group(1))
    return paths


def want(path):
    """判断文件是否应下载：不在跳过目录、是特殊文件/README 或扩展名可扫描。"""
    pl = path.lower()
    parts = pl.split("/")
    if any(p in SKIP_DIR_PARTS for p in parts[:-1]):  # 任一路径段命中跳过目录
        return False
    base = parts[-1]  # 文件名
    if base in SPECIAL or base.startswith("readme"):  # 特殊文件 / README
        return True
    ext = os.path.splitext(base)[1]
    return ext in SCAN_EXTS  # 扩展名可扫描


def main():
    summ = {}  # 各仓库拉取结果
    for full, branch, cache in REPOS:
        print(f"=== {full} ===", flush=True)
        # 已落盘且文件数>5 → 跳过（断点续跑）
        if Path(cache).exists() and len(list(Path(cache).rglob("*"))) > 5:
            print("  already populated, skip", flush=True)
            summ[full] = "skip"
            continue
        os.makedirs(cache, exist_ok=True)  # 创建缓存目录
        paths = fetch_tree(full, branch)   # 获取文件树
        time.sleep(1)
        chosen = [p for p in paths if want(p)]  # 筛选可下载文件
        if len(chosen) > 400:  # 数量上限 400
            chosen = chosen[:400]
        print(f"  tree={len(paths)} chosen={len(chosen)}", flush=True)
        ok=0; fail=0
        for p in chosen:  # 逐个下载 raw 内容
            url = f"https://raw.githubusercontent.com/{full}/{branch}/{p}"
            data = http_get(url)
            if data is None:
                fail += 1; continue
            dest = Path(cache)/p  # 落盘（保持相对目录结构）
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                dest.write_bytes(data); ok += 1
            except Exception:
                fail += 1
            time.sleep(0.08)  # 礼貌延迟
        summ[full] = f"ok={ok} fail={fail}"
        print(f"  done ok={ok} fail={fail}", flush=True)
    print("=== SUMMARY ===", flush=True)
    for k,v in summ.items(): print(k, v, flush=True)


if __name__ == "__main__":
    main()  # 程序入口
