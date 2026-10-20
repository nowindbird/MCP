#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fetch 'clone' repos via codeload tarball (git protocol unreachable), extract to cache_dir.
通过 codeload 下载 tar.gz 整仓并解包到缓存目录（git 协议不可达时的备选通道）。
"""
import os, sys, time, io, tarfile, urllib.request, urllib.error, http.client
from pathlib import Path
import tempfile

# 缓存根目录（%TEMP%\mcp_scan_cache，动态获取，可移植）
CACHE_ROOT = Path(tempfile.gettempdir()) / "mcp_scan_cache"

# 待拉取仓库列表：(full_name, 默认分支, 缓存目录)
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


def download(url, retries=4):
    """下载整个文件到内存（bytes）。带重试；IncompleteRead/异常时退避重试。"""
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=120) as r:
                chunks = []
                while True:  # 分块读取（每次 1MB），避免一次性载入超大文件
                    b = r.read(1 << 20)
                    if not b:
                        break
                    chunks.append(b)
                return b"".join(chunks)
        except (http.client.IncompleteRead, Exception) as e:
            print(f"    download err {type(e).__name__}: {e} (try {i+1})")
            time.sleep(5 * (i + 1))  # 递增退避
    return None


def main():
    results = {}  # 各仓库拉取结果
    for full, branch, cache in REPOS:
        name = full.split("/")[-1]
        # 缓存已非空 → 跳过（断点续跑）
        if Path(cache).exists() and any(Path(cache).iterdir()):
            print(f"=== {full} already populated, skip ===")
            results[full] = "skip_existing"
            continue
        print(f"=== {full} ({branch}) ===")
        os.makedirs(cache, exist_ok=True)  # 创建缓存目录
        url = f"https://codeload.github.com/{full}/tar.gz/refs/heads/{branch}"  # codeload tarball 地址
        data = download(url)
        if not data:  # 下载失败
            print("  DOWNLOAD FAILED")
            results[full] = "download_failed"
            continue
        print(f"  tarball {len(data)/1e6:.1f} MB, extracting")
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")  # 内存中打开 tar.gz
            members = tf.getmembers()
            # 去掉首层目录（repo-branch/），手动解包到缓存目录
            for m in members:
                parts = m.name.split("/", 1)
                if len(parts) < 2 or not parts[1]:
                    continue
                target = os.path.join(cache, parts[1])  # 去掉首层后的目标路径
                if m.isdir():
                    os.makedirs(target, exist_ok=True)
                elif m.isfile():
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    f = tf.extractfile(m)
                    if f is None:
                        continue
                    with open(target, "wb") as out:  # 写文件
                        out.write(f.read())
            tf.close()
            results[full] = f"ok ({len(members)} members)"
            print(f"  OK extracted {len(members)} members")
        except Exception as e:
            print(f"  EXTRACT FAILED: {e}")
            results[full] = f"extract_failed: {e}"
    print("=== SUMMARY ===")
    for k, v in results.items():
        print(k, v)


if __name__ == "__main__":
    main()  # 程序入口
