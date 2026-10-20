#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fetch 'clone' repos via codeload tarball, smallest-first, with hard per-repo timeout.
通过 codeload 下载 tar.gz，小仓库优先，并对每个仓库设硬超时（150s）避免卡死。
"""
import os, time, io, tarfile, threading, urllib.request, urllib.error, http.client
from pathlib import Path
import tempfile

# 缓存根目录（%TEMP%\mcp_scan_cache，动态获取，可移植）
CACHE_ROOT = Path(tempfile.gettempdir()) / "mcp_scan_cache"

# (full_name, 分支, 缓存目录, 仓库大小KB)  -- 按大小升序排列（小仓库优先拉取）
REPOS = [
  ("tadata-org/fastapi_mcp", "main", str(CACHE_ROOT / "tadata-org_fastapi_mcp"), 423),
  ("duty1g/x64dbg-mcp-server", "main", str(CACHE_ROOT / "duty1g_x64dbg-mcp-server"), 1756),
  ("mobile-next/mobile-mcp", "main", str(CACHE_ROOT / "mobile-next_mobile-mcp"), 2990),
  ("jacob-bd/gemini-notebook-mcp-cli", "main", str(CACHE_ROOT / "jacob-bd_gemini-notebook-mcp-cli"), 4338),
  ("snyk/agent-scan", "main", str(CACHE_ROOT / "snyk_agent-scan"), 5584),
  ("modelcontextprotocol/csharp-sdk", "main", str(CACHE_ROOT / "modelcontextprotocol_csharp-sdk"), 6587),
  ("54yyyu/zotero-mcp", "main", str(CACHE_ROOT / "54yyyu_zotero-mcp"), 8017),
  ("cheshire-cat-ai/core", "main", str(CACHE_ROOT / "cheshire-cat-ai_core"), 15848),
  ("zhayujie/CowAgent", "master", str(CACHE_ROOT / "zhayujie_CowAgent"), 17199),
  ("nowork-studio/notfair-plugin", "main", str(CACHE_ROOT / "nowork-studio_notfair-plugin"), 21120),
  ("lastmile-ai/mcp-agent", "main", str(CACHE_ROOT / "lastmile-ai_mcp-agent"), 27351),
  ("yamadashy/repomix", "main", str(CACHE_ROOT / "yamadashy_repomix"), 29588),
  ("upstash/context7", "master", str(CACHE_ROOT / "upstash_context7"), 37854),
  ("creativetimofficial/ui", "main", str(CACHE_ROOT / "creativetimofficial_ui"), 60696),
  ("assafelovic/gpt-researcher", "main", str(CACHE_ROOT / "assafelovic_gpt-researcher"), 54737),
  ("AstrBotDevs/AstrBot", "master", str(CACHE_ROOT / "AstrBotDevs_AstrBot"), 74094),
  ("headroomlabs-ai/headroom", "main", str(CACHE_ROOT / "headroomlabs-ai_headroom"), 83954),
  ("rocketride-org/rocketride-server", "develop", str(CACHE_ROOT / "rocketride-org_rocketride-server"), 121340),
]
UA = {"User-Agent": "mcp-scan-shard4"}  # 请求头
# 临时 tarball 存放目录（%TEMP%\mcp_scan_cache\_tmp_tarballs）
TMP = CACHE_ROOT / "_tmp_tarballs"
TMP.mkdir(parents=True, exist_ok=True)


def download_to(url, dest, hold=150):
    """在后台线程下载到文件，主线程等待最多 hold 秒；超时则放弃（防止卡死）。

    返回 (是否成功, 错误信息或 'unknown'/'timeout')。
    """
    box = {}  # 线程间结果传递容器
    def worker():  # 后台下载线程
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=30) as r, open(dest, "wb") as f:
                while True:
                    b = r.read(1 << 16)  # 分块写入
                    if not b:
                        break
                    f.write(b)
            box["ok"] = True
        except Exception as e:
            box["err"] = str(e)
    t = threading.Thread(target=worker, daemon=True)  # 守护线程
    t.start(); t.join(hold)  # 主线程等待上限
    if t.is_alive():  # 超时仍在下载
        return False, "timeout"
    return box.get("ok", False), box.get("err", "unknown")


def extract(tgz, cache):
    """解包 tar.gz 到缓存目录（去掉首层目录），返回解出的文件数。"""
    os.makedirs(cache, exist_ok=True)
    tf = tarfile.open(tgz, "r:gz")
    members = tf.getmembers()
    n = 0  # 解包文件计数
    for m in members:
        parts = m.name.split("/", 1)
        if len(parts) < 2 or not parts[1]:  # 去掉首层（repo-branch/）
            continue
        if m.isdir():
            os.makedirs(os.path.join(cache, parts[1]), exist_ok=True)
        elif m.isfile():
            target = os.path.join(cache, parts[1])
            os.makedirs(os.path.dirname(target), exist_ok=True)
            f = tf.extractfile(m)
            if f is None: continue
            with open(target, "wb") as out:  # 写文件
                out.write(f.read())
            n += 1
    tf.close()
    return n


def main():
    summ = {}  # 各仓库拉取结果
    for full, branch, cache, sz in REPOS:
        p = Path(cache)
        # 已落盘且文件数>5 → 跳过
        if p.exists() and len(list(p.rglob("*"))) > 5:
            print(f"=== {full} populated, skip ===", flush=True)
            summ[full] = "skip"; continue
        print(f"=== {full} (size_kb={sz}) ===", flush=True)
        url = f"https://codeload.github.com/{full}/tar.gz/refs/heads/{branch}"
        tgz = TMP / (full.replace("/", "_") + ".tar.gz")  # 临时 tarball 文件
        ok, err = download_to(url, str(tgz), hold=150)  # 硬超时下载
        if not ok:
            print(f"  download failed: {err}", flush=True)
            try: tgz.unlink()
            except Exception: pass
            summ[full] = f"dl_failed:{err}"
            continue
        mb = tgz.stat().st_size / 1e6  # 大小（MB）
        try:
            n = extract(str(tgz), cache)  # 解包
            print(f"  OK {mb:.1f}MB extracted {n} files", flush=True)
            summ[full] = f"ok n={n}"
        except Exception as e:
            print(f"  extract failed: {e}", flush=True)
            summ[full] = f"extract_failed:{e}"
        finally:
            try: tgz.unlink()  # 删除临时 tarball
            except Exception: pass
    print("=== SUMMARY ===", flush=True)
    for k, v in summ.items(): print(k, v, flush=True)


if __name__ == "__main__":
    main()  # 程序入口
