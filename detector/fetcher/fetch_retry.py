#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Retry missing/thin repos via codeload tarball, 300s per-repo hold.
针对缺失/文件过少的仓库，通过 codeload tarball 重试拉取，每仓库硬超时 300s。
"""
import os, time, tarfile, threading, urllib.request
from pathlib import Path
import tempfile

# 缓存根目录（%TEMP%\mcp_scan_cache，动态获取，可移植）
CACHE_ROOT = Path(tempfile.gettempdir()) / "mcp_scan_cache"

# 待重试仓库列表：(full_name, 默认分支, 缓存目录)
REPOS = [
  ("oraios/serena", "main", str(CACHE_ROOT / "oraios_serena")),
  ("lastmile-ai/mcp-agent", "main", str(CACHE_ROOT / "lastmile-ai_mcp-agent")),
  ("yamadashy/repomix", "main", str(CACHE_ROOT / "yamadashy_repomix")),
  ("upstash/context7", "master", str(CACHE_ROOT / "upstash_context7")),
  ("assafelovic/gpt-researcher", "main", str(CACHE_ROOT / "assafelovic_gpt-researcher")),
  ("creativetimofficial/ui", "main", str(CACHE_ROOT / "creativetimofficial_ui")),
  ("headroomlabs-ai/headroom", "main", str(CACHE_ROOT / "headroomlabs-ai_headroom")),
  ("zhayujie/CowAgent", "master", str(CACHE_ROOT / "zhayujie_CowAgent")),
  ("rocketride-org/rocketride-server", "develop", str(CACHE_ROOT / "rocketride-org_rocketride-server")),
]
UA = {"User-Agent": "mcp-scan-shard4"}  # 请求头
# 临时 tarball 存放目录（%TEMP%\mcp_scan_cache\_tmp_tarballs2）
TMP = CACHE_ROOT / "_tmp_tarballs2"
TMP.mkdir(parents=True, exist_ok=True)


def download_to(url, dest, hold=300):
    """后台线程下载到文件，主线程最多等待 hold 秒；超时则放弃（防止卡死）。

    返回 (是否成功, 错误信息或 '?'/'timeout')。
    """
    box = {}  # 线程间结果容器
    def worker():  # 后台下载线程
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=30) as r, open(dest, "wb") as f:
                while True:
                    b = r.read(1 << 16)  # 分块写入
                    if not b: break
                    f.write(b)
            box["ok"] = True
        except Exception as e:
            box["err"] = str(e)
    t = threading.Thread(target=worker, daemon=True)  # 守护线程
    t.start(); t.join(hold)  # 等待上限
    if t.is_alive(): return False, "timeout"  # 超时
    return box.get("ok", False), box.get("err", "?")


def extract(tgz, cache):
    """解包 tar.gz 到缓存目录（去掉首层目录），返回文件数。"""
    os.makedirs(cache, exist_ok=True)
    tf = tarfile.open(tgz, "r:gz")
    n = 0  # 解包文件计数
    for m in tf.getmembers():
        parts = m.name.split("/", 1)
        if len(parts) < 2 or not parts[1]: continue  # 去掉首层
        if m.isdir():
            os.makedirs(os.path.join(cache, parts[1]), exist_ok=True)
        elif m.isfile():
            target = os.path.join(cache, parts[1])
            os.makedirs(os.path.dirname(target), exist_ok=True)
            f = tf.extractfile(m)
            if f is None: continue
            with open(target, "wb") as out: out.write(f.read())  # 写文件
            n += 1
    tf.close()
    return n


def main():
    summ = {}  # 各仓库拉取结果
    for full, branch, cache in REPOS:
        print(f"=== {full} ===", flush=True)
        url = f"https://codeload.github.com/{full}/tar.gz/refs/heads/{branch}"
        tgz = TMP / (full.replace("/", "_") + ".tar.gz")  # 临时 tarball 文件
        ok, err = download_to(url, str(tgz), hold=300)  # 300s 硬超时下载
        if not ok:
            print(f"  fail: {err}", flush=True)
            try: tgz.unlink()
            except: pass
            summ[full] = f"fail:{err}"; continue
        mb = tgz.stat().st_size/1e6  # 大小（MB）
        try:
            n = extract(str(tgz), cache)  # 解包
            print(f"  OK {mb:.1f}MB n={n}", flush=True)
            summ[full] = f"ok n={n}"
        except Exception as e:
            print(f"  extract fail: {e}", flush=True)
            summ[full] = f"ex:{e}"
        finally:
            try: tgz.unlink()  # 删除临时文件
            except: pass
    print("=== SUMMARY ===", flush=True)
    for k,v in summ.items(): print(k,v,flush=True)


if __name__ == "__main__":
    main()  # 程序入口
