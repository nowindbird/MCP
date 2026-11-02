#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仓库代码获取（统一 fetcher）
============================
重构前这里有 5 个一次性脚本（fetch_tarballs / fetch_tarballs2 / fetch_small_repos /
fetch_retry / fetch_api_selective）——每个都自带一份写死的 REPOS 清单、一份几乎相同的
下载/重试/解包逻辑，还有各自的 "shard4" UA，既无法复用也无法维护。

现在合并成一个**清单驱动**的 fetcher：

* ``--manifest`` 读 CSV（每行一个仓库，可带 branch / cache_dir），或 ``--repos`` 直接指定；
* 两条获取通道，``--method auto`` 先 tarball 失败再回退 tree+raw：
    - ``tarball``: codeload tar.gz 整仓下载（快，含全量文件），**带硬超时**防止挂死；
    - ``tree``   : GitHub tree API 列文件 + raw 逐个下载（仓库过大时的精选通道）；
* 断点续跑：缓存目录非空即跳过（``--force`` 覆盖）；
* 结果写回 ``<cache-root>/fetch_manifest.csv``，列口径可直接喂给
  ``python -m detector.cli scan --manifest ...``。

网络客户端、缓存路径、扫描口径全部来自 ``detector.deps``。

用法::

    python -m detector.cli fetch --manifest output/scan_manifest.csv
    python -m detector.cli fetch --repos modelcontextprotocol/servers --method tarball
    python -m detector.cli fetch --manifest m.csv --branch main --workers 4 --force
"""

import argparse
import sys
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from detector.deps import (
    CACHE_ROOT,
    FETCH_CONFIG,
    GITHUB_CONFIG,
    SKIP_DIRS,
    GitHubClient,
    MissingDependency,
    ensure_dir,
    ensure_utf8_stdio,
    is_scannable_file,
    read_text,
    write_csv,
    write_json,
)

# tree 通道最多下载的文件数（防止超大仓库把树遍历变成无底洞）
MAX_TREE_FILES = 2000


# ---------------------------------------------------------------------------
# 清单解析
# ---------------------------------------------------------------------------
def _split_repo(full_name: str) -> Optional[tuple]:
    """``owner/repo`` → (owner, repo)；非法返回 None。"""
    parts = [p for p in full_name.strip().split("/") if p]
    return (parts[0], parts[1]) if len(parts) >= 2 else None


def parse_manifest(path: Path | str) -> List[Dict[str, Any]]:
    """读取清单 CSV（``full_name`` 必需；branch/cache_dir 可选）。"""
    import csv

    text = read_text(path)
    if text is None:
        raise FileNotFoundError(path)
    rows = list(csv.DictReader(text.splitlines()))
    items = []
    for row in rows:
        full_name = (row.get("full_name") or row.get("repo") or "").strip()
        if not full_name or not _split_repo(full_name):
            continue
        items.append({
            "full_name": full_name,
            "branch": (row.get("branch") or "").strip(),
            "cache_dir": (row.get("cache_dir") or "").strip(),
            "size_kb": row.get("size_kb") or 0,
            "stars": row.get("stars") or 0,
            "language": row.get("language") or "",
        })
    return items


def _cache_dir_for(item: Dict[str, Any], cache_root: Path) -> Path:
    """缓存目录：清单里显式指定的优先，否则 <cache_root>/<owner>_<repo>。"""
    if item.get("cache_dir"):
        return Path(item["cache_dir"])
    return cache_root / item["full_name"].replace("/", "_")


# ---------------------------------------------------------------------------
# 通道 1：codeload tarball（整仓，硬超时）
# ---------------------------------------------------------------------------
def _safe_extract(archive: Path, dest: Path) -> int:
    """解包 tar.gz 到 dest（去掉顶层目录），拒绝路径穿越；返回解出的文件数。"""
    count = 0
    dest = dest.resolve()
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            # 去掉 codeload 包内的 "<repo>-<sha>/" 顶层目录
            rel = member.name.split("/", 1)[1] if "/" in member.name else ""
            if not rel:
                continue
            target = (dest / rel).resolve()
            if dest not in target.parents:  # 路径穿越防护
                continue
            src = tf.extractfile(member)
            if src is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(src.read())
            count += 1
    return count


def fetch_tarball(client: GitHubClient, owner: str, repo: str, branch: str,
                  dest: Path) -> Dict[str, Any]:
    """整仓 tarball 下载并解包；失败返回 error。"""
    ref = branch or "HEAD"
    url = client.tarball_url(owner, repo, ref)
    ensure_dir(dest)
    with tempfile.TemporaryDirectory(dir=str(dest.parent)) as tmp:
        archive = Path(tmp) / f"{repo}.tar.gz"
        ok, err = client.download_to_file(
            url, archive, hard_timeout=FETCH_CONFIG["hard_timeout"])
        if not ok:
            return {"status": "failed", "method": "tarball", "error": err}
        try:
            files = _safe_extract(archive, dest)
        except (tarfile.TarError, OSError) as e:
            return {"status": "failed", "method": "tarball", "error": str(e)}
    return {"status": "ok" if files else "empty", "method": "tarball", "files": files}


# ---------------------------------------------------------------------------
# 通道 2：tree + raw（只取可扫描文件，适合超大仓库）
# ---------------------------------------------------------------------------
def _is_wanted(path: str) -> bool:
    """tree 里的路径是否需要下载（跳过噪声目录 + 非扫描文件）。

    目录口径直接复用 deps 的 SKIP_DIRS，与 scanner / docgen 保持一致。
    """
    parts = Path(path).parts
    if any(p.lower() in SKIP_DIRS for p in parts[:-1]):
        return False
    return is_scannable_file(Path(path))


def fetch_tree(client: GitHubClient, owner: str, repo: str, branch: str,
               dest: Path, max_files: int = MAX_TREE_FILES) -> Dict[str, Any]:
    """按 tree 列出的可扫描文件逐个 raw 下载。"""
    tree = client.repo_tree(owner, repo, branch or "HEAD")
    if not tree:
        return {"status": "failed", "method": "tree", "error": "tree 为空"}
    wanted = [item["path"] for item in tree
              if item.get("type") == "blob" and item.get("path") and _is_wanted(item["path"])]
    wanted = wanted[:max_files]
    ensure_dir(dest)
    files = 0
    for rel in wanted:
        content = client.file_content(owner, repo, rel)
        if content is None:
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        files += 1
    return {"status": "ok" if files else "empty", "method": "tree", "files": files}


# ---------------------------------------------------------------------------
# 单仓库获取
# ---------------------------------------------------------------------------
def fetch_one(client: GitHubClient, item: Dict[str, Any], cache_root: Path,
              method: str, force: bool) -> Dict[str, Any]:
    """获取单个仓库，返回带状态的清单行。"""
    full_name = item["full_name"]
    dest = _cache_dir_for(item, cache_root)
    row = {
        "full_name": full_name,
        "cache_dir": str(dest),
        "branch": item.get("branch", ""),
        "method": "",
        "status": "",
        "files": 0,
        "size_kb": item.get("size_kb", 0),
        "stars": item.get("stars", 0),
        "language": item.get("language", ""),
        "error": "",
    }

    # 断点续跑：已有内容直接跳过
    if not force and dest.is_dir() and any(dest.iterdir()):
        row.update(status="skip_existing", method="cached")
        return row

    parts = _split_repo(full_name)
    if not parts:
        row.update(status="failed", error="非法仓库名")
        return row
    owner, repo = parts
    branch = item.get("branch", "")

    attempts = [method] if method in ("tarball", "tree") else ["tarball", "tree"]
    last_err = ""
    for m in attempts:
        try:
            result = (fetch_tarball(client, owner, repo, branch, dest) if m == "tarball"
                      else fetch_tree(client, owner, repo, branch, dest))
        except Exception as e:  # noqa: BLE001 - 单仓库失败不能拖垮整批
            result = {"status": "failed", "method": m, "error": f"{type(e).__name__}: {e}"}
        if result["status"] in ("ok", "empty"):
            row.update(status=result["status"], method=m, files=result.get("files", 0))
            return row
        last_err = result.get("error", "")
        print(f"  [{full_name}] {m} 失败: {last_err}")

    row.update(status="failed", error=last_err)
    return row


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description="MCP 仓库代码获取（tarball / tree+raw）")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--manifest", help="清单 CSV（需含 full_name，可选 branch/cache_dir）")
    src.add_argument("--repos", nargs="+", help="直接指定 owner/repo（可多个）")
    ap.add_argument("--branch", default="", help="--repos 模式的默认分支")
    ap.add_argument("--method", choices=["auto", "tarball", "tree"],
                    default=FETCH_CONFIG["method"], help="获取通道（默认 auto）")
    ap.add_argument("--cache-root", default=str(CACHE_ROOT), help="缓存根目录")
    ap.add_argument("--workers", type=int, default=FETCH_CONFIG["workers"],
                    help="并发仓库数")
    ap.add_argument("--force", action="store_true", help="忽略已有缓存重新获取")
    ap.add_argument("--token", default=GITHUB_CONFIG["token"],
                    help="GitHub Token（也可用 GITHUB_TOKEN 环境变量）")
    args = ap.parse_args()

    cache_root = Path(args.cache_root)
    if args.manifest:
        try:
            items = parse_manifest(args.manifest)
        except FileNotFoundError:
            print(f"[错误] 清单不存在: {args.manifest}")
            return 1
    else:
        items = [{"full_name": r, "branch": args.branch} for r in args.repos if _split_repo(r)]
    if not items:
        print("[错误] 清单为空（需要 full_name 列，或 --repos owner/repo）")
        return 1

    try:
        client = GitHubClient(token=args.token or None)
    except MissingDependency as e:
        print(f"[错误] {e}")
        return 1

    print(f"[fetch] 目标 {len(items)} 个仓库，通道={args.method}，缓存根={cache_root}，"
          f"并发={args.workers}")
    rows: List[Dict[str, Any]] = []
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {pool.submit(fetch_one, client, item, cache_root, args.method, args.force): item
                   for item in items}
        for fut in as_completed(futures):
            row = fut.result()
            rows.append(row)
            done += 1
            print(f"[{done}/{len(items)}] {row['full_name']}: {row['status']} "
                  f"{row['method']} files={row['files']}"
                  + (f" err={row['error']}" if row["error"] else ""))

    rows.sort(key=lambda r: r["full_name"])
    ok = sum(1 for r in rows if r["status"] in ("ok", "empty", "skip_existing"))
    failed = len(rows) - ok
    manifest_out = ensure_dir(cache_root) / "fetch_manifest.csv"
    write_csv(manifest_out, rows)
    write_json(manifest_out.with_suffix(".json"), rows)
    print(f"\n[fetch] 完成：成功/已存在 {ok}，失败 {failed}")
    print(f"[fetch] 清单: {manifest_out}")
    print("[fetch] 下一步: python -m detector.cli scan --manifest "
          f"{manifest_out} --out-dir output/scan_results")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
