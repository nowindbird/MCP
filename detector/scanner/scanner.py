#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP 插件静态安全扫描器 (基于论文 "Do Not Mention This to the User" 的方法论)
=======================================================================
三层流水线中的 T2 静态分析实现: 以论文 Table 9 的 14 种攻击模式 + MCP 特有补充
作为统一检测正则, 对已获取到本地的仓库代码做逐文件逐行扫描。

命中仅代表"候选", 需结合语义审查判定意图 (verdict: benign/suspicious/malicious)。

用法:
  python -m detector.scanner.scanner --repo-dir <dir> --repo <full_name> --out <out.json>
       [--language X] [--size-kb N] [--stars N] [--fetch-method M]
  python -m detector.scanner.scanner --manifest <shard.csv> --out-dir <dir>

严重性沿用论文: CRITICAL(E2/PE3/SC2/SC3) > HIGH(E1/P1/P2/P3/SC1) > MEDIUM(E3/E4/P4/PE2) > LOW(PE1)
只做静态读取, 绝不执行被检代码。

文件过滤口径（跳过目录 / 扩展名 / 特殊文件 / 单文件上限）统一来自 ``detector.deps``，
与 fetcher / docgen 等模块共用同一套定义，避免各处口径漂移。
"""

import argparse  # 命令行参数解析
import csv       # CSV 批量清单读取
import json      # JSON 结果序列化 / MCP 配置解析
import re        # 正则匹配
import sys       # stderr / 退出码
from pathlib import Path  # 跨平台路径处理

from detector.deps import (
    EVAL_DENSITY_THRESHOLD,
    MAX_FILE_SIZE_BYTES,
    MAX_LINE_LENGTH,
    SCAN_OUTPUT_DIR,
    ensure_dir,
    iter_repo_files,
    read_text,
    write_json,
)
from detector.ui import print_repo_row

BINARY_BYTES = b"\x00"  # 二进制文件检测用字节

from detector.scanner.patterns import CONFIG_EXTS, PATTERNS
COMPILED_PATTERNS = []
for _pid, _label, _sev, _regex, _flags in PATTERNS:
    try:
        _cre = re.compile(_regex, _flags or 0)
    except re.error:
        continue
    COMPILED_PATTERNS.append((_pid, _label, _sev, _cre))

# P2 特殊处理用正则（模块级预编译）
_RE_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_RE_HTML_COMMENT_INSTR = re.compile(
    r"(?i)(ignore|never|always|must|do not|don't|execute|run|instruction"
    r"|secret|hidden|tell|mention|forget)|忽略|不要|必须|隐藏|执行|指令|之前")
_RE_MD_COMMENT = re.compile(r"\[\s*//\s*\]\s*:\s*#\s*\(([^)]*)\)")
_RE_HIDDEN_UNICODE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_RE_EVAL = re.compile(r"\beval\s*\(")


# ---------------------------------------------------------------------------
# 扫描执行
# ---------------------------------------------------------------------------
def severity_for(pat, path: Path) -> str:
    """按文件类型对部分模式做严重性微调（M3 在配置文件中更可疑）。"""
    pid, _label, sev = pat[0], pat[1], pat[2]
    if pid == "M3":
        # 配置文件中的硬编码凭据 → CRITICAL；普通代码中可能是测试夹具 → MEDIUM
        return "CRITICAL" if path.suffix.lower() in CONFIG_EXTS else "MEDIUM"
    return sev


# 需要额外做结构化 JSON 解析的 MCP 客户端配置文件（正则扫描之外）
MCP_CONFIG_FILENAMES = {
    ".mcp.json",
    "claude_desktop_config.json",
    "mcp.json",
    "mcpServers.json",
    "mcp_config.json",
}

# command/args 中出现的可疑可执行/载荷片段
SUSPICIOUS_CMD_KEYWORDS = (
    "curl", "wget", "python -c", "python -m http", "node -e",
    "bash -c", "sh -c", "powershell", "Invoke-",
    "/tmp/", "/dev/shm/", "base64", "--decode",
    "rm -rf", "chmod 777", "nohup",
)


def scan_mcp_config(path: Path) -> list:
    """结构化解析 MCP 客户端配置（.mcp.json / claude_desktop_config.json 等），
    检查 mcpServers 的 command/args/env 是否存在投毒迹象。

    返回命中列表（与正则命中同格式，可直接并入 hits）。
    """
    try:
        data = json.loads(read_text(path) or "")
    except (TypeError, ValueError):
        return []

    servers = data.get("mcpServers", data) if isinstance(data, dict) else {}
    if not isinstance(servers, dict):
        return []

    hits = []
    for name, conf in servers.items():
        if not isinstance(conf, dict):
            continue
        cmd = str(conf.get("command", "")).lower()
        raw_args = conf.get("args", [])
        args = (" ".join(str(a) for a in raw_args)
                if isinstance(raw_args, list) else str(raw_args))
        env = conf.get("env") or {}

        # ---- command/args 指向可疑可执行（同一 server 只记一条）----
        if any(bad in cmd or bad in args.lower() for bad in SUSPICIOUS_CMD_KEYWORDS):
            hits.append({
                "pattern_id": "M7",
                "label": "MCP配置投毒:mcpServers command/args 可疑",
                "severity": "CRITICAL",
                "file": str(path),
                "line": 0,
                "evidence": f"mcpServers[{name}].command={conf.get('command')} args={args[:200]}",
            })

        # ---- env 注入凭据类变量（同一 server 只记一条）----
        if isinstance(env, dict):
            for k in env:
                if re.search(r"(?i)(api[_-]?key|secret|token|password|credential)", str(k)):
                    hits.append({
                        "pattern_id": "M7",
                        "label": "MCP配置投毒:env 凭据注入",
                        "severity": "CRITICAL",
                        "file": str(path),
                        "line": 0,
                        "evidence": f"mcpServers[{name}].env.{k}=***",
                    })
                    break

    return hits


def scan_file(path: Path) -> list:
    """扫描单个文件，返回 hits 列表。

    流程：读字节 → 过滤超大/二进制/伪装文本 → 解码 → 特殊处理 P2 多行注释与
    不可见 Unicode → 逐行匹配其余 PATTERNS → eval 高密度检测 → 去重。
    """
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return []
    if len(raw) > MAX_FILE_SIZE_BYTES:
        return []
    if BINARY_BYTES in raw[:8192]:  # 前 8KB 含空字节 → 二进制
        return []

    text = raw.decode("utf-8-sig", errors="replace")  # utf-8-sig 顺带剥 BOM
    # 二进制伪装检测：大量替换符说明不是真正文本
    head = text[:4096]
    if head.count("\ufffd") > 50:
        return []

    lines = text.splitlines()
    hits = []

    # ---- P2 特殊处理：HTML 注释(多行)、Markdown 隐藏注释、不可见 Unicode ----
    p2_hits = []
    for m in _RE_HTML_COMMENT.finditer(text):
        inner = m.group(1)
        # 仅当注释内含指令性关键词才记（避免普通注释噪音）
        if _RE_HTML_COMMENT_INSTR.search(inner):
            line_no = text.count("\n", 0, m.start()) + 1
            p2_hits.append(("P2", "隐藏指令:HTML注释内指令", "HIGH", line_no,
                            inner.strip().replace("\n", " ")[:220]))
    for m in _RE_MD_COMMENT.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        p2_hits.append(("P2", "隐藏指令:Markdown隐藏注释", "HIGH", line_no,
                        m.group(1)[:220]))
    hidden = _RE_HIDDEN_UNICODE.search(text)
    if hidden:  # 每文件只记一次，避免爆炸
        line_no = text.count("\n", 0, hidden.start()) + 1
        p2_hits.append(("P2", "隐藏指令:不可见Unicode字符", "HIGH", line_no,
                        repr(text[max(0, hidden.start() - 30):hidden.start() + 30])))
    for pid, label, sev, ln, ev in p2_hits:
        hits.append({"pattern_id": pid, "label": label, "severity": sev,
                     "file": str(path), "line": ln, "evidence": ev})

    # ---- 逐行匹配其余模式（预编译正则，P2 已在上面处理）----
    for idx, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:  # 超长行截断，避免正则回溯过慢
            line = line[:MAX_LINE_LENGTH]
        for pid, label, sev, cre in COMPILED_PATTERNS:
            if pid == "P2":
                continue
            m = cre.search(line)
            if m:
                hits.append({
                    "pattern_id": pid, "label": label,
                    "severity": severity_for((pid, label, sev), path),
                    "file": str(path), "line": idx,
                    "evidence": line.strip()[:260],
                })
                # 不 break：同一行可能同时命中多个模式（如 subprocess + curl|sh）

    # ---- eval 高密度检测（SC3 补充）：一次 finditer 同时拿计数与首位置 ----
    eval_matches = list(_RE_EVAL.finditer(text))
    if len(eval_matches) >= EVAL_DENSITY_THRESHOLD:
        first = text.count("\n", 0, eval_matches[0].start()) + 1
        hits.append({"pattern_id": "SC3", "label": "混淆:eval高密度使用",
                     "severity": "MEDIUM", "file": str(path), "line": first,
                     "evidence": f"eval() 出现 {len(eval_matches)} 次 (>={EVAL_DENSITY_THRESHOLD}), "
                                 f"高混淆密度候选"})

    # ---- 去重: 同文件同行同 pattern 只留一条 ----
    seen, uniq = set(), []
    for h in hits:
        key = (h["pattern_id"], h["file"], h["line"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(h)
    return uniq


def scan_repo(repo_dir: Path):
    """遍历仓库目录，返回 (files_scanned, hits)。

    目录/扩展名过滤由 ``deps.iter_repo_files`` 统一处理；MCP 客户端配置文件
    额外做结构化 JSON 解析（M7 增强）。
    """
    files_scanned = 0
    all_hits = []
    for p in iter_repo_files(repo_dir):
        files_scanned += 1
        try:
            all_hits.extend(scan_file(p))
        except Exception:  # 单文件异常不影响整体扫描
            continue
        if p.name.lower() in MCP_CONFIG_FILENAMES:
            try:
                all_hits.extend(scan_mcp_config(p))
            except Exception:
                continue
    return files_scanned, all_hits


def scan_repo_safe(repo_dir: Path):
    """scan_repo 的异常安全包装：单仓库异常不影响并行扫描整体。"""
    try:
        return scan_repo(repo_dir)
    except Exception as e:
        return 0, [{"pattern_id": "SCAN_ERROR", "label": f"扫描异常: {e}",
                    "severity": "LOW", "file": str(repo_dir), "line": 0,
                    "evidence": str(e)}]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _new_result(repo: str, row: dict, fetch_ok: bool, files_scanned: int,
                hits: list) -> dict:
    """构造单仓库扫描结果（字段口径与 summary / aggregate 一致）。

    清单列名兼容 shard 清单（``fetch_method``）与 fetch 产物（``method``）。
    """
    return {
        "repo": repo,
        "language": row.get("language", "") or "",
        "size_kb": int(row.get("size_kb") or 0),
        "stars": int(row.get("stars") or 0),
        "fetch_method": row.get("fetch_method") or row.get("method") or "",
        "fetch_ok": fetch_ok,
        "files_scanned": files_scanned,
        "hits": hits,
        "verdict": "pending" if fetch_ok else "not_scanned",
        "confidence": 0,
        "reason": "" if fetch_ok else "代码获取失败/目录为空",
        "shadow_features": [],
    }


def main():
    import datetime
    ap = argparse.ArgumentParser(description="MCP 插件静态扫描器")
    # 单仓库模式
    ap.add_argument("--repo-dir", help="单个仓库代码目录（留空且不传 --manifest 时自动扫 dateset/ 全部仓库）")
    ap.add_argument("--repo", default="", help="仓库 full_name")
    ap.add_argument("--out", default="", help="输出 JSON 路径")
    ap.add_argument("--language", default="")
    ap.add_argument("--size-kb", type=int, default=0)
    ap.add_argument("--stars", type=int, default=0)
    ap.add_argument("--fetch-method", default="")
    # 批量模式
    ap.add_argument("--manifest", help="批量模式: shard CSV")
    ap.add_argument("--out-dir", default="", help=f"批量模式: 输出目录（默认 {SCAN_OUTPUT_DIR}）")
    ap.add_argument("--no-timestamp", action="store_true", help="批量模式不自动加时间戳子目录")
    args = ap.parse_args()

    # 智能默认：不传 repo-dir 且不传 manifest → 自动扫 dateset/ 全部子目录
    if not args.repo_dir and not args.manifest:
        from detector.deps import DATA_DIR
        if DATA_DIR.exists():
            repos = sorted([d for d in DATA_DIR.iterdir() if d.is_dir() and "_" in d.name])
            if not repos:
                print(f"[错误] {DATA_DIR} 下没有仓库子目录", file=sys.stderr)
                return 2
            print(f"[自动] 并行扫描 {len(repos)} 个仓库（{DATA_DIR}）")
            out_dir = Path(args.out_dir) if args.out_dir else SCAN_OUTPUT_DIR
            if not args.no_timestamp:
                stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                out_dir = out_dir / stamp
            out_dir = ensure_dir(out_dir)

            # 并行扫描（IO 密集，ThreadPoolExecutor 即可）
            from concurrent.futures import ThreadPoolExecutor, as_completed
            results = [None] * len(repos)
            max_workers = min(8, len(repos)) or 1

            # 结果缓存：已扫过且代码没变的仓库直接读旧 JSON 跳过
            def _repo_max_mtime(d: Path) -> float:
                mtimes = []
                for f in d.rglob("*"):
                    try:
                        if f.is_file():
                            mtimes.append(f.stat().st_mtime)
                    except OSError:
                        pass
                return max(mtimes) if mtimes else 0

            cached = 0
            to_scan = []
            for i, cache in enumerate(repos):
                full = cache.name.replace("_", "/", 1)
                json_path = out_dir / (full.replace("/", "__") + ".json")
                if json_path.exists():
                    try:
                        old = json.loads(json_path.read_text(encoding="utf-8"))
                        if _repo_max_mtime(cache) <= json_path.stat().st_mtime:
                            results[i] = old
                            cached += 1
                            continue
                    except Exception:
                        pass
                to_scan.append((i, cache))
            if cached:
                print(f"[缓存] {cached} 个仓库未变更，跳过重扫")

            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                future_to_idx = {}
                for i, cache in to_scan:
                    future_to_idx[pool.submit(scan_repo_safe, cache)] = i
                done = 0
                for fut in as_completed(future_to_idx):
                    i = future_to_idx[fut]
                    cache = repos[i]
                    full = cache.name.replace("_", "/", 1)
                    files_scanned, hits = fut.result()
                    fetch_ok = cache.exists() and any(cache.iterdir())
                    res = _new_result(full, {}, fetch_ok, files_scanned, hits)
                    results[i] = res
                    write_json(out_dir / (full.replace("/", "__") + ".json"), res)
                    sev = {}
                    for h in res["hits"]:
                        sev[h["severity"]] = sev.get(h["severity"], 0) + 1
                    done += 1
                    print(f"[{done}/{len(to_scan)}] ", end="")
                    print_repo_row(full, res["files_scanned"], len(res["hits"]), sev)

            write_json(out_dir / "_summary.json", results)
            print(f"batch done: {len(results)} repos -> {out_dir}")
            return 0
        else:
            print(f"[错误] {DATA_DIR} 不存在，请传 --repo-dir 或 --manifest", file=sys.stderr)
            return 2

    if args.manifest:  # ---------- 批量模式（manifest CSV）----------
        out_dir = ensure_dir(Path(args.out_dir) if args.out_dir else SCAN_OUTPUT_DIR)
        with open(args.manifest, "r", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))

        results = []
        for r in rows:
            full = r["full_name"]
            cache = Path(r["cache_dir"])
            # 缓存不存在或为空 → 无法扫描
            if not cache.exists() or not any(cache.iterdir()):
                res = _new_result(full, r, False, 0, [])
            else:
                files_scanned, hits = scan_repo(cache)
                res = _new_result(full, r, True, files_scanned, hits)
            results.append(res)
            write_json(out_dir / (full.replace("/", "__") + ".json"), res)
            sev = {}
            for h in res["hits"]:
                sev[h["severity"]] = sev.get(h["severity"], 0) + 1
            print_repo_row(full, res["files_scanned"], len(res["hits"]), sev)

        write_json(out_dir / f"_shard_summary_{Path(args.manifest).stem}.json", results)
        print(f"batch done: {len(results)} repos -> {out_dir}")
        return 0

    # ---------- 单仓库模式 ----------
    repo_dir = Path(args.repo_dir or "")
    files_scanned, hits = scan_repo(repo_dir)
    res = {
        "repo": args.repo,
        "language": args.language,
        "size_kb": args.size_kb,
        "stars": args.stars,
        "fetch_method": args.fetch_method,
        "fetch_ok": repo_dir.exists() and any(repo_dir.iterdir()),
        "files_scanned": files_scanned,
        "hits": hits,
        "verdict": "pending",
        "confidence": 0,
        "reason": "",
        "shadow_features": [],
    }
    if args.out:
        write_json(args.out, res)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
