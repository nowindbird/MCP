#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.fileio —— 统一文件 IO（JSON / CSV / 文本）
=====================================================
从 deps.py 抽出，所有编码口径统一在这里。
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from detector.paths import SCAN_OUTPUT_DIR


def read_text(path: Path | str, limit: Optional[int] = None,
              errors: str = "replace") -> Optional[str]:
    """读取文本（utf-8-sig 去 BOM）；失败返回 None；可截断前 limit 字符。"""
    try:
        text = Path(path).read_text(encoding="utf-8-sig", errors=errors)
    except (OSError, UnicodeError):
        return None
    return text[:limit] if limit is not None else text


def write_text(path: Path | str, content: str) -> Path:
    """写文本（自动建父目录，utf-8）。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def read_json(path: Path | str, default: Any = None) -> Any:
    """读 JSON；文件不存在/解析失败返回 default。"""
    text = read_text(path)
    if text is None:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return default


def write_json(path: Path | str, data: Any) -> Path:
    """写 JSON（utf-8，不转义中文，缩进 2）。"""
    return write_text(path, json.dumps(data, ensure_ascii=False, indent=2))


def read_jsonl(path: Path | str) -> List[Any]:
    """读 JSONL；空行/坏行跳过。"""
    text = read_text(path) or ""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def write_jsonl(path: Path | str, rows: Iterable[Any]) -> Path:
    """写 JSONL（utf-8，不转义中文）。"""
    lines = [json.dumps(r, ensure_ascii=False) for r in rows]
    return write_text(path, "\n".join(lines) + ("\n" if lines else ""))


def write_csv(path: Path | str, rows: Sequence[Dict[str, Any]],
              fieldnames: Optional[Sequence[str]] = None,
              bom: bool = True) -> Path:
    """写 CSV（默认 utf-8-sig，方便 Excel 打开）；rows 为空时只写表头。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fields = list(fieldnames or (list(rows[0].keys()) if rows else []))
    with open(p, "w", encoding="utf-8-sig" if bom else "utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return p


def iter_scan_results(results_dir: Optional[Path | str] = None,
                      ) -> Iterator[Tuple[Path, Dict[str, Any]]]:
    """遍历扫描结果 JSON（跳过 ``_`` 开头的汇总文件），按文件名排序。"""
    base = Path(results_dir) if results_dir else SCAN_OUTPUT_DIR
    if not base.is_dir():
        return
    for f in sorted(base.glob("*.json")):
        if f.name.startswith("_"):
            continue
        data = read_json(f)
        if isinstance(data, dict):
            yield f, data


def load_targets(path: Path | str) -> List[str]:
    """读取目标清单（每行一个 owner_repo，支持 ``#`` 注释与空行）。"""
    text = read_text(path)
    if text is None:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def normalize_repo_key(repo: str) -> str:
    """仓库名比较键：``owner/repo`` 与 ``owner_repo`` 归一到同一形式。"""
    return str(repo).strip().replace("/", "_")


def load_scan_summary(path: Path | str) -> Dict[str, Dict[str, int]]:
    """读取扫描汇总 CSV → ``{repo_key: {crit, high, hits}}``。"""
    text = read_text(path)
    if text is None:
        return {}
    data: Dict[str, Dict[str, int]] = {}
    for row in csv.DictReader(text.splitlines()):
        repo = (row.get("repo") or "").strip()
        if not repo:
            continue
        try:
            data[normalize_repo_key(repo)] = {
                "crit": int(row.get("CRITICAL") or row.get("crit") or 0),
                "high": int(row.get("HIGH") or row.get("high") or 0),
                "hits": int(row.get("hits") or 0),
            }
        except (TypeError, ValueError):
            continue
    return data
