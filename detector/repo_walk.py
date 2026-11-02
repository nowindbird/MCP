#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.repo_walk —— 仓库遍历口径
=====================================
从 deps.py 抽出，扫描 / 语义文档 / AST 事实共用同一套遍历规则。
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple

from detector.config import STATIC_CONFIG
from detector.fileio import read_text
from detector.paths import (
    CODE_EXTS,
    MAX_FILE_SIZE_BYTES,
    SCAN_EXTS,
    SPECIAL_FILES,
    _SKIP_DIRS_FOR_SCAN,
)


def should_skip_dir(name: str, extra: Iterable[str] = ()) -> bool:
    """目录名是否应跳过（忽略大小写；extra 为额外跳过集合）。"""
    low = name.lower()
    return low in _SKIP_DIRS_FOR_SCAN or low in {e.lower() for e in extra}


def is_scannable_file(path: Path) -> bool:
    """文件是否参与静态扫描：README / 特殊文件名 / 已知扩展名。"""
    name = path.name.lower()
    if name.startswith("readme") or name in SPECIAL_FILES:
        return True
    return path.suffix.lower() in SCAN_EXTS


def iter_repo_files(
    repo: Path | str,
    *,
    exts: Optional[Iterable[str]] = None,
    extra_skip: Iterable[str] = (),
    skip_dirs: Iterable[str] = (),
    with_specials: bool = False,
    max_bytes: Optional[int] = MAX_FILE_SIZE_BYTES,
) -> Iterator[Path]:
    """遍历仓库文件（跳过噪声目录 + 超大文件）。"""
    root = Path(repo)
    if not root.exists():
        return
    ext_set = {e.lower() for e in exts} if exts else None
    skip = {d.lower() for d in skip_dirs} if skip_dirs else None
    extra = {e.lower() for e in extra_skip}

    for dirpath, dirnames, filenames in os.walk(str(root)):
        if skip is not None:
            dirnames[:] = [d for d in dirnames if d.lower() not in skip]
        else:
            dirnames[:] = [d for d in dirnames if not should_skip_dir(d, extra)]
        dirnames.sort()
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if ext_set is not None:
                if p.suffix.lower() not in ext_set:
                    continue
            elif not is_scannable_file(p):
                continue
            if max_bytes is not None:
                try:
                    if p.stat().st_size > max_bytes:
                        continue
                except OSError:
                    continue
            yield p


def iter_repo_texts(
    repo: Path | str,
    **kwargs,
) -> Iterator[Tuple[Path, str]]:
    """遍历仓库文本文件，产出 ``(path, text)``；解码失败的跳过。"""
    for p in iter_repo_files(repo, **kwargs):
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:8192]:
            continue
        yield p, raw.decode("utf-8-sig", errors="replace")


_README_NAMES = (
    "README.md", "README.markdown", "README.rst", "README.txt", "README",
    "readme.md", "Readme.md", "Readme", "readme",
)


def read_readme(repo: Path | str,
                max_chars: int = STATIC_CONFIG["MAX_README_CHARS"]) -> Optional[str]:
    """读取仓库 README 文本（大小写不敏感；没有则返回 None）。"""
    root = Path(repo)
    if not root.is_dir():
        return None
    for name in _README_NAMES:
        p = root / name
        if p.is_file():
            return read_text(p, limit=max_chars)
    for p in sorted(root.iterdir()):
        if p.is_file() and p.name.lower().startswith("readme"):
            return read_text(p, limit=max_chars)
    return None


_LANG_EXT = {
    "python": (".py",),
    "js": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"),
    "go": (".go",),
    "rust": (".rs",),
    "java": (".java",),
    "csharp": (".cs",),
    "ruby": (".rb",),
    "php": (".php",),
}


def detect_languages(repo: Path | str, max_files: int = 20000,
                     skip_dirs: Optional[Iterable[str]] = None) -> List[str]:
    """探测仓库包含哪些语言的源文件。"""
    found: set = set()
    for i, p in enumerate(iter_repo_files(repo, exts=CODE_EXTS, max_bytes=None,
                                          skip_dirs=skip_dirs or ())):
        if i >= max_files:
            break
        suffix = p.suffix.lower()
        for lang, exts in _LANG_EXT.items():
            if suffix in exts:
                found.add(lang)
                break
    return sorted(found)
