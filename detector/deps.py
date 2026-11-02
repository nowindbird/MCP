#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.deps —— 全项目唯一依赖接口层
=====================================
本文件是项目的**唯一依赖入口**：所有跨模块依赖（路径、配置、文件 IO、仓库遍历、
HTTP / GitHub、LLM、可选第三方库）都在这里实现并对外暴露。

为什么要有这个文件
------------------
重构前每个模块各自 ``Path(__file__).parent.parent...`` 拼路径、各自定义
``SKIP_DIRS`` / ``SCAN_EXTS`` / 重试逻辑、各自 ``sys.path.insert`` 后
``from config import ...`` / ``from align_rate import ...``。结果是:

* 换目录/换机器就要改多处；
* 同一份“扫描口径”在 scanner / docgen / align_rate / fetcher 里各写一遍且互不一致；
* 三个模块里的 ``from config import CONFIG`` 在 ``python -m`` 下静默失败（被
  ``try/except`` 吞掉），配置实际未生效；
* 依赖关系无法一眼看清。

现在约定：

.. code-block:: python

    from detector.deps import CONFIG, write_json, GitHubClient, iter_repo_files

* **禁止**再写 ``sys.path.insert``；**禁止**再自己拼 ``output/`` 之类的路径。
* 需要新增外部依赖（第三方库、外部服务）时，只改本文件。
* ``detector/config.py`` 只放纯配置数据，本文件负责把配置变成可用接口。
* 唯一例外：``detector/executor/mcp_probe.py`` 在沙箱容器内运行，只用标准库，
  故意不依赖本文件（镜像里没有项目代码）。

按需加载
--------
``requests`` 只在真正发起网络请求时才 import（``require_requests()``），
因此静态扫描 / 对齐率 / 沙箱解析等离线功能在没装 requests 时依然可用。

自检::

    python -m detector.deps            # 打印对外接口清单
    python -m detector.deps --check    # 路径/依赖/各子包导入是否正常
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from detector.config import (  # 配置是纯数据，不做反向依赖
    ALIGN_CONFIG,
    CACHE_ROOT,
    CONFIG,
    DEFAULT_MODEL,
    DOC_GEN_CONFIG,
    FETCH_CONFIG,
    GITHUB_CONFIG,
    LARGE_REPO_SOURCE,
    MEDIUM_REPO_META,
    OLLAMA_API_BASE,
    OLLAMA_HOST,
    OUTPUT_DIR,
    PROJECT_ROOT,
    REPORT_HTML,
    SANDBOX_CONFIG,
    SANDBOX_WORK_DIR,
    SCAN_OUTPUT_DIR,
    SCAN_SUMMARY_CSV,
    SEVERITIES,
    STATIC_CONFIG,
    TARGETS_FILE,
    GEN_DOCS_DIR,
)

__all__ = [
    # 路径
    "PROJECT_ROOT", "DATA_DIR", "METADATA_DIR", "OUTPUT_DIR", "SCAN_OUTPUT_DIR",
    "SCAN_SUMMARY_CSV", "CACHE_ROOT", "SANDBOX_WORK_DIR", "SANDBOX_IMAGE_DIR",
    "TARGETS_FILE", "GEN_DOCS_DIR", "REPORT_HTML",
    "LARGE_REPO_SOURCE", "CONFIG",
    "STATIC_CONFIG", "ALIGN_CONFIG", "SANDBOX_CONFIG", "DOC_GEN_CONFIG",
    "GITHUB_CONFIG", "FETCH_CONFIG", "SEVERITIES", "SCAN_SUMMARY_FIELDS",
    "OLLAMA_HOST", "OLLAMA_API_BASE", "DEFAULT_MODEL",
    "ensure_dir", "repo_dir", "scan_result_path", "read_repo_meta",
    # 扫描口径
    "SKIP_DIRS", "DOC_SKIP_DIRS", "SCAN_EXTS", "SPECIAL_FILES", "CODE_EXTS",
    "MAX_FILE_SIZE_BYTES", "MAX_LINE_LENGTH", "EVAL_DENSITY_THRESHOLD",
    "should_skip_dir", "is_scannable_file", "iter_repo_files", "iter_repo_texts",
    "read_readme", "detect_languages",
    # 文件 IO
    "read_text", "write_text", "read_json", "write_json", "read_jsonl",
    "write_jsonl", "write_csv", "iter_scan_results", "load_targets",
    "load_scan_summary", "now_iso", "normalize_repo_key",
    # 可选依赖
    "MissingDependency", "require_requests", "has_module", "docker_available",
    "ensure_ollama", "ensure_utf8_stdio",
    # 网络
    "HTTPClient", "GitHubClient", "LLMClient",
]

# ---------------------------------------------------------------------------
# 0. 路径（已移到 detector.paths，这里 re-export 保持兼容）
# ---------------------------------------------------------------------------
from detector.paths import (  # noqa: F401
    DATA_DIR, METADATA_DIR, SCAN_SUMMARY_FIELDS, SANDBOX_IMAGE_DIR,
    SKIP_DIRS, DOC_SKIP_DIRS, SCAN_EXTS, SPECIAL_FILES, CODE_EXTS,
    MAX_FILE_SIZE_BYTES, MAX_LINE_LENGTH, EVAL_DENSITY_THRESHOLD,
    _SKIP_DIRS_FOR_SCAN,
    ensure_dir, repo_dir, scan_result_path, now_iso, ensure_utf8_stdio,
)


def read_repo_meta(repo_path: Path | str) -> Dict[str, Any]:
    """读取仓库元数据 info.json（不存在或损坏时返回空 dict）。"""
    info = Path(repo_path) / "info.json"
    data = read_json(info, default={}) or {}
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# 1. 仓库遍历 + 2. 文件 IO（已移到 repo_walk.py / fileio.py，这里 re-export）
# ---------------------------------------------------------------------------
from detector.repo_walk import (  # noqa: F401
    should_skip_dir, is_scannable_file, iter_repo_files, iter_repo_texts,
    read_readme, detect_languages,
)
from detector.fileio import (  # noqa: F401
    read_text, write_text, read_json, write_json, read_jsonl, write_jsonl,
    write_csv, iter_scan_results, load_targets, load_scan_summary,
    normalize_repo_key,
)


# ---------------------------------------------------------------------------
# 3. 可选依赖 + 4. HTTP 客户端（已移到 optional_deps.py / http_client.py，re-export）
# ---------------------------------------------------------------------------
from detector.optional_deps import (  # noqa: F401
    MissingDependency, has_module, require_requests,
)
from detector.http_client import (  # noqa: F401
    HTTPClient, GitHubClient, LLMClient,
)
from detector.executor.docker_check import docker_available  # noqa: F401


# ---------------------------------------------------------------------------
# 5. 本地 LLM 环境（Ollama）
# ---------------------------------------------------------------------------
def ensure_ollama(model: str = "", host: str = "", auto_start: bool = True) -> bool:
    """检查本地 Ollama 是否就绪且含指定模型；未启动时尝试自动拉起。

    返回 True 表示"模型可用"。任何网络异常都视为未就绪，不抛异常。
    """
    requests = require_requests()
    model = model or DEFAULT_MODEL
    base = (host or OLLAMA_HOST).rstrip("/")
    tags_url = f"{base}/api/tags"

    def _models_ready() -> bool:
        try:
            r = requests.get(tags_url, timeout=5)
        except Exception:  # noqa: BLE001 - 连接失败即视为未就绪
            return False
        if r.status_code != 200:
            return False
        names = [m.get("name") for m in r.json().get("models", [])]
        return model in names

    if _models_ready():
        print(f"[prereq] Ollama 就绪，模型 {model} 可用")
        return True
    try:
        requests.get(tags_url, timeout=3)
    except Exception:  # noqa: BLE001 - 服务没起，尝试拉起
        pass
    else:
        print(f"[prereq] Ollama 在跑，但模型 {model} 未拉取。请先: ollama pull {model}")
        return False

    if not auto_start:
        print("[prereq] Ollama 未运行（已禁用自动启动）")
        return False

    print("[prereq] Ollama 未运行，尝试自动启动 ollama serve ...")
    candidates: List[str] = []
    from_path = shutil.which("ollama")
    if from_path:
        candidates.append(from_path)
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    if local_appdata:
        candidates.append(os.path.join(local_appdata, "Programs", "Ollama", "ollama.exe"))
    for env_key in ("ProgramFiles", "ProgramFiles(x86)"):
        base_dir = os.environ.get(env_key, "")
        if base_dir:
            candidates.append(os.path.join(base_dir, "Ollama", "ollama.exe"))
    exe = next((c for c in candidates if os.path.isfile(c)), None)
    if not exe:
        print("[prereq] 未找到 ollama 可执行文件，请手动启动 Ollama")
        return False

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        subprocess.Popen([exe, "serve"], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=creationflags)
    except OSError as e:
        print(f"[prereq] 启动 Ollama 失败: {e}")
        return False
    for _ in range(12):
        time.sleep(2)
        if _models_ready():
            print("[prereq] Ollama 已自动启动")
            return True
    print("[prereq] Ollama 启动超时，请手动启动后重试")
    return False


# ---------------------------------------------------------------------------
# 6. 自检入口
# ---------------------------------------------------------------------------
def _selfcheck() -> int:
    """校验路径解析与各子包导入；返回退出码（0 = 正常）。"""
    ensure_utf8_stdio()
    problems: List[str] = []

    print("== 路径 ==")
    for name in ("project_root", "data", "output", "scan_results",
                 "scan_summary", "cache", "sandbox_work"):
        p = Path(CONFIG["paths"][name])
        print(f"  {name:<14} {p}  [{'存在' if p.exists() else '未创建'}]")
    print(f"  {'metadata':<14} {METADATA_DIR}  "
          f"[{'存在' if METADATA_DIR.exists() else '未创建'}]")

    print("== 扫描口径 ==")
    print(f"  SKIP_DIRS={len(SKIP_DIRS)}  SCAN_EXTS={len(SCAN_EXTS)}  "
          f"SPECIAL_FILES={len(SPECIAL_FILES)}  CODE_EXTS={len(CODE_EXTS)}")
    print(f"  阈值: max_file={MAX_FILE_SIZE_BYTES}B  max_line={MAX_LINE_LENGTH}  "
          f"eval_density={EVAL_DENSITY_THRESHOLD}")

    print("== 可选依赖 ==")
    print(f"  requests : {'已安装' if has_module('requests') else '未安装（网络功能不可用）'}")
    print(f"  docker   : {'可用' if docker_available() else '不可用（沙箱模式需要）'}")

    print("== 子包导入 ==")
    import importlib

    for mod in ("detector.scanner.scanner", "detector.scanner.summary",
                "detector.analyzer.align_rate", "detector.analyzer.docgen",
                "detector.executor.sandbox_rules", "detector.executor.behavior_monitor",
                "detector.executor.mcp_probe", "detector.crawler.github_crawler",
                "detector.fetcher.fetch_repo", "detector.pipeline.run_flow",
                "detector.pipeline.pipeline", "detector.cli"):
        try:
            importlib.import_module(mod)
            print(f"  OK   {mod}")
        except Exception as e:  # noqa: BLE001 - 自检需汇总所有失败
            problems.append(f"{mod}: {type(e).__name__}: {e}")
            print(f"  FAIL {mod}: {type(e).__name__}: {e}")

    if problems:
        print(f"\n自检失败 {len(problems)} 项")
        return 1
    print("\n自检通过")
    return 0


if __name__ == "__main__":
    import sys

    if "--check" in sys.argv:
        sys.exit(_selfcheck())

    # 默认：打印对外接口清单（按类别分组）
    groups = [
        ("路径 / 配置", ["PROJECT_ROOT", "DATA_DIR", "METADATA_DIR", "OUTPUT_DIR",
                         "SCAN_OUTPUT_DIR", "SCAN_SUMMARY_CSV", "CACHE_ROOT",
                         "SANDBOX_WORK_DIR", "SANDBOX_IMAGE_DIR",
                         "TARGETS_FILE", "GEN_DOCS_DIR", "REPORT_HTML",
                         "LARGE_REPO_SOURCE"]),
        ("扫描口径", ["SKIP_DIRS", "DOC_SKIP_DIRS", "SCAN_EXTS", "SPECIAL_FILES",
                      "CODE_EXTS", "MAX_FILE_SIZE_BYTES", "MAX_LINE_LENGTH",
                      "should_skip_dir", "is_scannable_file", "iter_repo_files",
                      "read_readme", "detect_languages"]),
        ("文件 IO", ["read_text", "write_text", "read_json", "write_json",
                     "read_jsonl", "write_jsonl", "write_csv", "iter_scan_results",
                     "load_targets", "load_scan_summary", "normalize_repo_key"]),
        ("可选依赖", ["MissingDependency", "require_requests", "has_module",
                      "docker_available", "ensure_ollama", "ensure_utf8_stdio"]),
        ("网络 / LLM", ["HTTPClient", "GitHubClient", "LLMClient"]),
    ]
    print(f"detector.deps 对外接口（{len(__all__)} 项）：")
    for title, names in groups:
        print(f"\n  [{title}]")
        for n in names:
            print(f"    {n}")
    print("\n自检: python -m detector.deps --check")
