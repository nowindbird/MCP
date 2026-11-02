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

    python -m detector.deps            # 打印接口清单 + 路径解析结果
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
    SANDBOX_CONFIG,
    SANDBOX_WORK_DIR,
    SCAN_OUTPUT_DIR,
    SCAN_SUMMARY_CSV,
    SEVERITIES,
    STATIC_CONFIG,
)

__all__ = [
    # 路径
    "PROJECT_ROOT", "DATA_DIR", "METADATA_DIR", "OUTPUT_DIR", "SCAN_OUTPUT_DIR",
    "SCAN_SUMMARY_CSV", "CACHE_ROOT", "SANDBOX_WORK_DIR", "SANDBOX_IMAGE_DIR",
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
# 0. 路径
# ---------------------------------------------------------------------------
DATA_DIR: Path = LARGE_REPO_SOURCE       # 被检代码根（默认 mcp插件/）
METADATA_DIR: Path = MEDIUM_REPO_META    # 插件元数据根（默认 mcp插件/）

SCAN_SUMMARY_FIELDS: List[str] = list(CONFIG["scan_summary_fields"])

# 沙箱镜像资源目录（Dockerfile / entrypoint.sh / fixtures 所在）
SANDBOX_IMAGE_DIR: Path = Path(__file__).resolve().parent / "executor"

# 扫描口径：直接取自 config，杜绝各模块自己定义
SKIP_DIRS = frozenset(d.lower() for d in STATIC_CONFIG["SKIP_DIRS"])
DOC_SKIP_DIRS = frozenset(d.lower() for d in STATIC_CONFIG["DOC_SKIP_DIRS"])
SCAN_EXTS = frozenset(e.lower() for e in STATIC_CONFIG["SCAN_EXTS"])
SPECIAL_FILES = frozenset(f.lower() for f in STATIC_CONFIG["SPECIAL_FILES"])
CODE_EXTS = frozenset(e.lower() for e in STATIC_CONFIG["CODE_EXTS"])
MAX_FILE_SIZE_BYTES: int = STATIC_CONFIG["MAX_FILE_SIZE_BYTES"]
MAX_LINE_LENGTH: int = STATIC_CONFIG["MAX_LINE_LENGTH"]
EVAL_DENSITY_THRESHOLD: int = STATIC_CONFIG["EVAL_DENSITY_THRESHOLD"]

# 静态扫描允许 docs/ 参与（README 可能藏在 docs 下）；语义文档生成则跳过
_SKIP_DIRS_FOR_SCAN = SKIP_DIRS - {"docs"}


def ensure_dir(path: Path | str) -> Path:
    """创建目录（幂等）并返回 Path。"""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def repo_dir(repo: str, root: Optional[Path | str] = None) -> Path:
    """把 ``owner/repo`` 或 ``owner_repo`` 解析为本地仓库目录。"""
    base = Path(root) if root else DATA_DIR
    return base / str(repo).replace("/", "_")


def scan_result_path(repo: str, results_dir: Optional[Path | str] = None) -> Path:
    """单仓库扫描结果 JSON 路径（``<owner>__<repo>.json``）。"""
    base = Path(results_dir) if results_dir else SCAN_OUTPUT_DIR
    return base / (str(repo).replace("/", "__") + ".json")


def read_repo_meta(repo_path: Path | str) -> Dict[str, Any]:
    """读取仓库元数据 info.json（不存在或损坏时返回空 dict）。"""
    info = Path(repo_path) / "info.json"
    data = read_json(info, default={}) or {}
    return data if isinstance(data, dict) else {}


def now_iso() -> str:
    """UTC ISO8601 时间戳（统一时区口径）。"""
    return datetime.now(timezone.utc).isoformat()


def ensure_utf8_stdio() -> None:
    """把 stdout/stderr 切到 UTF-8，避免 Windows GBK 控制台遇到 emoji 直接崩。

    被检仓库的 README / 代码里常含 emoji、数学符号；不做这一步时，
    ``print`` 会抛 ``UnicodeEncodeError`` 让整条检测链路中断。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            continue  # 被重定向为管道/不支持 reconfigure 时忽略


# ---------------------------------------------------------------------------
# 1. 仓库遍历（扫描 / 语义文档 / AST 事实共用同一口径）
# ---------------------------------------------------------------------------
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
    """遍历仓库文件（跳过噪声目录 + 超大文件）。

    :param exts: 只产出这些扩展名（为空则用 ``is_scannable_file`` 判定）
    :param extra_skip: 额外跳过的目录名（如 docgen 要跳过 tests/docs）
    :param skip_dirs: 覆盖默认跳过集合（如各语言的构建目录）
    :param with_specials: 不按扩展名过滤时，是否额外保留特殊文件名
    """
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
            elif with_specials and p.name.lower() in SPECIAL_FILES:
                pass  # 特殊文件已在 is_scannable_file 中放行
            if max_bytes is not None:
                try:
                    if p.stat().st_size > max_bytes:
                        continue
                except OSError:
                    continue
            yield p


def iter_repo_texts(
    repo: Path | str,
    **kwargs: Any,
) -> Iterator[Tuple[Path, str]]:
    """遍历仓库文本文件，产出 ``(path, text)``；解码失败的跳过。"""
    for p in iter_repo_files(repo, **kwargs):
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:8192]:  # 二进制
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
    """探测仓库包含哪些语言的源文件（报告 / 覆盖率统计用）。"""
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


# ---------------------------------------------------------------------------
# 2. 文件 IO（JSON / CSV / 文本，编码口径统一）
# ---------------------------------------------------------------------------
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


def load_scan_summary(path: Path | str) -> Dict[str, Dict[str, int]]:
    """读取扫描汇总 CSV → ``{repo_key: {crit, high, hits}}``。

    兼容两种表头：新口径 ``CRITICAL/HIGH/hits`` 与旧口径 ``crit/high/hits``；
    键统一用 :func:`normalize_repo_key`（``owner/repo`` 与 ``owner_repo`` 互通），
    避免"清单用下划线、扫描结果用斜杠"导致的对不上。
    """
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


def normalize_repo_key(repo: str) -> str:
    """仓库名比较键：``owner/repo`` 与 ``owner_repo`` 归一到同一形式。"""
    return str(repo).strip().replace("/", "_")


# ---------------------------------------------------------------------------
# 3. 可选依赖（第三方库 / 外部命令）
# ---------------------------------------------------------------------------
class MissingDependency(RuntimeError):
    """缺少可选的第三方依赖时抛出（附带安装提示）。"""


def has_module(name: str) -> bool:
    """判断第三方模块是否可导入（不真正 import 其全部依赖）。"""
    import importlib.util

    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def require_requests():
    """按需导入 requests；缺失时给出可执行的安装提示。"""
    try:
        import requests  # noqa: F401  (延迟导入，离线功能不依赖它)
        return requests
    except ImportError as e:  # pragma: no cover - 环境相关
        raise MissingDependency(
            "缺少依赖 requests，请先执行: pip install -r requirements.txt"
        ) from e


def docker_available() -> bool:
    """探测 Docker 守护进程是否可用（CLI 存在 != 守护进程在跑）。"""
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# ---------------------------------------------------------------------------
# 4. HTTP 客户端（GitHub / LLM 共用的重试与限流逻辑）
# ---------------------------------------------------------------------------
class HTTPClient:
    """基于 requests.Session 的极简 HTTP 客户端：重试 / 限流 / 下载超时。

    只在这里 import requests，因此其它模块可安全地在无网络环境导入本文件。
    """

    def __init__(
        self,
        *,
        base_url: str = "",
        token: Optional[str] = None,
        user_agent: Optional[str] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        retry_delay: Optional[float] = None,
        headers: Optional[Dict[str, str]] = None,
        auth_header: str = "Authorization",
        auth_scheme: str = "Bearer",
        verbose: bool = True,
    ):
        requests = require_requests()
        self._requests = requests
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout or GITHUB_CONFIG["timeout"])
        self.max_retries = int(max_retries or GITHUB_CONFIG["max_retries"])
        self.retry_delay = float(retry_delay or GITHUB_CONFIG["retry_delay"])
        self.verbose = verbose

        self.session = requests.Session()
        self.session.headers.update(headers or {})
        self.session.headers.setdefault("User-Agent", user_agent or GITHUB_CONFIG["user_agent"])
        if token:
            self.session.headers[auth_header] = f"{auth_scheme} {token}".strip()

        # 速率限制状态（由响应头 X-RateLimit-* 回填；LLM 端点不会设置）
        self.rate_remaining: Optional[int] = None
        self.rate_reset: Optional[int] = None

    # -- 内部工具 ---------------------------------------------------------
    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def _update_rate(self, resp) -> None:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        reset = resp.headers.get("X-RateLimit-Reset")
        if remaining is not None:
            try:
                self.rate_remaining = int(remaining)
            except ValueError:
                pass
        if reset is not None:
            try:
                self.rate_reset = int(reset)
            except ValueError:
                pass

    def _wait_for_rate_reset(self) -> None:
        wait = 0.0
        if self.rate_reset:
            wait = max(self.rate_reset - int(time.time()), 0) + 5
        if wait:
            self._log(f"[速率限制] 等待 {wait:.0f}s ...")
            time.sleep(wait)

    def respect_rate_limit(self, threshold: int = 5) -> None:
        """剩余配额过少时主动等待，避免撞上 GitHub 限流。"""
        if self.rate_remaining is not None and self.rate_remaining <= threshold:
            self._wait_for_rate_reset()

    def url(self, path: str) -> str:
        """拼接绝对 URL（path 以 http 开头时原样返回）。"""
        if path.startswith(("http://", "https://")):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    # -- 请求 -------------------------------------------------------------
    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        as_json: bool = True,
        retries: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """发起请求并返回 JSON / 文本；失败返回 None（重试耗尽）。

        * 403 + 配额耗尽 → 等到 reset 后重试
        * 422 / 502 / 503 / 网络异常 → 退避重试
        * 404 → 直接返回 None（资源不存在，重试无意义）
        """
        url = self.url(path)
        attempts = int(retries or self.max_retries)
        for i in range(attempts):
            try:
                resp = self.session.request(
                    method, url, params=params, json=json_body, headers=headers,
                    timeout=timeout or self.timeout,
                )
            except self._requests.RequestException as e:
                self._log(f"  [请求异常] {e}（{i + 1}/{attempts}）")
                time.sleep(self.retry_delay)
                continue

            self._update_rate(resp)
            if resp.status_code == 200:
                if not as_json:
                    return resp.text
                ctype = resp.headers.get("Content-Type", "")
                return resp.json() if "application/json" in ctype else resp.text
            if resp.status_code == 404:
                return None
            if resp.status_code in (403, 429) and not (self.rate_remaining or 0):
                self._wait_for_rate_reset()
                continue
            if resp.status_code in (422, 500, 502, 503):
                self._log(f"  [HTTP {resp.status_code}] 稍后重试（{i + 1}/{attempts}）")
                time.sleep(self.retry_delay)
                continue
            self._log(f"  [HTTP {resp.status_code}] {url} {resp.text[:200]}")
            return None
        return None

    def get_json(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, as_json=True, **kwargs)

    def get_text(self, path: str, **kwargs: Any) -> Optional[str]:
        return self.request("GET", path, as_json=False, **kwargs)

    def post_json(self, path: str, body: Dict[str, Any], **kwargs: Any) -> Any:
        return self.request("POST", path, json_body=body, **kwargs)

    def download_to_file(
        self,
        path: str,
        dest: Path | str,
        *,
        hard_timeout: Optional[float] = None,
        chunk_size: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """流式下载到文件，带**硬超时**（防止对端挂死导致整批卡住）。

        返回 ``(是否成功, 错误信息)``；失败时不留半成品文件。
        """
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        url = self.url(path)
        hold = float(hard_timeout or FETCH_CONFIG["hard_timeout"])
        chunk = int(chunk_size or FETCH_CONFIG["chunk_size"])
        box: Dict[str, Any] = {}

        def _worker() -> None:
            try:
                with self.session.get(url, stream=True, timeout=(15, 60)) as r:
                    if r.status_code != 200:
                        box["err"] = f"HTTP {r.status_code}"
                        return
                    with open(tmp, "wb") as fh:
                        for block in r.iter_content(chunk):
                            if block:
                                fh.write(block)
                tmp.replace(dest)
                box["ok"] = True
            except Exception as e:  # noqa: BLE001 - 下载失败原因多样，统一上报
                box["err"] = f"{type(e).__name__}: {e}"

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        thread.join(hold)
        if thread.is_alive():
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            return False, f"timeout>{hold:.0f}s"
        if box.get("ok"):
            return True, ""
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, str(box.get("err") or "unknown")


class GitHubClient(HTTPClient):
    """GitHub REST API 封装（统一 token / 限流 / 重试；tree / raw / search）。"""

    def __init__(self, token: Optional[str] = None, **kwargs: Any):
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_CONFIG["api_version"],
        }
        super().__init__(
            base_url=GITHUB_CONFIG["api_url"],
            token=token if token is not None else GITHUB_CONFIG["token"],
            user_agent=GITHUB_CONFIG["user_agent"],
            headers=headers,
            **kwargs,
        )

    def repo_tree(self, owner: str, repo: str, branch: str = "HEAD") -> List[Dict[str, Any]]:
        """仓库文件树（递归，branch 默认 HEAD）。"""
        data = self.get_json(f"/repos/{owner}/{repo}/git/trees/{branch}",
                             params={"recursive": "1"})
        return (data or {}).get("tree", []) if isinstance(data, dict) else []

    def file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        """单文件原始内容（raw；二进制走 base64 时解码）。"""
        data = self.get_text(f"/repos/{owner}/{repo}/contents/{path}",
                             headers={"Accept": "application/vnd.github.raw"})
        if isinstance(data, str):
            return data
        if isinstance(data, dict) and data.get("content"):
            import base64

            try:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                return None
        return None

    def readme(self, owner: str, repo: str) -> Optional[str]:
        """README 原始文本。"""
        return self.get_text(f"/repos/{owner}/{repo}/readme",
                             headers={"Accept": "application/vnd.github.raw"})

    def repo_detail(self, owner: str, repo: str) -> Optional[Dict[str, Any]]:
        self.respect_rate_limit()
        return self.get_json(f"/repos/{owner}/{repo}")

    def commits(self, owner: str, repo: str, count: int = 5) -> List[Dict[str, str]]:
        """最近提交（精简字段）。"""
        self.respect_rate_limit()
        data = self.get_json(f"/repos/{owner}/{repo}/commits", params={"per_page": count})
        if not isinstance(data, list):
            return []
        return [
            {
                "sha": (c.get("sha") or "")[:8],
                "message": (c.get("commit", {}).get("message") or "").split("\n")[0],
                "date": c.get("commit", {}).get("author", {}).get("date", ""),
                "author": c.get("commit", {}).get("author", {}).get("name", ""),
            }
            for c in data
        ]

    def search(self, query: str, page: int = 1, per_page: int = 100,
               sort: str = "stars") -> Optional[Dict[str, Any]]:
        """Search API 单页查询（分页循环由调用方负责）。"""
        self.respect_rate_limit()
        return self.get_json("/search/repositories", params={
            "q": query, "sort": sort, "order": "desc",
            "per_page": per_page, "page": page,
        })

    def tarball_url(self, owner: str, repo: str, ref: str = "HEAD") -> str:
        """codeload 整仓 tar.gz 下载地址。"""
        return f"{GITHUB_CONFIG['codeload_url']}/{owner}/{repo}/tar.gz/{ref}"


class LLMClient(HTTPClient):
    """OpenAI 兼容（Ollama / vLLM / OpenAI）与 Anthropic 两种后端。"""

    def __init__(
        self,
        backend: str = "openai",
        api_base: str = "",
        api_key: str = "",
        model: str = "",
        temperature: float = float(DOC_GEN_CONFIG["temperature"]),
        max_tokens: int = int(DOC_GEN_CONFIG["max_tokens"]),
        timeout: Optional[float] = None,
        **kwargs: Any,
    ):
        self.backend = backend
        self.model = model or DOC_GEN_CONFIG["model"]
        self.temperature = temperature
        self.max_tokens = max_tokens
        super().__init__(
            base_url=api_base or DOC_GEN_CONFIG["api_base"],
            token=api_key or None,
            timeout=timeout or DOC_GEN_CONFIG["timeout"],
            max_retries=DOC_GEN_CONFIG.get("max_retries", 3),
            verbose=True,
            **kwargs,
        )

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        """一次对话补全；失败返回空串（调用方按"生成失败"处理）。"""
        if self.backend == "anthropic":
            return self._chat_anthropic(system_prompt, user_prompt)
        return self._chat_openai(system_prompt, user_prompt)

    def _chat_openai(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        data = self.post_json("/chat/completions", payload)
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            return ""

    def _chat_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        self.session.headers["anthropic-version"] = "2023-06-01"
        data = self.post_json("/v1/messages", payload)
        try:
            return "".join(b.get("text", "") for b in data.get("content", []))
        except (AttributeError, TypeError):
            return ""


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

    sys.exit(_selfcheck())
