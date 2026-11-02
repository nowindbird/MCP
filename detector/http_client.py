#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.http_client —— HTTP 客户端（GitHub / LLM 共用重试与限流）
=================================================================
从 deps.py 抽出。只在这里 import requests，离线功能不依赖它。
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from detector.config import DOC_GEN_CONFIG, FETCH_CONFIG, GITHUB_CONFIG
from detector.optional_deps import require_requests


class HTTPClient:
    """基于 requests.Session 的极简 HTTP 客户端：重试 / 限流 / 下载超时。"""

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

        self.rate_remaining: Optional[int] = None
        self.rate_reset: Optional[int] = None

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
        if self.rate_remaining is not None and self.rate_remaining <= threshold:
            self._wait_for_rate_reset()

    def url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

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
            except Exception as e:
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
    """GitHub REST API 封装。"""

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
        data = self.get_json(f"/repos/{owner}/{repo}/git/trees/{branch}",
                             params={"recursive": "1"})
        return (data or {}).get("tree", []) if isinstance(data, dict) else []

    def file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
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
        return self.get_text(f"/repos/{owner}/{repo}/readme",
                             headers={"Accept": "application/vnd.github.raw"})

    def repo_detail(self, owner: str, repo: str) -> Optional[Dict[str, Any]]:
        self.respect_rate_limit()
        return self.get_json(f"/repos/{owner}/{repo}")

    def commits(self, owner: str, repo: str, count: int = 5) -> List[Dict[str, str]]:
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
        self.respect_rate_limit()
        return self.get_json("/search/repositories", params={
            "q": query, "sort": sort, "order": "desc",
            "per_page": per_page, "page": page,
        })

    def tarball_url(self, owner: str, repo: str, ref: str = "HEAD") -> str:
        return f"{GITHUB_CONFIG['codeload_url']}/{owner}/{repo}/tar.gz/{ref}"


class LLMClient(HTTPClient):
    """OpenAI 兼容与 Anthropic 两种后端。"""

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
