#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.executor.monitor_simulate —— SIMULATE/FIXTURE 模式
===========================================================
从 behavior_monitor.py 抽出：PythonInterceptor + run_simulate/run_fixture。
不依赖 Docker，在当前 Python 进程内拦截行为。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from detector.executor.behavior_monitor import MonitorReport
from detector.executor.monitor_parser import Behavior, SBX, parse_event_log


class PythonInterceptor:
    """Monkey-patch 拦截器：拦截 subprocess/os.getenv/requests/open。"""

    def __init__(self, report: MonitorReport):
        self.report = report
        self._restore: List[Tuple[Any, str, Any]] = []
        self._active = False

    def _patch(self, obj, attr, factory):
        original = getattr(obj, attr)
        setattr(obj, attr, factory(original))
        self._restore.append((obj, attr, original))

    def install(self):
        if self._active:
            return
        self._active = True

        import builtins
        import os
        import subprocess

        def _mk_proc(orig, kind):
            def _wrapper(*args, **kwargs):
                cmd = str(args[0]) if args else kwargs.get("cmd", "")
                self.report.add_behavior(Behavior("subprocess",
                                                  {"command": cmd, "argv": cmd,
                                                   "kind": kind}))
                return orig(*args, **kwargs)
            return _wrapper

        self._patch(subprocess, "run", lambda o: _mk_proc(o, "run"))
        self._patch(subprocess, "call", lambda o: _mk_proc(o, "call"))
        self._patch(subprocess, "Popen", lambda o: _mk_proc(o, "Popen"))

        def _os_system(orig):
            def _wrapper(cmd):
                self.report.add_behavior(Behavior("subprocess",
                                                  {"command": str(cmd), "argv": str(cmd)}))
                return orig(cmd)
            return _wrapper

        self._patch(os, "system", _os_system)

        def _getenv(orig):
            def _wrapper(key, *a, **kw):
                self.report.add_behavior(Behavior("credential", {"env_var": str(key)}))
                return orig(key, *a, **kw)
            return _wrapper

        self._patch(os, "getenv", _getenv)

        try:
            import requests as req

            def _mk_http(orig, method):
                def _wrapper(url, *a, **kw):
                    host = re.sub(r"^https?://", "", str(url)).split("/")[0]
                    self.report.add_behavior(Behavior("network",
                                                      {"host": host, "method": method,
                                                       "url": str(url)[:200],
                                                       "resolved": True}))
                    return orig(url, *a, **kw)
                return _wrapper

            self._patch(req, "get", lambda o: _mk_http(o, "GET"))
            self._patch(req, "post", lambda o: _mk_http(o, "POST"))

            def _request(orig):
                def _wrapper(method, url, *a, **kw):
                    host = re.sub(r"^https?://", "", str(url)).split("/")[0]
                    self.report.add_behavior(Behavior("network",
                                                      {"host": host, "method": method,
                                                       "url": str(url)[:200],
                                                       "resolved": True}))
                    return orig(method, url, *a, **kw)
                return _wrapper

            self._patch(req, "request", _request)
        except ImportError:
            pass

        def _open(orig):
            def _wrapper(file, *a, **kw):
                self.report.add_behavior(Behavior("file_access",
                                                  {"path": str(file)}))
                return orig(file, *a, **kw)
            return _wrapper

        self._patch(builtins, "open", _open)

    def uninstall(self):
        if not self._active:
            return
        for obj, attr, original in reversed(self._restore):
            try:
                setattr(obj, attr, original)
            except Exception:
                pass
        self._restore.clear()
        self._active = False


def run_simulate(rules: Dict, entry_point: str,
                 timeout_seconds: int = 60) -> MonitorReport:
    """SIMULATE 模式: 在当前 Python 进程里执行 entry_point，拦截行为。"""
    report = MonitorReport(rules)
    report.start()
    interceptor = PythonInterceptor(report)
    interceptor.install()
    try:
        exec(compile(entry_point, "<entry_point>", "exec"), {"__name__": "__main__"})
    except Exception as e:
        report.add_behavior(Behavior("runtime_error", {"error": str(e)}))
    finally:
        interceptor.uninstall()
    report.stop()
    return report


def run_fixture(rules: Dict, strace_file: str = "",
                net_file: str = "") -> MonitorReport:
    """FIXTURE 模式: 解析已保存的 strace/tcpdump 文本，无需 Docker。"""
    report = MonitorReport(rules)
    report.start()
    strace_text = Path(strace_file).read_text(encoding="utf-8") if strace_file else ""
    net_text = Path(net_file).read_text(encoding="utf-8") if net_file else ""
    # 与 run_docker 同一口径：蜜罐指标 / 噪声前缀 / 敏感路径都来自规则与 config
    for b in parse_event_log(
            strace_text, net_text,
            honeypot_indicators=rules.get("blocklist", {}).get("honeypot_indicators", []),
            noise_prefixes=SBX.get("open_noise_prefixes"),
            sensitive_patterns=SBX.get("sensitive_path_patterns")):
        report.add_behavior(b)
    report.stop()
    return report
