#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.executor.monitor_parser —— 沙箱行为数据模型 + 事件解析纯函数
=====================================================================
strace/tcpdump 文本 → Behavior 列表。Behavior / 噪声与敏感路径口径在此定义
（叶子模块，只依赖 deps），behavior_monitor / monitor_docker / monitor_simulate
都从这里取用，避免循环导入。与 Docker 守护进程完全解耦，可独立单元测试。
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from detector.deps import CONFIG

# 解析用默认值（取自 config，与 behavior_monitor 同一来源）
SBX: Dict[str, Any] = CONFIG.get("sandbox", {})
DEFAULT_OPEN_NOISE = SBX.get("open_noise_prefixes", [
    "/usr/", "/lib/", "/lib64/", "/proc/", "/sys/", "/dev/null",
    "/dev/urandom", "/dev/random", "/etc/ld.so", "/etc/ssl/",
])
DEFAULT_SENSITIVE_PATTERNS = SBX.get("sensitive_path_patterns", [
    r"\.ssh/", r"\.aws/", r"\.env$", r"id_rsa", r"credential",
    r"/etc/passwd", r"/etc/shadow", r"honeypot",
])

ERROR_CATEGORIES = {"sandbox_error", "runtime_error"}


class Behavior:
    """单次被观测到的行为。"""
    __slots__ = ("category", "details", "timestamp", "severity", "rule_hit")

    def __init__(self, category: str, details: Dict, severity: str = "INFO"):
        self.category = category         # network / file_access / subprocess / credential
        self.details = details           # 具体参数 (host/path/command/argv/env_var)
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.severity = severity         # INFO / WARN / BLOCK / CRITICAL
        self.rule_hit: Optional[Dict] = None  # 命中的规则

    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "details": self.details,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "rule_hit": self.rule_hit,
        }


_RE_EXECVE = re.compile(r'execve\("((?:[^"\\]|\\.)*)"\s*,\s*\[([^\]]*)\]')
_RE_OPENAT = re.compile(r'openat2?\([^,]+,\s*"((?:[^"\\]|\\.)*)"')
_RE_CONNECT4 = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),'
    r'\s*sin_addr=inet_addr\("([\d.]+)"\)')
_RE_CONNECT6 = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6,\s*sin_port=htons\((\d+)\),'
    r'\s*sin_addr=inet_pton\(AF_INET6,\s*"([^"]+)"\)')
_RE_CAPTURE_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
_RE_TCP_DST = re.compile(r'IP\s+([\d.]+)\.(\d+)\s*>\s*([\d.]+)\.(\d+):')
_RE_DNS_Q = re.compile(r'\b(?:A|AAAA|CNAME|MX|TXT)\?\s+([A-Za-z0-9_.\-]+)\.')


def parse_strace_text(text: str) -> Dict[str, List]:
    """解析 strace -f -e trace=execve,openat,connect,sendto 的文本输出。"""
    execs: List[Dict[str, str]] = []
    opens: List[str] = []
    connects: List[Tuple[str, int]] = []

    for line in text.splitlines():
        m = _RE_EXECVE.search(line)
        if m:
            path, raw = m.group(1), m.group(2)
            args = _RE_CAPTURE_STR.findall(raw)
            prog = args[0] if args else path
            argv = " ".join(args) if args else path
            execs.append({"command": prog, "argv": argv})
            continue

        m = _RE_OPENAT.search(line)
        if m:
            opens.append(m.group(1))
            continue

        m = _RE_CONNECT4.search(line)
        if m:
            connects.append((m.group(2), int(m.group(1))))
            continue

        m = _RE_CONNECT6.search(line)
        if m:
            connects.append((m.group(2), int(m.group(1))))

    return {"execs": execs, "opens": opens, "connects": connects}


def parse_tcpdump_text(text: str,
                       honeypot_indicators: Optional[List[str]] = None) -> Dict[str, List]:
    """解析 tcpdump -nn -A 文本。"""
    honeypot_indicators = honeypot_indicators or []
    dns_queries: List[str] = []
    tcp_dsts: List[Tuple[str, int]] = []

    for line in text.splitlines():
        for m in _RE_DNS_Q.finditer(line):
            dns_queries.append(m.group(1))
        m = _RE_TCP_DST.search(line)
        if m:
            tcp_dsts.append((m.group(3), int(m.group(4))))

    low = text.lower()
    honeypot_hits = [ind for ind in honeypot_indicators
                     if ind and ind.lower() in low]

    return {"dns_queries": dns_queries, "tcp_dsts": tcp_dsts,
            "honeypot_hits": honeypot_hits}


def parse_event_log(strace_text: str,
                    tcpdump_text: str = "",
                    honeypot_indicators: Optional[List[str]] = None,
                    noise_prefixes: Optional[List[str]] = None,
                    sensitive_patterns: Optional[List[str]] = None) -> List[Behavior]:
    """把采集文本转换成 Behavior 列表（纯函数，无副作用，可单测）。"""
    honeypot_indicators = honeypot_indicators or []
    noise_prefixes = DEFAULT_OPEN_NOISE if noise_prefixes is None else noise_prefixes
    sensitive_patterns = (DEFAULT_SENSITIVE_PATTERNS
                          if sensitive_patterns is None else sensitive_patterns)
    sens_re = [re.compile(p) for p in sensitive_patterns]

    behaviors: List[Behavior] = []
    strace = parse_strace_text(strace_text)
    net = parse_tcpdump_text(tcpdump_text, honeypot_indicators)

    for e in strace["execs"]:
        behaviors.append(Behavior("subprocess",
                                  {"command": e["command"], "argv": e["argv"]}))

    seen_paths = set()
    for path in strace["opens"]:
        if path in seen_paths:
            continue
        is_sensitive = (any(rx.search(path) for rx in sens_re)
                        or any(h and h in path for h in honeypot_indicators))
        if not is_sensitive and any(path.startswith(p) for p in noise_prefixes):
            continue
        seen_paths.add(path)
        behaviors.append(Behavior("file_access", {"path": path}))

    for domain in sorted(set(net["dns_queries"])):
        behaviors.append(Behavior("network",
                                  {"host": domain, "proto": "dns", "resolved": True}))
    # 网络连接合并两个来源：strace connect 系统调用 + tcpdump 目的地址（去重）
    for ip, port in sorted(set(strace["connects"]) | set(net["tcp_dsts"])):
        if port == 53:
            continue
        behaviors.append(Behavior("network",
                                  {"host": ip, "port": port, "proto": "tcp",
                                   "resolved": False}))

    for indicator in net["honeypot_hits"]:
        behaviors.append(Behavior("credential",
                                  {"exfil": indicator, "channel": "payload"},
                                  severity="CRITICAL"))

    return behaviors
