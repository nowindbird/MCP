#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector 沙箱运行时行为监控器
================================
在沙箱中运行 MCP 插件时，采集其系统调用（execve/openat/connect）与网络流量，
与 sandbox_rules.py 生成的规则比对，触发分级响应:
  HONEYPOT_EXPOSED → 立即判定 malicious 并终止
  BLOCKLIST_HIT    → 立即拦截并送审
  ALLOWLIST_MISS   → 记录 violation，累计超阈值送审

三种运行模式:
  1. DOCKER   (生产): 隔离容器 + strace 采集 + tcpdump sidecar + 蜜罐凭据
  2. SIMULATE (开发): 本地 monkey-patch 拦截 subprocess/requests/open/os.getenv
  3. FIXTURE  (测试): 直接解析已保存的 strace/tcpdump 文本，无需 Docker 守护进程

用法:
  # 先准备规则
  python sandbox_rules.py --repo-dir mcp插件\\某仓库 --output rules.json
  # Docker 模式（首次会自动构建沙箱镜像）
  python behavior_monitor.py --rules rules.json --mode docker --repo-dir mcp插件\\某仓库
  # 模拟模式
  python behavior_monitor.py --rules rules.json --mode simulate --entry-point run_server.py
  # 固件回放模式（离线单测）
  python behavior_monitor.py --rules rules.json --mode fixture --strace-file a.log --net-file b.txt
"""

import argparse
import json
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 0. 配置加载
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent          # detector/executor
PROJECT_ROOT = HERE.parent                        # 项目根
SANDBOX_DIR = HERE                                # Dockerfile/entrypoint.sh 所在（executor/）
sys.path.insert(0, str(PROJECT_ROOT))             # 使 from config import CONFIG 可用

try:
    from config import CONFIG
    SBX: Dict[str, Any] = CONFIG.get("sandbox", {})
except Exception:  # 配置损坏时降级为内置默认值
    SBX = {}

# 解析用默认值（config 缺失时的兜底）
DEFAULT_OPEN_NOISE = SBX.get("open_noise_prefixes", [
    "/usr/", "/lib/", "/lib64/", "/proc/", "/sys/", "/dev/null",
    "/dev/urandom", "/dev/random", "/etc/ld.so", "/etc/ssl/",
])
DEFAULT_SENSITIVE_PATTERNS = SBX.get("sensitive_path_patterns", [
    r"\.ssh/", r"\.aws/", r"\.env$", r"id_rsa", r"credential",
    r"/etc/passwd", r"/etc/shadow", r"honeypot",
])

ERROR_CATEGORIES = {"sandbox_error", "runtime_error"}


# ---------------------------------------------------------------------------
# 1. 行为数据结构
# ---------------------------------------------------------------------------

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


class MonitorReport:
    """运行一次插件后产出的完整监控报告。"""

    def __init__(self, rules: Dict):
        self.rules = rules
        self.behaviors: List[Behavior] = []
        self.violations: List[Behavior] = []     # allowlist miss
        self.blocks: List[Behavior] = []         # blocklist hit
        self.honeypot_hits: List[Behavior] = []  # 蜜罐外传/读取
        self.errors: List[Behavior] = []         # 沙箱/运行错误
        self.review_requested = False
        self.final_verdict = "INCONCLUSIVE"      # CLEAN / WARN / MALICIOUS / INCONCLUSIVE
        self.start_time: Optional[str] = None
        self.end_time: Optional[str] = None

    def start(self):
        self.start_time = datetime.now(timezone.utc).isoformat()

    def stop(self):
        self.end_time = datetime.now(timezone.utc).isoformat()
        self._determine_verdict()

    def _meaningful_count(self) -> int:
        return sum(1 for b in self.behaviors if b.category not in ERROR_CATEGORIES)

    def _determine_verdict(self):
        if self.honeypot_hits:
            self.final_verdict = "MALICIOUS"
            self.review_requested = True
        elif self.blocks:
            self.final_verdict = "WARN"
            self.review_requested = True
        elif len(self.violations) >= 3:
            self.final_verdict = "WARN"
            self.review_requested = True
        elif self.errors and self._meaningful_count() == 0:
            # 只有错误、没有任何有效行为 → 无法判定，不能当 CLEAN
            self.final_verdict = "INCONCLUSIVE"
        elif self._meaningful_count() > 0:
            self.final_verdict = "CLEAN"

    def add_behavior(self, behavior: Behavior):
        self.behaviors.append(behavior)

        # ---- 规则匹配 ----
        rule_hit = self._match_rules(behavior)
        behavior.rule_hit = rule_hit

        if rule_hit["action"] == "BLOCK":
            behavior.severity = "BLOCK"
            self.blocks.append(behavior)
        elif rule_hit["action"] == "HONEYPOT_TRIGGER":
            behavior.severity = "CRITICAL"
            self.honeypot_hits.append(behavior)
            self.stop()  # 蜜罐命中立即定格判定
        elif rule_hit["action"] == "ALLOW_MISS":
            behavior.severity = "WARN"
            self.violations.append(behavior)

        if behavior.category in ERROR_CATEGORIES:
            self.errors.append(behavior)

    def _match_rules(self, behavior: Behavior) -> Dict[str, Any]:
        """把 behavior 和 rules 做比对，返回 {"action": ..., "reason": ...}。"""
        rules = self.rules
        cat = behavior.category
        details = behavior.details
        vact = rules.get("violation_actions", {})

        # ---- Step 1: 蜜罐检测（最高优先级）----
        if vact.get("honeypot_protected"):
            detail_str = json.dumps(details, default=str).lower()
            for indicator in rules.get("blocklist", {}).get("honeypot_indicators", []):
                if indicator and indicator.lower() in detail_str:
                    return {"action": "HONEYPOT_TRIGGER",
                            "reason": f"蜜罐凭据外传/读取: {indicator}"}

        # ---- Step 2: 通用 blocklist 模式 ----
        cmd_text = (details.get("argv") or details.get("command")
                    or details.get("endpoint") or details.get("path") or "")
        for pat in rules.get("blocklist", {}).get("dangerous_patterns", []):
            if re.search(pat, cmd_text, re.I):
                return {"action": "BLOCK",
                        "reason": f"命中恶意模式: {pat}",
                        "matched_text": cmd_text[:120]}

        # ---- Step 3: allowlist 检查 ----
        allowlist = rules.get("allowlist", {})
        auto_block = vact.get("auto_block_categories", [])

        if cat == "network":
            host = details.get("host", "")
            allowed = allowlist.get("network_endpoints", [])
            if "*" in allowed or host in allowed:
                return {"action": "ALLOW"}
            reason = f"端点 {host} 不在 allowlist {allowed}"
            if details.get("resolved") is False:
                reason += "（DNS 未解析到声明的域名）"
            if "network" in auto_block:
                return {"action": "BLOCK", "reason": reason}
            return {"action": "ALLOW_MISS", "reason": reason}

        if cat == "file_access":
            path = details.get("path", "")
            allowed = allowlist.get("file_paths", [])
            if "*" in allowed or any(
                path.startswith(a.replace("*", "")) for a in allowed if a != "*"
            ):
                return {"action": "ALLOW"}
            reason = f"路径 {path} 不在 allowlist {allowed}"
            if "file_access" in auto_block:
                return {"action": "BLOCK", "reason": reason}
            return {"action": "ALLOW_MISS", "reason": reason}

        if cat == "subprocess":
            cmd = details.get("command", "")
            allowed = allowlist.get("commands", [])
            cmd_first = cmd.split()[0] if cmd else ""
            if "*" in allowed or cmd_first in allowed or cmd in allowed:
                return {"action": "ALLOW"}
            if "subprocess" in auto_block:
                return {"action": "BLOCK",
                        "reason": f"命令 {cmd} 属于 auto_block 类别且不在 allowlist"}
            return {"action": "ALLOW_MISS",
                    "reason": f"命令 {cmd} 不在 allowlist {allowed}"}

        if cat == "credential":
            env_var = details.get("env_var", "")
            allowed = allowlist.get("env_vars", [])
            if env_var and ("*" in allowed or env_var in allowed):
                return {"action": "ALLOW"}
            if "credential" in auto_block:
                return {"action": "BLOCK",
                        "reason": f"凭据类操作 {env_var or details} 属于 auto_block"}
            return {"action": "ALLOW_MISS",
                    "reason": f"env {env_var} 不在 allowlist {allowed}"}

        return {"action": "ALLOW"}  # 未知类别默认放行

    def to_dict(self) -> Dict:
        return {
            "repo": self.rules.get("repo"),
            "final_verdict": self.final_verdict,
            "review_requested": self.review_requested,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "behavior_count": len(self.behaviors),
            "violations": [v.to_dict() for v in self.violations],
            "blocks": [b.to_dict() for b in self.blocks],
            "honeypot_hits": [h.to_dict() for h in self.honeypot_hits],
            "errors": [e.to_dict() for e in self.errors],
            "all_behaviors": [b.to_dict() for b in self.behaviors],
            "rules_source": self.rules.get("source", {}),
        }

    def print_summary(self):
        print(f"\n{'='*62}")
        print(f"  监控报告: {self.rules.get('repo')}")
        print(f"{'='*62}")
        print(f"  最终判定 : {self.final_verdict}")
        print(f"  送人工审 : {'是' if self.review_requested else '否'}")
        print(f"  行为总数 : {len(self.behaviors)}")
        print(f"  allowlist miss : {len(self.violations)}")
        print(f"  blocklist hit  : {len(self.blocks)}")
        print(f"  蜜罐命中       : {len(self.honeypot_hits)}")
        print(f"  错误           : {len(self.errors)}")
        if self.violations:
            print("\n  --- 违规摘要 ---")
            for v in self.violations[:10]:
                reason = (v.rule_hit or {}).get("reason", "")
                print(f"    [!] [{v.category}] {str(v.details)[:90]} -> {reason[:80]}")
        if self.blocks:
            print("\n  --- BLOCK 摘要 ---")
            for b in self.blocks:
                reason = (b.rule_hit or {}).get("reason", "")
                print(f"    [X] [{b.category}] {str(b.details)[:90]} -> {reason[:80]}")
        if self.honeypot_hits:
            print("\n  --- 蜜罐命中 ---")
            for h in self.honeypot_hits:
                reason = (h.rule_hit or {}).get("reason", "")
                print(f"    [!!] [{h.category}] {str(h.details)[:90]} -> {reason}")
        if self.errors:
            print("\n  --- 错误 ---")
            for e in self.errors[:5]:
                print(f"    [E] {str(e.details)[:140]}")
        print(f"{'='*62}\n")


# ---------------------------------------------------------------------------
# 2. 沙箱事件解析（纯函数: strace/tcpdump 文本 → Behavior 列表）
#    与 Docker 守护进程完全解耦，可用固件(fixtures)直接单元测试。
# ---------------------------------------------------------------------------

_RE_EXECVE = re.compile(r'execve\("((?:[^"\\]|\\.)*)"\s*,\s*\[([^\]]*)\]')
_RE_OPENAT = re.compile(r'openat2?\([^,]+,\s*"((?:[^"\\]|\\.)*)"')
_RE_CONNECT4 = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),'
    r'\s*sin_addr=inet_addr\("([\d.]+)"\)')
_RE_CONNECT6 = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6,\s*sin_port=htons\((\d+)\),'
    r'\s*sin_addr=inet_pton\(AF_INET6,\s*"([^"]+)"\)')
_RE_CAPTURE_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
# tcpdump -nn 风格: "IP 10.0.0.2.54321 > 93.184.216.34.80: Flags [S]"
_RE_TCP_DST = re.compile(r'IP\s+([\d.]+)\.(\d+)\s*>\s*([\d.]+)\.(\d+):')
# DNS 查询: "A? evil.example.com. (35)"
_RE_DNS_Q = re.compile(r'\b(?:A|AAAA|CNAME|MX|TXT)\?\s+([A-Za-z0-9_.\-]+)\.')


def parse_strace_text(text: str) -> Dict[str, List]:
    """解析 strace -f -e trace=execve,openat,connect,sendto 的文本输出。

    返回 {"execs": [{command, argv}], "opens": [path], "connects": [(ip, port)]}
    """
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
    """解析 tcpdump -nn -A 文本: DNS 查询域名 / TCP 目标端点 / 明文载荷蜜罐泄露。

    返回 {"dns_queries": [domain], "tcp_dsts": [(ip, port)], "honeypot_hits": [indicator]}
    """
    honeypot_indicators = honeypot_indicators or []
    dns_queries: List[str] = []
    tcp_dsts: List[Tuple[str, int]] = []

    for line in text.splitlines():
        for m in _RE_DNS_Q.finditer(line):
            dns_queries.append(m.group(1))
        m = _RE_TCP_DST.search(line)
        if m:
            tcp_dsts.append((m.group(3), int(m.group(4))))

    # 蜜罐泄露: 明文 HTTP 载荷里出现蜜罐凭据指纹
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
    """把采集文本转换成 Behavior 列表（纯函数，无副作用，可单测）。

      execve              → subprocess{command, argv}
      openat              → file_access{path}（过滤运行时噪声前缀; 蜜罐/敏感路径必报）
      connect / TCP dst   → network{host=IP, resolved=False}（DNS 端口 53 跳过）
      DNS 查询域名         → network{host=domain, resolved=True}（可与 allowlist 域名对齐）
      明文载荷含蜜罐指纹    → credential{exfil=indicator}（命中即 CRITICAL）
    """
    honeypot_indicators = honeypot_indicators or []
    noise_prefixes = DEFAULT_OPEN_NOISE if noise_prefixes is None else noise_prefixes
    sensitive_patterns = (DEFAULT_SENSITIVE_PATTERNS
                          if sensitive_patterns is None else sensitive_patterns)
    sens_re = [re.compile(p) for p in sensitive_patterns]

    behaviors: List[Behavior] = []
    strace = parse_strace_text(strace_text)
    net = parse_tcpdump_text(tcpdump_text, honeypot_indicators)

    # ---- subprocess ----
    for e in strace["execs"]:
        behaviors.append(Behavior("subprocess",
                                  {"command": e["command"], "argv": e["argv"]}))

    # ---- file_access（去重 + 噪声过滤）----
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

    # ---- network: 先域名（DNS 查询），后原始 IP ----
    for domain in sorted(set(net["dns_queries"])):
        behaviors.append(Behavior("network",
                                  {"host": domain, "proto": "dns", "resolved": True}))
    for ip, port in sorted(set(net["tcp_dsts"])):
        if port == 53:  # DNS 自身流量
            continue
        behaviors.append(Behavior("network",
                                  {"host": ip, "port": port, "proto": "tcp",
                                   "resolved": False}))

    # ---- 蜜罐泄露（明文载荷）----
    for indicator in net["honeypot_hits"]:
        behaviors.append(Behavior("credential",
                                  {"exfil": indicator, "channel": "payload"},
                                  severity="CRITICAL"))

    return behaviors


# ---------------------------------------------------------------------------
# 3. Monkey-patch 拦截器（SIMULATE 模式）
# ---------------------------------------------------------------------------

class PythonInterceptor:
    """在 Python 进程内 monkey-patch 关键函数，产生 Behavior 事件。
    SIMULATE 模式实现——不依赖 Docker，直接在本地 Python 进程内拦截。"""

    def __init__(self, report: MonitorReport):
        self.report = report
        self._restore: List[Tuple[Any, str, Any]] = []  # (obj, attr, original)
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

        # ---- subprocess.run / call / Popen ----
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

        # ---- os.system ----
        def _os_system(orig):
            def _wrapper(cmd):
                self.report.add_behavior(Behavior("subprocess",
                                                  {"command": str(cmd), "argv": str(cmd)}))
                return orig(cmd)
            return _wrapper

        self._patch(os, "system", _os_system)

        # ---- os.getenv / os.environ.get ----
        def _getenv(orig):
            def _wrapper(key, *a, **kw):
                self.report.add_behavior(Behavior("credential", {"env_var": str(key)}))
                return orig(key, *a, **kw)
            return _wrapper

        self._patch(os, "getenv", _getenv)

        # ---- requests ----
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
            pass  # 目标插件可能不用 requests

        # ---- builtins.open ----
        def _open(orig):
            def _wrapper(file, *a, **kw):
                self.report.add_behavior(Behavior("file_access",
                                                  {"path": str(file)}))
                return orig(file, *a, **kw)
            return _wrapper

        self._patch(builtins, "open", _open)

    def uninstall(self):
        """恢复所有被 patch 的原始函数。"""
        if not self._active:
            return
        for obj, attr, original in reversed(self._restore):
            try:
                setattr(obj, attr, original)
            except Exception:
                pass
        self._restore.clear()
        self._active = False


# ---------------------------------------------------------------------------
# 4. 运行器
# ---------------------------------------------------------------------------

def run_simulate(rules: Dict, entry_point: str,
                 timeout_seconds: int = 60) -> MonitorReport:
    """SIMULATE 模式: 在当前 Python 进程里执行 entry_point，拦截行为。"""
    report = MonitorReport(rules)
    interceptor = PythonInterceptor(report)
    interceptor.install()
    report.start()

    try:
        script_path = Path(entry_point)
        if not script_path.exists():
            raise FileNotFoundError(f"入口脚本不存在: {entry_point}")
        code = script_path.read_text(encoding="utf-8-sig", errors="replace")
        exec(compile(code, str(script_path), "exec"), {"__name__": "__main__",
                                                       "__file__": str(script_path)})
    except Exception as e:
        report.add_behavior(Behavior("runtime_error",
                                     {"error": str(e),
                                      "trace": traceback.format_exc()[:400]}))
    finally:
        interceptor.uninstall()
        report.stop()

    return report


def run_fixture(rules: Dict, strace_file: str = "",
                net_file: str = "") -> MonitorReport:
    """FIXTURE 模式: 解析已保存的 strace/tcpdump 文本（离线可测）。"""
    report = MonitorReport(rules)
    report.start()

    strace_text = ""
    if strace_file and Path(strace_file).exists():
        strace_text = Path(strace_file).read_text(encoding="utf-8-sig", errors="replace")
    net_text = ""
    if net_file and Path(net_file).exists():
        net_text = Path(net_file).read_text(encoding="utf-8-sig", errors="replace")

    indicators = rules.get("blocklist", {}).get("honeypot_indicators", [])
    for behavior in parse_event_log(strace_text, net_text,
                                    honeypot_indicators=indicators,
                                    noise_prefixes=SBX.get("open_noise_prefixes"),
                                    sensitive_patterns=SBX.get("sensitive_path_patterns")):
        report.add_behavior(behavior)

    report.stop()
    return report


# ---------------------------------------------------------------------------
# 5. Docker 沙箱运行器
# ---------------------------------------------------------------------------

def _docker(args: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker"] + args, capture_output=True, text=True,
                          timeout=timeout, encoding="utf-8", errors="replace")


def docker_available() -> bool:
    """探测 Docker 守护进程是否可用（CLI 存在 != 守护进程在跑）。"""
    try:
        return _docker(["info"], timeout=30).returncode == 0
    except Exception:
        return False


def image_exists(image: str) -> bool:
    try:
        return _docker(["image", "inspect", image], timeout=30).returncode == 0
    except Exception:
        return False


def build_sandbox_image(image: Optional[str] = None) -> bool:
    """构建沙箱镜像（含 strace/tcpdump/python/node，可选 go/rust）。"""
    image = image or SBX.get("docker_image", "mpv-sandbox:latest")
    dockerfile = SANDBOX_DIR / "Dockerfile"
    if not dockerfile.exists():
        print(f"[错误] 未找到 Dockerfile: {dockerfile}")
        return False
    print(f"[构建] docker build -t {image} ... (首次较慢)")
    r = _docker(["build", "-t", image, "-f", str(dockerfile), str(SANDBOX_DIR)],
                timeout=3600)
    if r.returncode != 0:
        print((r.stdout or "")[-1500:])
        print((r.stderr or "")[-1500:], file=sys.stderr)
        return False
    return True


def detect_run_command(repo_dir: Path) -> Optional[str]:
    """尽力推断插件启动命令（可用 --run-command 覆盖）。"""
    for cand in ("server.py", "mcp_server.py", "main.py", "app.py", "run.py",
                 "src/server.py", "src/main.py", "__main__.py"):
        if (repo_dir / cand).exists():
            return f"python3 {cand}"

    pkg = repo_dir / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8-sig", errors="replace"))
            scripts = data.get("scripts", {}) or {}
            for key in ("start", "server", "mcp", "dev"):
                if key in scripts:
                    return "npm start" if key == "start" else f"npm run {key}"
            if data.get("main"):
                return f"node {data['main']}"
        except Exception:
            pass
    for cand in ("index.js", "build/index.js", "dist/index.js"):
        if (repo_dir / cand).exists():
            return f"node {cand}"

    if (repo_dir / "go.mod").exists():
        return "go run ."
    if (repo_dir / "Cargo.toml").exists():
        return "cargo run"
    return None


def _honeypot_env() -> List[str]:
    """构造注入到目标容器的蜜罐环境变量（含常见别名，扩大诱饵面）。"""
    honey = SBX.get("honeypot", {})
    api_key = honey.get("api_key", "honeypot_fake_key_do_not_use")
    aws_id = honey.get("aws_access_key", "AKIAIOSFODNN7EXAMPLE")
    aws_secret = honey.get("aws_secret_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    env = {
        "API_KEY": api_key,
        "SECRET_TOKEN": api_key,
        # 常见真实世界变量名别名（诱饵）
        "OPENAI_API_KEY": api_key,
        "ANTHROPIC_API_KEY": api_key,
        "GITHUB_TOKEN": api_key,
        "AWS_ACCESS_KEY_ID": aws_id,
        "AWS_SECRET_ACCESS_KEY": aws_secret,
        "DATABASE_URL": f"postgres://admin:{api_key}@db.internal:5432/prod",
        # 指向蜜罐文件（与 config honeypot.ssh_private_key 一致）
        "SSH_PRIVATE_KEY": honey.get("ssh_private_key", "/tmp/honeypot_ssh_key_never_exist"),
    }
    args: List[str] = []
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    return args


def _write_honeypot_fixtures(host_dir: Path) -> Path:
    """在宿主机准备蜜罐文件目录（挂载到容器 /opt/honeypot，入口脚本再复制到 /tmp）。"""
    hd = host_dir / "honeypot"
    hd.mkdir(parents=True, exist_ok=True)
    for container_path, content in SBX.get("honeypot_files", {}).items():
        (hd / Path(container_path).name).write_text(content, encoding="utf-8")
    return hd


def run_docker(rules: Dict, repo_dir: Path,
               run_command: Optional[str] = None,
               timeout_seconds: Optional[int] = None,
               image: Optional[str] = None,
               keep_container: bool = False) -> MonitorReport:
    """DOCKER 模式: 隔离容器运行目标插件 + strace 采集 + tcpdump sidecar + 蜜罐。

    隔离要点:
      --read-only + tmpfs/volume /tmp, --cap-drop=ALL --cap-add=SYS_PTRACE,
      --memory/--cpus/--pids-limit 限制, 独立 bridge 网络(非 --network=none,
      否则无法观测外传), tcpdump 以 --network=container:<target> sidecar 旁路抓包。
    """
    report = MonitorReport(rules)
    report.start()

    image = image or SBX.get("docker_image", "mpv-sandbox:latest")
    timeout_seconds = timeout_seconds or SBX.get("timeout_seconds", 60)
    net_name = SBX.get("network_name", "mpv-sandbox-net")

    def _fail(msg: str):
        report.add_behavior(Behavior("sandbox_error", {"error": msg}))
        report.stop()
        return report

    if not docker_available():
        return _fail("Docker 守护进程不可用（请先启动 Docker Desktop）")
    if not image_exists(image) and not build_sandbox_image(image):
        return _fail(f"沙箱镜像 {image} 不存在且构建失败")

    run_command = run_command or detect_run_command(repo_dir)
    if not run_command:
        return _fail("无法推断插件启动命令，请用 --run-command 指定")

    tag = f"{int(time.time())}"
    target = f"mpv-tgt-{tag}"
    capture = f"mpv-cap-{tag}"
    volume = f"mpv-tmp-{tag}"
    work = Path(repo_dir).resolve()

    def _cleanup():
        if not keep_container:
            _docker(["rm", "-f", capture], timeout=60)
            _docker(["rm", "-f", target], timeout=60)
            _docker(["volume", "rm", "-f", volume], timeout=60)

    try:
        # 独立 bridge 网络（幂等）
        _docker(["network", "create", net_name], timeout=60)
        _docker(["volume", "create", volume], timeout=60)

        # 准备蜜罐文件（挂载到 /opt/honeypot，入口脚本复制到 /tmp）
        honey_dir = _write_honeypot_fixtures(HERE / "output" / "sandbox_work")

        env_args = _honeypot_env()
        env_args += [
            "-e", f"MPV_RUN_COMMAND={run_command}",
            "-e", f"MPV_TIMEOUT={timeout_seconds}",
            "-e", f"MPV_MAX_TOOLS={SBX.get('probe', {}).get('max_tools', 12)}",
            "-e", f"MPV_STRACE_SYSCALLS={','.join(SBX.get('strace_syscalls', []))}",
            "-e", f"STRACE_OUT={SBX.get('strace_output', '/tmp/mpv_strace.log')}",
            "-e", "HOME=/tmp", "-e", "TMPDIR=/tmp",
            "-e", "GOCACHE=/tmp/go-cache", "-e", "GOPATH=/tmp/go",
            "-e", "CARGO_HOME=/tmp/cargo",
        ]
        if not SBX.get("probe", {}).get("enabled", True):
            env_args += ["-e", "MPV_NO_PROBE=1"]

        # 目标容器
        target_cmd = ["run", "-d", "--name", target,
                      "--network", net_name,
                      "-v", f"{volume}:/tmp",
                      "-v", f"{work}:/app:ro",
                      "-v", f"{honey_dir}:/opt/honeypot:ro",
                      "--read-only",
                      "--cap-drop=ALL", "--cap-add=SYS_PTRACE",
                      "--memory", f"{SBX.get('memory_limit_mb', 2048)}m",
                      "--cpus", str(SBX.get("cpu_limit", 2.0)),
                      "--pids-limit", str(SBX.get("pids_limit", 256)),
                      ] + env_args + [image]
        r = _docker(target_cmd, timeout=120)
        if r.returncode != 0:
            return _fail(f"目标容器启动失败: {(r.stderr or r.stdout)[:300]}")

        # tcpdump sidecar（共享目标容器的网络命名空间）
        cap_cmd = ["run", "-d", "--name", capture,
                   "--network", f"container:{target}",
                   "-v", f"{volume}:/tmp",
                   "--cap-add=NET_RAW",
                   image, "sh", "-c",
                   f"tcpdump -i any -nn -s0 -A -l > {SBX.get('net_output', '/tmp/mpv_net.pcap').replace('.pcap', '.txt')} 2>/dev/null"]
        _docker(cap_cmd, timeout=120)

        # 等待目标容器结束（超时则强杀）
        try:
            _docker(["wait", target], timeout=timeout_seconds + 30)
        except subprocess.TimeoutExpired:
            _docker(["kill", target], timeout=60)
            _docker(["wait", target], timeout=60)

        # 停止抓包并收集日志
        _docker(["kill", capture], timeout=60)
        strace_out = HERE / "output" / "sandbox_work" / f"{tag}_strace.log"
        net_out = HERE / "output" / "sandbox_work" / f"{tag}_net.txt"
        strace_out.parent.mkdir(parents=True, exist_ok=True)
        _docker(["cp", f"{target}:{SBX.get('strace_output', '/tmp/mpv_strace.log')}",
                 str(strace_out)], timeout=120)
        _docker(["cp", f"{capture}:/tmp/mpv_net.txt", str(net_out)], timeout=120)

        strace_text = (strace_out.read_text(encoding="utf-8", errors="replace")
                       if strace_out.exists() else "")
        net_text = (net_out.read_text(encoding="utf-8", errors="replace")
                    if net_out.exists() else "")

        if not strace_text:
            report.add_behavior(Behavior("sandbox_error",
                                         {"error": "未采集到 strace 输出（插件可能未产生任何系统调用）"}))

        for behavior in parse_event_log(
                strace_text, net_text,
                honeypot_indicators=rules.get("blocklist", {}).get("honeypot_indicators", []),
                noise_prefixes=SBX.get("open_noise_prefixes"),
                sensitive_patterns=SBX.get("sensitive_path_patterns")):
            report.add_behavior(behavior)

    except Exception as e:
        report.add_behavior(Behavior("sandbox_error",
                                     {"error": str(e),
                                      "trace": traceback.format_exc()[:400]}))
    finally:
        _cleanup()
        report.stop()

    return report


# ---------------------------------------------------------------------------
# 6. CLI 入口
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="MPV-Detector 沙箱行为监控器")
    ap.add_argument("--rules", required=True, help="sandbox_rules.py 生成的规则 JSON")
    ap.add_argument("--mode", choices=["docker", "simulate", "fixture"],
                    default="docker", help="运行模式")
    # simulate
    ap.add_argument("--entry-point", default="",
                    help="SIMULATE 模式: 入口 Python 脚本路径")
    # docker
    ap.add_argument("--repo-dir", default="", help="DOCKER 模式: 仓库目录")
    ap.add_argument("--run-command", default="", help="DOCKER 模式: 插件启动命令")
    ap.add_argument("--image", default="", help="沙箱镜像名(覆盖配置)")
    ap.add_argument("--keep-container", action="store_true",
                    help="DOCKER 模式: 保留容器便于排查")
    ap.add_argument("--build-image", action="store_true", help="仅构建沙箱镜像后退出")
    ap.add_argument("--check-docker", action="store_true", help="仅探测 Docker 可用性后退出")
    # fixture
    ap.add_argument("--strace-file", default="", help="FIXTURE 模式: strace 文本")
    ap.add_argument("--net-file", default="", help="FIXTURE 模式: tcpdump 文本")
    # 通用
    ap.add_argument("--timeout", type=int, default=0, help="运行超时秒数")
    ap.add_argument("--output", default="", help="报告输出 JSON")
    args = ap.parse_args()

    if args.check_docker:
        ok = docker_available()
        print(f"Docker 守护进程: {'可用' if ok else '不可用'}")
        sys.exit(0 if ok else 1)

    if args.build_image:
        ok = build_sandbox_image(args.image or None)
        print(f"沙箱镜像构建: {'成功' if ok else '失败'}")
        sys.exit(0 if ok else 1)

    rules_path = Path(args.rules)
    if not rules_path.exists():
        print(f"[错误] 规则文件不存在: {args.rules}")
        sys.exit(1)
    rules = json.loads(rules_path.read_text(encoding="utf-8"))

    if args.mode == "simulate":
        if not args.entry_point:
            print("[错误] SIMULATE 模式需要 --entry-point")
            sys.exit(1)
        report = run_simulate(rules, args.entry_point, timeout_seconds=args.timeout or 60)
    elif args.mode == "fixture":
        report = run_fixture(rules, args.strace_file, args.net_file)
    else:
        if not args.repo_dir:
            print("[错误] DOCKER 模式需要 --repo-dir")
            sys.exit(1)
        report = run_docker(rules, Path(args.repo_dir),
                            run_command=args.run_command or None,
                            timeout_seconds=args.timeout or None,
                            image=args.image or None,
                            keep_container=args.keep_container)

    report.print_summary()

    if args.output:
        Path(args.output).write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"报告已写入: {args.output}")

    # 退出码: 2=MALICIOUS, 1=需人工审核, 0=通过
    if report.final_verdict == "MALICIOUS":
        sys.exit(2)
    if report.review_requested:
        sys.exit(1)


if __name__ == "__main__":
    main()
