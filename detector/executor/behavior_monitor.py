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

用法::

  # 先准备规则
  python -m detector.cli sandbox-rules --repo-dir dateset/<owner>_<repo> --output rules.json
  # Docker 模式（首次会自动构建沙箱镜像）
  python -m detector.cli monitor --rules rules.json --mode docker --repo-dir dateset/<owner>_<repo>
  # 模拟模式
  python -m detector.cli monitor --rules rules.json --mode simulate --entry-point run_server.py
  # 固件回放模式（离线单测）
  python -m detector.cli monitor --rules rules.json --mode fixture --strace-file a.log --net-file b.txt

配置与路径统一来自 ``detector.deps``（strace/tcpdump 采集物落在 config 的
``output/sandbox_work``，不再写到代码目录下）。
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

from detector.deps import (
    CONFIG,
    SANDBOX_IMAGE_DIR,
    SANDBOX_WORK_DIR,
    docker_available,
    ensure_utf8_stdio,
    read_json,
    write_json,
)

# ---------------------------------------------------------------------------
# 0. 行为数据模型 / 解析口径（已下沉到 monitor_parser.py，避免循环导入）
# ---------------------------------------------------------------------------
from detector.executor.monitor_parser import (  # noqa: F401
    Behavior, SBX, DEFAULT_OPEN_NOISE, DEFAULT_SENSITIVE_PATTERNS,
    ERROR_CATEGORIES, parse_strace_text, parse_tcpdump_text, parse_event_log,
)


# ---------------------------------------------------------------------------
# 1. 行为数据结构（MonitorReport：规则比对与判定逻辑）
# ---------------------------------------------------------------------------


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
# 2. 沙箱事件解析（在 monitor_parser.py，顶部已导入并 re-export）
# ---------------------------------------------------------------------------
# 注意：monitor_simulate / monitor_docker 在 main() 内按需导入，
# 避免「behavior_monitor ↔ monitor_simulate」循环导入；两模块需要
# Behavior / MonitorReport 时直接从本模块取用（它们不反向被本模块模块级导入）。


# ---------------------------------------------------------------------------
# 6. CLI 入口
# ---------------------------------------------------------------------------

def main() -> int:
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description="MPV-Detector 沙箱行为监控器")
    ap.add_argument("--rules", required=True, help="sandbox_rules 生成的规则 JSON")
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
        return 0 if ok else 1

    if args.build_image:
        from detector.executor.monitor_docker import build_sandbox_image
        ok = build_sandbox_image(args.image or None)
        print(f"沙箱镜像构建: {'成功' if ok else '失败'}")
        return 0 if ok else 1

    rules_path = Path(args.rules)
    if not rules_path.exists():
        print(f"[错误] 规则文件不存在: {args.rules}")
        return 1
    rules = read_json(rules_path)
    if not isinstance(rules, dict):
        print(f"[错误] 规则文件不是合法 JSON 对象: {args.rules}")
        return 1

    if args.mode == "simulate":
        if not args.entry_point:
            print("[错误] SIMULATE 模式需要 --entry-point")
            return 1
        from detector.executor.monitor_simulate import run_simulate
        report = run_simulate(rules, args.entry_point, timeout_seconds=args.timeout or 60)
    elif args.mode == "fixture":
        from detector.executor.monitor_simulate import run_fixture
        report = run_fixture(rules, args.strace_file, args.net_file)
    else:
        if not args.repo_dir:
            print("[错误] DOCKER 模式需要 --repo-dir")
            return 1
        from detector.executor.monitor_docker import run_docker
        report = run_docker(rules, Path(args.repo_dir),
                            run_command=args.run_command or None,
                            timeout_seconds=args.timeout or None,
                            image=args.image or None,
                            keep_container=args.keep_container)

    report.print_summary()

    if args.output:
        write_json(args.output, report.to_dict())
        print(f"报告已写入: {args.output}")

    # 退出码: 2=MALICIOUS, 1=需人工审核, 0=通过
    if report.final_verdict == "MALICIOUS":
        return 2
    if report.review_requested:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
