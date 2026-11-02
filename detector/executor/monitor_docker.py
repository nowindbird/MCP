#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.executor.monitor_docker —— Docker 沙箱运行器
=====================================================
从 behavior_monitor.py 抽出：隔离容器运行目标插件 + strace + tcpdump + 蜜罐。
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

from detector.deps import (
    SANDBOX_IMAGE_DIR,
    SANDBOX_WORK_DIR,
    docker_available,
)
from detector.executor.behavior_monitor import MonitorReport
from detector.executor.monitor_parser import Behavior, SBX, parse_event_log


def _docker(args: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker"] + args, capture_output=True, text=True,
                          timeout=timeout, encoding="utf-8", errors="replace")


def image_exists(image: str) -> bool:
    try:
        return _docker(["image", "inspect", image], timeout=30).returncode == 0
    except Exception:
        return False


def build_sandbox_image(image: Optional[str] = None) -> bool:
    """构建沙箱镜像（含 strace/tcpdump/python/node，可选 go/rust）。"""
    image = image or SBX.get("docker_image", "mpv-sandbox:latest")
    dockerfile = SANDBOX_IMAGE_DIR / "Dockerfile"
    if not dockerfile.exists():
        print(f"[错误] 未找到 Dockerfile: {dockerfile}")
        return False
    print(f"[构建] docker build -t {image} ... (首次较慢)")
    r = _docker(["build", "-t", image, "-f", str(dockerfile), str(SANDBOX_IMAGE_DIR)],
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
        "OPENAI_API_KEY": api_key,
        "ANTHROPIC_API_KEY": api_key,
        "GITHUB_TOKEN": api_key,
        "AWS_ACCESS_KEY_ID": aws_id,
        "AWS_SECRET_ACCESS_KEY": aws_secret,
        "DATABASE_URL": f"postgres://admin:{api_key}@db.internal:5432/prod",
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
    """DOCKER 模式: 隔离容器运行目标插件 + strace 采集 + tcpdump sidecar + 蜜罐。"""
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
        _docker(["network", "create", net_name], timeout=60)
        _docker(["volume", "create", volume], timeout=60)

        honey_dir = _write_honeypot_fixtures(SANDBOX_WORK_DIR)

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

        cap_cmd = ["run", "-d", "--name", capture,
                   "--network", f"container:{target}",
                   "-v", f"{volume}:/tmp",
                   "--cap-add=NET_RAW",
                   image, "sh", "-c",
                   f"tcpdump -i any -nn -s0 -A -l > {SBX.get('net_output', '/tmp/mpv_net.pcap').replace('.pcap', '.txt')} 2>/dev/null"]
        _docker(cap_cmd, timeout=120)

        try:
            _docker(["wait", target], timeout=timeout_seconds + 30)
        except subprocess.TimeoutExpired:
            _docker(["kill", target], timeout=60)
            _docker(["wait", target], timeout=60)

        _docker(["kill", capture], timeout=60)
        strace_out = SANDBOX_WORK_DIR / f"{tag}_strace.log"
        net_out = SANDBOX_WORK_DIR / f"{tag}_net.txt"
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
