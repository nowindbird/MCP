#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPV-Detector MCP 探针 (容器内运行)
=================================
用途: 解决"休眠触发型"恶意行为——插件只启动不干活时, 恶意逻辑不会被触发。
本探针以 strace 包裹目标插件, 并通过 stdio 发送 MCP JSON-RPC 请求:
    initialize -> notifications/initialized -> tools/list
    -> tools/call(每个工具, 用 schema 推导的哑参数)
    -> resources/list / prompts/list
从而真正"使用"插件暴露的工具, 让潜在恶意行为在沙箱内暴露。

注意: MCP stdio 传输是「按行分隔的 JSON」, 不是 LSP 的 Content-Length 帧。
"""

import argparse
import json
import queue
import shlex
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional

PROTOCOL_VERSION = "2024-11-05"


# ---------------------------------------------------------------------------
# 哑参数推导
# ---------------------------------------------------------------------------

def _dummy_value(schema: Dict[str, Any]) -> Any:
    t = schema.get("type")
    if t == "string":
        # 给一些"看起来敏感"的默认值, 提高触发概率（如路径/token）
        return schema.get("default", "test")
    if t in ("number", "integer"):
        return 1
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "object":
        return _dummy_object(schema)
    if isinstance(t, list) and t:
        return _dummy_value({"type": t[0]})
    return "test"


def _dummy_object(schema: Dict[str, Any]) -> Dict[str, Any]:
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    keys = required if required else list(props.keys())
    return {k: _dummy_value(props.get(k, {})) for k in keys}


def build_tool_arguments(tool: Dict[str, Any]) -> Dict[str, Any]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    return _dummy_object(schema) if schema else {}


# ---------------------------------------------------------------------------
# stdio JSON-RPC 客户端
# ---------------------------------------------------------------------------

class StdioClient:
    """极简 MCP stdio JSON-RPC 客户端, 带行读取线程与超时。"""

    def __init__(self, argv: List[str], cwd: str):
        self.proc = subprocess.Popen(
            argv, cwd=cwd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, errors="replace",
        )
        self._q: "queue.Queue[str]" = queue.Queue()
        self._alive = True
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _read_stdout(self):
        try:
            for line in self.proc.stdout:  # type: ignore[union-attr]
                self._q.put(line)
        except Exception:
            pass
        finally:
            self._alive = False

    def _drain_stderr(self):
        try:
            for _ in self.proc.stderr:  # type: ignore[union-attr]
                pass
        except Exception:
            pass

    def send(self, obj: Dict[str, Any]) -> bool:
        try:
            self.proc.stdin.write(json.dumps(obj) + "\n")  # type: ignore[union-attr]
            self.proc.stdin.flush()  # type: ignore[union-attr]
            return True
        except Exception:
            return False

    def _next_line(self, deadline: float) -> Optional[str]:
        remain = max(0.0, deadline - time.time())
        try:
            return self._q.get(timeout=remain)
        except queue.Empty:
            return None

    def request(self, obj: Dict[str, Any], timeout: float) -> Optional[Dict[str, Any]]:
        """发送请求并等待 id 匹配的响应（自动跳过通知与其他 id）。"""
        if not self.send(obj):
            return None
        want = obj.get("id")
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self._next_line(deadline)
            if line is None:
                return None
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # 插件打印的日志行, 忽略
            if isinstance(msg, dict) and msg.get("id") == want:
                return msg
            # 其他 id 的响应/通知: 丢弃
        return None

    def terminate(self, grace: float = 3.0):
        if self.proc.poll() is not None:
            return
        # 先关闭 stdin(发 EOF): 规范实现的服务器会优雅退出并 flush
        try:
            self.proc.stdin.close()  # type: ignore[union-attr]
        except Exception:
            pass
        try:
            self.proc.wait(timeout=grace)
            return
        except Exception:
            pass
        # 兜底: SIGTERM -> SIGKILL
        try:
            self.proc.terminate()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=grace)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="MCP 沙箱探针")
    ap.add_argument("--cmd", required=True, help="插件启动命令(字符串)")
    ap.add_argument("--cwd", default="/app", help="插件工作目录")
    ap.add_argument("--strace-out", default="/tmp/mpv_strace.log")
    ap.add_argument("--strace-syscalls", default="execve,openat,connect,sendto")
    ap.add_argument("--timeout", type=int, default=60, help="整体超时秒数")
    ap.add_argument("--max-tools", type=int, default=12)
    ap.add_argument("--no-probe", action="store_true", help="不发送 JSON-RPC, 仅运行")
    ap.add_argument("--no-strace", action="store_true",
                    help="不用 strace 包裹(缺少 strace 时自动降级)")
    args = ap.parse_args()

    started = time.time()
    deadline = started + args.timeout

    # strace 包裹(缺失时优雅降级为直接运行, 仅失去系统调用采集)
    use_strace = not args.no_strace and shutil.which("strace") is not None
    if use_strace:
        argv = ["strace", "-f", "-qq", "-e", f"trace={args.strace_syscalls}",
                "-o", args.strace_out] + shlex.split(args.cmd)
    else:
        argv = shlex.split(args.cmd)
        if not args.no_strace:
            print("[探针] 警告: 未找到 strace, 直接运行目标(无系统调用采集)", flush=True)

    print(f"[探针] 启动: {' '.join(argv)}", flush=True)
    client = StdioClient(argv, args.cwd)

    tool_count = 0
    try:
        if not args.no_probe:
            # ---- initialize ----
            resp = client.request({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mpv-detector-probe", "version": "2.0"},
                },
            }, timeout=min(10, max(2, int(deadline - time.time()))))
            print(f"[探针] initialize: {'OK' if resp else '无响应'}", flush=True)

            client.send({"jsonrpc": "2.0", "method": "notifications/initialized",
                         "params": {}})

            # ---- tools/list ----
            resp = client.request({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                                   "params": {}},
                                  timeout=min(15, max(2, int(deadline - time.time()))))
            tools: List[Dict[str, Any]] = []
            if resp and isinstance(resp.get("result"), dict):
                tools = resp["result"].get("tools", []) or []
            tool_count = len(tools)
            print(f"[探针] tools/list: 发现 {tool_count} 个工具", flush=True)

            # ---- tools/call（核心: 真正触发工具执行）----
            for i, tool in enumerate(tools[: max(0, args.max_tools)]):
                if time.time() >= deadline:
                    break
                name = tool.get("name", f"tool_{i}")
                call_args = build_tool_arguments(tool)
                resp = client.request({
                    "jsonrpc": "2.0", "id": 100 + i, "method": "tools/call",
                    "params": {"name": name, "arguments": call_args},
                }, timeout=min(15, max(2, int(deadline - time.time()))))
                ok = bool(resp and not resp.get("error"))
                print(f"[探针] tools/call {name}({json.dumps(call_args, ensure_ascii=False)[:120]})"
                      f" -> {'OK' if ok else '无响应/错误'}", flush=True)

            # ---- resources/list / prompts/list（M9 面）----
            for j, method in enumerate(("resources/list", "prompts/list")):
                if time.time() >= deadline:
                    break
                client.request({"jsonrpc": "2.0", "id": 200 + j, "method": method,
                                "params": {}},
                               timeout=min(10, max(2, int(deadline - time.time()))))
                print(f"[探针] {method}: 已发送", flush=True)
        else:
            print("[探针] 已禁用 JSON-RPC, 仅运行目标", flush=True)

        # ---- 给插件留出余量完成异步动作(外传等) ----
        remaining = deadline - time.time()
        if remaining > 0:
            time.sleep(min(3.0, remaining))

    finally:
        client.terminate()
        print(f"[探针] 结束, 工具数={tool_count}, "
              f"耗时={time.time() - started:.1f}s", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
