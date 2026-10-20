#!/bin/sh
# MPV-Detector 沙箱入口脚本
# ---------------------------------------------------------------
# 1. 落地蜜罐凭据文件(内容由宿主机挂载到 /opt/honeypot)
# 2. 以 strace 包裹目标插件, 并由 mcp_probe.py 驱动其 MCP 工具执行
# ---------------------------------------------------------------
set -u

STRACE_OUT="${STRACE_OUT:-/tmp/mpv_strace.log}"
mkdir -p /tmp

# ---- 1. 落地蜜罐文件到 /tmp（路径与 config.sandbox.honeypot 指纹一致）----
if [ -d /opt/honeypot ]; then
  cp -a /opt/honeypot/. /tmp/ 2>/dev/null || true
fi

# ---- 2. 运行探针（内含 strace 包裹与 JSON-RPC 工具调用）----
CMD="${MPV_RUN_COMMAND:-}"
if [ -z "$CMD" ]; then
  echo "[沙箱] 未提供 MPV_RUN_COMMAND，无法运行目标插件" >&2
  exit 3
fi

set -- \
  --cmd "$CMD" \
  --cwd /app \
  --strace-out "$STRACE_OUT" \
  --strace-syscalls "${MPV_STRACE_SYSCALLS:-execve,openat,connect,sendto}" \
  --timeout "${MPV_TIMEOUT:-60}" \
  --max-tools "${MPV_MAX_TOOLS:-12}"

if [ -n "${MPV_NO_PROBE:-}" ]; then
  set -- "$@" --no-probe
fi

exec python3 /opt/mcp_probe.py "$@"
