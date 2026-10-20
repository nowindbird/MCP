# MPV-Detector 沙箱镜像
# ---------------------------------------------------------------
# 用途: 在隔离容器内运行被测 MCP 插件, 用 strace 采集系统调用,
#       配合 tcpdump sidecar 抓网络, 检测蜜罐凭据外传与未声明行为。
#
# 构建:
#   docker build -t mpv-sandbox:latest -f sandbox/Dockerfile sandbox
# 可选关闭重型工具链(默认都装, 便于跑 Go/Rust 插件):
#   docker build --build-arg INSTALL_GO=0 --build-arg INSTALL_RUST=0 ...
# ---------------------------------------------------------------
FROM ubuntu:22.04

ARG INSTALL_GO=1
ARG INSTALL_RUST=1

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp \
    TMPDIR=/tmp

# 基础监控与运行时(python/node/strace/tcpdump 为必需)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl strace tcpdump iproute2 procps \
        python3 python3-pip python3-venv \
        nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Go 工具链(可选)
RUN if [ "$INSTALL_GO" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends golang-go \
        && rm -rf /var/lib/apt/lists/* ; \
    fi

# Rust 工具链(可选)
RUN if [ "$INSTALL_RUST" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends rustc cargo \
        && rm -rf /var/lib/apt/lists/* ; \
    fi

COPY mcp_probe.py /opt/mcp_probe.py
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

WORKDIR /app
ENTRYPOINT ["/opt/entrypoint.sh"]
