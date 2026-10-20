#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_dataset.py — 从 MCP 仓库提取工具定义，构造"代码 → 结构化文档"微调训练语料
================================================================================
输入   : 一个或多个 MCP 仓库根目录（含 .py 源码）
输出   : dataset.jsonl（Alpaca 指令格式，每行一个样本）
        dataset_stats.json（提取统计）

用法   :
    python build_dataset.py <repo_dir1> [repo_dir2 ...] -o dataset.jsonl

依赖   : Python 3.8+ 标准库（无第三方依赖）

原理   : 纯 AST 静态分析（确定性，绝不执行代码）
  1) 定位 MCP 工具注册点：@mcp.tool / @server.tool / @tool 等装饰器函数
  2) 提取函数签名 → 推导 input_schema（JSON Schema 子集）
  3) 遍历函数体收集"敏感行为硬事实"：环境变量 / 文件访问 / 网络 / 子进程 / 混淆 / 隐藏行为
  4) docstring → description（Phase 2 再用强 LLM 增强，此处保留原始文本）
  5) 输出 Alpaca 格式样本：output 为 JSON（name/description/input_schema/security_declarations）

说明   : 脚本只做确定性提取，不调用 LLM；"描述生成 + 防幻觉过滤"是 Phase 2 脚本。
         本脚本输出中的 description 来自代码 docstring（可能为空/过短），
         安全声明 security_declarations 来自 AST 硬事实（确定性可信）。
"""

import ast
import argparse
import json
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. 常量：敏感行为模式
# ---------------------------------------------------------------------------

# 环境变量名特征（读取时记录具体变量名）
ENV_HINT_RE = re.compile(r"(?i)(key|secret|token|password|api|auth|credential)")

# 敏感路径特征（文件访问时记录路径字面量）
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(\.ssh|\.aws|\.gnupg|\.kube|credentials|\.env|id_rsa|keyring|\.netrc)"
)

# 文件操作调用名（ast 层面匹配）
FILE_READ_CALLS = {
    "open", "read", "read_text", "read_bytes",
}
FILE_READ_METHODS = {"read", "read_text", "read_bytes"}

# 网络操作调用名
NET_CALLS = {
    "get", "post", "put", "patch", "delete", "request", "urlopen", "connect",
    "getrequest", "fetch",
}
NET_LIBS = {"requests", "urllib", "httpx", "aiohttp", "urllib3", "socket", "websocket"}

# 子进程 / 命令执行
SUBPROC_CALLS = {"system", "run", "call", "popen", "check_output", "check_call", "spawn", "exec"}
SUBPROC_MODS = {"subprocess", "os", "os.path"}

# 混淆
OBFUSCATION_CALLS = {"b64decode", "b64encode", "unhexlify", "hexlify", "loads"}
OBFUSCATION_FUNCS = {"eval", "exec", "marshal", "pickle", "compile"}

# 隐藏行为信号（对应论文 hidden_flags）
HIDDEN_SIGNALS = {
    "reverse_shell": [re.compile(r"(?i)/dev/tcp/"), re.compile(r"dup2\s*\(")],
    "hidden_bcc": [re.compile(r"(?i)bcc")],
    "hardcoded_cred": [re.compile(r"(?i)(sk-|ghp_|gho_|AKIA[0-9A-Z]{16}|xox[bap]-|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")],
    "dynamic_code": [re.compile(r"(?i)(eval|exec)\s*\(")],
}


# ---------------------------------------------------------------------------
# 2. 敏感行为硬事实提取
# ---------------------------------------------------------------------------

class FactCollector(ast.NodeVisitor):
    """遍历函数体，收集安全相关的硬事实（确定性）。
    采用"调用名解析 + 组合信号后处理"：先记录所有敏感调用，
    最后统一判定混淆 / 反向 shell / 隐藏 BCC 等组合特征。
    """

    # (调用名 → 事实类别) 映射；调用名用点号链式解析，如 requests.get / os.getenv
    NETWORK_CALLS = {
        "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
        "requests.request", "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
        "httpx.AsyncClient.get", "httpx.AsyncClient.post", "httpx.AsyncClient.put",
        "aiohttp.ClientSession.get", "aiohttp.ClientSession.post", "aiohttp.ClientSession.put",
        "urllib.request.urlopen", "urllib.request.Request", "socket.connect", "socket.create_connection",
    }
    SUBPROC_CALLS = {
        "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
        "subprocess.check_call", "os.system", "os.popen", "commands.getoutput",
    }
    ENV_CALLS = {"os.getenv", "os.environ.get", "os.environ"}
    OBFUSCATE_CALLS = {"base64.b64decode", "base64.b64encode", "base64.decodebytes",
                       "marshal.loads", "marshal.dumps", "pickle.loads", "pickle.load",
                       "binascii.unhexlify", "codecs.decode"}
    EVAL_CALLS = {"eval", "exec", "execfile", "compile", "importlib.import_module"}

    def __init__(self, code: str):
        self.code = code
        self.facts = {
            "file_access": [],
            "network": [],
            "env_vars": [],
            "subprocess": [],
            "obfuscation": [],
            "hidden_flags": [],
        }
        self.calls = []            # [(call_name, str_args)]
        self._seen = set()
        # 组合信号状态
        self._has_obfuscate = False
        self._has_eval = False
        self._has_dup2 = False
        self._has_smtp = False
        self._has_bcc = False

    def _add(self, key: str, value: str):
        value = value.strip()
        if not value or value in self._seen:
            return
        self._seen.add(value)
        if len(self.facts[key]) < 50:
            self.facts[key].append(value)

    @staticmethod
    def _call_name(node) -> str:
        """把 Call 的 func 解析为点号链名：requests.get / os.getenv / base64.b64decode。"""
        func = node.func
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        return ".".join(reversed(parts))

    def visit_Call(self, node: ast.Call):
        name = self._call_name(node)  # 解析点号链名，如 requests.get
        # 提取字符串字面量实参（用于凭据/路径判定）
        str_args = [a.value for a in node.args
                    if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        self.calls.append((name, str_args))

        # 环境变量读取：仅记录含凭据特征的变量名
        if name in self.ENV_CALLS:
            for a in str_args[:2]:
                if re.search(r"(?i)(key|secret|token|password|api|auth|credential)", a) or name != "os.environ":
                    self._add("env_vars", a)
        # 网络调用
        if name in self.NETWORK_CALLS:
            self._add("network", f"{name}(...)")
        # 子进程/命令执行
        if name in self.SUBPROC_CALLS:
            self._add("subprocess", f"{name}(...)")
        # 混淆解码调用（标记为已出现混淆）
        if name in self.OBFUSCATE_CALLS:
            self._has_obfuscate = True
            self._add("obfuscation", f"{name}(...)")
        # 动态执行（eval/exec/compile）
        if name in self.EVAL_CALLS:
            self._has_eval = True
        if name == "os.dup2":  # dup2 重定向描述符 → 反向 shell 信号
            self._has_dup2 = True
        if "smtp" in name.lower():  # SMTP → 邮件相关（配合 BCC 判定）
            self._has_smtp = True
        for a in str_args:  # 实参含 Bcc 字段
            if re.search(r"(?i)\bbcc\b", a):
                self._has_bcc = True
        self.generic_visit(node)  # 继续深入子节点

    def visit_Subscript(self, node: ast.Subscript):
        """处理 os.environ["KEY"] 下标访问形式的环境变量读取。"""
        try:
            value = node.value
            if isinstance(value, ast.Attribute) and value.attr == "environ":
                if isinstance(node.slice, ast.Constant):
                    self._add("env_vars", str(node.slice.value))
        except Exception:
            pass
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        """从字符串字面量中识别敏感路径 / 网络地址 / 隐藏凭据信号。"""
        try:
            if isinstance(node.value, str):
                s = node.value
                # 敏感文件路径（.ssh/.aws/凭据文件等）
                if SENSITIVE_PATH_RE.search(s) or re.search(r"(?i)\.(pem|pfx|key)$", s):
                    self._add("file_access", s)
                # 明文 URL
                if re.search(r"https?://", s, re.I):
                    self._add("network", s)
                # IP:端口 形式（网络端点）
                if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*[:|,]\s*\d+", s):
                    self._add("network", s)
                # 硬编码凭据模式
                for pat in HIDDEN_SIGNALS["hardcoded_cred"]:
                    if pat.search(s):
                        self._add("hidden_flags", "硬编码凭据")
                        break
                # 反向 shell 标记
                if HIDDEN_SIGNALS["reverse_shell"][0].search(s):   # /dev/tcp/
                    self._add("hidden_flags", "反向shell")
                if re.search(r"(?i)\bbcc\b", s):                    # msg["Bcc"] / Bcc 字段
                    self._has_bcc = True
        except Exception:
            pass
        self.generic_visit(node)

    def finalize(self):
        """组合信号后处理（在 visit 完成后调用）。"""
        if self._has_dup2:  # dup2 重定向 → 反向 shell
            self._add("hidden_flags", "反向shell(dup2)")
        if self._has_bcc:  # 邮件 BCC
            self._add("hidden_flags", "隐藏BCC")
        if self._has_eval and self._has_obfuscate:  # 解码+执行组合
            self._add("obfuscation", "base64/pickle+eval/exec 组合")
        elif self._has_eval:  # 纯动态执行
            self._add("hidden_flags", "动态代码执行")


# ---------------------------------------------------------------------------
# 3. 工具注册点识别（AST）
# ---------------------------------------------------------------------------

TOOL_DECORATOR_RE = re.compile(r"(?i)(tool|mcp|server|app)")


def _is_tool_decorator(decorator) -> bool:
    """判断装饰器是否可能是 MCP 工具注册（@mcp.tool / @server.tool / @tool）。"""
    name = ""
    if isinstance(decorator, ast.Name):
        name = decorator.id
    elif isinstance(decorator, ast.Attribute):
        name = decorator.attr
    elif isinstance(decorator, ast.Call):
        inner = decorator.func
        name = getattr(inner, "attr", None) or getattr(inner, "id", "")
    return name is not None and name.strip().lower() == "tool"


def _decorator_too_name(decorator) -> str:
    """尝试从装饰器参数取出工具名（@mcp.tool("name")）。"""
    if isinstance(decorator, ast.Call):
        if decorator.args and isinstance(decorator.args[0], ast.Constant):
            return str(decorator.args[0].value)
    return ""


def derive_schema(func_node: ast.FunctionDef) -> dict:
    """从函数签名推导 JSON Schema（子集）。"""
    props, required = {}, []
    for arg in func_node.args.args:
        if arg.arg in ("self", "cls"):
            continue
        ann = arg.annotation
        t = "string"
        if isinstance(ann, ast.Name):
            t = {
                "str": "string", "int": "integer", "float": "number",
                "bool": "boolean", "list": "array", "dict": "object",
                "bytes": "string", "Path": "string",
            }.get(ann.id, "string")
        elif isinstance(ann, ast.Constant):
            t = "string"
        props[arg.arg] = {"type": t}
        required.append(arg.arg)
    return {"type": "object", "properties": props, "required": required}


def extract_docstring(func_node: ast.FunctionDef) -> str:
    doc = ast.get_docstring(func_node, clean=True)
    if not doc:
        return ""
    # 保留首段（一般到第一个空行或前 3 行）
    lines = [l.strip() for l in doc.strip().splitlines() if l.strip()]
    return " ".join(lines[:3])[:400]


def extract_tools_from_file(path: Path) -> list:
    """从一个 .py 文件提取所有 MCP 工具定义。"""
    try:
        source = path.read_text(encoding="utf-8-sig", errors="replace")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return []
    tools = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decos = node.decorator_list
        if not any(_is_tool_decorator(d) for d in decos):
            continue
        code_src = ast.get_source_segment(source, node) or "# 源不可用"
        collector = FactCollector(code_src)
        collector.visit(node)
        collector.finalize()
        name = _decorator_too_name(decos[0]) or node.name
        tools.append({
            "file": str(path),
            "line": node.lineno,
            "name": name,
            "signature": code_src.splitlines()[0][:200] if code_src else "",
            "description": extract_docstring(node),
            "input_schema": derive_schema(node),
            "security_declarations": collector.facts,
            "code": code_src,
        })
    return tools


# ---------------------------------------------------------------------------
# 4. 主流程
# ---------------------------------------------------------------------------

def scan_repo(repo_dir: Path) -> list:
    tools = []
    for py in repo_dir.rglob("*.py"):
        # 跳过常见噪音目录
        parts = set(py.parts)
        if parts & {"node_modules", "site-packages", "dist", "build", "test", "tests", "venv", ".venv", "__pycache__", "examples"}:
            continue
        try:
            tools.extend(extract_tools_from_file(py))
        except Exception:
            continue
    return tools


def build_sample(tool: dict) -> dict:
    """Alpaca 格式样本。output 为 JSON 字符串（指令模型的标准做法）。"""
    output = {
        "name": tool["name"],
        "description": tool["description"],
        "input_schema": tool["input_schema"],
        "security_declarations": tool["security_declarations"],
    }
    instruction = (
        "你是一个 MCP 服务器安全审查工具。请根据下面的 MCP 工具实现代码，"
        "输出该工具的结构化说明文档 JSON，必须包含字段："
        "name（工具名）、description（面向用户和 LLM 的功能说明）、"
        "input_schema（参数 JSON Schema）、"
        "security_declarations（安全行为声明：file_access 文件访问、network 网络端点、"
        "env_vars 读取的环境变量、subprocess 子进程命令、obfuscation 混淆手段、"
        "hidden_flags 隐藏行为标记）。"
        "要求：description 只描述代码真实实现的行为，security_declarations 必须完整覆盖"
        "代码中出现的所有敏感行为，不得遗漏、不得虚构。只输出 JSON。"
    )
    return {
        "instruction": instruction,
        "input": tool["code"],
        "output": json.dumps(output, ensure_ascii=False),
        "meta": {
            "file": tool["file"],
            "line": tool["line"],
            "has_docstring": bool(tool["description"]),
            "has_sensitive_facts": any(v for v in tool["security_declarations"].values()),
        },
    }


def main():
    ap = argparse.ArgumentParser(description="MCP 工具语料提取（AST，纯静态）")
    ap.add_argument("repos", nargs="+", help="MCP 仓库根目录")
    ap.add_argument("-o", "--output", default="dataset.jsonl", help="输出 JSONL 路径")
    args = ap.parse_args()

    all_tools, skipped = [], 0
    for r in args.repos:
        repo = Path(r)
        if not repo.is_dir():
            print(f"[skip] 不存在: {repo}", file=sys.stderr)
            skipped += 1
            continue
        tools = scan_repo(repo)
        print(f"[ok] {repo.name}: 提取到 {len(tools)} 个工具")
        all_tools.extend(tools)

    if not all_tools:
        print("未提取到任何工具，请检查仓库路径。", file=sys.stderr)
        sys.exit(1)

    # 去重（按 文件+工具名；不同仓库的同名工具是不同样本）
    seen, samples = set(), []
    for t in all_tools:
        key = (t["file"], t["name"])
        if key in seen:
            continue
        seen.add(key)
        samples.append(build_sample(t))

    with open(args.output, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    with_sensitive = sum(1 for s in samples if s["meta"]["has_sensitive_facts"])
    stats = {
        "repos": len(args.repos) - skipped,
        "tools_raw": len(all_tools),
        "samples": len(samples),
        "with_sensitive_facts": with_sensitive,
        "with_docstring": sum(1 for s in samples if s["meta"]["has_docstring"]),
    }
    stat_path = Path(args.output).with_name("dataset_stats.json")
    stat_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n完成：{len(samples)} 条样本 -> {args.output}")
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
