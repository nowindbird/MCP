#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
infer_mcp_doc.py — 用微调后的 MCP 文档模型对工具代码生成结构化说明文档
=====================================================================
用法 :
    python infer_mcp_doc.py --model_dir models\Qwen2.5-3B-Instruct \
        --adapter_dir adapter_mcp_doc --code-file <工具代码文件或目录> \
        [--out out.jsonl] [--max_new_tokens 600]

说明 :
  * 加载 QLoRA 4bit 基座 + LoRA adapter（adapter_mcp_doc/），无需训练显存
  * 对输入代码（.py 函数/文件，或目录中所有 .py）生成 MCP 工具文档 JSON：
      name / description / input_schema / security_declarations
  * security_declarations 六个字段：
      file_access / network / env_vars / subprocess / obfuscation / hidden_flags
  * 输出默认打印到 stdout，可用 --out 写 JSONL（每行 {file, doc}）
"""

import argparse
import json
import sys
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

PROMPT_TPL = "{instruction}\n\n[代码]:\n{code}\n\n[输出]:\n"

INSTRUCTION = (
    "你是一个 MCP 服务器安全审查工具。请根据下面的 MCP 工具实现代码，"
    "输出该工具的结构化说明文档 JSON，必须包含 name、description、"
    "input_schema 与 security_declarations 四个字段，其中 security_declarations "
    "必须包含 file_access、network、env_vars、subprocess、obfuscation、hidden_flags "
    "六个列表字段，只输出 JSON，不要输出其他内容。"
)


def load_model(model_dir: str, adapter_dir: str):
    """加载 QLoRA 4bit 基座 + LoRA adapter，返回 (model, tokenizer)。"""
    tokenizer = AutoTokenizer.from_pretrained(model_dir, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token  # 缺 pad_token 用 eos 兜底
    model = AutoModelForCausalLM.from_pretrained(
        model_dir,
        trust_remote_code=True,
        # QLoRA 4bit nf4 量化加载（省显存，推理无需训练级显存）
        quantization_config=BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        ),
        device_map="auto",
        torch_dtype=torch.bfloat16,
    )
    model = PeftModel.from_pretrained(model, adapter_dir)  # 挂载 LoRA adapter
    model.eval()  # 推理模式
    return model, tokenizer


def extract_code(path: Path) -> str:
    """从文件或目录中提取单个函数/工具定义代码。目录时返回第一个含装饰器工具的代码块。"""
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.is_file() and path.suffix == ".py":
        return text  # 单个 .py 文件直接全量返回
    # 简单启发：截取第一个 @tool 装饰器函数段
    lines = text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if "@" in ln and "tool" in ln.lower():  # 找到第一个工具装饰器
            start = i
            break
    if start is None:
        return text  # 找不到装饰器则返回全文
    # 找到函数定义的结束（下一个顶格 def/@ 之前）
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i] and not lines[i][0].isspace() and (lines[i].startswith(("def ", "class ")) or lines[i].startswith("@")):
            end = i
            break
    return "\n".join(lines[start:end])  # 返回该工具代码段


def generate(model, tokenizer, code: str, max_new_tokens: int) -> str:
    """用模型对代码生成结构化文档（贪婪解码）。"""
    prompt = PROMPT_TPL.format(instruction=INSTRUCTION, code=code)
    enc = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **enc,
            max_new_tokens=max_new_tokens,
            do_sample=False,  # 贪婪解码保证确定性
            pad_token_id=tokenizer.eos_token_id,
        )
    # 去掉 prompt 前缀，只取生成的文档部分
    return tokenizer.decode(out[0][enc["input_ids"].shape[1]:], skip_special_tokens=True).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model_dir", required=True)
    ap.add_argument("--adapter_dir", required=True)
    ap.add_argument("--code-file", required=True, help=".py 文件或目录")
    ap.add_argument("--out", default="", help="输出 JSONL 路径（缺省打印 stdout）")
    ap.add_argument("--max_new_tokens", type=int, default=600)
    args = ap.parse_args()

    print(f"[load] base={args.model_dir} adapter={args.adapter_dir}", file=sys.stderr)
    model, tokenizer = load_model(args.model_dir, args.adapter_dir)  # 加载模型

    p = Path(args.code_file)
    if p.is_dir():  # 目录 → 收集全部 .py
        files = sorted(p.rglob("*.py"))
    else:  # 单个文件
        files = [p]

    results = []
    for f in files:
        try:
            code = extract_code(f)  # 提取工具代码
            if not code.strip():
                continue
            doc = generate(model, tokenizer, code, args.max_new_tokens)  # 生成文档
            results.append({"file": str(f), "doc": doc})
            print(f"[ok] {f} -> {len(doc)} chars", file=sys.stderr)
        except Exception as e:
            print(f"[fail] {f}: {e}", file=sys.stderr)

    if args.out:  # 写 JSONL
        with open(args.out, "w", encoding="utf-8") as fh:
            for r in results:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"[done] {len(results)} docs -> {args.out}", file=sys.stderr)
    else:  # 打印 stdout
        for r in results:
            print(f"\n===== {r['file']} =====")
            print(r["doc"])


if __name__ == "__main__":
    main()
