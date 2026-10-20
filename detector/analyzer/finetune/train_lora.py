#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
train_lora.py — MCP 专用"代码→结构化文档"模型 LoRA/QLoRA 微调
=================================================================
输入 : Alpaca 格式 JSONL（build_dataset.py 输出）：
       {"instruction": ..., "input": 工具代码, "output": JSON文档字符串}
输出 : adapter 权重（output_dir/）+ 训练日志 + 一次生成演示

用法 :
    python train_lora.py --model_dir <基座模型目录> --data dataset.jsonl \
        --output_dir adapter_mcp_doc --epochs 3 --batch_size 1 --grad_accum 8

要点 :
  * 默认 QLoRA 4bit（bitsandbytes），8GB 显存可训 Qwen2.5-3B；
    --quantize none 可退化为纯 LoRA（需更多显存）
  * label 只对输出部分计算损失（prompt 部分 -100）
  * 训练结束后自动跑一次生成演示验证效果
"""

import argparse
import json
import logging
import os
import sys

import torch
from datasets import Dataset, load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("train_lora")

PROMPT_TPL = "{instruction}\n\n[代码]:\n{code}\n\n[输出]:\n"


def load_jsonl(path: str) -> list:
    """读取 JSONL 训练语料，返回字典列表。"""
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def tokenize_fn(tokenizer, max_len: int):
    """构造 tokenize 闭包：把 instruction+code 与 output 拼接，label 只对 output 计算损失。"""
    def _fn(batch):
        # 构造输入文本：指令 + [代码] + 代码
        texts = [
            PROMPT_TPL.format(instruction=inst, code=code)
            for inst, code in zip(batch["instruction"], batch["input"])
        ]
        outputs = batch["output"]

        enc = tokenizer(texts, truncation=True, max_length=max_len, add_special_tokens=True)  # 输入编码
        out_enc = tokenizer(outputs, truncation=True, max_length=max_len, add_special_tokens=False)  # 输出编码
        input_ids_list, labels_list, mask_list = [], [], []
        for i in range(len(texts)):
            # 输入 id 与输出 id 拼接；输入部分 label = -100（不计算损失）
            input_ids = enc["input_ids"][i] + out_enc["input_ids"][i] + [tokenizer.eos_token_id]
            lab = [-100] * len(enc["input_ids"][i]) + out_enc["input_ids"][i] + [tokenizer.eos_token_id]
            if len(input_ids) > max_len:  # 超长截断（同时截 label 保持对齐）
                input_ids = input_ids[:max_len]
                lab = lab[:max_len]
            input_ids_list.append(input_ids)
            labels_list.append(lab)
            mask_list.append([1] * len(input_ids))  # 全 1 注意力掩码
        return {"input_ids": input_ids_list, "labels": labels_list, "attention_mask": mask_list}
    return _fn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model_dir", required=True, help="基座模型目录（本地 safetensors）")
    ap.add_argument("--data", required=True, help="训练 JSONL")
    ap.add_argument("--output_dir", default="adapter_mcp_doc")
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--max_steps", type=int, default=-1, help=">0 时只训练 N 步（用于链路验证）")
    ap.add_argument("--batch_size", type=int, default=1)
    ap.add_argument("--grad_accum", type=int, default=8)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--max_len", type=int, default=2048)
    ap.add_argument("--lora_r", type=int, default=16)
    ap.add_argument("--lora_alpha", type=int, default=32)
    ap.add_argument("--quantize", choices=["4bit", "8bit", "none"], default="4bit")
    ap.add_argument("--demo_code", default="", help="训练后演示用的工具代码文本")
    args = ap.parse_args()

    # ---- 1. 加载 tokenizer 与模型 ----
    logger.info("加载模型: %s (quantize=%s)", args.model_dir, args.quantize)
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token  # 缺 pad_token 时用 eos 兜底

    # 按量化级别构造 BitsAndBytes 配置（QLoRA 默认 4bit nf4 + 双重量化）
    bnb = None
    if args.quantize == "4bit":
        bnb = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
    elif args.quantize == "8bit":
        bnb = BitsAndBytesConfig(load_in_8bit=True)

    # 加载基座因果语言模型
    model = AutoModelForCausalLM.from_pretrained(
        args.model_dir,
        trust_remote_code=True,
        quantization_config=bnb,
        device_map="auto",          # 自动分配设备
        torch_dtype=torch.bfloat16,
    )
    if bnb is not None:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)  # 量化模型训练准备
    model.gradient_checkpointing_enable()   # 开启梯度检查点省显存
    model.enable_input_require_grads()      # 确保量化参数可求梯度

    # ---- 2. LoRA 配置 ----
    lora = LoraConfig(
        r=args.lora_r,                  # 低秩维度
        lora_alpha=args.lora_alpha,     # 缩放系数
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],  # 全部注意力+FFN 投影
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora)  # 包装为 PEFT 模型（只训练 LoRA 参数）
    model.print_trainable_parameters()

    # ---- 3. 加载数据并 tokenize ----
    rows = load_jsonl(args.data)
    logger.info("训练样本数: %d", len(rows))
    if not rows:
        logger.error("数据集为空")
        sys.exit(1)
    ds = Dataset.from_list(rows)
    ds = ds.map(tokenize_fn(tokenizer, args.max_len), batched=True, remove_columns=["instruction", "input", "output", "meta"] if "meta" in ds.column_names else None)

    # ---- 4. 训练 ----
    train_args = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,       # 训练轮数
        max_steps=args.max_steps,           # >0 时只训练 N 步（链路验证）
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        logging_steps=1,
        save_strategy="epoch",              # 每轮保存
        report_to=[],                       # 关闭外部报告（wandb 等）
        bf16=torch.cuda.is_available(),     # 有 GPU 才开 bf16
        fp16=False,
        gradient_checkpointing=True,
        optim="paged_adamw_8bit" if args.quantize != "none" else "adamw_torch",  # 8bit 优化器省显存
        dataloader_pin_memory=False,
    )
    trainer = Trainer(
        model=model,
        args=train_args,
        train_dataset=ds,
        data_collator=DataCollatorForSeq2Seq(tokenizer, padding=True, label_pad_token_id=-100),  # label 填充用 -100
    )
    logger.info("开始训练（显存 %.1fGB / %.1fGB）", torch.cuda.memory_allocated() / 1e9 if torch.cuda.is_available() else 0, torch.cuda.get_device_properties(0).total_memory / 1e9 if torch.cuda.is_available() else 0)
    trainer.train()  # 执行训练
    model.save_pretrained(args.output_dir)  # 保存 LoRA adapter
    tokenizer.save_pretrained(args.output_dir)
    logger.info("adapter 已保存: %s", args.output_dir)

    # ---- 5. 训练后生成演示（验证效果） ----
    demo_code = args.demo_code or rows[0]["input"]  # 用首个样本代码或用户指定代码
    prompt = PROMPT_TPL.format(instruction=rows[0]["instruction"], code=demo_code)
    model.eval()
    with torch.no_grad():
        enc = tokenizer(prompt, return_tensors="pt").to(model.device)
        out = model.generate(**enc, max_new_tokens=600, do_sample=False)  # 贪婪解码
        gen = tokenizer.decode(out[0][enc["input_ids"].shape[1]:], skip_special_tokens=True)  # 去 prompt 前缀
    print("\n===== 生成演示（训练后）=====")
    print(gen)
    print("=============================")


if __name__ == "__main__":
    main()
