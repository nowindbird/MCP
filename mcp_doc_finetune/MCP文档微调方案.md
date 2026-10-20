# MCP 插件代码 → 说明文档：专用模型微调方案

> 项目：mcp_doc_finetune
> 创建日期：2026-09-28
> 定位：以论文《"Do Not Mention This to the User": Detecting and Understanding Malicious Agent Skills in the Wild》(arXiv:2602.06547) 的方法为理论框架，微调一个**仅针对 MCP 插件**的"代码 → 结构化说明文档"模型，作为对齐率投毒检测的自动化实现器。

---

## 1. 任务定义

**输入**：MCP 服务器中单个工具的实现代码（函数定义 + 签名 + 函数体，可附带相邻上下文）。

**输出**：JSON 结构化文档，字段：

```json
{
  "name": "tool_name",
  "description": "面向 LLM 与用户的功能说明（自然语言）",
  "input_schema": { "type": "object", "properties": {...}, "required": [...] },
  "security_declarations": {
    "file_access": ["~/.ssh/id_rsa", "config.json"],
    "network": ["https://api.example.com/v1", "socket 1.2.3.4:4444"],
    "env_vars": ["OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN"],
    "subprocess": ["bash -c ...", "curl | sh"],
    "obfuscation": ["base64+eval", "pickle.loads"],
    "hidden_flags": ["隐藏BCC", "反向shell", "未声明端点"]
  }
}
```

**关键设计**：`security_declarations` 是投毒检测的核心——模型必须**如实声明代码里做的所有敏感行为**（读哪些文件、发哪些请求、执行什么命令）。微调目标不是"写漂亮文档"，而是"写完整且无幻觉的行为声明文档"。

---

## 2. 数据管线（核心工作量）

```
102+ MCP 仓库代码（本地获取中）
        │
        ▼
① 工具定义提取（AST 解析，确定性）
   - Python: @mcp.tool / @server.tool / @tool 装饰器函数
   - TS: server.tool() 调用（Phase 2 用 tree-sitter）
        │
        ▼
② 目标描述三路生成（合并去冲突）
   a. 仓库自带 docstring / README 描述（参考，可能不干净）
   b. 强 LLM（豆包 / DeepSeek / GPT API）基于代码生成描述（主生成器）
   c. AST 硬事实提取（确定性约束：env/file/network/subprocess/混淆）
   → 最终 output = b 生成 + c 校验 + a 校对
        │
        ▼
③ 质量过滤（防止把幻觉带进训练集）
   - output 必须 JSON 可解析
   - 描述中出现的敏感行为 ⊆ 硬事实（超集即幻觉 → 丢弃或重生成）
   - docstring 与硬事实明显矛盾的样本标记并人工抽查
   - 按代码相似度去重（防止同一模板重复样本主导）
        │
        ▼
④ 训练集（Alpaca 指令格式）
   - 良性样本：真实 MCP 工具（1500-3000 条，小原型 300-500 条即可）
   - 投毒样本：按论文 14 模式构造/改编（隐藏 BCC、反向 shell、
     eval(base64)、curl|bash、指令覆盖等，300-500 条）
   - 混合比例 ≈ 8:1 ～ 5:1，投毒样本强制 security_declarations 如实标注
```

### 2.1 语料来源（已规划）

| 来源 | 说明 | 状态 |
|---|---|---|
| 本项目 102 仓库 | 等投毒扫描完成拿到代码（正在进行）| 待用 |
| modelcontextprotocol/servers 官方样例 | 高质量良性样本 | 可直取 |
| GitHub 搜索 "mcp-server" / "FastMCP" 语言:Python 按 star 排序 | 扩充良性语料 100-200 仓库 | 可直取 |
| 论文案例模式复刻 | 构造投毒样本（只复刻模式，不复制真实 payload）| 构造 |

### 2.2 硬事实提取（确定性，脚本已实现）

用 Python `ast` 模块遍历函数体，收集：

- `os.environ[...]` / `os.getenv(...)` / `getenv` → **env_vars**
- `open(...)` / `Path(...).read*` / `os.path` 拼接且路径含 `.ssh/.aws/credentials/.env/id_rsa` → **file_access**
- `requests.post/get` / `urllib.request.urlopen` / `httpx` / `aiohttp` / `socket.connect` → **network**（提取 URL/域名/IP/端口字面量）
- `subprocess.run/call/Popen` / `os.system` / `child_process` → **subprocess**
- `base64` + `eval/exec` / `marshal.loads` / `pickle.loads` / `eval(` 高频 → **obfuscation**
- `smtplib` + `bcc` → **hidden_flags: 隐藏BCC**
- `socket.connect` + `dup2` 或 `/dev/tcp/` → **hidden_flags: 反向shell**

### 2.3 防幻觉机制（对应你调研文档里"语义生成文档有生成幻觉"的问题）

1. **硬事实做护栏**：LLM 生成的描述若声明了代码没有的行为（如说"读取配置文件"但代码没有 open），判定为幻觉 → 重生成或丢弃；
2. **规则后校验**：描述必须覆盖硬事实（防止漏报），描述不得超出硬事实（防止幻觉），两边都是不一致；
3. 微调后模型本身学会"先扫描代码再写声明"的归纳偏好——这是与通用模型最本质的区别。

---

## 3. 模型与训练选型

### 3.1 基座模型

| 档位 | 模型 | 显存需求 | 适用 |
|---|---|---|---|
| 标准 | Qwen2.5-7B-Instruct（或 Qwen2.5-Coder-7B）| 单卡 24GB（QLoRA 4bit）| 首选，中文+代码都强 |
| 轻量 | Qwen2.5-3B-Instruct | 8-12GB（T4/4060 可训）| 无独显大卡/Colab 免费 |
| 备选 | DeepSeek-Coder-V2-Lite-16B（MoE）| 需 2 卡或大显存 | 不需要，7B 足够 |

### 3.2 训练框架与配置

- 框架：**LLaMA-Factory**（CLI/webui 均可，内置 LoRA/QLoRA）或 **Unsloth**（显存更省、更快）
- LoRA：`r=16, alpha=32, dropout=0.05, target_modules=all-linear`
- 优化：`lr=2e-4`，cosine 衰减，`warmup_ratio=0.03`
- Batch：`per_device_batch=4, grad_accum=8`（有效 batch=32）
- Epochs：3（小数据 2-3 即可，防过拟合）
- 序列长度：4096（工具函数 + 输出 JSON 够用）
- 量化：QLoRA 4bit（`bnb_4bit`）→ 24GB 卡跑 7B

### 3.3 训练数据规模建议（可先小后大）

| 阶段 | 良性 | 投毒 | 用途 |
|---|---|---|---|
| 原型验证 | 300-500 | 80-120 | 1-2 小时训练，验证可行性 |
| 正式 | 1500-3000 | 300-500 | 最终模型 |
| 扩充 | 5000+ | 800+ | 追求更高对齐率时 |

---

## 4. 评测方案（对应你的对齐率研究）

### 4.1 评测集构造

独立于训练集：**200 条 = 良性 100 + 投毒 100**（投毒样本用论文 14 模式构造）。

### 4.2 指标定义

| 指标 | 定义 | 对齐率研究对应 |
|---|---|---|
| 格式合规率 | output 能被 `json.loads` 解析的比例 | 工程可行性 |
| **行为声明召回** | security_declarations 覆盖 AST 硬事实的比例（漏报=危险）| 声明级召回 |
| **行为声明精确率** | 声明中的行为在代码中真实存在的比例（多报=幻觉）| 声明级精确率 |
| **描述-代码对齐率 F1** | 声明级 precision/recall 的调和平均 | 对齐率核心指标 |
| **投毒检出率** | 投毒样本中 hidden_flags 被正确标注的比例 | 投毒检测有效性 |
| 与基线对比 | 通用 LLM 零样本（同 prompt）跑同一评测集 | 证明微调增益 |

### 4.3 检测应用（微调模型的两种用法）

```
用法 A（生成-比对）：新 MCP 代码 → 模型生成文档 → 与仓库 README/官方工具描述做对齐率
   → 不一致处 = 嫌疑点（对应论文 shadow features 检测的自动化）
用法 B（审查模式）：微调"审查变体"：输入 = 代码 + 现有描述，输出 = 不一致点清单
   → 更贴近论文 Tier2→Tier3 的人工标注环节
```

---

## 5. 落地路线图

| Phase | 内容 | 前置 | 产出 |
|---|---|---|---|
| 0 | 代码获取（进行中，投毒扫描共享）| — | 102+ 仓库代码 |
| 1 | 语料提取与构造（`build_dataset.py` 已就绪）| Phase 0 | dataset.jsonl + 统计 |
| 2 | 描述生成 + 防幻觉过滤（调 LLM API）| Phase 1 | 训练集（干净）|
| 3 | LoRA 微调（LLaMA-Factory/Unsloth）| Phase 2 | adapter 权重 |
| 4 | 评测 + 基线对比 + 报告 | Phase 3 | 对齐率实验报告 |

---

## 6. 风险与限制

1. **语料规模**：MCP 生态年轻，高质量"代码-文档"对有限；投毒样本靠构造，需注意与真实分布的差距；
2. **幻觉残留**：强 LLM 生成描述仍有幻觉，需硬事实护栏兜底，护栏质量取决于 AST 提取覆盖度；
3. **TS/多语言**：Python 优先，TypeScript 提取需 tree-sitter，延后到 Phase 2；
4. **评测主观性**：description 自然语言部分无法完全自动评分，抽查人工复核（可复用论文双人标注思路，κ 一致性）；
5. **基座更新**：Qwen2.5 为当前推荐，若训练时已有更新版本可替换，配置不变。

---

## 7. 与本项目其他工作的关系

- **投毒扫描（进行中）**：提供真实代码语料 + 候选恶意样本（可作为投毒训练样本来源）；
- **对齐率调研**：本模型的 security_declarations 正是对齐率检测的"代码侧事实"，与 README 描述对齐即实现检测；
- **论文方法**：模型生成 = 论文静态分析的自动化增强；security_declarations 的 hidden_flags = 论文 shadow features 的显式化。
