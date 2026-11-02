# MPV-Detector · MCP 插件投毒检测

面向 MCP（Model Context Protocol）插件生态的**投毒/恶意行为检测**工程实现。

参照论文《"Do Not Mention This to the User..."》(USENIX Security 2026,
arXiv:2602.06547) 的思路，把检测拆成一条可分段运行的流水线：

```
采集 → 代码获取 → 静态扫描 → 语义分析 → 沙箱执行 → 汇总统计
```

> 论文原文与中文翻译见 `项目相关文档/`。

---

## 检测思路

单靠"扫关键字"误报极高，本项目的核心是**把"插件声明自己做什么"和"代码实际做什么"做交叉验证**：

| 阶段 | 做什么 | 产出信号 |
|---|---|---|
| 静态扫描 | 规则匹配危险模式（敏感路径、动态下载、混淆执行等） | CRITICAL / HIGH 命中数 |
| 语义分析 | LLM 读代码生成"它声称做什么"的文档 → 与 AST 提取的硬事实比对 | 语义对齐率（矛盾率越高越可疑） |
| 沙箱执行 | Docker 内实际跑起来，strace 采集系统调用 + tcpdump 抓包 + 蜜罐文件诱捕 | 未声明的命令/网络/敏感文件访问 |

三层信号汇总后给出 `LOW / REVIEW / HIGH_RISK_REVIEW` 判定。

---

## 目录结构

```
├── detector/                  # ★检测器主包（所有代码在这里）
│   ├── deps.py                #   唯一依赖接口：路径 / IO / 仓库遍历 / HTTP / LLM
│   ├── config.py              #   纯配置：路径、阈值、端点默认值
│   ├── cli.py                 #   统一入口：python -m detector.cli <子命令>
│   ├── crawler/               #   采集：GitHub MCP 仓库抓取
│   ├── fetcher/               #   获取：清单驱动的 tarball / tree+raw 拉取
│   ├── scanner/               #   扫描：静态规则 + 规范化/汇总/报告
│   ├── analyzer/              #   语义：docgen / align_rate / finetune
│   ├── executor/              #   沙箱：mcp_probe / behavior_monitor / sandbox_rules
│   └── pipeline/              #   编排：pipeline（步骤清单）/ run_flow（一键跑完）
├── mcp插件/                    # 插件元数据（<owner>_<repo>/info.json）
├── MaliciousAgentSkillsBench/ # 论文官方基准（上游开源数据集，非本项目代码）
├── mcp_doc_finetune/          # 微调语料与产物（权重不入库，见下）
└── 一键跑完.ps1                # Windows 一键入口（薄封装 detector.cli flow）
```

### 依赖约定（重要）

所有跨模块依赖只走一个文件：**`detector/deps.py`**。

```python
from detector.deps import CONFIG, write_json, GitHubClient, iter_repo_files
```

- 新增外部依赖 / 端点 / 路径，**只改 `deps.py` + `config.py`**；
- 代码里**不允许**再出现 `sys.path.insert`、`from config import ...` 之类的平铺导入，
  也不要自己拼 `output/xxx` 路径（CI 会拦住这类回退）；
- 静态扫描的跳过目录、扩展名、文件大小上限等"口径"集中定义，scanner / fetcher /
  docgen / align 共用同一套，避免各写一份导致结果不可比。

---

## 快速开始

### 1. 环境要求

- Python 3.9+
- **[Ollama](https://ollama.com)**（语义分析依赖本地 LLM，默认模型 `qwen3-coder:30b`）
- Docker（**仅沙箱执行阶段需要**；只跑静态扫描 + 语义分析可跳过）

### 2. 安装

```bash
pip install -r requirements.txt
ollama pull qwen3-coder:30b
```

### 3. 拉取被检代码

仓库自带的 `mcp插件/` 是**插件元数据**（`info.json`），不是完整源码。
要跑完整流水线，需先把仓库代码拉下来（缓存默认落 `output/cache/`）：

```bash
# 清单 CSV 需含 full_name 列（可带 branch / cache_dir）
python -m detector.cli fetch --manifest output/scan_manifest.csv
python -m detector.cli fetch --repos modelcontextprotocol/servers --method tarball
```

### 4. 运行

```bash
python -m detector.cli scan --manifest output/shard1.csv --out-dir output/scan_results
python -m detector.cli summary --stage all          # 规范化 + 汇总 + 报告
python -m detector.cli docgen --repo-list output/targets.txt --out-dir output/gen_docs
python -m detector.cli align --repo-dir mcp插件/<owner>_<repo> --brief
python -m detector.cli sandbox-rules --repo-dir mcp插件/<owner>_<repo> --output rules.json
python -m detector.cli monitor --rules rules.json --mode docker --repo-dir mcp插件/<owner>_<repo>
```

可用子命令见 `python -m detector.cli --list`；分步流水线见 `detector/README.md`。

**Windows 用户**可直接运行 `一键跑完.ps1`，它会串起
`docgen → align → verdict → report` 并支持断点续跑。

---

## 配置：不写死路径

所有路径与端点都在 `detector/config.py`，优先级为 **环境变量 > 项目内默认目录**。
换机器无需改代码：

| 环境变量 | 说明 | 默认值 |
|---|---|---|
| `MPV_LARGE_REPO_SOURCE` | 完整仓库代码根目录 | 项目内 `mcp插件/` |
| `MPV_MEDIUM_REPO_META` | 插件元数据目录 | 项目内 `mcp插件/` |
| `MPV_OUTPUT_DIR` | 输出根目录 | 项目内 `output/` |
| `MPV_CACHE_ROOT` | 代码获取缓存根 | 项目内 `output/cache/` |
| `MPV_FETCH_METHOD` | 获取通道 `auto/tarball/tree` | `auto` |
| `OLLAMA_HOST` | Ollama 地址 | `http://localhost:11434` |
| `MPV_MODEL` | 默认模型名 | `qwen3-coder:30b` |
| `GITHUB_TOKEN` | 提高 GitHub API 限流 | 空 |

> ⚠️ **请勿在代码中写入绝对路径**（如 `C:\Users\xxx\...`）。需要新路径请加环境变量，见 `CONTRIBUTING.md`。

---

## 关于模型权重（重要）

`mcp_doc_finetune/` 下的**模型权重、适配器、分词器词典均不在仓库中**（体积远超 GitHub 限制）。
克隆后该目录只有语料与配置，需自行准备：

- 基座模型：从 Hugging Face 下载 `Qwen/Qwen2.5-3B-Instruct` 到
  `mcp_doc_finetune/models/Qwen2.5-3B-Instruct/`
- LoRA 适配器：重新训练
  ```bash
  python -m detector.cli finetune-train --model_dir <基座目录> --data mcp_doc_finetune/dataset_real_v2.jsonl
  ```

`.gitignore` 已排除 `*.safetensors` / `*.pt` / `tokenizer.json` / 各类缓存，请勿强行提交大文件。

---

## 参与建设

欢迎提 Issue 和 PR。请先读 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

- 流程：Fork → 新分支 → 提交 → 开 PR → Review → 合并
- 不熟悉 Git 也可以只开 Issue 反馈问题或提想法

## 许可证

[MIT](LICENSE)
