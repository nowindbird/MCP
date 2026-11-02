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
│   ├── config.py              #   配置组装：从 config.yaml 读取，环境变量最高优先
│   ├── cli.py                 #   统一入口：python -m detector.cli <子命令>
│   ├── crawler/               #   采集：GitHub MCP 仓库抓取
│   ├── fetcher/               #   获取：清单驱动的 tarball / tree+raw 拉取
│   ├── scanner/               #   扫描：静态规则 + 规范化/汇总/报告
│   ├── analyzer/              #   语义：docgen / align_rate / finetune
│   ├── executor/              #   沙箱：mcp_probe / behavior_monitor / sandbox_rules
│   └── pipeline/              #   编排：pipeline（步骤清单）/ run_flow（一键跑完）
├── config.yaml                # 本机配置（路径/模型/阈值，已 gitignore）
├── config.yaml.example        #   配置模板（clone 后复制为 config.yaml）
├── dateset/                   # 被检仓库代码（<owner>_<repo>/，可重新下载）
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

仓库自带的 `dateset/` 是被检仓库代码（<owner>_<repo>/）。
要跑完整流水线，需先把仓库代码拉下来（缓存默认落 `output/cache/`）：

```bash
# 清单 CSV 需含 full_name 列（可带 branch / cache_dir）
python -m detector.cli fetch --manifest output/scan_manifest.csv
python -m detector.cli fetch --repos modelcontextprotocol/servers --method tarball
```

### 4. 运行

三条链路对应三个入口，参数全部有默认值：

```bash
# ① 静态链路（无需网络 / LLM / Docker）：扫描 dateset/ 全部仓库 → 汇总 → HTML 报告
python -m detector.cli run

# ② 语义链路（需本地 Ollama）：从静态扫描结果自动挑可疑仓库，跑对齐率与综合判定
python -m detector.cli targets --from-scan-summary   # 生成 output/targets.txt（也可 --from-dir 枚举全部）
python -m detector.cli flow                          # docgen → align → verdict → 报告（断点续跑）

# ③ 沙箱链路（需 Docker）：对齐结果 → 拦截规则 → 容器内行为监控
python -m detector.cli sandbox-rules --repo-dir dateset/<owner>_<repo> --output rules.json
python -m detector.cli monitor --rules rules.json --mode docker --repo-dir dateset/<owner>_<repo>
```

分步执行（数据采集走 GitHub 时）：

```bash
python -m detector.cli crawl --fetch-readme
python -m detector.cli fetch --manifest output/scan_manifest.csv
python -m detector.cli scan --manifest output/shard1.csv --out-dir output/scan_results
python -m detector.cli summary --stage all          # 规范化 + 汇总 + 报告
```

流水线步骤清单与单步执行见 `detector/README.md`；子命令清单见 `python -m detector.cli --list`。
改完代码先跑 `python -m detector.cli check`（环境自检）与 `python -m detector.cli test`（单元测试）。

**Windows 用户**可直接运行 `一键跑完.ps1`：它串起静态链路 + 语义链路
（`docgen → align → verdict → report`），目标清单缺失时自动从扫描汇总生成，
并支持断点续跑。

---

## 配置：不写死路径

所有路径、模型权重地址、阈值都集中在项目根 **`config.yaml`**（本机配置，已 gitignore）。
优先级为 **环境变量 > config.yaml > 内置默认值**。换机器/换模型/调阈值只改 YAML，不动代码：

```bash
cp config.yaml.example config.yaml   # clone 后首次配置
```

| 环境变量 | 说明 | config.yaml 对应键 |
|---|---|---|
| `MPV_LARGE_REPO_SOURCE` | 被检代码根目录 | `paths.repo_root`（默认 `dateset/`） |
| `MPV_MEDIUM_REPO_META` | 插件元数据目录 | `paths.medium_repo_meta` |
| `MPV_OUTPUT_DIR` | 输出根目录 | `paths.output_dir` |
| `MPV_CACHE_ROOT` | 代码获取缓存根 | `paths.cache_root` |
| `MPV_FETCH_METHOD` | 获取通道 `auto/tarball/tree` | `fetch.method` |
| `OLLAMA_HOST` | Ollama 地址 | `llm.ollama_host` |
| `MPV_MODEL` | 默认模型名 | `llm.default_model` |
| `GITHUB_TOKEN` | 提高 GitHub API 限流 | `github.token` |

模型权重路径、训练数据集、manifest 清单、扫描阈值、沙箱参数等均在 `config.yaml` 中，详见文件内注释。

> ⚠️ **请勿在代码中写入绝对路径**（如 `C:\Users\xxx\...`）。需要新路径请加到 `config.yaml`，见 `CONTRIBUTING.md`。

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
