# MPV-Detector · MCP 插件投毒检测

面向 MCP（Model Context Protocol）插件生态的投毒与恶意行为检测工程。项目将采集、源码获取、静态扫描、语义分析、沙箱执行和结果汇总组织为可分段运行的流水线。

> 研究依据、实现映射和维护约定请先阅读下方文档。当前重构在独立分支进行，原始数据与上游基准不会在未核验前删除。

## 文档导航

- [项目结构与模块职责](docs/PROJECT_STRUCTURE.md)
- [重构计划与清理记录](docs/REFACTORING_PLAN.md)
- [已知问题与待办](docs/KNOWN_ISSUES.md)
- [贡献指南](CONTRIBUTING.md)
- [检测器详细说明](detector/README.md)

## 核心检测流程

```text
采集 → 源码获取 → 静态扫描 → 语义分析 → 沙箱执行 → 统计与报告
```

| 模块 | 职责 |
|---|---|
| `detector/crawler` | GitHub MCP 项目元数据采集 |
| `detector/fetcher` | 获取待分析项目源码 |
| `detector/scanner` | 静态规则扫描、结果归一化与汇总 |
| `detector/analyzer` | LLM 代码文档生成、语义对齐与微调相关功能 |
| `detector/executor` | MCP 探测、沙箱执行与行为监控 |
| `detector/pipeline` | 多阶段任务编排 |
| `detector/cli.py` | 统一命令行入口 |
| `detector/config.py` | 路径、模型、阈值和运行参数配置 |

## 快速开始

### 环境

- Python 3.9+
- Ollama：语义分析需要；默认模型配置为 `qwen3-coder:30b`
- Docker：仅动态沙箱分析需要

### 安装

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
python -m pip install -r requirements.txt
```

如需运行语义分析，再安装并启动 Ollama，按本机资源选择模型。不要为了只运行静态扫描而安装大型模型。

### 查看命令

```bash
python -m detector.cli --help
python -m detector.pipeline.pipeline --help
```

常见任务示例（具体参数以各子命令的 `--help` 为准）：

```bash
python -m detector.cli crawl --help
python -m detector.cli fetch-tarballs --help
python -m detector.cli scan --help
python -m detector.cli docgen --help
python -m detector.cli monitor --help
```

仓库内的 `mcp插件/` 目录包含插件元数据和项目材料，不应假定其中每个条目都包含完整、可执行源码。执行完整流水线前，先按 fetcher 文档获取源码。

## 数据与产物管理

- `mcp插件/`：现有插件元数据/本地项目材料，保留现有路径以兼容代码。
- `MaliciousAgentSkillsBench/`：上游基准及其代码，保留来源与许可证。
- `mcp_doc_finetune/`：微调语料、配置和训练说明；大模型权重、缓存和训练产物不应提交。
- `output/`：运行产物；请勿把可再生成的大型输出当作源代码管理。
- 原始数据与实验输入应视为只读；清洗结果、日志和报告写入独立输出位置。

路径、模型与运行参数集中在 `detector/config.py`。不要提交个人绝对路径、访问令牌或私密配置。

## 安全提示

待检测 MCP 项目属于不可信输入。不要在宿主机直接运行未知代码；动态分析必须使用隔离环境，并限制网络访问、文件挂载和资源使用。静态扫描与动态执行是不同风险等级的操作。

## 研究材料

- 原始论文：`malicious-agent-skills-2602.06547.pdf`
- 中文翻译：`论文_中文翻译.md`
- 论文与实现映射：`论文代码对接梳理.md`
- 代码说明：`代码说明文档.md`

## 许可证

本项目许可证见 [LICENSE](LICENSE)。上游基准目录可能包含独立许可证，请以其原始声明为准。
