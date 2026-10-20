# detector/ — MPV-Detector 检测器包

重构后的规范工程结构，按论文《"Do Not Mention This to the User"...》(USENIX Security 2026,
arXiv:2602.06547) 的流水线分层组织：**采集 → 获取 → 静态扫描 → 语义分析 → 沙箱执行 → 统计**。

```
detector/
├── cli.py                  # ★统一命令行入口（python -m detector.cli <子命令>）
├── config.py               # 统一配置中心（原根 config.py，路径指向项目数据目录）
├── crawler/                # 数据采集（原 mcp_github_crawler/）
│   ├── github_crawler.py   #   GitHub MCP 仓库抓取
│   └── organize_plugins.py #   抓取结果落盘 + 路径清单
├── fetcher/                # 代码获取（原 output/fetch_*）
│   ├── fetch_*.py          #   多通道获取（tarball / tree+raw / api）
│   └── cache_inventory.py  #   缓存盘点
├── scanner/                # 静态扫描（原 output 扫描/汇总）
│   ├── scanner.py          #   静态规则扫描（T2 候选）
│   ├── normalize.py        #   判定规范化
│   ├── aggregate.py        #   汇总 → output/scan_summary.csv
│   └── report.py           #   报告统计
├── analyzer/               # 语义分析
│   ├── docgen.py           #   通用 LLM 语义文档生成（原 code_to_doc/）
│   ├── align_rate.py       #   语义对齐率（AST 硬事实 vs 声明）
│   └── finetune/           #   专用文档模型微调（原 mcp_doc_finetune/ 代码）
├── executor/               # 沙箱执行（原 sandbox/ + 顶层脚本）
│   ├── mcp_probe.py        #   MCP 探针（strace + JSON-RPC 触发）
│   ├── behavior_monitor.py #   运行时行为监控
│   ├── sandbox_rules.py    #   拦截规则生成
│   ├── Dockerfile / entrypoint.sh / fixtures/
├── analysis/               # 统计（可扩展，参考论文 analysis/）
├── pipeline/               # ★端到端流水线编排（python -m detector.pipeline.pipeline）
└── __init__.py
```

## 快速使用

统一入口（推荐）：

```powershell
python -m detector.cli crawl            # 抓取
python -m detector.cli scan             # 静态扫描
python -m detector.cli align            # 对齐率
python -m detector.cli monitor          # 沙箱行为监控
```

流水线清单 / 单步执行：

```powershell
python -m detector.pipeline.pipeline              # 打印 01→11 步骤与命令
python -m detector.pipeline.pipeline --run scan   # 只执行某一步
```

## 路径与数据约定

- **项目数据目录保留原位**（重构只移动代码，不动数据）：`mcp插件/`（插件元数据）、
  `output/`（扫描产物 scan_results + csv）、`mcp_doc_finetune/`（模型/权重/语料）、`mcp_sources/`。
- 所有路径以 `detector/config.py` 为唯一事实来源，指向项目根（`PROJECT_ROOT`）。
- 原 `sandbox/`、`mcp_github_crawler/`、`code_to_doc/` 的空代码目录已并入本包并移除。
