# detector/ — MPV-Detector 检测器包

按论文《"Do Not Mention This to the User"...》(USENIX Security 2026,
arXiv:2602.06547) 的流水线分层组织：
**采集 → 获取 → 静态扫描 → 语义分析 → 沙箱执行 → 统计**。

```
detector/
├── deps.py                  # ★唯一依赖接口（路径 / IO / 仓库遍历 / HTTP / LLM / 可选依赖）
├── config.py                # 纯配置中心（只定义数据，不 import 本项目其它模块）
├── cli.py                   # 统一命令行入口（python -m detector.cli <子命令>）
├── targets.py               # 生成语义分析目标清单（flow 的输入，可自动闭环）
├── selftest.py              # 单元测试入口（python -m detector.cli test）
├── tests/                   # unittest 用例（零额外依赖；临时目录 .tmp/ 已 gitignore）
├── crawler/
│   └── github_crawler.py    # GitHub MCP 仓库搜索 / 详情 / README / 提交抓取
├── fetcher/
│   └── fetch_repo.py        # 清单驱动获取：tarball（整仓）/ tree+raw（精选）
├── scanner/
│   ├── scanner.py           # 静态规则扫描（论文 Table 9 的 14 模式 + MCP 补充）
│   ├── patterns.py          # 检测规则正则库（单独维护，改规则只需动这里）
│   └── summary.py           # 规范化 + 汇总（scan_summary.csv）+ 报告
├── analyzer/
│   ├── docgen.py            # LLM 语义文档生成
│   ├── align_rate.py        # 语义对齐率（AST/正则硬事实 vs 声明）
│   └── finetune/            # 专用文档模型微调（build/infer/train）
├── executor/
│   ├── mcp_probe.py         # 容器内 MCP 探针（strace + JSON-RPC 触发；唯一不依赖 deps 的模块）
│   ├── behavior_monitor.py  # 运行时行为监控（判定引擎 + CLI；docker / simulate / fixture）
│   ├── monitor_parser.py    # Behavior 模型 + strace/tcpdump 解析纯函数（叶子模块）
│   ├── monitor_simulate.py  # SIMULATE / FIXTURE 模式运行器
│   ├── monitor_docker.py    # Docker 沙箱运行器
│   ├── sandbox_rules.py     # 拦截规则生成（allowlist / blocklist / 阈值）
│   └── Dockerfile / entrypoint.sh / fixtures/
└── pipeline/
    ├── pipeline.py          # 步骤清单 / 单步执行 / run_auto_chain（一键静态链路）
    └── run_flow.py          # 一键语义链路：docgen → align → verdict → report
```

## 依赖约定

**所有跨模块依赖只经过 `detector/deps.py`。**

```python
from detector.deps import (
    CONFIG, write_json, read_json,          # 配置与 IO
    iter_repo_files, read_readme,           # 仓库遍历（统一跳过目录/扩展名口径）
    GitHubClient, LLMClient,                # 网络与 LLM
    require_requests, docker_available,     # 可选依赖探测
)
```

规则：

- ❌ 不写 `sys.path.insert`，不写 `from config import ...`、`from align_rate import ...` 这类平铺导入
  （包内一律 `from detector.xxx import ...`，CI 会检查）；
- ❌ 不自己拼 `output/...`、`mcp插件/...` 路径，统一用 `deps` 里的常量；
- ❌ 不重复定义扫描跳过目录 / 扩展名 / 文件大小上限，统一用 `deps` 的常量；
- ✅ 需要新路径 → `config.py` 加 `_resolve_dir()` 注册；需要新端点 → 加环境变量；
- ✅ 需要新第三方库 → 只在 `deps.py` 里做按需导入（`require_xxx()`）。

`mcp_probe.py` 是唯一例外：它在沙箱容器内运行，镜像里没有项目代码，因此只用标准库。

## 快速使用

三条链路对应三个入口，参数全部有默认值：

```powershell
# ① 静态链路（无需网络 / LLM / Docker）：扫描全部本地仓库 → 汇总 → HTML 报告
python -m detector.cli run            # 等价于 pipeline --all

# ② 语义链路（需本地 Ollama）：可疑仓库 docgen → align → verdict → 报告
python -m detector.cli targets        # 从 scan_summary 自动生成目标清单（默认 output/targets.txt）
python -m detector.cli flow           # 断点续跑；清单缺失且给了 --scan-summary 时自动生成

# ③ 沙箱链路（需 Docker）：对齐结果 → 拦截规则 → 行为监控
python -m detector.cli sandbox-rules --repo-dir dateset/<owner>_<repo> --output rules.json
python -m detector.cli monitor --rules rules.json --mode docker --repo-dir dateset/<owner>_<repo>
```

分步 / 数据采集（走 GitHub 时）：

```powershell
python -m detector.cli crawl --fetch-readme                         # 抓取仓库元数据
python -m detector.cli fetch --manifest output/scan_manifest.csv    # 按清单获取代码
python -m detector.cli scan --manifest output/shard1.csv --out-dir output/scan_results
python -m detector.cli summary --stage all                          # 规范化 + 汇总 + 报告
```

流水线步骤清单 / 单步执行（打印出的命令可直接复制重跑）：

```powershell
python -m detector.pipeline.pipeline                     # 打印步骤与可复现命令
python -m detector.pipeline.pipeline --run scan          # 只执行某一步
python -m detector.pipeline.pipeline --run align sandbox-rules monitor --repo a_b   # 占位参数代入
python -m detector.pipeline.pipeline --all               # 一键静态链路 scan → summary → report-html
```

自检与测试（改完代码先跑这两条）：

```powershell
python -m detector.cli check       # 环境自检：路径 / 导入 / 可选依赖
python -m detector.cli test        # 单元测试（tests 共 72 例，零外部依赖）
python -m detector.cli --list      # 列出所有子命令
```

## 路径与数据约定

- **项目数据目录保留原位**：`mcp插件/`（插件元数据）、`output/`（扫描产物、缓存、
  沙箱工作目录；已在 .gitignore）、`mcp_doc_finetune/`（模型/权重/语料）。
- 所有路径以 `config.py` 为唯一事实来源，指向项目根（`PROJECT_ROOT`）；
  运行时代码通过 `deps` 取用。
