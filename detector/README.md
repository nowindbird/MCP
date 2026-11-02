# detector/ — MPV-Detector 检测器包

按论文《"Do Not Mention This to the User"...》(USENIX Security 2026,
arXiv:2602.06547) 的流水线分层组织：
**采集 → 获取 → 静态扫描 → 语义分析 → 沙箱执行 → 统计**。

```
detector/
├── deps.py                  # ★唯一依赖接口（路径 / IO / 仓库遍历 / HTTP / LLM / 可选依赖）
├── config.py                # 纯配置中心（只定义数据，不 import 本项目其它模块）
├── cli.py                   # 统一命令行入口（python -m detector.cli <子命令>）
├── crawler/
│   └── github_crawler.py    # GitHub MCP 仓库搜索 / 详情 / README / 提交抓取
├── fetcher/
│   └── fetch_repo.py        # 清单驱动获取：tarball（整仓）/ tree+raw（精选）
├── scanner/
│   ├── scanner.py           # 静态规则扫描（论文 Table 9 的 14 模式 + MCP 补充）
│   └── summary.py           # 规范化 + 汇总（scan_summary.csv）+ 报告
├── analyzer/
│   ├── docgen.py            # LLM 语义文档生成
│   ├── align_rate.py        # 语义对齐率（AST/正则硬事实 vs 声明）
│   └── finetune/            # 专用文档模型微调（build/infer/train）
├── executor/
│   ├── mcp_probe.py         # 容器内 MCP 探针（strace + JSON-RPC 触发；唯一不依赖 deps 的模块）
│   ├── behavior_monitor.py  # 运行时行为监控（docker / simulate / fixture）
│   ├── sandbox_rules.py     # 拦截规则生成（allowlist / blocklist / 阈值）
│   └── Dockerfile / entrypoint.sh / fixtures/
└── pipeline/
    ├── pipeline.py          # 步骤清单 / 单步执行
    └── run_flow.py          # 一键跑完：docgen → align → verdict → report
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

```powershell
python -m detector.cli --list          # 列出所有子命令
python -m detector.cli crawl           # 抓取仓库元数据
python -m detector.cli fetch --manifest output/scan_manifest.csv
python -m detector.cli scan --manifest output/shard1.csv --out-dir output/scan_results
python -m detector.cli summary         # 规范化 + 汇总 + 报告
python -m detector.cli docgen --repo-list output/targets.txt --out-dir output/gen_docs
python -m detector.cli align --repo-dir mcp插件/<owner>_<repo> --brief
python -m detector.cli sandbox-rules --repo-dir mcp插件/<owner>_<repo> --output rules.json
python -m detector.cli monitor --rules rules.json --mode fixture --strace-file a.log
```

流水线步骤清单 / 单步执行：

```powershell
python -m detector.pipeline.pipeline                     # 打印步骤与可复现命令
python -m detector.pipeline.pipeline --run scan          # 只执行某一步
python -m detector.pipeline.pipeline --run scan summary  # 按序执行多步
python -m detector.pipeline.pipeline --all               # 全链路（跳过需占位参数的步骤）
```

自检（路径解析 / 子包导入 / 可选依赖）：

```powershell
python detector/config.py          # 打印配置
python -m detector.deps --check    # 依赖接口自检
```

## 路径与数据约定

- **项目数据目录保留原位**：`mcp插件/`（插件元数据）、`output/`（扫描产物、缓存、
  沙箱工作目录；已在 .gitignore）、`mcp_doc_finetune/`（模型/权重/语料）。
- 所有路径以 `config.py` 为唯一事实来源，指向项目根（`PROJECT_ROOT`）；
  运行时代码通过 `deps` 取用。
