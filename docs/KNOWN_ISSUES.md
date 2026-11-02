# 已知问题与待办

本文件只记录可复现、可追踪的问题。新问题优先通过 Issue 管理。

## 待核查

- [ ] 检查 `detector/config.py` 是否仍包含个人机器路径或历史兼容路径。
- [ ] 检查 `一键跑完.ps1` 调用的 CLI 子命令是否与当前 `detector/cli.py` 一致。
- [ ] 检查 `mcp_doc_finetune/adapter_mcp_doc`、`adapter_mcp_doc_v2`、`adapter_smoke` 的用途和相互关系。
- [ ] 检查 `dataset_real.jsonl`、`dataset_real_v2.jsonl`、`dataset_smoke.jsonl` 的生成来源、版本关系和引用情况。
- [ ] 检查 `qwen_tags.html` 是否仍被任何文档或脚本引用。
- [ ] 检查沙箱执行的默认网络策略、挂载目录和资源限制。

## 处理规则

完成一项后记录验证命令、结果和对应提交；没有验证依据时不要标记为已解决。
