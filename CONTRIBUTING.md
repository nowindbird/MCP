# 贡献指南

感谢你愿意一起建设。本项目处于研究/实验阶段， Issue 与 PR 都欢迎。

## 两种参与方式

1. **Fork + Pull Request**（推荐，任何人可参与）
   Fork 本仓库 → 建分支 → 提交 → 开 PR → Review → 合并。
2. **直接写权限**
   长期合作者可由仓库所有者通过 *Settings → Collaborators* 邀请，获得直接推送权限。

即便是协作者，**涉及架构改动、新增检测规则、修改 `config.py` 时仍建议走 PR**，方便留痕与讨论。

---

## 开发流程

```bash
# 1. Fork 后克隆你的副本
git clone https://github.com/<你的用户名>/MCP.git
cd MCP

# 2. 建分支（分支名用前缀，见下）
git switch -c feat/新的检测规则

# 3. 安装依赖
pip install -r requirements.txt

# 4. 改动后自检
python detector/config.py          # 打印配置，确认路径解析正常
python -m compileall detector      # 语法检查

# 5. 提交（遵循 Conventional Commits）
git commit -m "feat(scanner): 新增对动态 import 的检测规则"

# 6. 推送并开 PR
git push origin feat/新的检测规则
```

分支命名前缀：`feat/` `fix/` `docs/` `refactor/` `test/` `chore/`

提交信息建议遵循 [Conventional Commits](https://www.conventionalcommits.org/)：
`feat(scope): 描述` / `fix(scope): 描述` / `docs: 描述`

---

## 代码规范

### 1. 禁止硬编码绝对路径 ⚠️

这是本项目的**首要规范**。曾经因为写死 `D:\mcp插件` 和
`C:\Users\<用户名>\AppData\...\ollama.exe`，导致换一台机器就跑不起来。

- 需要新的路径 → 在 `detector/config.py` 用 `_resolve_dir()` 注册，支持环境变量覆盖
- 需要新的服务端点 → 用 `_env()` 注册，提供合理默认值
- 文档/注释里写示例路径 → 用**相对路径**（`mcp插件/某仓库`）或占位符（`<你的路径>`）

新增环境变量请同步更新 `README.md` 的配置表格。

改完务必验证：
```bash
python detector/config.py                              # 默认路径解析是否正确
MPV_LARGE_REPO_SOURCE=/tmp/x python detector/config.py  # 环境变量是否生效
```

### 2. 不要提交大文件

GitHub 单文件上限 100MB。以下**一律不入库**（已在 `.gitignore`）：

- 模型权重 `*.safetensors` `*.bin` `*.pt` `*.pth` `*.gguf` `*.onnx`
- 分词器词典 `tokenizer.json`（单份约 11MB，各 checkpoint 重复）
- 下载缓存 `mcp_doc_finetune/cache/`
- 运行产物 `output/`

如果你 `git add` 时报文件过大，说明该走"重新下载/重新训练"而不是入库。

### 3. 其他约定

- Python 代码保留 UTF-8 与中文注释风格，与现有代码保持一致
- 新增检测规则请放在 `detector/scanner/scanner.py` 的对应规则区，
  并说明它命中什么行为、误报风险如何
- 新增子命令需在 `detector/cli.py` 的 `COMMANDS` 字典注册
- 涉及沙箱的改动（`detector/executor/`）请在 PR 里说明是否实测过 Docker 模式

---

## 提 Issue

开 Issue 时请尽量包含：

- **问题现象**：做了什么、期望什么、实际发生什么
- **环境**：操作系统、Python 版本、是否装了 Ollama / Docker
- **复现步骤**：关键命令与参数（注意脱敏，别贴 token）

想法类、讨论类 Issue 同样欢迎。

---

## PR 检查清单

提交前请确认：

- [ ] 没有引入硬编码绝对路径
- [ ] 没有提交大文件或 `output/` 产物
- [ ] `python -m compileall detector` 通过
- [ ] `python detector/config.py` 能正常输出
- [ ] 新增的环境变量/子命令已同步到 `README.md`
- [ ] 提交信息符合 Conventional Commits
