# =====================================================================
# MCP 投毒检测 · 一键跑完
# 用法：右键"使用 PowerShell 运行"，或
#   powershell -ExecutionPolicy Bypass -File "一键跑完.ps1" [-Targets output\targets.txt]
#
# 链路：docgen(生成语义文档) → align(语义对齐率) → verdict(综合判定) → 报告
# 可重复执行：docgen / align 已完成的会自动跳过（断点续跑）。
# 实际编排逻辑在 detector/pipeline/run_flow.py，本脚本只是薄封装。
# =====================================================================
param(
    # 目标清单：每行一个 owner_repo
    [string]$Targets = "output\targets.txt",
    # 仓库代码根；留空则用 detector/config.py 解析（默认项目内 mcp插件\）
    [string]$LocalRoot = $env:MPV_LARGE_REPO_SOURCE,
    # 模型名；留空则沿用 config.py 的默认模型
    [string]$Model = $env:MPV_MODEL,
    # 输出目录
    [string]$OutDir = "output\gen_docs",
    # 静态扫描汇总 CSV（可选，用于综合判定）
    [string]$ScanSummary = "output\scan_summary.csv"
)

$root = $PSScriptRoot
$targetsFile = Join-Path $root $Targets
$outDirPath = Join-Path $root $OutDir
$scanFile = Join-Path $root $ScanSummary

Write-Host "===== MCP 投毒检测 · 一键跑完 =====" -ForegroundColor Cyan
Write-Host "目标清单 : $targetsFile"
Write-Host "输出目录 : $outDirPath"

# 目标清单缺失时自动从静态扫描汇总生成（可疑仓库），无需手工建清单
if (-not (Test-Path $targetsFile)) {
    if (Test-Path $scanFile) {
        Write-Host "目标清单缺失，自动从扫描汇总生成 ..." -ForegroundColor Yellow
        Push-Location $root
        try { python -X utf8 -m detector.cli targets --from-scan-summary $scanFile --out $targetsFile } finally { Pop-Location }
    }
}

if (-not (Test-Path $targetsFile)) {
    Write-Host "[错误] 找不到目标清单: $targetsFile" -ForegroundColor Red
    Write-Host "       请先生成清单（每行一个 owner_repo），或先跑静态扫描:" -ForegroundColor Yellow
    Write-Host "       python -m detector.cli run   （生成 output\scan_summary.csv 后可自动生成清单）" -ForegroundColor Yellow
    exit 1
}

# 按需拼装参数（未传的项交给 config.py 的默认值/环境变量）
$runArgs = @("-X", "utf8", "-m", "detector.cli", "flow", "--targets", $targetsFile, "--out-dir", $outDirPath)
if ($LocalRoot) { $runArgs += @("--local-root", $LocalRoot) }
if ($Model) { $runArgs += @("--model", $Model) }
if (Test-Path $scanFile) { $runArgs += @("--scan-summary", $scanFile) }

# 统一从项目根运行（包内绝对导入依赖项目根在 sys.path）
Push-Location $root
try {
    $env:PYTHONUNBUFFERED = "1"
    python @runArgs
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

Write-Host "`n===== 完成，报告位置 =====" -ForegroundColor Green
Write-Host "  明细 : $outDirPath\flow_results.csv"
Write-Host "  汇总 : $outDirPath\flow_report.md"
Write-Host "  退出码: $code"
exit $code
