# =====================================================================
# MCP 投毒检测 · 一键跑完
# 用法：右键"使用 PowerShell 运行"，或直接执行
#   powershell -ExecutionPolicy Bypass -File "一键跑完.ps1" [目标清单.txt]
# 默认对 40 个可疑子集跑；也可传入全量清单（如 800 全部）继续扩跑。
# 可重复执行：docgen/align 已完成的会自动跳过（断点续跑）。
# =====================================================================
param(
    [string]$Targets = "output\gen_docs_800_targets.txt",
    # 仓库代码根目录；留空则由 detector/config.py 解析
    # （默认项目内 mcp插件\，也可设环境变量 MPV_LARGE_REPO_SOURCE）
    [string]$LocalRoot = $env:MPV_LARGE_REPO_SOURCE,
    # 模型名；留空则沿用 config.py 的默认模型
    [string]$Model = $env:MPV_MODEL
)

$root = $PSScriptRoot
$det = Join-Path $root "detector"
$out = Join-Path $root "output\gen_docs_800"
$scan = Join-Path $root "output\scan_results_800_summary.csv"
$targetsFile = Join-Path $root $Targets

Write-Host "===== MCP 投毒检测 · 一键跑完 =====" -ForegroundColor Cyan
Write-Host "目标清单 : $targetsFile"
Write-Host "输出目录 : $out"

if (-not (Test-Path $targetsFile)) {
    Write-Host "[错误] 找不到目标清单: $targetsFile" -ForegroundColor Red
    exit 1
}

# 按需拼装参数（不传的项交给 config.py 的默认值/环境变量）
$runArgs = @("-m", "pipeline.run_flow")
if ($LocalRoot) { $runArgs += @("--local-root", $LocalRoot) }
$runArgs += @("--targets", $targetsFile)
$runArgs += @("--out-dir", $out)
$runArgs += @("--scan-summary", $scan)
if ($Model) { $runArgs += @("--model", $Model) }

Push-Location $det
try {
    $env:PYTHONUNBUFFERED = "1"
    python @runArgs
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

Write-Host "`n===== 完成，报告位置 =====" -ForegroundColor Green
Write-Host "  明细 : $out\flow_results.csv"
Write-Host "  汇总 : $out\flow_report.md"
Write-Host "  退出码: $code"
exit $code