# PyInstaller spec: mpv-detector
# 用法: pyinstaller mpv-detector.spec
# 产物: dist/mpv-detector.exe

block_cipher = None

# 所有子命令模块（cli.py 用 importlib 动态加载，PyInstaller 静态分析不到）
hidden_imports = [
    "detector",
    "detector.cli",
    "detector.config",
    "detector.deps",
    "detector.ui",
    "detector.report_html",
    "detector.tui",
    "detector.crawler.github_crawler",
    "detector.fetcher.fetch_repo",
    "detector.scanner.scanner",
    "detector.scanner.summary",
    "detector.analyzer.docgen",
    "detector.analyzer.align_rate",
    "detector.analyzer.finetune.build_dataset",
    "detector.analyzer.finetune.build_dataset_v2",
    "detector.analyzer.finetune.train_lora",
    "detector.analyzer.finetune.infer_mcp_doc",
    "detector.executor.sandbox_rules",
    "detector.executor.behavior_monitor",
    "detector.pipeline.run_flow",
    "detector.pipeline.pipeline",
    "yaml",
    "rich.console",
    "rich.table",
    "rich.progress",
    "rich.prompt",
    "textual",
]

a = Analysis(
    ["launcher.py"],
    pathex=[],
    binaries=[],
    datas=[("config.yaml.example", ".")],
    hiddenimports=hidden_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="mpv-detector",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
