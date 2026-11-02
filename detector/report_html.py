#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.report_html —— 生成单文件 HTML 可视化报告
=================================================
读取 scan_results/*.json，生成含 ECharts 图表（severity 饼图、pattern TOP10、
verdict 分布）和仓库明细表格的单文件 HTML。

用法::

    python -m detector.cli report-html [--results-dir scan_results] [--out report.html]
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from detector.deps import SCAN_OUTPUT_DIR, ensure_dir, now_iso


def _iter_results(results_dir: Path):
    for p in sorted(results_dir.glob("*.json")):
        if p.name.startswith("_"):
            continue
        try:
            yield json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue


def build_report(results_dir: Path, out_path: Path) -> dict:
    results = list(_iter_results(results_dir))
    total = len(results)
    verdict_counter = Counter()
    sev_counter = Counter()
    pattern_counter = Counter()
    repos = []

    for r in results:
        verdict_counter[r.get("verdict", "unknown")] += 1
        hits = r.get("hits") or []
        for h in hits:
            sev_counter[h.get("severity", "UNKNOWN")] += 1
            pattern_counter[h.get("pattern_id", "?")] += 1
        repos.append({
            "repo": r.get("repo", ""),
            "verdict": r.get("verdict", ""),
            "files_scanned": r.get("files_scanned", 0),
            "hits_count": len(hits),
            "hits": hits,
        })

    # 按命中数排序
    repos.sort(key=lambda x: (-x["hits_count"], x["repo"]))
    top_patterns = pattern_counter.most_common(10)

    stats = {
        "total": total,
        "by_verdict": dict(verdict_counter),
        "by_severity": dict(sev_counter),
        "top_patterns": top_patterns,
        "repos": repos,
    }

    html = _render_html(stats)
    out_path.write_text(html, encoding="utf-8")
    return stats


def _render_html(stats: dict) -> str:
    verdict_data = [{"name": k, "value": v} for k, v in stats["by_verdict"].items()]
    sev_data = [{"name": k, "value": v} for k, v in stats["by_severity"].items()]
    pattern_names = [k for k, _ in stats["top_patterns"]]
    pattern_values = [v for _, v in stats["top_patterns"]]

    # 仓库明细行（只取前 50 个命中最多的，每个仓库只显示前 5 条命中，避免 HTML 过大）
    rows_html = []
    for r in stats["repos"][:50]:
        hits_preview = r["hits"][:5]
        hits_json = json.dumps(hits_preview, ensure_ascii=False)
        more = len(r["hits"]) - 5
        more_str = f'<div class="more">+{more} more hits</div>' if more > 0 else ""
        rows_html.append(f"""
        <tr onclick="toggleHits(this)">
          <td class="repo">{r['repo']}</td>
          <td><span class="v {r['verdict']}">{r['verdict']}</span></td>
          <td class="num">{r['files_scanned']}</td>
          <td class="num">{r['hits_count']}</td>
        </tr>
        <tr class="hits-row" style="display:none">
          <td colspan="4">
            <pre>{hits_json}</pre>
            {more_str}
          </td>
        </tr>""")

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>MPV-Detector 扫描报告</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
<style>
  body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
         margin: 24px; background: #f8f9fa; color: #222; }}
  h1 {{ margin-bottom: 4px; }}
  .meta {{ color: #666; margin-bottom: 24px; }}
  .kpis {{ display: flex; gap: 16px; margin-bottom: 24px; }}
  .kpi {{ background: #fff; padding: 16px 24px; border-radius: 8px;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .kpi .v {{ font-size: 28px; font-weight: 700; }}
  .kpi .l {{ color: #666; font-size: 13px; }}
  .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }}
  .chart {{ background: #fff; padding: 16px; border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,.08); height: 320px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border-radius: 8px; overflow: hidden;
           box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #eee; }}
  th {{ background: #f1f3f5; font-weight: 600; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  td.repo {{ font-family: ui-monospace, Consolas, monospace; }}
  .v {{ padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
  .v.malicious {{ background: #ffe3e3; color: #c92a2a; }}
  .v.suspicious {{ background: #fff3bf; color: #e67700; }}
  .v.pending {{ background: #d0ebff; color: #1971c2; }}
  .v.benign {{ background: #d3f9d8; color: #2b8a3e; }}
  .v.not_scanned {{ background: #e9ecef; color: #868e96; }}
  .hits-row pre {{ background: #f8f9fa; padding: 12px; border-radius: 4px;
                   font-size: 12px; overflow-x: auto; }}
  .hits-row .more {{ color: #868e96; font-size: 12px; margin-top: 8px; }}
  tr:hover {{ background: #f1f3f5; cursor: pointer; }}
</style>
</head>
<body>
<h1>MPV-Detector 扫描报告</h1>
<div class="meta">生成时间：{now_iso()} · 数据源：{len(stats['repos'])} 个仓库结果</div>

<div class="kpis">
  <div class="kpi"><div class="v">{stats['total']}</div><div class="l">仓库总数</div></div>
  <div class="kpi"><div class="v">{stats['by_verdict'].get('malicious', 0) + stats['by_verdict'].get('suspicious', 0)}</div><div class="l">可疑/恶意</div></div>
  <div class="kpi"><div class="v">{stats['by_severity'].get('CRITICAL', 0)}</div><div class="l">CRITICAL 命中</div></div>
  <div class="kpi"><div class="v">{sum(stats['by_severity'].values())}</div><div class="l">总命中数</div></div>
</div>

<div class="charts">
  <div id="chart-verdict" class="chart"></div>
  <div id="chart-severity" class="chart"></div>
  <div id="chart-pattern" class="chart" style="grid-column: 1 / span 2"></div>
</div>

<h2>仓库明细（按命中数 TOP 50，点击行展开前 5 条命中）</h2>
<table>
  <thead><tr><th>仓库</th><th>verdict</th><th class="num">文件数</th><th class="num">命中数</th></tr></thead>
  <tbody>{"".join(rows_html)}</tbody>
</table>

<script>
function toggleHits(tr) {{
  const next = tr.nextElementSibling;
  next.style.display = next.style.display === 'none' ? 'table-row' : 'none';
}}
const verdictChart = echarts.init(document.getElementById('chart-verdict'));
verdictChart.setOption({{
  title: {{ text: 'verdict 分布', left: 'center' }},
  tooltip: {{ trigger: 'item' }},
  series: [{{ type: 'pie', radius: '60%', data: {json.dumps(verdict_data, ensure_ascii=False)} }}]
}});
const sevChart = echarts.init(document.getElementById('chart-severity'));
sevChart.setOption({{
  title: {{ text: 'severity 分布', left: 'center' }},
  tooltip: {{ trigger: 'item' }},
  series: [{{ type: 'pie', radius: '60%', data: {json.dumps(sev_data, ensure_ascii=False)} }}]
}});
const patternChart = echarts.init(document.getElementById('chart-pattern'));
patternChart.setOption({{
  title: {{ text: 'pattern 命中 TOP10', left: 'center' }},
  tooltip: {{}},
  xAxis: {{ type: 'category', data: {json.dumps(pattern_names)} }},
  yAxis: {{ type: 'value' }},
  series: [{{ type: 'bar', data: {json.dumps(pattern_values)}, itemStyle: {{ color: '#4c6ef5' }} }}]
}});
window.addEventListener('resize', () => {{
  verdictChart.resize(); sevChart.resize(); patternChart.resize();
}});
</script>
</body>
</html>"""


def main():
    ap = argparse.ArgumentParser(description="生成 HTML 可视化报告")
    ap.add_argument("--results-dir", default=str(SCAN_OUTPUT_DIR))
    ap.add_argument("--out", default="output/report.html")
    args = ap.parse_args()

    results_dir = Path(args.results_dir)
    out_path = Path(args.out)
    ensure_dir(out_path.parent)
    stats = build_report(results_dir, out_path)
    print(f"报告已生成: {out_path}")
    print(f"  仓库: {stats['total']}")
    print(f"  verdict: {stats['by_verdict']}")
    print(f"  severity: {stats['by_severity']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
