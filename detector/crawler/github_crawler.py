#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub MCP 工具插件抓取脚本
============================
用于从 GitHub 搜索并抓取 MCP（Model Context Protocol）相关的工具/插件仓库，
支持多关键词搜索、分页、详情抓取、README 提取，结果输出为 JSON / CSV。

使用方式：
    # 基础使用（匿名，速率限制 10 次/分钟）
    python github_mcp_crawler.py

    # 使用 GitHub Token（速率限制 30 次/分钟，推荐）
    python github_mcp_crawler.py --token ghp_xxxxxxxxxxxx

    # 指定关键词和最大结果数
    python github_mcp_crawler.py --keywords "mcp server" "model context protocol" --max-results 200

    # 抓取 README 内容（用于安全分析/投毒检测）
    python github_mcp_crawler.py --fetch-readme

    # 指定输出目录
    python github_mcp_crawler.py --output ./data

筛选条件（可组合使用）：
    # 只抓 star >= 100 的仓库
    python github_mcp_crawler.py --min-stars 100

    # 只抓 2024 年之后创建的仓库
    python github_mcp_crawler.py --created-after 2024-01-01

    # 只抓最近 3 个月有更新的仓库
    python github_mcp_crawler.py --pushed-after 2025-06-01

    # 只抓 Python 语言、MIT 协议的仓库
    python github_mcp_crawler.py --language Python --license mit

    # 排除已归档/已禁用的仓库
    python github_mcp_crawler.py --exclude-archived --exclude-disabled

    # 组合筛选：star 50~500，TypeScript，2024年后创建，排除归档
    python github_mcp_crawler.py --min-stars 50 --max-stars 500 \
        --language TypeScript --created-after 2024-01-01 --exclude-archived

依赖：requests
    pip install requests
"""

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    print("[错误] 缺少依赖 requests，请先执行: pip install requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
GITHUB_API = "https://api.github.com"
DEFAULT_KEYWORDS = [
    "mcp server",
    "model context protocol",
    "mcp tool",
    "mcp plugin",
    "mcp-server",
    "modelcontextprotocol",
]

# 每页结果数（GitHub API 最大 100）
PER_PAGE = 100

# 请求超时（秒）
TIMEOUT = 30

# 重试次数
MAX_RETRIES = 3

# 重试间隔（秒）
RETRY_DELAY = 5


class GitHubMCPCrawler:
    """GitHub MCP 仓库抓取器"""

    def __init__(self, token: Optional[str] = None, fetch_readme: bool = False):
        self.token = token
        self.fetch_readme = fetch_readme
        # 复用 Session 以保持连接与头信息，避免每个请求都重建 TCP 连接
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",       # GitHub REST API 媒体类型
            "X-GitHub-Api-Version": "2022-11-28",          # API 版本固定
            "User-Agent": "MCP-GitHub-Crawler/1.0",        # GitHub 要求提供 UA
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"  # Bearer Token 鉴权

        # 速率限制状态（由响应头 X-RateLimit-* 回填）
        self.rate_limit_remaining = None
        self.rate_limit_reset = None

    # ------------------------------------------------------------------
    # 基础请求
    # ------------------------------------------------------------------
    def _request(self, url: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """带重试和速率限制处理的 GET 请求（返回 JSON 或 None）。"""
        for attempt in range(MAX_RETRIES):  # 最多 MAX_RETRIES 次尝试
            try:
                resp = self.session.get(url, params=params, timeout=TIMEOUT)

                # 从响应头更新速率限制状态（剩余次数 / 重置时间戳）
                self.rate_limit_remaining = int(resp.headers.get("X-RateLimit-Remaining", 0))
                self.rate_limit_reset = int(resp.headers.get("X-RateLimit-Reset", 0))

                if resp.status_code == 200:  # 成功
                    return resp.json()

                # 403 且配额耗尽：等 reset 时刻 + 5 秒再重试
                if resp.status_code == 403 and self.rate_limit_remaining == 0:
                    wait_time = max(self.rate_limit_reset - int(time.time()), 0) + 5
                    print(f"[速率限制] 已达上限，等待 {wait_time:.0f} 秒后重试...")
                    time.sleep(wait_time)
                    continue

                # 可重试的临时性错误码（422 校验失败 / 403 / 502 / 503 网关错误）
                if resp.status_code in (422, 403, 502, 503):
                    print(f"[警告] HTTP {resp.status_code}，{RETRY_DELAY}秒后重试 "
                          f"({attempt + 1}/{MAX_RETRIES})")
                    time.sleep(RETRY_DELAY)
                    continue

                print(f"[错误] HTTP {resp.status_code}: {resp.text[:200]}")
                return None  # 其他错误码不重试

            except requests.RequestException as e:
                print(f"[错误] 请求异常: {e}，{RETRY_DELAY}秒后重试 "
                      f"({attempt + 1}/{MAX_RETRIES})")
                time.sleep(RETRY_DELAY)

        return None  # 重试耗尽仍失败

    def _check_rate_limit(self) -> None:
        """检查速率限制，剩余次数少时主动等待"""
        if self.rate_limit_remaining is not None and self.rate_limit_remaining <= 5:
            wait_time = max(self.rate_limit_reset - int(time.time()), 0) + 5
            if wait_time > 0:
                print(f"[速率限制] 剩余 {self.rate_limit_remaining} 次，等待 {wait_time:.0f} 秒...")
                time.sleep(wait_time)

    # ------------------------------------------------------------------
    # 搜索仓库
    # ------------------------------------------------------------------
    @staticmethod
    def build_query(keyword: str, filters: Optional[Dict] = None) -> str:
        """将关键词和筛选条件拼接为 GitHub Search API 查询语句"""
        if not filters:
            return keyword

        parts = [keyword]

        # star 数
        if filters.get("min_stars") is not None and filters.get("max_stars") is not None:
            parts.append(f"stars:{filters['min_stars']}..{filters['max_stars']}")
        elif filters.get("min_stars") is not None:
            parts.append(f"stars:>={filters['min_stars']}")
        elif filters.get("max_stars") is not None:
            parts.append(f"stars:<={filters['max_stars']}")

        # fork 数
        if filters.get("min_forks") is not None and filters.get("max_forks") is not None:
            parts.append(f"forks:{filters['min_forks']}..{filters['max_forks']}")
        elif filters.get("min_forks") is not None:
            parts.append(f"forks:>={filters['min_forks']}")
        elif filters.get("max_forks") is not None:
            parts.append(f"forks:<={filters['max_forks']}")

        # 创建时间
        if filters.get("created_after"):
            parts.append(f"created:>={filters['created_after']}")
        if filters.get("created_before"):
            parts.append(f"created:<={filters['created_before']}")

        # 推送时间
        if filters.get("pushed_after"):
            parts.append(f"pushed:>={filters['pushed_after']}")
        if filters.get("pushed_before"):
            parts.append(f"pushed:<={filters['pushed_before']}")

        # 语言
        if filters.get("language"):
            parts.append(f"language:{filters['language']}")

        # license
        if filters.get("license"):
            parts.append(f"license:{filters['license']}")

        # topic
        if filters.get("topic"):
            parts.append(f"topic:{filters['topic']}")

        # 排除归档/禁用
        if filters.get("exclude_archived"):
            parts.append("archived:false")
        if filters.get("exclude_disabled"):
            parts.append("is:public")  # disabled 仓库通常不可搜索，用 public 兜底

        return " ".join(parts)

    def search_repos(self, keyword: str, max_results: int = 100,
                     filters: Optional[Dict] = None) -> List[Dict]:
        """按关键词和筛选条件搜索 GitHub 仓库（自动分页）。"""
        results = []
        page = 1
        total_fetched = 0
        query = self.build_query(keyword, filters)  # 拼接查询串

        while total_fetched < max_results:  # 循环直到达到上限或没有更多
            self._check_rate_limit()  # 主动等待，避免撞上配额

            params = {
                "q": query,
                "sort": "stars",       # 按 star 降序
                "order": "desc",
                "per_page": PER_PAGE,  # 每页 100
                "page": page,
            }

            print(f"[搜索] 查询='{query}'  第 {page} 页...")
            data = self._request(f"{GITHUB_API}/search/repositories", params=params)

            if not data:  # 请求失败
                break
            items = data.get("items", [])
            if not items:  # 本页无结果 → 结束
                break

            results.extend(items)
            total_fetched += len(items)
            print(f"  -> 获取 {len(items)} 条，累计 {total_fetched} 条")

            if len(items) < PER_PAGE:  # 非整页 → 已到末尾
                break
            page += 1
            time.sleep(1)  # 避免触发次级速率限制

        return results[:max_results]  # 截断到上限

    # ------------------------------------------------------------------
    # 客户端二次筛选（兜底，确保服务端 qualifier 之外的条件也生效）
    # ------------------------------------------------------------------
    @staticmethod
    def apply_client_filters(repos: List[Dict], filters: Optional[Dict] = None) -> List[Dict]:
        """在客户端对已抓取的仓库做二次筛选（服务端 qualifier 之外的兜底）。"""
        if not filters:
            return repos

        def _parse_date(s: str) -> Optional[datetime]:
            """把 ISO 时间串解析为 datetime；失败返回 None。"""
            if not s:
                return None
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00"))  # 兼容 Z 后缀
            except (ValueError, TypeError):
                return None

        filtered = []
        for r in repos:  # 逐仓库按所有筛选条件检查
            # star 数区间
            stars = r.get("stars", 0)
            if filters.get("min_stars") is not None and stars < filters["min_stars"]:
                continue
            if filters.get("max_stars") is not None and stars > filters["max_stars"]:
                continue

            # fork 数区间
            forks = r.get("forks", 0)
            if filters.get("min_forks") is not None and forks < filters["min_forks"]:
                continue
            if filters.get("max_forks") is not None and forks > filters["max_forks"]:
                continue

            # 创建时间区间（与 UTC 截止值比较）
            created = _parse_date(r.get("created_at", ""))
            if filters.get("created_after") and created:
                cutoff = datetime.fromisoformat(filters["created_after"]).replace(tzinfo=timezone.utc)
                if created < cutoff:
                    continue
            if filters.get("created_before") and created:
                cutoff = datetime.fromisoformat(filters["created_before"]).replace(tzinfo=timezone.utc)
                if created > cutoff:
                    continue

            # 推送时间区间
            pushed = _parse_date(r.get("pushed_at", ""))
            if filters.get("pushed_after") and pushed:
                cutoff = datetime.fromisoformat(filters["pushed_after"]).replace(tzinfo=timezone.utc)
                if pushed < cutoff:
                    continue
            if filters.get("pushed_before") and pushed:
                cutoff = datetime.fromisoformat(filters["pushed_before"]).replace(tzinfo=timezone.utc)
                if pushed > cutoff:
                    continue

            # 语言（忽略大小写）
            if filters.get("language"):
                if (r.get("language") or "").lower() != filters["language"].lower():
                    continue

            # license（忽略大小写）
            if filters.get("license"):
                if (r.get("license") or "").lower() != filters["license"].lower():
                    continue

            # topic（必须包含该标签）
            if filters.get("topic"):
                topics = [t.lower() for t in r.get("topics", [])]
                if filters["topic"].lower() not in topics:
                    continue

            # 排除归档 / 禁用
            if filters.get("exclude_archived") and r.get("archived"):
                continue
            if filters.get("exclude_disabled") and r.get("disabled"):
                continue

            filtered.append(r)  # 通过全部条件 → 保留

        return filtered

    # ------------------------------------------------------------------
    # 抓取仓库详情
    # ------------------------------------------------------------------
    def fetch_repo_detail(self, owner: str, repo: str) -> Optional[Dict]:
        """获取单个仓库的详细信息"""
        self._check_rate_limit()
        return self._request(f"{GITHUB_API}/repos/{owner}/{repo}")

    def fetch_readme(self, owner: str, repo: str) -> Optional[str]:
        """获取仓库 README 内容（纯文本）；没有 README 返回 None。"""
        self._check_rate_limit()
        resp = None
        for attempt in range(MAX_RETRIES):
            try:
                r = self.session.get(
                    f"{GITHUB_API}/repos/{owner}/{repo}/readme",
                    headers={"Accept": "application/vnd.github.raw"},  # raw 类型直接拿纯文本
                    timeout=TIMEOUT,
                )
                self.rate_limit_remaining = int(r.headers.get("X-RateLimit-Remaining", 0))
                self.rate_limit_reset = int(r.headers.get("X-RateLimit-Reset", 0))

                if r.status_code == 200:  # 成功
                    return r.text
                if r.status_code == 404:  # 仓库没有 README
                    return None
                if r.status_code == 403 and self.rate_limit_remaining == 0:  # 配额耗尽
                    wait_time = max(self.rate_limit_reset - int(time.time()), 0) + 5
                    time.sleep(wait_time)
                    continue
                time.sleep(RETRY_DELAY)  # 其他错误稍等重试
            except requests.RequestException:
                time.sleep(RETRY_DELAY)
        return None  # 重试耗尽

    def fetch_recent_commits(self, owner: str, repo: str, count: int = 5) -> List[Dict]:
        """获取最近的提交记录（精简字段：sha 前 8 位/首行 message/日期/作者）。"""
        self._check_rate_limit()
        data = self._request(
            f"{GITHUB_API}/repos/{owner}/{repo}/commits",
            params={"per_page": count},
        )
        if not data:
            return []
        commits = []
        for c in data:  # 抽取核心字段
            commits.append({
                "sha": c.get("sha", "")[:8],
                "message": c.get("commit", {}).get("message", "").split("\n")[0],  # 取首行
                "date": c.get("commit", {}).get("author", {}).get("date", ""),
                "author": c.get("commit", {}).get("author", {}).get("name", ""),
            })
        return commits

    # ------------------------------------------------------------------
    # 数据清洗
    # ------------------------------------------------------------------
    @staticmethod
    def normalize_repo(raw: Dict, readme: Optional[str] = None,
                       commits: Optional[List[Dict]] = None) -> Dict:
        """将 GitHub API 返回的原始仓库数据清洗为统一格式字典。"""
        owner = raw.get("owner", {}) or {}
        license_info = raw.get("license") or {}

        return {
            # 基本信息
            "id": raw.get("id"),
            "name": raw.get("name", ""),
            "full_name": raw.get("full_name", ""),
            "owner": owner.get("login", ""),
            "owner_type": owner.get("type", ""),
            "html_url": raw.get("html_url", ""),
            "description": raw.get("description", "") or "",

            # 统计信息
            "stars": raw.get("stargazers_count", 0),
            "forks": raw.get("forks_count", 0),
            "watchers": raw.get("watchers_count", 0),
            "open_issues": raw.get("open_issues_count", 0),
            "subscribers_count": raw.get("subscribers_count", 0),

            # 技术信息
            "language": raw.get("language", "") or "",
            "topics": raw.get("topics", []) or [],
            "license": license_info.get("spdx_id", "") or license_info.get("key", ""),
            "default_branch": raw.get("default_branch", ""),
            "size_kb": raw.get("size", 0),       # GitHub 的 size 单位是 KB
            "has_issues": raw.get("has_issues", False),
            "has_wiki": raw.get("has_wiki", False),
            "archived": raw.get("archived", False),
            "disabled": raw.get("disabled", False),

            # 时间
            "created_at": raw.get("created_at", ""),
            "updated_at": raw.get("updated_at", ""),
            "pushed_at": raw.get("pushed_at", ""),

            # 主页/链接
            "homepage": raw.get("homepage", "") or "",
            "clone_url": raw.get("clone_url", ""),

            # 扩展信息（README + 最近提交，供安全分析）
            "readme": readme,
            "readme_length": len(readme) if readme else 0,
            "recent_commits": commits or [],
        }

    # ------------------------------------------------------------------
    # 主流程
    # ------------------------------------------------------------------
    def crawl(self, keywords: List[str], max_results: int = 100,
              fetch_commits: bool = False,
              filters: Optional[Dict] = None) -> List[Dict]:
        """执行完整抓取流程：搜索→去重→抓详情/README→二次筛选→排序。"""
        all_repos: Dict[str, Dict] = {}  # 用 full_name 作键去重

        # 阶段一：多关键词搜索并去重
        for keyword in keywords:
            print(f"\n{'='*60}")
            print(f"开始搜索关键词: {keyword}")
            print(f"{'='*60}")

            raw_repos = self.search_repos(keyword, max_results, filters)

            for raw in raw_repos:  # 按 full_name 去重合并
                full_name = raw.get("full_name", "")
                if full_name and full_name not in all_repos:
                    all_repos[full_name] = raw

            print(f"[去重后] 当前累计 {len(all_repos)} 个唯一仓库")

        # 阶段二：逐仓抓详情 + README + 最近提交
        print(f"\n{'='*60}")
        print(f"开始抓取详情（共 {len(all_repos)} 个仓库）")
        print(f"{'='*60}")

        normalized = []
        for idx, (full_name, raw) in enumerate(all_repos.items(), 1):
            owner = raw.get("owner", {}).get("login", "")
            repo = raw.get("name", "")

            print(f"[{idx}/{len(all_repos)}] {full_name}")

            readme = None
            if self.fetch_readme:  # 可选：抓 README（供投毒/对齐分析）
                readme = self.fetch_readme(owner, repo)
                if readme:
                    print(f"  -> README: {len(readme)} 字符")

            commits = None
            if fetch_commits:  # 可选：抓最近提交
                commits = self.fetch_recent_commits(owner, repo)
                if commits:
                    print(f"  -> 最近提交: {len(commits)} 条")

            normalized.append(self.normalize_repo(raw, readme, commits))
            time.sleep(0.5)  # 礼貌延迟，防止速率限制

        # 阶段三：客户端二次筛选（兜底服务端 qualifier 之外的过滤）
        if filters:
            before = len(normalized)
            normalized = self.apply_client_filters(normalized, filters)
            after = len(normalized)
            if before != after:
                print(f"\n[客户端筛选] {before} -> {after}（过滤掉 {before - after} 个不符合条件的仓库）")

        # 阶段四：按 star 数降序排序
        normalized.sort(key=lambda x: x.get("stars", 0), reverse=True)
        return normalized


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def save_json(data: List[Dict], filepath: str) -> None:
    """保存为 JSON"""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[保存] JSON -> {filepath} ({len(data)} 条)")


def save_csv(data: List[Dict], filepath: str) -> None:
    """保存为 CSV（不含 README 和 commits 等长文本字段）"""
    if not data:
        return

    # 排除长文本字段
    exclude_fields = {"readme", "recent_commits", "topics"}
    fieldnames = [k for k in data[0].keys() if k not in exclude_fields]
    # 单独处理 topics
    fieldnames.append("topics")

    with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            row_copy = {k: v for k, v in row.items() if k not in exclude_fields}
            row_copy["topics"] = ", ".join(row.get("topics", []))
            writer.writerow(row_copy)
    print(f"[保存] CSV  -> {filepath} ({len(data)} 条)")


def save_summary(data: List[Dict], filepath: str) -> None:
    """保存统计摘要"""
    total = len(data)
    total_stars = sum(r.get("stars", 0) for r in data)
    total_forks = sum(r.get("forks", 0) for r in data)

    # 语言分布
    lang_dist: Dict[str, int] = {}
    for r in data:
        lang = r.get("language", "Unknown") or "Unknown"
        lang_dist[lang] = lang_dist.get(lang, 0) + 1

    # 有 README 的数量
    with_readme = sum(1 for r in data if r.get("readme"))

    summary = {
        "crawl_time": datetime.now(timezone.utc).isoformat(),
        "total_repos": total,
        "total_stars": total_stars,
        "total_forks": total_forks,
        "avg_stars": round(total_stars / total, 1) if total else 0,
        "with_readme": with_readme,
        "language_distribution": dict(sorted(lang_dist.items(), key=lambda x: -x[1])),
        "top_10_by_stars": [
            {
                "full_name": r["full_name"],
                "stars": r["stars"],
                "language": r["language"],
                "description": r["description"][:100],
            }
            for r in data[:10]
        ],
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[保存] 摘要 -> {filepath}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="GitHub MCP 工具插件抓取脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("GITHUB_TOKEN", ""),
        help="GitHub Personal Access Token（也可通过环境变量 GITHUB_TOKEN 设置）",
    )
    parser.add_argument(
        "--keywords",
        nargs="+",
        default=DEFAULT_KEYWORDS,
        help=f"搜索关键词列表（默认: {' | '.join(DEFAULT_KEYWORDS)}）",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=100,
        help="每个关键词最多抓取的结果数（默认: 100，GitHub 搜索上限 1000）",
    )
    parser.add_argument(
        "--fetch-readme",
        action="store_true",
        help="抓取每个仓库的 README 内容（用于安全分析）",
    )
    parser.add_argument(
        "--fetch-commits",
        action="store_true",
        help="抓取每个仓库的最近 5 条提交记录",
    )
    parser.add_argument(
        "--output",
        default="./output",
        help="输出目录（默认: ./output）",
    )

    # ---- 筛选条件 ----
    filter_group = parser.add_argument_group("筛选条件（可组合使用）")
    filter_group.add_argument(
        "--min-stars",
        type=int,
        default=None,
        help="最小 star 数",
    )
    filter_group.add_argument(
        "--max-stars",
        type=int,
        default=None,
        help="最大 star 数",
    )
    filter_group.add_argument(
        "--min-forks",
        type=int,
        default=None,
        help="最小 fork 数",
    )
    filter_group.add_argument(
        "--max-forks",
        type=int,
        default=None,
        help="最大 fork 数",
    )
    filter_group.add_argument(
        "--created-after",
        default=None,
        help="创建时间不早于该日期（格式: YYYY-MM-DD）",
    )
    filter_group.add_argument(
        "--created-before",
        default=None,
        help="创建时间不晚于该日期（格式: YYYY-MM-DD）",
    )
    filter_group.add_argument(
        "--pushed-after",
        default=None,
        help="最近推送时间不早于该日期（格式: YYYY-MM-DD）",
    )
    filter_group.add_argument(
        "--pushed-before",
        default=None,
        help="最近推送时间不晚于该日期（格式: YYYY-MM-DD）",
    )
    filter_group.add_argument(
        "--language",
        default=None,
        help="编程语言（如 Python, TypeScript, JavaScript, Go）",
    )
    filter_group.add_argument(
        "--license",
        default=None,
        help="开源协议（如 mit, apache-2.0, gpl-3.0）",
    )
    filter_group.add_argument(
        "--topic",
        default=None,
        help="GitHub Topic 标签（如 mcp, ai, agent）",
    )
    filter_group.add_argument(
        "--exclude-archived",
        action="store_true",
        help="排除已归档的仓库",
    )
    filter_group.add_argument(
        "--exclude-disabled",
        action="store_true",
        help="排除已禁用的仓库",
    )

    args = parser.parse_args()

    # 校验日期格式
    for date_arg in ("created_after", "created_before", "pushed_after", "pushed_before"):
        val = getattr(args, date_arg, None)
        if val:
            try:
                datetime.strptime(val, "%Y-%m-%d")
            except ValueError:
                parser.error(f"--{date_arg.replace('_', '-')} 日期格式错误，应为 YYYY-MM-DD，当前值: {val}")

    # 组装筛选字典
    filters = {
        "min_stars": args.min_stars,
        "max_stars": args.max_stars,
        "min_forks": args.min_forks,
        "max_forks": args.max_forks,
        "created_after": args.created_after,
        "created_before": args.created_before,
        "pushed_after": args.pushed_after,
        "pushed_before": args.pushed_before,
        "language": args.language,
        "license": args.license,
        "topic": args.topic,
        "exclude_archived": args.exclude_archived,
        "exclude_disabled": args.exclude_disabled,
    }
    # 去掉 None 和 False 的项，只保留实际设置的筛选条件
    filters = {k: v for k, v in filters.items() if v is not None and v is not False}

    # 创建输出目录
    os.makedirs(args.output, exist_ok=True)

    # 打印配置
    print("=" * 60)
    print("GitHub MCP 工具插件抓取器")
    print("=" * 60)
    print(f"  Token:    {'已配置' if args.token else '未配置（匿名，速率受限）'}")
    print(f"  关键词:   {', '.join(args.keywords)}")
    print(f"  每词上限: {args.max_results}")
    print(f"  抓README: {'是' if args.fetch_readme else '否'}")
    print(f"  抓提交:   {'是' if args.fetch_commits else '否'}")
    print(f"  输出目录: {args.output}")
    if filters:
        print(f"  筛选条件:")
        for k, v in filters.items():
            label = k.replace("_", " ")
            print(f"    - {label}: {v}")
    else:
        print(f"  筛选条件: 无（抓取全部）")
    print("=" * 60)

    # 执行抓取
    crawler = GitHubMCPCrawler(token=args.token or None, fetch_readme=args.fetch_readme)
    results = crawler.crawl(
        keywords=args.keywords,
        max_results=args.max_results,
        fetch_commits=args.fetch_commits,
        filters=filters if filters else None,
    )

    if not results:
        print("\n[警告] 未抓取到任何结果，请检查网络或关键词。")
        sys.exit(1)

    # 生成文件名（带时间戳）
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(args.output, f"mcp_repos_{timestamp}.json")
    csv_path = os.path.join(args.output, f"mcp_repos_{timestamp}.csv")
    summary_path = os.path.join(args.output, f"mcp_summary_{timestamp}.json")

    # 保存
    save_json(results, json_path)
    save_csv(results, csv_path)
    save_summary(results, summary_path)

    # 打印 Top 10
    print(f"\n{'='*60}")
    print(f"抓取完成！共 {len(results)} 个 MCP 相关仓库")
    print(f"{'='*60}")
    print(f"\nTop 10（按 Star 排序）:")
    for i, r in enumerate(results[:10], 1):
        print(f"  {i:2d}. ★{r['stars']:>6}  {r['full_name']:<45} "
              f"[{r['language'] or 'N/A'}]")
        if r["description"]:
            print(f"      {r['description'][:80]}")

    print(f"\n输出文件:")
    print(f"  - {json_path}")
    print(f"  - {csv_path}")
    print(f"  - {summary_path}")


if __name__ == "__main__":
    main()
