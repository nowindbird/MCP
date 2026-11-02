#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_crawler —— GitHub 抓取器纯函数测试（不发起网络）"""
import unittest

from detector.crawler.github_crawler import GitHubMCPCrawler


class TestBuildQuery(unittest.TestCase):
    def test_keyword_only(self):
        self.assertEqual(GitHubMCPCrawler.build_query("mcp server", None),
                         "mcp server")

    def test_full_filters(self):
        q = GitHubMCPCrawler.build_query("mcp", {
            "min_stars": 10, "max_stars": 100,
            "language": "Python", "topic": "mcp",
            "exclude_archived": True,
        })
        for part in ("stars:10..100", "language:Python", "topic:mcp",
                     "archived:false"):
            self.assertIn(part, q)


class TestApplyClientFilters(unittest.TestCase):
    def setUp(self):
        self.repos = [
            {"full_name": "a/x", "stars": 50, "forks": 1, "language": "Python",
             "topics": ["mcp"], "archived": False, "disabled": False,
             "created_at": "2024-01-01T00:00:00Z", "pushed_at": "2025-01-01T00:00:00Z"},
            {"full_name": "b/y", "stars": 5, "forks": 0, "language": "Go",
             "topics": [], "archived": True, "disabled": False,
             "created_at": "2024-06-01T00:00:00Z", "pushed_at": "2025-06-01T00:00:00Z"},
        ]

    def test_filters(self):
        got = GitHubMCPCrawler.apply_client_filters(self.repos, {
            "min_stars": 10, "language": "python", "topic": "mcp",
            "exclude_archived": True,
        })
        self.assertEqual([r["full_name"] for r in got], ["a/x"])

    def test_no_filters_passthrough(self):
        got = GitHubMCPCrawler.apply_client_filters(self.repos, None)
        self.assertEqual(len(got), 2)


class TestNormalizeRepo(unittest.TestCase):
    def test_normalize(self):
        raw = {
            "id": 1, "name": "r", "full_name": "o/r",
            "owner": {"login": "o", "type": "User"},
            "html_url": "https://github.com/o/r",
            "description": "d", "stargazers_count": 10, "forks_count": 2,
            "watchers_count": 3, "open_issues_count": 4, "subscribers_count": 5,
            "language": "Python", "topics": ["mcp"], "license": {"spdx_id": "MIT"},
            "default_branch": "main", "size": 100,
            "has_issues": True, "has_wiki": True, "archived": False,
            "disabled": False,
            "created_at": "2024-01-01", "updated_at": "2024-01-02",
            "pushed_at": "2024-01-03", "homepage": "", "clone_url": "x",
        }
        n = GitHubMCPCrawler.normalize_repo(raw, readme="hi", commits=[])
        self.assertEqual(n["full_name"], "o/r")
        self.assertEqual(n["stars"], 10)
        self.assertEqual(n["license"], "MIT")
        self.assertEqual(n["readme_length"], 2)
        self.assertEqual(n["size_kb"], 100)


if __name__ == "__main__":
    unittest.main()
