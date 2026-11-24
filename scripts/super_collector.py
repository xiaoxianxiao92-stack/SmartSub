#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Discover public proxy subscription sources and pages for the existing collector.

Discovery is bounded, HTTPS-only, public-network-only, and keeps discovery separate
from node admission. It never writes subscription output or quality-gate state.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import time
from pathlib import Path
from urllib.parse import parse_qs, quote, quote_plus, unquote, urljoin, urlparse

import requests

try:
    from scrapling.fetchers import Fetcher, StealthyFetcher
except Exception:  # pragma: no cover - exercised in minimal environments
    Fetcher = None
    StealthyFetcher = None

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime"
SOURCE_OUT = RUNTIME / "super_collector_sources.txt"
PAGE_OUT = RUNTIME / "super_collector_pages.txt"
REPORT_OUT = ROOT / "super_collector_report.json"
QUERIES = (
    '"vless://" "subscription" github',
    '"vmess://" "clash" github',
    '"hysteria2://" "subscription" github',
    '"sing-box" "proxy" "subscribe" github',
    'free proxy subscription clash yaml',
)
SUBSCRIPTION_HINTS = re.compile(
    r"(sub(?:scribe)?|config|clash|v2ray|sing.?box|proxy|nodes?|all\.(?:txt|yaml|yml)|"
    r"base64|raw\.githubusercontent|gist\.githubusercontent)", re.I
)
NODE_PATTERN = re.compile(r"(?:vmess|ss|trojan|vless|hysteria2|tuic)://", re.I)
STATIC_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".woff", ".zip", ".pdf")


def public_https_url(value: str) -> bool:
    """Reject non-HTTPS, credentialed, local, private, and reserved destinations."""
    try:
        parsed = urlparse(value.strip())
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        host = parsed.hostname.rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal")):
            return False
        try:
            addresses = {ipaddress.ip_address(host)}
        except ValueError:
            addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None)}
        return bool(addresses) and all(
            addr.is_global and not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
            for addr in addresses
        )
    except (ValueError, OSError, socket.gaierror):
        return False


def is_subscription_candidate(value: str) -> bool:
    if not public_https_url(value):
        return False
    parsed = urlparse(value)
    if parsed.path.lower().endswith(STATIC_SUFFIXES):
        return False
    host = (parsed.hostname or "").lower()
    return bool(SUBSCRIPTION_HINTS.search(value)) or host in {
        "raw.githubusercontent.com", "gist.githubusercontent.com"
    }


def normalize_url(value: str, base: str = "") -> str:
    value = urljoin(base, value.strip()) if base else value.strip()
    parsed = urlparse(value)
    if parsed.scheme != "https":
        return ""
    # Drop fragments; retain query strings because many subscription URLs use them.
    return parsed._replace(fragment="").geturl()


class SuperCollector:
    def __init__(self, max_repos: int = 40, max_pages: int = 80, browser_fallback: bool = True):
        self.max_repos = max(1, min(max_repos, 100))
        self.max_pages = max(1, min(max_pages, 200))
        self.browser_fallback = browser_fallback
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SmartSub-SuperCollector/1.0 (+public-source-discovery)"})
        self.sources: set[str] = set()
        self.pages: set[str] = set()
        self.stats = {"github_repositories": 0, "pages_fetched": 0, "browser_fallbacks": 0,
                      "sources_found": 0, "pages_found": 0, "errors": 0}

    def fetch_page(self, url: str):
        if not public_https_url(url):
            return None
        try:
            if Fetcher is not None:
                page = Fetcher.get(url, timeout=15, stealthy_headers=True)
                if getattr(page, "status", 0) < 400:
                    self.stats["pages_fetched"] += 1
                    return page
        except Exception:
            pass
        if self.browser_fallback and StealthyFetcher is not None:
            try:
                page = StealthyFetcher.fetch(url, headless=True, disable_resources=True, timeout=20000)
                if getattr(page, "status", 0) < 400:
                    self.stats["pages_fetched"] += 1
                    self.stats["browser_fallbacks"] += 1
                    return page
            except Exception:
                self.stats["errors"] += 1
        try:
            response = self.session.get(url, timeout=15, allow_redirects=True)
            if response.status_code < 400 and len(response.content) <= 3 * 1024 * 1024:
                self.stats["pages_fetched"] += 1
                return response.text
        except requests.RequestException:
            self.stats["errors"] += 1
        return None

    @staticmethod
    def page_links(page, base: str) -> list[str]:
        if isinstance(page, str):
            raw = re.findall(r'''https://[^\s"'<>\\]+''', page)
        else:
            try:
                raw = page.css("a::attr(href)").getall()
            except Exception:
                raw = []
        links = []
        for item in raw:
            candidate = normalize_url(str(item), base)
            if candidate and (urlparse(candidate).hostname or "").lower().endswith("duckduckgo.com"):
                target = parse_qs(urlparse(candidate).query).get("uddg", [])
                if target:
                    candidate = normalize_url(unquote(target[0]))
            if candidate and public_https_url(candidate):
                links.append(candidate)
        return list(dict.fromkeys(links))

    def add_candidate(self, url: str):
        url = normalize_url(url)
        if not url or not public_https_url(url):
            return
        if is_subscription_candidate(url):
            self.sources.add(url)
        elif len(self.pages) < self.max_pages and urlparse(url).hostname not in {
            "api.github.com", "raw.githubusercontent.com"
        }:
            self.pages.add(url)

    def github_discovery(self):
        api = "https://api.github.com/search/repositories"
        for query in ("v2ray subscription", "clash subscription", "sing-box proxy", "free proxy nodes"):
            if self.stats["github_repositories"] >= self.max_repos:
                break
            try:
                response = self.session.get(api, params={"q": query, "sort": "updated",
                                                         "per_page": min(30, self.max_repos)}, timeout=15)
                if response.status_code == 403 or response.status_code == 429:
                    break
                response.raise_for_status()
                items = response.json().get("items", [])
            except (requests.RequestException, ValueError):
                self.stats["errors"] += 1
                continue
            for item in items:
                if self.stats["github_repositories"] >= self.max_repos:
                    break
                full_name = str(item.get("full_name", ""))
                branch = str(item.get("default_branch") or "main")
                html_url = str(item.get("html_url", ""))
                if not full_name or not html_url:
                    continue
                self.stats["github_repositories"] += 1
                self.pages.add(html_url)
                encoded_branch = quote(branch, safe="")
                readme = f"https://raw.githubusercontent.com/{full_name}/{encoded_branch}/README.md"
                page = self.fetch_page(readme)
                if page is not None:
                    text = page if isinstance(page, str) else ""
                    if not text:
                        try:
                            text = page.get_all_text()
                        except Exception:
                            text = ""
                    for found in re.findall(r"https://[^\s\"'<>\\]+", text or ""):
                        self.add_candidate(found.rstrip(").,;]"))
                    for link in self.page_links(page, readme):
                        self.add_candidate(link)

                # Inspect a bounded Git tree for likely subscription/config artifacts.
                tree_api = f"https://api.github.com/repos/{full_name}/git/trees/{encoded_branch}?recursive=1"
                try:
                    tree_response = self.session.get(tree_api, timeout=15)
                    if tree_response.status_code == 200:
                        entries = tree_response.json().get("tree", [])
                        likely = [
                            entry.get("path", "") for entry in entries
                            if entry.get("type") == "blob"
                            and entry.get("path", "").lower().endswith((".txt", ".yaml", ".yml", ".json"))
                            and re.search(r"(sub|config|proxy|node|clash|v2ray|sing.?box)", entry.get("path", ""), re.I)
                        ][:4]
                        for path in likely:
                            raw_url = f"https://raw.githubusercontent.com/{full_name}/{encoded_branch}/{quote(path, safe='/')}"
                            artifact = self.fetch_page(raw_url)
                            body = artifact if isinstance(artifact, str) else ""
                            if artifact is not None and not body:
                                try:
                                    body = artifact.get_all_text()
                                except Exception:
                                    body = ""
                            if body and (NODE_PATTERN.search(body) or "proxies:" in body):
                                self.sources.add(raw_url)
                except (requests.RequestException, ValueError):
                    self.stats["errors"] += 1
                time.sleep(0.15)

    def search_web(self):
        for query in QUERIES:
            if len(self.pages) >= self.max_pages:
                break
            url = "https://html.duckduckgo.com/html/?q=" + quote_plus(query)
            page = self.fetch_page(url)
            if page is None:
                continue
            for link in self.page_links(page, url):
                host = (urlparse(link).hostname or "").lower()
                if host.endswith("duckduckgo.com"):
                    continue
                self.add_candidate(link)
            time.sleep(0.5)

    def crawl_discovered_pages(self):
        queue = list(self.pages)[:self.max_pages]
        visited = set()
        while queue and len(visited) < self.max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            page = self.fetch_page(url)
            if page is None:
                continue
            for link in self.page_links(page, url):
                self.add_candidate(link)
                host = (urlparse(link).hostname or "").lower()
                if len(queue) + len(visited) < self.max_pages and host == (urlparse(url).hostname or "").lower():
                    if link not in visited and link not in queue and not is_subscription_candidate(link):
                        queue.append(link)
            time.sleep(0.2)

    def run(self) -> dict:
        self.github_discovery()
        self.search_web()
        self.crawl_discovered_pages()
        RUNTIME.mkdir(parents=True, exist_ok=True)
        SOURCE_OUT.write_text("\n".join(sorted(self.sources)) + ("\n" if self.sources else ""), encoding="utf-8")
        PAGE_OUT.write_text("\n".join(sorted(self.pages)) + ("\n" if self.pages else ""), encoding="utf-8")
        self.stats["sources_found"] = len(self.sources)
        self.stats["pages_found"] = len(self.pages)
        report = {"version": 1, "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "limits": {"max_repositories": self.max_repos, "max_pages": self.max_pages},
                  "stats": self.stats, "outputs": {"sources": str(SOURCE_OUT.relative_to(ROOT)),
                  "pages": str(PAGE_OUT.relative_to(ROOT))}}
        REPORT_OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover public proxy subscription sources")
    parser.add_argument("--max-repos", type=int, default=int(os.getenv("SMARTSUB_DISCOVERY_MAX_REPOS", "40")))
    parser.add_argument("--max-pages", type=int, default=int(os.getenv("SMARTSUB_DISCOVERY_MAX_PAGES", "80")))
    parser.add_argument("--no-browser-fallback", action="store_true")
    args = parser.parse_args()
    report = SuperCollector(args.max_repos, args.max_pages, not args.no_browser_fallback).run()
    print(json.dumps(report["stats"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
