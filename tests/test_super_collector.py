import socket
import unittest
from unittest.mock import patch

from scripts.super_collector import (
    is_subscription_candidate,
    normalize_url,
    public_https_url,
)


class SuperCollectorUrlTests(unittest.TestCase):
    @patch("scripts.super_collector.socket.getaddrinfo")
    def test_public_https_hostname_allowed(self, resolver):
        resolver.return_value = [(None, None, None, None, ("8.8.8.8", 443))]
        self.assertTrue(public_https_url("https://example.com/sub"))

    @patch("scripts.super_collector.socket.getaddrinfo")
    def test_private_dns_result_rejected(self, resolver):
        resolver.return_value = [(None, None, None, None, ("127.0.0.1", 443))]
        self.assertFalse(public_https_url("https://example.com/sub"))

    def test_local_and_non_https_rejected(self):
        self.assertFalse(public_https_url("http://example.com/sub"))
        self.assertFalse(public_https_url("https://localhost/sub"))
        self.assertFalse(public_https_url("https://127.0.0.1/sub"))

    @patch("scripts.super_collector.socket.getaddrinfo")
    def test_subscription_candidate_requires_public_https(self, resolver):
        resolver.return_value = [(None, None, None, None, ("1.1.1.1", 443))]
        self.assertTrue(is_subscription_candidate("https://example.com/subscribe"))
        self.assertFalse(is_subscription_candidate("https://example.com/logo.png"))

    def test_raw_github_readme_is_not_a_subscription(self):
        with patch("scripts.super_collector.socket.getaddrinfo") as resolver:
            resolver.return_value = [(None, None, None, None, ("185.199.108.133", 443))]
            self.assertFalse(is_subscription_candidate("https://raw.githubusercontent.com/example/repo/main/README.md"))

    @patch("scripts.super_collector.socket.getaddrinfo")
    def test_duckduckgo_redirect_unwraps_target(self, resolver):
        resolver.return_value = [(None, None, None, None, ("8.8.8.8", 443))]
        from scripts.super_collector import SuperCollector
        links = SuperCollector.page_links(
            'https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fsubscribe',
            'https://html.duckduckgo.com/html/',
        )
        self.assertEqual(links, ['https://example.com/subscribe'])

    def test_normalize_relative_link(self):
        self.assertEqual(
            normalize_url("/sub/all.txt", "https://example.com/page"),
            "https://example.com/sub/all.txt",
        )
        self.assertEqual(normalize_url("http://example.com/sub"), "")


if __name__ == "__main__":
    unittest.main()
