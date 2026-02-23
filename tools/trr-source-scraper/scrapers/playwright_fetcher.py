"""
Playwright-based page fetcher for JS-rendered sites.

Optional dependency — the scraper works without Playwright installed.
Only used for domains listed in config's js_rendered_domains.
"""

from typing import Optional

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class PlaywrightFetcher:
    """Manages a single headless browser instance for JS page rendering."""

    def __init__(self, timeout_ms: int = 15000):
        self._browser = None
        self._playwright = None
        self.timeout_ms = timeout_ms

    def _ensure_browser(self):
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright is not installed")
        if self._browser is None:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=True)

    def fetch_page_html(self, url: str) -> Optional[str]:
        """
        Fetch a page using headless Chromium and return rendered HTML.
        Returns None on failure (including browser launch errors).
        """
        page = None
        try:
            self._ensure_browser()
            page = self._browser.new_page()
            page.goto(url, timeout=self.timeout_ms, wait_until="networkidle")
            return page.content()
        except Exception:
            return None
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass

    def close(self):
        """Shut down the browser."""
        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass
        if self._playwright:
            try:
                self._playwright.stop()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
