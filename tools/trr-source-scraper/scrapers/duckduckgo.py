"""
DuckDuckGo search scraper for finding research sources.

Uses the ddgs Python package for reliable, API-based search access.
Falls back to HTML scraping if ddgs is not installed.
"""

import hashlib
import re
import time
import urllib.parse
from typing import Dict, Optional, List
from bs4 import BeautifulSoup

try:
    from ddgs import DDGS
    DDGS_AVAILABLE = True
except ImportError:
    try:
        from duckduckgo_search import DDGS
        DDGS_AVAILABLE = True
    except ImportError:
        DDGS_AVAILABLE = False

import requests

from utils import (
    RateLimiter,
    clean_text,
    create_session,
    is_valid_url,
    extract_domain,
    is_generic_landing_page,
    get_cached,
    set_cached,
)


class DuckDuckGoScraper:
    """
    Searches DuckDuckGo for research sources.

    Uses the ddgs package when available for reliable results.
    Falls back to HTML scraping of html.duckduckgo.com as a secondary option.
    """

    SEARCH_URL = "https://html.duckduckgo.com/html/"

    def __init__(self, rate_limiter: Optional[RateLimiter] = None, user_agent: str = "",
                 verbose: bool = False, use_cache: bool = True):
        self.rate_limiter = rate_limiter or RateLimiter(delay=1.5)
        self.session = create_session(user_agent or "TRR-Source-Scraper/1.0")
        self.verbose = verbose
        self.use_cache = use_cache

    @staticmethod
    def _cache_key(query: str) -> str:
        """Generate a stable cache key for a search query."""
        return f"ddg_{hashlib.md5(query.encode()).hexdigest()}"

    def search(self, query: str, max_results: int = 10) -> List[Dict]:
        """
        Perform a search and return results.

        Args:
            query: Search query string
            max_results: Maximum number of results to return

        Returns:
            List of dictionaries with 'title', 'url', 'description' keys
        """
        # Check cache first (1-day TTL)
        if self.use_cache:
            cache_key = self._cache_key(query)
            cached = get_cached(cache_key, ttl_days=1)
            if cached is not None:
                if self.verbose:
                    print(f"  [cache] Hit for query: {query[:60]}...")
                return cached

        self.rate_limiter.wait()

        if DDGS_AVAILABLE:
            results = self._search_via_ddgs(query, max_results)
        else:
            results = self._search_via_html(query, max_results)

        # Store in cache
        if self.use_cache and results:
            set_cached(self._cache_key(query), results)

        return results

    def _search_via_ddgs(self, query: str, max_results: int) -> List[Dict]:
        """Use the ddgs package for searching."""
        try:
            results = []
            with DDGS() as ddgs:
                for r in ddgs.text(query, max_results=max_results):
                    url = r.get('href', '') or r.get('url', '')
                    if not url or not is_valid_url(url):
                        continue
                    results.append({
                        'title': clean_text(r.get('title', 'Untitled')),
                        'url': url,
                        'description': clean_text(r.get('body', ''), 300),
                        'display_url': extract_domain(url),
                        'domain': extract_domain(url),
                    })
            return results
        except Exception as e:
            if self.verbose:
                print(f"  [warn] DDGS API failed ({e}), falling back to HTML scraping")
            return self._search_via_html(query, max_results)

    def _search_via_html(self, query: str, max_results: int) -> List[Dict]:
        """Fallback: scrape html.duckduckgo.com directly."""
        params = {
            'q': query,
            'kl': 'wt-wt',
        }

        try:
            response = self.session.get(
                self.SEARCH_URL,
                params=params,
                timeout=15
            )
            response.raise_for_status()
        except requests.RequestException:
            return []

        return self._parse_html_results(response.text, max_results)

    def _parse_html_results(self, html: str, max_results: int) -> List[Dict]:
        """Parse HTML search results from DuckDuckGo."""
        soup = BeautifulSoup(html, 'lxml')
        results = []

        for result_div in soup.find_all('div', class_='result'):
            if len(results) >= max_results:
                break

            result = self._parse_single_result(result_div)
            if result and is_valid_url(result['url']):
                results.append(result)

        return results

    def _parse_single_result(self, result_div) -> Optional[Dict]:
        """Parse a single search result div."""
        try:
            link = result_div.find('a', class_='result__a')
            if not link:
                return None

            title = clean_text(link.get_text())
            raw_url = link.get('href', '')
            url = self._extract_real_url(raw_url)

            if not url:
                return None

            snippet = result_div.find('a', class_='result__snippet')
            if snippet:
                description = clean_text(snippet.get_text())
            else:
                desc_elem = result_div.find('td', class_='result__snippet')
                description = clean_text(desc_elem.get_text()) if desc_elem else ""

            display_url_elem = result_div.find('span', class_='result__url')
            display_url = clean_text(display_url_elem.get_text()) if display_url_elem else ""

            return {
                'title': title,
                'url': url,
                'description': description,
                'display_url': display_url,
                'domain': extract_domain(url),
            }

        except Exception:
            return None

    def _extract_real_url(self, duckduckgo_url: str) -> Optional[str]:
        """Extract the real URL from a DuckDuckGo redirect URL."""
        if not duckduckgo_url:
            return None

        if duckduckgo_url.startswith('http'):
            return duckduckgo_url

        if 'uddg=' in duckduckgo_url:
            try:
                parsed = urllib.parse.urlparse(duckduckgo_url, scheme='https')
                query_params = urllib.parse.parse_qs(parsed.query)
                if 'uddg' in query_params:
                    return urllib.parse.unquote(query_params['uddg'][0])
            except Exception:
                pass

        match = re.search(r'uddg=([^&]+)', duckduckgo_url)
        if match:
            try:
                return urllib.parse.unquote(match.group(1))
            except Exception:
                pass

        return None

    def search_with_site_filter(self, query: str, sites: List[str], max_results: int = 10) -> List[Dict]:
        """
        Search with a site: filter for specific domains.

        Args:
            query: Base search query
            sites: List of domains to search
            max_results: Maximum results per search

        Returns:
            Combined list of deduplicated results
        """
        all_results = []
        seen_urls = set()

        if sites:
            # Build site filter — limit to 5 domains to avoid overly long queries
            site_filter = ' OR '.join(f'site:{site}' for site in sites[:5])
            full_query = f"{query} ({site_filter})"
        else:
            full_query = query

        results = self.search(full_query, max_results)

        for result in results:
            if result['url'] not in seen_urls:
                seen_urls.add(result['url'])
                all_results.append(result)

        return all_results


def _build_queries(
    technique_id: str,
    technique_name: str,
    category_name: str,
    extra: str,
) -> List[str]:
    """
    Build search queries tailored to each category's purpose.

    Returns 2-3 queries per category, using exact-phrase quoting on the
    technique's short name to force DuckDuckGo to match precisely.
    """
    # For sub-techniques like "OS Credential Dumping: DCSync", extract "DCSync"
    short_name = (
        technique_name.split(":")[-1].strip()
        if ":" in technique_name
        else technique_name
    )

    # Shared precise queries used across most categories
    common = [
        f'"{technique_id}" "{short_name}"{extra}',
        f'"{short_name}" detection{extra}',
    ]

    category_specific = {
        'security_research': [f'"{short_name}" attack analysis write-up{extra}'],
        'microsoft_docs': [f'"{short_name}" site:learn.microsoft.com OR site:techcommunity.microsoft.com{extra}'],
        'conferences': [f'"{short_name}" presentation talk defcon OR blackhat{extra}'],
        'github': [f'"{technique_id}" detection rule{extra}'],
        'sigma_rules': [f'site:github.com/SigmaHQ/sigma "{technique_id}"'],
        'lolbas_gtfobins': [f'"{short_name}" LOLBAS OR GTFOBins{extra}'],
        'academic': [f'"{short_name}" detection research paper{extra}'],
    }

    return common + category_specific.get(category_name, [])


def search_technique_sources(
    technique_id: str,
    technique_name: str,
    categories: Dict,
    max_per_category: int = 10,
    user_agent: str = "",
    extra_terms: str = "",
    verbose: bool = False,
    mitre_refs: Optional[List[Dict]] = None,
    use_cache: bool = True,
) -> Dict[str, List[Dict]]:
    """
    Search for sources across multiple categories.

    Args:
        technique_id: MITRE ATT&CK technique ID
        technique_name: Human-readable technique name
        categories: Dictionary of category configs from sources.json
        max_per_category: Maximum results per category
        user_agent: Custom user agent string
        extra_terms: Additional search terms appended to every query
        verbose: Print diagnostic information
        mitre_refs: References extracted from the MITRE ATT&CK page (used
                    to boost domains that MITRE itself cites)
        use_cache: Whether to use cached search results (1-day TTL)

    Returns:
        Dictionary mapping category names to lists of results
    """
    scraper = DuckDuckGoScraper(user_agent=user_agent, verbose=verbose, use_cache=use_cache)
    results = {}

    extra = f" {extra_terms.strip()}" if extra_terms and extra_terms.strip() else ""

    # Extract domains from MITRE references — these are known to have
    # technique-relevant content and can supplement the configured domain list
    mitre_ref_domains = set()
    if mitre_refs:
        for ref in mitre_refs:
            url = ref.get('url', '')
            if url:
                domain = extract_domain(url)
                if domain:
                    mitre_ref_domains.add(domain)

    # Cross-category dedup: each URL appears in at most one category
    global_seen_urls = set()

    for category_name, category_config in categories.items():
        category_results = []
        domains = category_config.get('domains', [])
        search_suffix = category_config.get('search_suffix', '')

        # Merge MITRE-cited domains into the domain list for this category
        # (only domains not already present, limited to keep queries short)
        combined_domains = list(domains)
        for mrd in mitre_ref_domains:
            if mrd not in combined_domains:
                combined_domains.append(mrd)

        queries = _build_queries(technique_id, technique_name, category_name, extra)

        # Use top 2 queries for this category
        for query in queries[:2]:
            full_query = f"{query} {search_suffix}".strip()

            search_results = scraper.search_with_site_filter(
                full_query,
                combined_domains,
                max_per_category
            )

            category_results.extend(search_results)

        # Deduplicate within + across categories, filter landing pages
        seen = set()
        unique_results = []
        for r in category_results:
            url = r['url']
            if url in seen or url in global_seen_urls:
                continue
            if is_generic_landing_page(url):
                if verbose:
                    print(f"  [filter] Skipped generic landing page: {url}")
                continue
            seen.add(url)
            unique_results.append(r)

        global_seen_urls.update(seen)
        results[category_name] = unique_results[:max_per_category]

    return results
