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
from utils.helpers import extract_attack_keywords, is_broad_technique


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


# URL path segments that indicate generic Microsoft reference docs, not security content
_MSLEARN_NOISE_PATHS = [
    '/powershell/module/',
    '/powershell/scripting/',
    '/dotnet/api/',
    '/sql/relational-databases/',
    '/visualstudio/',
    '/office/vba/',
]

# GitHub path patterns that indicate non-rule content in the SigmaHQ repo
_SIGMA_NOISE_PATTERNS = [
    '/pull/',
    '/issues/',
    '/other/',
    '/tests/',
    'indexes/',
]


def _is_offtopic_mslearn(url: str, technique_name: str) -> bool:
    """
    Return True if the URL is a learn.microsoft.com generic reference page
    unrelated to security. Skipped entirely for PowerShell-specific techniques.
    """
    if 'learn.microsoft.com' not in url:
        return False
    if 'powershell' in technique_name.lower():
        return False
    url_lower = url.lower()
    for noise_path in _MSLEARN_NOISE_PATHS:
        if noise_path in url_lower:
            return True
    return False


def _is_non_english_mslearn(url: str) -> bool:
    """Return True if the URL is a non-English Microsoft Learn or Docs page."""
    url_lower = url.lower()
    if 'learn.microsoft.com/' not in url_lower and 'docs.microsoft.com/' not in url_lower:
        return False
    locale_match = re.search(r'microsoft\.com/([a-z]{2}-[a-z]{2})/', url_lower)
    if locale_match and locale_match.group(1) != 'en-us':
        return True
    return False


def _is_noise_sigma_result(url: str) -> bool:
    """Return True if the URL is non-rule content from the SigmaHQ GitHub repo."""
    if 'github.com/SigmaHQ/sigma' not in url:
        return False
    url_lower = url.lower()
    for pattern in _SIGMA_NOISE_PATTERNS:
        if pattern.lower() in url_lower:
            return True
    return False



# Microsoft legacy community forums — return outdated forum noise
_MSFT_FORUM_NOISE_DOMAINS = [
    'social.msdn.microsoft.com',
    'social.technet.microsoft.com',
]


def _is_noise_msft_forum(url: str) -> bool:
    """Return True if the URL is from a retired Microsoft community forum."""
    url_lower = url.lower()
    return any(d in url_lower for d in _MSFT_FORUM_NOISE_DOMAINS)


def _build_queries(
    technique_id: str,
    technique_name: str,
    category_name: str,
    extra: str,
    attack_keywords: Optional[List[str]] = None,
) -> List[str]:
    """
    Build search queries tailored to each category's purpose.

    Returns 2-3 queries per category (up to 4 when attack_keywords are
    provided for broad techniques).  Category-specific queries come first
    (most targeted), followed by shared common queries.  Uses exact-phrase
    quoting on the technique's short name to force DuckDuckGo to match
    precisely.
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
        'microsoft_docs': [f'"{short_name}" site:docs.microsoft.com OR site:msdn.microsoft.com OR site:technet.microsoft.com{extra}'],
        'conferences': [f'"{short_name}" presentation talk defcon OR blackhat{extra}'],
        'github': [f'"{technique_id}" detection rule{extra}'],
        'sigma_rules': [f'site:github.com/SigmaHQ/sigma "{technique_id}"'],
        'lolbas_gtfobins': [f'"{short_name}" LOLBAS OR GTFOBins{extra}'],
        'academic': [f'"{short_name}" detection research paper{extra}'],
    }

    queries = category_specific.get(category_name, []) + common

    # For broad techniques, add an enhanced query using ATT&CK description keywords
    if attack_keywords:
        kw_str = ' '.join(attack_keywords[:3])
        queries.append(f'"{short_name}" {kw_str}{extra}')

    return queries


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
    tier1_domains: Optional[List[str]] = None,
    technique_description: str = "",
) -> Dict[str, List[Dict]]:
    """
    Search for sources across multiple categories using a two-tier strategy.

    Tier 1: Individual targeted queries for high-value domains (max 2 results each).
    Tier 2: Batched OR queries for remaining domains (groups of 5).

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
        tier1_domains: List of high-value domains that get individual queries
        technique_description: ATT&CK technique description text (used to
                    extract keywords for broad techniques)

    Returns:
        Dictionary mapping category names to lists of results
    """
    scraper = DuckDuckGoScraper(user_agent=user_agent, verbose=verbose, use_cache=use_cache)
    results = {}
    tier1_set = set(tier1_domains or [])

    extra = f" {extra_terms.strip()}" if extra_terms and extra_terms.strip() else ""

    # For broad techniques, extract keywords from the ATT&CK description
    attack_keywords = []
    if is_broad_technique(technique_name) and technique_description:
        attack_keywords = extract_attack_keywords(technique_description)
        if verbose and attack_keywords:
            print(f"  [broad-technique] Using ATT&CK keywords: {attack_keywords}")

    # Extract short name for tier-1 queries
    short_name = (
        technique_name.split(":")[-1].strip()
        if ":" in technique_name
        else technique_name
    )

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
    tier1_query_count = 0
    tier2_query_count = 0
    filtered_mslearn = 0
    filtered_nonenglish = 0
    filtered_index = 0
    filtered_sigma = 0
    filtered_msft_forum = 0

    for category_name, category_config in categories.items():
        category_results = []
        domains = category_config.get('domains', [])

        # Split domains into tier-1 (individual queries) and tier-2 (batched)
        cat_tier1 = [d for d in domains if d in tier1_set]
        cat_tier2 = [d for d in domains if d not in tier1_set]

        # Add MITRE-cited domains to tier-2 pool
        for mrd in mitre_ref_domains:
            if mrd not in cat_tier1 and mrd not in cat_tier2:
                cat_tier2.append(mrd)

        # --- Tier 1: Individual queries per high-value domain ---
        for domain in cat_tier1:
            query = f'"{short_name}" site:{domain}'
            # Short names (< 4 chars) are too broad; add technique_id for precision
            if len(short_name) < 4:
                query = f'"{short_name}" {technique_id} site:{domain}'
            query += extra

            tier1_results = scraper.search(query, max_results=2)
            for r in tier1_results:
                r['_search_tier'] = 'tier1'
            category_results.extend(tier1_results)
            tier1_query_count += 1

        # --- Tier 2: Batched OR queries (groups of 5, no search_suffix) ---
        queries = _build_queries(technique_id, technique_name, category_name, extra,
                                 attack_keywords=attack_keywords or None)

        for batch_start in range(0, max(len(cat_tier2), 1), 5):
            batch = cat_tier2[batch_start:batch_start + 5]
            if not batch:
                # No tier-2 domains; still run category queries without site filter
                for query in queries[:3]:
                    tier2_results = scraper.search(query, max_results=max_per_category)
                    for r in tier2_results:
                        r['_search_tier'] = 'tier2'
                    category_results.extend(tier2_results)
                    tier2_query_count += 1
                break

            for query in queries[:3]:
                # If the query already has a site: scope (e.g. sigma_rules),
                # run it directly so the built-in scope isn't overridden
                scoped = 'site:' in query
                if scoped:
                    tier2_results = scraper.search(query, max_results=max_per_category)
                else:
                    tier2_results = scraper.search_with_site_filter(
                        query, batch, max_per_category
                    )
                for r in tier2_results:
                    r['_search_tier'] = 'tier2'
                    if scoped:
                        r['_scoped_query'] = True
                category_results.extend(tier2_results)
                tier2_query_count += 1

        # Deduplicate within + across categories, filter landing pages
        # Sort tier-1 results first within the category
        category_results.sort(key=lambda r: 0 if r.get('_search_tier') == 'tier1' else 1)

        seen = set()
        unique_results = []
        for r in category_results:
            url = r['url']
            if url in seen or url in global_seen_urls:
                continue
            if is_generic_landing_page(url):
                if verbose:
                    print(f"  [filter] Skipped generic landing page: {url}")
                filtered_index += 1
                continue
            if _is_offtopic_mslearn(url, technique_name):
                if verbose:
                    print(f"  [filter] Skipped off-topic MS Learn page: {url}")
                filtered_mslearn += 1
                continue
            if _is_non_english_mslearn(url):
                if verbose:
                    print(f"  [filter] Skipped non-English MS Learn page: {url}")
                filtered_nonenglish += 1
                continue
            if category_name == 'sigma_rules' and _is_noise_sigma_result(url):
                if verbose:
                    print(f"  [filter] Skipped noise Sigma result: {url}")
                filtered_sigma += 1
                continue
            if _is_noise_msft_forum(url):
                if verbose:
                    print(f"  [filter] Skipped noise MS forum: {url}")
                filtered_msft_forum += 1
                continue
            seen.add(url)
            unique_results.append(r)

        # Enforce strict_domains: only keep results matching configured domains
        if category_config.get('strict_domains'):
            allowed = set(category_config.get('domains', []))
            strict_filtered = []
            for r in unique_results:
                host = urllib.parse.urlparse(r['url']).netloc.lower().removeprefix('www.')
                if any(host == d or host.endswith('.' + d) for d in allowed):
                    strict_filtered.append(r)
                elif verbose:
                    print(f"  [strict] Removed non-domain result from {category_name}: {r['url']}")
            unique_results = strict_filtered

        global_seen_urls.update(seen)
        results[category_name] = unique_results[:max_per_category]

        if verbose:
            final = unique_results[:max_per_category]
            t1_count = sum(1 for r in final if r.get('_search_tier') == 'tier1')
            t2_count = len(final) - t1_count
            raw_total = len(category_results)
            dedup_note = f" (deduped to {len(final)})" if raw_total != len(final) else ""
            print(f"  {category_name}: {t1_count} tier-1 + {t2_count} tier-2 = {raw_total} results{dedup_note}")

    if verbose:
        print(f"  [search] Total queries: {tier1_query_count} focused + {tier2_query_count} sweep")
        if any([filtered_mslearn, filtered_nonenglish, filtered_index, filtered_sigma, filtered_msft_forum]):
            print(f"  [filter summary] {filtered_mslearn} off-topic MS Learn, "
                  f"{filtered_nonenglish} non-English, {filtered_index} index/landing pages, "
                  f"{filtered_sigma} Sigma noise, {filtered_msft_forum} MS forum noise")

    return results
