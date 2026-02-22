"""
Site metadata fetcher for extracting details from URLs.
"""

from typing import Dict, Optional, List
from bs4 import BeautifulSoup
import requests

from utils import (
    RateLimiter,
    clean_text,
    create_session,
    extract_domain,
    is_valid_url,
    extract_meta_description,
    extract_title,
    extract_date,
)
from utils.content_analysis import analyze_page_content


class SiteFetcher:
    """
    Fetches and extracts metadata from web pages.
    """
    
    def __init__(self, rate_limiter: Optional[RateLimiter] = None, user_agent: str = ""):
        self.rate_limiter = rate_limiter or RateLimiter(delay=2.0)
        self.session = create_session(user_agent or "TRR-Source-Scraper/1.0")
    
    def validate_url(self, url: str) -> bool:
        """Check if a URL is reachable via HEAD request."""
        if not is_valid_url(url):
            return False
        self.rate_limiter.wait()
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            return response.status_code < 400
        except requests.RequestException:
            return False

    def fetch_page_metadata(self, url: str) -> Optional[Dict]:
        """
        Fetch metadata from a single URL.

        Args:
            url: URL to fetch

        Returns:
            Dictionary with metadata or None if failed
        """
        if not is_valid_url(url):
            return None

        self.rate_limiter.wait()

        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
        except requests.RequestException as e:
            return {
                'url': url,
                'domain': extract_domain(url),
                'link_status': 'dead',
            }
        
        # Check content type
        content_type = response.headers.get('Content-Type', '')
        if 'text/html' not in content_type:
            # Not an HTML page, return basic info
            return {
                'url': url,
                'domain': extract_domain(url),
                'title': url.split('/')[-1] or 'Non-HTML Content',
                'description': f"Non-HTML content: {content_type}",
                'date': None,
                'content_type': content_type,
                'link_status': 'ok',
            }

        soup = BeautifulSoup(response.text, 'lxml')

        metadata = {
            'url': url,
            'domain': extract_domain(url),
            'title': extract_title(soup),
            'description': clean_text(extract_meta_description(soup), max_length=300),
            'date': extract_date(soup),
            'content_type': content_type,
            'link_status': 'ok',
        }

        # Content analysis — best-effort, don't fail the whole enrichment
        try:
            analysis = analyze_page_content(soup)
            metadata.update({
                'word_count': analysis['word_count'],
                'depth': analysis['depth'],
                'code_blocks': analysis['code_blocks'],
                'technical_markers': analysis['technical_markers'],
                'content_focus': analysis['content_focus'],
                'marker_summary': analysis['marker_summary'],
            })
        except Exception:
            metadata.update({
                'word_count': 0,
                'depth': 'Unknown',
                'code_blocks': 0,
                'technical_markers': {},
                'content_focus': [],
                'marker_summary': '',
            })

        return metadata
    
    def fetch_multiple(self, urls: List[str]) -> List[Dict]:
        """
        Fetch metadata from multiple URLs.
        
        Args:
            urls: List of URLs to fetch
            
        Returns:
            List of metadata dictionaries
        """
        results = []
        for url in urls:
            metadata = self.fetch_page_metadata(url)
            if metadata:
                results.append(metadata)
        return results


def _is_video_platform_url(url: str) -> bool:
    """Check if a URL is from a video platform (YouTube, Vimeo, etc.)."""
    domain = extract_domain(url)
    return domain in (
        'youtube.com', 'www.youtube.com', 'm.youtube.com', 'youtu.be',
        'vimeo.com', 'www.vimeo.com',
    )


def _clean_video_title(title: str) -> str:
    """
    Clean a potentially garbled video title from DuckDuckGo.

    DDG sometimes concatenates the main video title with sidebar suggestions,
    producing strings like "Main Title DEF CON 24 Another Talk Black Hat..."

    Heuristic: if the title is unreasonably long, truncate at the first
    plausible separator boundary.
    """
    if not title:
        return title

    # Strip common platform suffixes
    for suffix in (' - YouTube', ' - Vimeo', ' | YouTube', ' | Vimeo'):
        if title.endswith(suffix):
            title = title[:-len(suffix)]

    # If still reasonable length, return as-is
    if len(title) <= 120:
        return title.strip()

    # Try to find a natural break: separators that suggest concatenation
    for separator in [' | ', ' - ', ' — ', ' – ']:
        parts = title.split(separator, 2)
        if len(parts) >= 2 and len(parts[0]) > 15:
            return parts[0].strip()

    # Last resort: hard truncate with ellipsis
    return title[:117].rsplit(' ', 1)[0] + '...'


def _needs_enrichment(result: Dict) -> bool:
    """
    Determine whether a search result needs metadata enrichment.

    Heuristics:
    - Always enrich: missing/garbled title, short description, video platforms
    - Never enrich: PDF URLs (cannot extract HTML metadata)
    - Skip if: title is reasonable and description is adequate (>100 chars)
    """
    url = result.get('url', '')
    title = result.get('title', '')
    desc = result.get('description', '')

    # Always enrich video platforms (DDG titles often garbled)
    if _is_video_platform_url(url):
        return True

    # Never enrich PDFs
    if url.lower().endswith('.pdf') or '/pdf/' in url.lower():
        return False

    # Missing title
    if not title or title == 'Untitled':
        return True

    # Garbled title heuristics
    if len(title) > 150 or title.count('|') >= 3:
        return True

    # Missing or short description
    if not desc or len(desc) < 80:
        return True

    # DDG "Missing:" snippet — search engine couldn't find the query term
    if 'Missing:' in desc:
        return True

    # Already has adequate metadata
    if len(title) < 150 and len(desc) > 100:
        return False

    return True


def enrich_search_results(results: List[Dict], user_agent: str = "") -> List[Dict]:
    """
    Enrich search results with page metadata.

    Uses heuristics to skip results that already have good metadata,
    reducing unnecessary HTTP requests and improving runtime.

    Args:
        results: List of search result dictionaries
        user_agent: Custom user agent string

    Returns:
        Enriched list of results with '_enrichment_status' diagnostic field
    """
    fetcher = SiteFetcher(user_agent=user_agent)
    enriched = []

    for result in results:
        url = result.get('url', '')
        if not url:
            continue

        if not _needs_enrichment(result):
            result.setdefault('link_status', 'ok')
            result['_enrichment_status'] = 'skipped'
            enriched.append(result)
            continue

        is_video = _is_video_platform_url(url)
        metadata = fetcher.fetch_page_metadata(url)

        if metadata:
            enriched_result = {**result, **metadata}
            if is_video:
                enriched_result['title'] = _clean_video_title(
                    enriched_result.get('title', '')
                )
            enriched_result['_enrichment_status'] = 'enriched'
            enriched.append(enriched_result)
        else:
            # Even on fetch failure for video URLs, clean the DDG title
            if is_video:
                result['title'] = _clean_video_title(result.get('title', ''))
            result['link_status'] = 'unknown'
            result['_enrichment_status'] = 'failed'
            enriched.append(result)

    return enriched


def validate_search_result_links(results: List[Dict], user_agent: str = "") -> List[Dict]:
    """
    Lightweight link validation via HEAD requests (no page content fetched).

    Useful with --no-enrich --validate-links to check liveness without
    the overhead of full metadata enrichment.
    """
    fetcher = SiteFetcher(user_agent=user_agent)
    for result in results:
        url = result.get('url', '')
        if url:
            result['link_status'] = 'ok' if fetcher.validate_url(url) else 'dead'
    return results