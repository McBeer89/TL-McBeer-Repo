"""
Utility helper functions for the TRR Source Scraper.
"""

import time
import re
import json
from pathlib import Path
from urllib.parse import urlparse, unquote
from datetime import datetime
from typing import Optional, Dict, List, Any
import requests
from bs4 import BeautifulSoup


class RateLimiter:
    """Simple rate limiter to control request frequency."""
    
    def __init__(self, delay: float = 2.0):
        self.delay = delay
        self.last_request_time = 0
    
    def wait(self):
        """Wait for the required delay since last request."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request_time = time.time()


class ConfigManager:
    """Manages loading and accessing configuration."""
    
    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "sources.json"
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default config if file not found
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Return default configuration."""
        return {
            "trusted_sources": {},
            "search_settings": {
                "max_results_per_category": 10,
                "delay_between_requests": 2,
                "timeout": 15,
                "max_retries": 3,
                "user_agent": "TRR-Source-Scraper/1.0 (Educational Research Tool)"
            },
            "output_settings": {
                "default_output_dir": "output",
                "include_excerpts": True,
                "excerpt_length": 200,
                "include_dates": True
            }
        }
    
    @property
    def search_settings(self) -> Dict:
        return self.config.get("search_settings", {})
    
    @property
    def output_settings(self) -> Dict:
        return self.config.get("output_settings", {})
    
    @property
    def trusted_sources(self) -> Dict:
        return self.config.get("trusted_sources", {})

    @property
    def trr_repository(self) -> Dict:
        return self.config.get("trr_repository", {})

    @property
    def tier1_domains(self) -> List[str]:
        return self.config.get("tier1_domains", [])


def validate_technique_id(technique_id: str) -> bool:
    """
    Validate if a string is a valid MITRE ATT&CK technique ID.
    
    Valid formats:
    - T1003
    - T1003.006
    """
    pattern = r'^T\d{4}(\.\d{3})?$'
    return bool(re.match(pattern, technique_id))


def normalize_technique_id(technique_id: str) -> str:
    """
    Normalize technique ID format.
    
    Accepts formats like:
    - T1003
    - T1003.006
    - t1003.006 (converts to uppercase)
    """
    technique_id = technique_id.strip().upper()
    if not technique_id.startswith('T'):
        technique_id = 'T' + technique_id
    return technique_id


_BLOG_INDEX_PATTERNS = [
    '/author/', '/tag/', '/category/', '/page/', '/topics/', '/archives/',
]


def is_generic_landing_page(url: str) -> bool:
    """
    Return True if the URL points to a generic landing/index page
    rather than a specific content page.
    """
    try:
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')

        # Explicit blocklist of known generic paths
        generic_paths = {
            '', '/en-us', '/en-us/docs', '/en-us/previous-versions',
            '/html/archives.html', '/docs', '/blog', '/resources',
        }
        if path.lower() in generic_paths:
            return True

        # Paths with 1 or fewer segments and no query are almost always landing pages
        segments = [s for s in path.split('/') if s]
        if len(segments) <= 1 and not parsed.query:
            return True

        # Blog author/tag/index pages are listings, not content
        path_lower = path.lower()
        for pattern in _BLOG_INDEX_PATTERNS:
            if pattern in path_lower:
                return True

        return False
    except Exception:
        return False


def compute_relevance_score(
    result: dict,
    technique_id: str,
    technique_name: str,
    mitre_ref_domains: set = None,
    trusted_sources: dict = None,
) -> float:
    """
    Score a search result 0.0-1.0 based on how likely it is to contain
    substantive content about the given ATT&CK technique.

    Signals (max 1.0):
      Title:          technique ID (+0.20), technique name (+0.15)
      Description:    technique ID (+0.10), technique name (+0.05)
      URL path:       technique ID (+0.05)
      MITRE refs:     domain cited by MITRE (+0.10)
      Trust tier:     high-priority domain (+0.10), medium-priority (+0.05)
      Content depth:  Long-form (+0.10), Standard (+0.05)
      Code blocks:    >=2 code blocks (+0.05)
      Tech markers:   >=3 categories (+0.10), 1-2 categories (+0.05)
    """
    score = 0.0
    short_name = (
        technique_name.split(":")[-1].strip().lower()
        if ":" in technique_name
        else technique_name.lower()
    )
    tid_lower = technique_id.lower()

    title = (result.get('title') or '').lower()
    desc = (result.get('description') or '').lower()
    url = (result.get('url') or '').lower()
    domain = (result.get('domain') or '').lower()

    # Title signals
    if tid_lower in title:
        score += 0.20
    if short_name and short_name in title:
        score += 0.15

    # Description / snippet signals
    if tid_lower in desc:
        score += 0.10
    if short_name and short_name in desc:
        score += 0.05

    # URL path contains technique ID
    tid_in_path = tid_lower.replace('.', '/') if '.' in tid_lower else tid_lower
    if tid_in_path in url or tid_lower in url:
        score += 0.05

    # Domain appears in MITRE's own references
    if mitre_ref_domains and domain in mitre_ref_domains:
        score += 0.10

    # Domain trust tier
    if trusted_sources and domain:
        for cat_config in trusted_sources.values():
            if domain in cat_config.get('domains', []):
                priority = cat_config.get('priority', '')
                if priority == 'high':
                    score += 0.10
                elif priority == 'medium':
                    score += 0.05
                break

    # --- Content analysis signals (only present after enrichment) ---

    depth = result.get('depth', '')
    if depth == 'Long-form':
        score += 0.10
    elif depth == 'Standard':
        score += 0.05

    code_blocks = result.get('code_blocks', 0)
    if code_blocks >= 2:
        score += 0.05

    markers = result.get('technical_markers', {})
    populated_categories = sum(1 for v in markers.values() if v)
    if populated_categories >= 3:
        score += 0.10
    elif populated_categories >= 1:
        score += 0.05

    return min(score, 1.0)


def extract_domain(url: str) -> str:
    """Extract the domain from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def is_valid_url(url: str) -> bool:
    """Check if a URL is valid."""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ('http', 'https'), parsed.netloc])
    except Exception:
        return False


def clean_text(text: str, max_length: Optional[int] = None) -> str:
    """Clean and truncate text."""
    # Remove extra whitespace
    text = ' '.join(text.split())
    # Remove any non-printable characters
    text = ''.join(char for char in text if char.isprintable())
    # Truncate if needed
    if max_length and len(text) > max_length:
        text = text[:max_length - 3] + "..."
    return text.strip()


def extract_meta_description(soup: BeautifulSoup) -> str:
    """Extract meta description from a BeautifulSoup object."""
    # Try standard meta description
    meta = soup.find('meta', attrs={'name': 'description'})
    if meta and meta.get('content'):
        return meta['content']
    
    # Try Open Graph description
    meta = soup.find('meta', attrs={'property': 'og:description'})
    if meta and meta.get('content'):
        return meta['content']
    
    # Try Twitter description
    meta = soup.find('meta', attrs={'name': 'twitter:description'})
    if meta and meta.get('content'):
        return meta['content']
    
    # Fall back to first paragraph
    paragraph = soup.find('p')
    if paragraph:
        return paragraph.get_text(strip=True)
    
    return ""


def extract_title(soup: BeautifulSoup) -> str:
    """Extract title from a BeautifulSoup object."""
    # Try Open Graph title
    meta = soup.find('meta', attrs={'property': 'og:title'})
    if meta and meta.get('content'):
        return meta['content']
    
    # Try standard title tag
    title_tag = soup.find('title')
    if title_tag:
        return title_tag.get_text(strip=True)
    
    # Try h1
    h1 = soup.find('h1')
    if h1:
        return h1.get_text(strip=True)
    
    return "Untitled"


def extract_date(soup: BeautifulSoup) -> Optional[str]:
    """Extract publication date from a BeautifulSoup object."""
    # Try meta tags
    date_meta = soup.find('meta', attrs={'property': 'article:published_time'})
    if date_meta and date_meta.get('content'):
        return date_meta['content'][:10]  # Just the date part
    
    date_meta = soup.find('meta', attrs={'name': 'date'})
    if date_meta and date_meta.get('content'):
        return date_meta['content'][:10]
    
    # Try time element
    time_elem = soup.find('time')
    if time_elem and time_elem.get('datetime'):
        return time_elem['datetime'][:10]
    
    # Try common date patterns in text
    date_patterns = [
        r'(\d{4}-\d{2}-\d{2})',
        r'(\d{2}/\d{2}/\d{4})',
        r'((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4})'
    ]
    
    # Search in common date-containing elements
    for selector in ['span', 'div', 'p']:
        for elem in soup.find_all(selector, limit=20):
            text = elem.get_text()
            for pattern in date_patterns:
                match = re.search(pattern, text)
                if match:
                    return match.group(1)
    
    return None


def create_session(user_agent: str) -> requests.Session:
    """Create a requests session with proper headers."""
    session = requests.Session()
    session.headers.update({
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    })
    return session


def get_category_for_domain(domain: str, trusted_sources: Dict) -> tuple:
    """
    Determine the category and priority for a given domain.
    
    Returns:
        tuple: (category_name, priority) or (None, None) if not categorized
    """
    domain_lower = domain.lower()
    
    for category, data in trusted_sources.items():
        domains = data.get('domains', [])
        for trusted_domain in domains:
            if trusted_domain.lower() in domain_lower or domain_lower in trusted_domain.lower():
                return category, data.get('priority', 'medium')
    
    return None, None


def format_date(date_str: Optional[str]) -> str:
    """Format a date string for display."""
    if not date_str:
        return "Unknown"

    try:
        # Try to parse various date formats
        for fmt in ['%Y-%m-%d', '%m/%d/%Y', '%B %d, %Y', '%B %d %Y']:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.strftime('%Y-%m-%d')
            except ValueError:
                continue
        return date_str[:10] if len(date_str) >= 10 else date_str
    except Exception:
        return "Unknown"


# ---------------------------------------------------------------------------
# Search result deduplication
# ---------------------------------------------------------------------------

# Preferred GitHub orgs — earlier entries have higher priority
_PREFERRED_GITHUB_ORGS = [
    'redcanaryco', 'sigmahq', 'mitre-attack', 'mitre',
    'elastic', 'splunk', 'microsoft', 'neo23x0',
]


def deduplicate_results(
    results: Dict[str, List[Dict]],
    verbose: bool = False,
) -> Dict[str, List[Dict]]:
    """
    Remove duplicate search results across all categories.

    Handles:
      - GitHub forks: same file path in different repos
      - Academic papers: same paper in PDF vs HTML format (arXiv, IEEE)
      - Cross-platform title duplicates: very similar titles

    Args:
        results: Dict mapping category name to list of result dicts
        verbose: Log removed duplicates

    Returns:
        Deduplicated results dict (same structure)
    """
    from difflib import SequenceMatcher

    removed_urls: set = set()

    # -- helpers ----------------------------------------------------------

    def _github_file_key(url: str) -> Optional[str]:
        """Extract the file path portion from a GitHub URL, ignoring org/repo."""
        # Strip anchors and query strings, then decode percent-encoded chars
        clean_url = unquote(url.split('#')[0].split('?')[0])
        # Standard blob/tree URLs
        m = re.search(r'github\.com/[^/]+/[^/]+/(?:blob|tree)/[^/]+/(.+)', clean_url)
        if m:
            return m.group(1)
        # raw.githubusercontent.com URLs
        m = re.search(r'raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/(.+)', clean_url)
        if m:
            return m.group(1)
        return None

    def _github_org(url: str) -> str:
        m = re.search(r'github\.com/([^/]+)/', url)
        return m.group(1).lower() if m else ''

    def _github_org_priority(org: str) -> int:
        try:
            return _PREFERRED_GITHUB_ORGS.index(org)
        except ValueError:
            return len(_PREFERRED_GITHUB_ORGS)

    def _arxiv_id(url: str) -> Optional[str]:
        m = re.search(r'arxiv\.org/(?:abs|pdf|html)/(\d+\.\d+)', url)
        return m.group(1) if m else None

    def _ieee_id(url: str) -> Optional[str]:
        m = re.search(
            r'ieeexplore\.ieee\.org/(?:document|iel\d+/[^/]+/[^/]+)/(\d+)', url
        )
        return m.group(1) if m else None

    def _normalize_title(title: str) -> str:
        return re.sub(r'[^a-z0-9\s]', '', title.lower()).strip()

    # -- flatten ----------------------------------------------------------

    all_items = []
    for category, cat_results in results.items():
        for r in cat_results:
            all_items.append((category, r))

    # -- Pass 1: GitHub fork dedup ----------------------------------------

    github_file_map: Dict[str, tuple] = {}  # file_path -> (category, result)

    for category, r in all_items:
        url = r.get('url', '')
        fkey = _github_file_key(url)
        if not fkey:
            continue
        if fkey in github_file_map:
            existing_cat, existing_r = github_file_map[fkey]
            existing_org = _github_org(existing_r.get('url', ''))
            new_org = _github_org(url)
            if _github_org_priority(new_org) < _github_org_priority(existing_org):
                removed_urls.add(existing_r['url'])
                github_file_map[fkey] = (category, r)
                if verbose:
                    print(f"  [dedup] Removed fork: {existing_r['url']} (kept {url})")
            else:
                removed_urls.add(url)
                if verbose:
                    print(f"  [dedup] Removed fork: {url} (kept {existing_r['url']})")
        else:
            github_file_map[fkey] = (category, r)

    # -- Pass 1b: GitHub fork dedup by technique directory -----------------
    # Catches forks where the same technique directory exists but with
    # different file names/extensions (e.g., T1505.003.md vs .yaml)

    def _github_technique_dir_key(url: str) -> Optional[str]:
        """Return the technique-directory portion of a GitHub file path."""
        fkey = _github_file_key(url)
        if not fkey:
            return None
        m = re.search(r'((?:^|.*)T\d{4}(?:\.\d{3})?)(?:/|$)', fkey)
        if m:
            return m.group(1)
        return None

    github_dir_map: Dict[str, tuple] = {}

    for category, r in all_items:
        url = r.get('url', '')
        if url in removed_urls:
            continue
        dkey = _github_technique_dir_key(url)
        if not dkey:
            continue
        if dkey in github_dir_map:
            existing_cat, existing_r = github_dir_map[dkey]
            existing_org = _github_org(existing_r.get('url', ''))
            new_org = _github_org(url)
            # Only dedup across different orgs (same org may have
            # legitimately different files in the same technique dir)
            if new_org == existing_org:
                continue
            if _github_org_priority(new_org) < _github_org_priority(existing_org):
                removed_urls.add(existing_r['url'])
                github_dir_map[dkey] = (category, r)
                if verbose:
                    print(f"  [dedup] Removed fork (dir match): {existing_r['url']} (kept {url})")
            else:
                removed_urls.add(url)
                if verbose:
                    print(f"  [dedup] Removed fork (dir match): {url} (kept {existing_r['url']})")
        else:
            github_dir_map[dkey] = (category, r)

    # -- Pass 2: Academic paper dedup (arXiv + IEEE) ----------------------

    arxiv_map: Dict[str, tuple] = {}
    ieee_map: Dict[str, tuple] = {}

    for category, r in all_items:
        url = r.get('url', '')
        if url in removed_urls:
            continue

        aid = _arxiv_id(url)
        if aid:
            if aid in arxiv_map:
                existing_cat, existing_r = arxiv_map[aid]
                if r.get('relevance_score', 0) > existing_r.get('relevance_score', 0):
                    removed_urls.add(existing_r['url'])
                    arxiv_map[aid] = (category, r)
                    if verbose:
                        print(f"  [dedup] Removed arXiv duplicate: {existing_r['url']}")
                else:
                    removed_urls.add(url)
                    if verbose:
                        print(f"  [dedup] Removed arXiv duplicate: {url}")
            else:
                arxiv_map[aid] = (category, r)
            continue

        iid = _ieee_id(url)
        if iid:
            if iid in ieee_map:
                existing_cat, existing_r = ieee_map[iid]
                if r.get('relevance_score', 0) > existing_r.get('relevance_score', 0):
                    removed_urls.add(existing_r['url'])
                    ieee_map[iid] = (category, r)
                    if verbose:
                        print(f"  [dedup] Removed IEEE duplicate: {existing_r['url']}")
                else:
                    removed_urls.add(url)
                    if verbose:
                        print(f"  [dedup] Removed IEEE duplicate: {url}")
            else:
                ieee_map[iid] = (category, r)

    # -- Pass 3: Cross-platform title dedup (>90% similarity) ------------

    seen_titles: list = []  # list of (normalized_title, url, score)

    for _category, r in all_items:
        url = r.get('url', '')
        if url in removed_urls:
            continue
        title = _normalize_title(r.get('title', ''))
        if len(title) < 10:
            continue
        for existing_title, existing_url, existing_score in seen_titles:
            ratio = SequenceMatcher(None, title, existing_title).ratio()
            if ratio > 0.90:
                if r.get('relevance_score', 0) > existing_score:
                    removed_urls.add(existing_url)
                else:
                    removed_urls.add(url)
                if verbose:
                    print(f"  [dedup] Removed title duplicate: {url} (ratio={ratio:.2f})")
                break
        else:
            seen_titles.append((title, url, r.get('relevance_score', 0)))

    # -- Rebuild ----------------------------------------------------------

    deduped: Dict[str, List[Dict]] = {}
    for category, cat_results in results.items():
        deduped[category] = [
            r for r in cat_results if r.get('url', '') not in removed_urls
        ]

    return deduped