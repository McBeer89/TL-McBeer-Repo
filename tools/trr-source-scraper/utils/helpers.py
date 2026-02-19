"""
Utility helper functions for the TRR Source Scraper.
"""

import time
import re
import json
from pathlib import Path
from urllib.parse import urlparse
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