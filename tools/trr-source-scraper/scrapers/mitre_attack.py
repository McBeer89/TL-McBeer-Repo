"""
MITRE ATT&CK technique page scraper.
"""

import re
from typing import Dict, Optional, List
from bs4 import BeautifulSoup
import requests

from utils import (
    RateLimiter,
    clean_text,
    create_session,
    get_cached,
    set_cached,
)


class MitreAttackScraper:
    """Scrapes technique information from MITRE ATT&CK website."""
    
    BASE_URL = "https://attack.mitre.org"
    TECHNIQUE_URL = "{base}/techniques/{tech_id}"
    SUBTECHNIQUE_URL = "{base}/techniques/{parent}/{sub}"
    
    def __init__(self, rate_limiter: Optional[RateLimiter] = None, user_agent: str = ""):
        self.rate_limiter = rate_limiter or RateLimiter(delay=2.0)
        self.session = create_session(user_agent or "TRR-Source-Scraper/1.0")
    
    def _parse_technique_id(self, technique_id: str) -> tuple:
        """
        Parse technique ID into parent and sub-technique components.
        
        Args:
            technique_id: Technique ID like T1003 or T1003.006
            
        Returns:
            tuple: (parent_id, sub_id or None)
        """
        technique_id = technique_id.strip().upper()
        if not technique_id.startswith('T'):
            technique_id = 'T' + technique_id
        
        if '.' in technique_id:
            parts = technique_id.split('.')
            parent = parts[0]
            sub = parts[1]
            return parent, sub
        return technique_id, None
    
    def _build_url(self, technique_id: str) -> str:
        """Build the MITRE ATT&CK URL for a technique."""
        parent, sub = self._parse_technique_id(technique_id)
        
        if sub:
            return self.SUBTECHNIQUE_URL.format(
                base=self.BASE_URL,
                parent=parent,
                sub=sub
            )
        return self.TECHNIQUE_URL.format(
            base=self.BASE_URL,
            tech_id=parent
        )
    
    def fetch_technique(self, technique_id: str) -> Optional[Dict]:
        """
        Fetch technique information from MITRE ATT&CK.

        Results are cached locally for 7 days to avoid redundant network calls.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1003.006)

        Returns:
            Dictionary with technique information or None if not found
        """
        cache_key = f"mitre_{technique_id.upper()}"
        cached = get_cached(cache_key)
        if cached is not None:
            return cached

        self.rate_limiter.wait()
        url = self._build_url(technique_id)

        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Error fetching MITRE ATT&CK page: {e}")
            return None

        soup = BeautifulSoup(response.text, 'lxml')

        result = {
            'id': technique_id.upper(),
            'url': url,
            'name': self._extract_name(soup),
            'description': self._extract_description(soup),
            'tactics': self._extract_tactics(soup),
            'platforms': self._extract_platforms(soup),
            'data_sources': self._extract_data_sources(soup),
            'defense_bypassed': self._extract_defense_bypassed(soup),
            'permissions_required': self._extract_permissions_required(soup),
            'effective_permissions': self._extract_effective_permissions(soup),
            'references': self._extract_references(soup),
        }

        set_cached(cache_key, result)
        return result
    
    def _extract_name(self, soup: BeautifulSoup) -> str:
        """Extract technique name."""
        # Try h1 tag
        h1 = soup.find('h1')
        if h1:
            return clean_text(h1.get_text())
        return "Unknown"
    
    def _extract_description(self, soup: BeautifulSoup) -> str:
        """Extract technique description."""
        # Current ATT&CK site uses description-body div
        desc_div = soup.find('div', class_='description-body')
        if desc_div:
            paragraphs = desc_div.find_all('p')
            if paragraphs:
                return clean_text(' '.join(p.get_text() for p in paragraphs))
            return clean_text(desc_div.get_text())

        # Older fallback
        desc_div = soup.find('div', class_='description')
        if desc_div:
            return clean_text(desc_div.get_text())

        # Last resort: first long paragraph
        for p in soup.find_all('p'):
            text = p.get_text(strip=True)
            if len(text) > 100:
                return clean_text(text)

        return ""
    
    def _extract_tactics(self, soup: BeautifulSoup) -> List[str]:
        """Extract associated tactics."""
        tactics = []

        # Current ATT&CK site: card-data divs with card-title spans
        for card_data in soup.find_all('div', class_='card-data'):
            label = card_data.find('span', class_='h5')
            if label and 'tactic' in label.get_text().lower():
                for a in card_data.find_all('a'):
                    href = a.get('href', '')
                    if '/tactics/' in href:
                        text = clean_text(a.get_text())
                        if text:
                            tactics.append(text)

        # Fallback: any link to a tactics page
        if not tactics:
            for card in soup.find_all('div', class_='card-body'):
                for a in card.find_all('a'):
                    href = a.get('href', '')
                    if '/tactics/' in href:
                        text = clean_text(a.get_text())
                        if text and text not in tactics:
                            tactics.append(text)

        return list(dict.fromkeys(tactics))  # deduplicate, preserve order
    
    def _extract_platforms(self, soup: BeautifulSoup) -> List[str]:
        """Extract affected platforms."""
        platforms = []

        # Current ATT&CK site: card-data divs with "Platforms" label
        for card_data in soup.find_all('div', class_='card-data'):
            label = card_data.find('span', class_='h5')
            if label and 'platform' in label.get_text().lower():
                # Platforms are plain text after the label, often separated by commas
                text = card_data.get_text(separator=' ')
                # Remove the label text itself
                label_text = label.get_text()
                text = text.replace(label_text, '').strip().strip(':').strip()
                # Strip non-ASCII characters (page uses Unicode icons like ⓘ)
                text = text.encode('ascii', 'ignore').decode('ascii')
                for part in re.split(r'[,\n]', text):
                    part = clean_text(part)
                    if part:
                        platforms.append(part)

        # Fallback: hardcoded list scan
        if not platforms:
            known_platforms = ['Windows', 'Linux', 'macOS', 'Azure', 'AWS', 'GCP',
                               'SaaS', 'Office 365', 'Network', 'Containers', 'IaaS',
                               'PRE', 'Google Workspace']
            for card in soup.find_all('div', class_='card-body'):
                text = card.get_text()
                if 'Platform' in text:
                    for platform in known_platforms:
                        if platform in text:
                            platforms.append(platform)

        return list(dict.fromkeys(platforms))
    
    def _extract_data_sources(self, soup: BeautifulSoup) -> List[str]:
        """Extract data sources for detection."""
        data_sources = []

        # Current ATT&CK site: card-data div with "Data Sources" label
        for card_data in soup.find_all('div', class_='card-data'):
            label = card_data.find('span', class_='h5')
            if label and 'data source' in label.get_text().lower():
                for a in card_data.find_all('a'):
                    text = clean_text(a.get_text())
                    if text:
                        data_sources.append(text)
                # Also extract plain text if no links
                if not data_sources:
                    raw = card_data.get_text(separator=',').replace(label.get_text(), '')
                    for part in raw.split(','):
                        part = clean_text(part)
                        if part:
                            data_sources.append(part)

        # Fallback: heading-based search
        if not data_sources:
            for heading in soup.find_all(['h2', 'h3']):
                if 'data source' in heading.get_text().lower():
                    sibling = heading.find_next_sibling()
                    while sibling and sibling.name in ['p', 'ul', 'div']:
                        for a in sibling.find_all('a'):
                            text = clean_text(a.get_text())
                            if text:
                                data_sources.append(text)
                        sibling = sibling.find_next_sibling()

        return list(dict.fromkeys(data_sources))
    
    def _extract_defense_bypassed(self, soup: BeautifulSoup) -> List[str]:
        """Extract defenses bypassed by this technique."""
        defenses = []
        
        # Look in card data for "Defenses Bypassed"
        for card in soup.find_all('div', class_='card-body'):
            text = card.get_text()
            if 'Defenses Bypassed' in text or 'Defense Bypassed' in text:
                # Find links in this section
                for a in card.find_all('a'):
                    text = clean_text(a.get_text())
                    if text and text not in ['Defenses Bypassed', 'Defense Bypassed']:
                        defenses.append(text)
        
        return defenses
    
    def _extract_permissions_required(self, soup: BeautifulSoup) -> List[str]:
        """Extract permissions required for this technique."""
        permissions = []
        known_perms = ['User', 'Administrator', 'SYSTEM', 'root', 'rooted']
        
        for card in soup.find_all('div', class_='card-body'):
            text = card.get_text()
            if 'Permission' in text:
                for perm in known_perms:
                    if perm in text:
                        permissions.append(perm)
        
        return list(set(permissions))
    
    def _extract_effective_permissions(self, soup: BeautifulSoup) -> List[str]:
        """Extract effective permissions gained."""
        permissions = []
        known_perms = ['User', 'Administrator', 'SYSTEM', 'root', 'rooted']

        for card_data in soup.find_all('div', class_='card-data'):
            label = card_data.find('span', class_='h5')
            if label and 'effective permission' in label.get_text().lower():
                text = card_data.get_text()
                for perm in known_perms:
                    if perm in text:
                        permissions.append(perm)

        # Fallback: scan card-body
        if not permissions:
            for card in soup.find_all('div', class_='card-body'):
                text = card.get_text()
                if 'Effective Permission' in text:
                    for perm in known_perms:
                        if perm in text:
                            permissions.append(perm)

        return list(dict.fromkeys(permissions))
    
    def _extract_references(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract external references."""
        references = []
        
        # Look for references section
        for heading in soup.find_all(['h2', 'h3']):
            if 'reference' in heading.get_text().lower():
                # Find the table or list following this heading
                sibling = heading.find_next_sibling()
                while sibling:
                    if sibling.name == 'table':
                        for row in sibling.find_all('tr'):
                            cells = row.find_all('td')
                            if len(cells) >= 2:
                                link = cells[1].find('a')
                                if link:
                                    references.append({
                                        'name': clean_text(link.get_text()),
                                        'url': link.get('href', '')
                                    })
                    elif sibling.name in ['ul', 'ol']:
                        for li in sibling.find_all('li'):
                            link = li.find('a')
                            if link:
                                references.append({
                                    'name': clean_text(link.get_text()),
                                    'url': link.get('href', '')
                                })
                    sibling = sibling.find_next_sibling()
                break
        
        return references


def fetch_mitre_technique(technique_id: str, user_agent: str = "") -> Optional[Dict]:
    """
    Convenience function to fetch MITRE ATT&CK technique information.
    
    Args:
        technique_id: MITRE ATT&CK technique ID
        user_agent: Custom user agent string
        
    Returns:
        Dictionary with technique info or None
    """
    scraper = MitreAttackScraper(user_agent=user_agent)
    return scraper.fetch_technique(technique_id)