"""
Content analysis module for extracting structured triage signals from page HTML.

Extracts factual signals (word count, code blocks, technical markers, content
focus tags) from a BeautifulSoup object. Does NOT make quality judgments — the
report renderer and the researcher decide what matters.
"""

import re
from copy import copy
from typing import Dict, List

from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Technical marker patterns
# ---------------------------------------------------------------------------

MARKER_PATTERNS = {
    'event_ids': {
        'windows_event': re.compile(
            r'(?:Event\s*(?:ID)?[\s:]*(\d{4})|Sysmon\s+(?:Event\s+)?(\d{1,2}))',
            re.IGNORECASE,
        ),
    },
    'processes': {
        'exe_names': re.compile(r'\b([a-zA-Z][\w-]{1,30}\.exe)\b'),
    },
    'registry': {
        'reg_paths': re.compile(
            r'\b(HK(?:LM|CU|CR|U|CC|EY_[A-Z_]+)\\[^\s,)]{5,})',
            re.IGNORECASE,
        ),
    },
    'apis': {
        'win_api': re.compile(
            r'\b((?:Nt|Zw|Rtl|Ldr|Crypt|Reg|Virtual|Create|Open|Write|Read|Set|Get|Query|Enum|Load|Map|Queue)'
            r'[A-Z][a-zA-Z]{3,})\b'
        ),
        'dotnet': re.compile(r'\b(System\.[A-Z][\w.]{5,})\b'),
    },
    'network': {
        'ports': re.compile(r'\b(?:port|Port)\s+(\d{2,5})\b'),
        'protocols': re.compile(
            r'\b(RPC|LDAP|Kerberos|NTLM|SMB|WinRM|DCOM|WMI|HTTP|HTTPS|DNS|SSH|RDP)\b',
            re.IGNORECASE,
        ),
    },
    'file_paths': {
        'win_paths': re.compile(
            r'(?:[A-Z]:\\[^\s,)]{5,}|%[A-Za-z]+%\\[^\s,)]{5,})',
        ),
    },
    'detection_syntax': {
        'sigma': re.compile(r'^\s*(title|logsource|detection|condition)\s*:', re.MULTILINE),
        'kql': re.compile(r'\b(SecurityEvent|DeviceProcessEvents|SigninLogs)\s*\|', re.IGNORECASE),
        'spl': re.compile(r'\b(index\s*=|sourcetype\s*=|EventCode\s*=)', re.IGNORECASE),
        'yara': re.compile(r'^\s*rule\s+\w+\s*\{', re.MULTILINE),
    },
}

# Common non-security processes to filter out of the processes category
EXE_NOISE = {
    'setup.exe', 'install.exe', 'update.exe', 'chrome.exe', 'firefox.exe',
    'explorer.exe', 'notepad.exe', 'calc.exe', 'msiexec.exe',
    'consent.exe', 'dllhost.exe',
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_article_text(soup: BeautifulSoup, max_chars: int = 50000) -> str:
    """
    Extract the main article/content text from a page, stripping
    navigation, headers, footers, sidebars, and other boilerplate.

    Returns the cleaned text as a single string (capped at *max_chars*).
    """
    # GitHub wraps file content in <div class="markdown-body">
    github_body = soup.find('div', class_='markdown-body')
    if github_body:
        return github_body.get_text(separator=' ', strip=True)[:max_chars]

    # Remove known non-content elements
    for tag in soup.find_all(['nav', 'header', 'footer', 'aside',
                               'script', 'style', 'noscript']):
        tag.decompose()

    # Remove by common class/id patterns (two-pass to avoid BS4 decompose()
    # poisoning descendants still in the find_all list)
    noise_patterns = [
        'sidebar', 'nav', 'menu', 'footer', 'header', 'comment',
        'advertisement', 'ad-', 'social', 'share', 'related',
        'breadcrumb', 'pagination', 'cookie', 'banner',
    ]
    to_remove = []
    for element in soup.find_all(True):
        classes = ' '.join(element.get('class', []))
        elem_id = element.get('id', '')
        combined = f"{classes} {elem_id}".lower()
        if any(p in combined for p in noise_patterns):
            to_remove.append(element)
    for element in to_remove:
        element.decompose()

    # Try to find the main content container
    main = (
        soup.find('main') or
        soup.find('article') or
        soup.find('div', class_=re.compile(r'(content|post|entry|article)', re.I)) or
        soup.find('div', id=re.compile(r'(content|post|entry|article)', re.I)) or
        soup.body or
        soup
    )

    text = main.get_text(separator=' ', strip=True)
    return text[:max_chars]


def _count_words(text: str) -> int:
    """Count words in extracted article text."""
    return len(text.split())


def _depth_label(word_count: int) -> str:
    """Map word count to a human-readable depth label."""
    if word_count >= 3000:
        return "Long-form"
    elif word_count >= 1500:
        return "Standard"
    elif word_count >= 500:
        return "Brief"
    else:
        return "Minimal"


def _count_code_blocks(soup: BeautifulSoup) -> int:
    """
    Count code blocks in the page.

    Looks for: <pre>, <code> (block-level, not inline), and common
    syntax highlighter wrappers (highlight, codehilite, prism, rouge).
    """
    blocks = set()

    for pre in soup.find_all('pre'):
        blocks.add(id(pre))

    for code in soup.find_all('code'):
        if code.parent and code.parent.name == 'pre':
            continue
        if '\n' in code.get_text():
            blocks.add(id(code))

    highlight_classes = ['highlight', 'codehilite', 'prism', 'rouge',
                         'syntax', 'code-block', 'sourceCode']
    for cls in highlight_classes:
        for elem in soup.find_all(class_=re.compile(cls, re.I)):
            blocks.add(id(elem))

    return len(blocks)


def _extract_technical_markers(text: str) -> Dict[str, List[str]]:
    """
    Scan article text for technical markers grouped by category.

    Returns dict like::

        {
            'event_ids': ['4688', '4624', 'Sysmon 1'],
            'processes': ['w3wp.exe', 'cmd.exe'],
            ...
        }

    Each list is deduplicated and sorted. Only non-empty categories
    are included.
    """
    results = {}

    for category, patterns in MARKER_PATTERNS.items():
        found: set = set()
        for pattern_name, regex in patterns.items():
            for match in regex.finditer(text):
                value = next((g for g in match.groups() if g is not None), match.group(0))
                value = value.strip().rstrip('.,;:')
                if value:
                    found.add(value)

        if found:
            # Deduplicate case-insensitively for certain categories
            if category in ('processes', 'network', 'detection_syntax'):
                seen_lower: Dict[str, str] = {}
                for item in found:
                    key = item.lower()
                    if key not in seen_lower:
                        seen_lower[key] = item
                found = set(seen_lower.values())

            # Filter noise from processes
            if category == 'processes':
                found = {p for p in found if p.lower() not in EXE_NOISE}

            if found:
                results[category] = sorted(found)

    return results


def _classify_content_focus(
    markers: Dict[str, List[str]],
    code_block_count: int,
    text: str,
) -> List[str]:
    """
    Assign content focus tags based on extracted markers.

    Returns a list of tags like ``['Technical', 'Detection', 'Execution']``.
    Multiple tags are normal.
    """
    tags = []

    # Detection: has detection query syntax or multiple event IDs
    has_detection_syntax = bool(markers.get('detection_syntax'))
    has_event_ids = len(markers.get('event_ids', [])) >= 2
    if has_detection_syntax or has_event_ids:
        tags.append('Detection')

    # Execution / Red Team: has code blocks + process names or API calls
    has_code = code_block_count >= 2
    has_exec_markers = bool(markers.get('processes')) or bool(markers.get('apis'))
    if has_code and has_exec_markers:
        tags.append('Execution')

    # Technical Analysis: has multiple marker categories populated
    populated_categories = sum(1 for v in markers.values() if v)
    if populated_categories >= 3:
        tags.append('Technical')

    # Threat Intelligence: mentions threat groups, campaigns, or APT patterns
    apt_pattern = re.compile(
        r'\b(APT\d+|UNC\d+|FIN\d+|(?:Lazarus|Turla|Hafnium|Nobelium|Cozy Bear|Fancy Bear))\b',
        re.IGNORECASE,
    )
    if apt_pattern.search(text):
        tags.append('Threat Intel')

    if not tags:
        tags.append('General')

    return tags


def _build_marker_summary(markers: Dict[str, List[str]]) -> str:
    """Build a compact summary string from technical markers for the report."""
    summary_parts = []
    for cat in ['event_ids', 'processes', 'registry', 'apis', 'network',
                'file_paths', 'detection_syntax']:
        items = markers.get(cat, [])
        if items:
            display = items[:5]
            if len(items) > 5:
                display.append(f"+{len(items) - 5} more")
            summary_parts.append(f"{cat}: {', '.join(display)}")
    return '; '.join(summary_parts) if summary_parts else ''


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_page_content(soup: BeautifulSoup) -> Dict:
    """
    Analyze a page's content and return structured signals.

    Args:
        soup: BeautifulSoup object of the full page HTML.
              NOTE: This function works on a copy — the caller's soup
              is not modified.

    Returns:
        Dict with keys:
            word_count, depth, code_blocks, technical_markers,
            content_focus, marker_summary
    """
    soup_copy = copy(soup)

    text = _extract_article_text(soup_copy)
    word_count = _count_words(text)
    code_blocks = _count_code_blocks(soup)  # original soup for code blocks
    markers = _extract_technical_markers(text)
    focus = _classify_content_focus(markers, code_blocks, text)

    return {
        'word_count': word_count,
        'depth': _depth_label(word_count),
        'code_blocks': code_blocks,
        'technical_markers': markers,
        'content_focus': focus,
        'marker_summary': _build_marker_summary(markers),
    }


def analyze_raw_text(text: str, file_extension: str = "") -> Dict:
    """
    Analyze raw text content (non-HTML) for technical markers.

    Used for GitHub raw file content (YAML, markdown, XML, etc.)
    where we have the file text but no HTML structure.

    Args:
        text: Raw file content as string
        file_extension: File extension (e.g., '.yml', '.md', '.xml')
            Used to determine code block counting strategy.

    Returns:
        Same dict structure as analyze_page_content():
        {word_count, depth, code_blocks, technical_markers,
         content_focus, marker_summary}
    """
    if not text:
        return {
            'word_count': 0,
            'depth': 'Minimal',
            'code_blocks': 0,
            'technical_markers': {},
            'content_focus': [],
            'marker_summary': '',
        }

    # Cap input size (same as HTML path)
    if len(text) > 50000:
        text = text[:50000]

    word_count = len(text.split())
    depth = _depth_label(word_count)

    # Code block counting depends on file type
    ext = file_extension.lower()
    if ext in ('.yml', '.yaml', '.xml', '.toml', '.json', '.conf'):
        # The entire file IS structured config/code — count as 1 block
        code_blocks = 1
    elif ext in ('.md', '.markdown'):
        # Count fenced code blocks in markdown
        code_blocks = len(re.findall(r'^```', text, re.MULTILINE)) // 2
    else:
        code_blocks = 0

    # Technical markers — reuse the same extraction on raw text
    technical_markers = _extract_technical_markers(text)

    # Content focus classification — reuse same logic
    content_focus = _classify_content_focus(technical_markers, code_blocks, text)

    return {
        'word_count': word_count,
        'depth': depth,
        'code_blocks': code_blocks,
        'technical_markers': technical_markers,
        'content_focus': content_focus,
        'marker_summary': _build_marker_summary(technical_markers),
    }
