#!/usr/bin/env python3
"""
TRR Source Scraper - Main Entry Point

A tool for scraping the web to find potential research sources
for MITRE ATT&CK techniques when creating Technique Research Reports.

Usage:
    python trr_scraper.py T1003.006
    python trr_scraper.py T1003.006 --name "DCSync"
    python trr_scraper.py T1003.006 --output ./research/
    python trr_scraper.py T1003.006 --no-enrich           # fast scan
    python trr_scraper.py T1003.006 --no-ddg              # MITRE + ART only
    python trr_scraper.py T1003.006 --extra-terms mimikatz
    python trr_scraper.py T1003.006 --json                # also write JSON
    python trr_scraper.py T1003.006 --quiet               # minimal output
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import re as _re

# Ensure UTF-8 output on Windows to handle Unicode characters from web pages
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass

from scrapers import (
    fetch_mitre_technique,
    search_technique_sources,
    scan_for_existing_trrs,
    enrich_search_results,
    validate_search_result_links,
    fetch_atomic_tests,
)
from utils import (
    ConfigManager,
    RateLimiter,
    validate_technique_id,
    normalize_technique_id,
    clean_text,
    compute_relevance_score,
    deduplicate_results,
    extract_domain,
    format_date,
    get_category_for_domain,
    get_cache_stats,
    reset_cache_stats,
)
from utils.helpers import extract_attack_keywords, is_broad_technique

# v1.6: Query intelligence (broad technique keywords, noise penalties),
#        data quality (analysis confidence, cache stats, enrichment status),
#        report enhancements (coverage gaps, research checklist export),
#        optional Playwright integration for JS-rendered sites.
REPORT_VERSION = "1.6"

DEFAULT_TECHNIQUE_INFO = {
    "id": "",
    "url": "",
    "name": "",
    "description": "",
    "tactics": [],
    "platforms": [],
    "data_sources": [],
    "defense_bypassed": [],
    "permissions_required": [],
    "effective_permissions": [],
    "references": [],
}

# Platform keywords for --platform filtering (checked case-insensitively)
PLATFORM_KEYWORDS = {
    'windows': ['windows', 'powershell', 'cmd.exe', 'iis', 'registry',
                'svchost', '.exe', 'ntfs', 'mshta', 'wmi', 'sysmon',
                'active directory', 'kerberos', '.net framework'],
    'linux': ['linux', 'apache', 'nginx', 'ubuntu', 'centos', 'bash',
              '/etc/', 'systemd', 'cron', 'auditd', 'redhat', 'debian'],
    'macos': ['macos', 'mac os', 'darwin', 'launchd', 'dylib', 'osascript',
              'applescript', 'plist', 'mach-o'],
    'azure': ['azure', 'entra', 'saas', 'cloud', 'arm template',
              'subscription', 'tenant', 'microsoft 365', 'office 365'],
    'ad': ['active directory', 'ldap', 'kerberos', 'domain controller',
           'ntds', 'dcsync', 'krbtgt', 'spn', 'group policy'],
}


def _is_off_platform(result: Dict, target_platform: str) -> Optional[str]:
    """
    Check if a search result appears to target a different platform.

    Returns the detected off-platform name if the result matches a *different*
    platform's keywords but NOT the target platform, else None.
    """
    if not target_platform:
        return None

    text = ' '.join([
        (result.get('title') or ''),
        (result.get('description') or ''),
        (result.get('url') or ''),
    ]).lower()

    target_kws = PLATFORM_KEYWORDS.get(target_platform, [])
    matches_target = any(kw in text for kw in target_kws)

    # Check if it matches a different platform
    for plat, kws in PLATFORM_KEYWORDS.items():
        if plat == target_platform:
            continue
        if any(kw in text for kw in kws):
            # Only flag as off-platform if it does NOT also match the target
            if not matches_target:
                return plat

    return None


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Scrape the web for research sources on MITRE ATT&CK techniques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python trr_scraper.py T1003.006
    python trr_scraper.py T1003.006 --name "DCSync"
    python trr_scraper.py T1003.006 --output ./research/ --max-per-category 5
    python trr_scraper.py T1003.006 --no-enrich           # fast, no metadata fetch
    python trr_scraper.py T1003.006 --no-ddg              # skip web search entirely
    python trr_scraper.py T1003.006 --extra-terms mimikatz # add terms to every query
    python trr_scraper.py T1003.006 --json                # also write JSON output
    python trr_scraper.py T1003.006 --quiet               # suppress progress output
    python trr_scraper.py T1003.006 --trr-repo tired-labs/techniques  # override TRR repo
    python trr_scraper.py T1003.006 --min-score 0.5       # only Strong Match results
    python trr_scraper.py T1003.006 --min-score 0.0       # include all results (no filter)
        """
    )

    parser.add_argument(
        "technique_id",
        help="MITRE ATT&CK technique ID (e.g., T1003.006 or T1003)"
    )

    parser.add_argument(
        "--name", "-n",
        help="Technique name for better search results (e.g., 'DCSync')"
    )

    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output directory for the markdown report (default: ./output/)"
    )

    parser.add_argument(
        "--max-per-category", "-m",
        type=int,
        help="Maximum number of results per category (default: from config)"
    )

    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip fetching page metadata (faster but less detail). Saves as _quick_scan.md"
    )

    parser.add_argument(
        "--no-ddg",
        action="store_true",
        help="Skip DuckDuckGo search entirely (MITRE + Atomic Red Team data only)"
    )

    parser.add_argument(
        "--extra-terms", "-e",
        dest="extra_terms",
        default="",
        help="Additional search terms appended to every query (e.g., 'mimikatz lsass')"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Also write a JSON file with all raw collected data alongside the markdown"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress and diagnostic information"
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all output except the final 'Saved to:' line"
    )

    parser.add_argument(
        "--trr-repo",
        dest="trr_repo",
        default="",
        help="GitHub repo for TRR/DDM lookup (e.g., 'tired-labs/techniques'). Overrides config."
    )

    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass the search result cache and force fresh DuckDuckGo queries"
    )

    parser.add_argument(
        "--validate-links",
        action="store_true",
        help="Check link liveness via HEAD requests (works with --no-enrich for fast validation)"
    )

    parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        metavar="THRESHOLD",
        help=(
            "Minimum relevance score (0.0–1.0) to include a result. "
            "Default: value from config (currently 0.25). "
            "Use 0.0 to include all results regardless of score."
        ),
    )

    parser.add_argument(
        "--trr-id",
        dest="trr_id",
        default="",
        metavar="TRR_ID",
        help="TRR identifier (e.g., 'TRR0042') for the output filename and report header",
    )

    parser.add_argument(
        "--platform", "-p",
        choices=["windows", "linux", "macos", "azure", "ad"],
        default="",
        help="Target platform — moves off-platform results to end of report",
    )

    parser.add_argument(
        "--checklist",
        action="store_true",
        help="Generate a markdown research checklist alongside the report",
    )

    parser.add_argument(
        "--no-playwright",
        action="store_true",
        help="Skip Playwright rendering even for JS-heavy sites",
    )

    return parser.parse_args()


def print_progress(message: str, verbose: bool = False, quiet: bool = False, always: bool = False):
    """
    Print a progress message.

    Step headers (always=True) always print unless quiet mode is set.
    Detail messages (verbose=True) only print when --verbose is active.
    quiet=True suppresses everything except lines explicitly forced with always=True
    and the final save confirmation.
    """
    if quiet:
        return
    timestamp = datetime.now().strftime("%H:%M:%S")
    if always or verbose:
        print(f"[{timestamp}] {message}")


def _filter_ds_codes(data_sources: List[str]) -> List[str]:
    """Remove DS####-style ATT&CK identifiers from a data sources list."""
    return [ds for ds in data_sources if not _re.match(r'^DS\d{4}$', ds.strip())]


def _build_ddm_hints(data_sources: List[str]) -> List[Tuple[str, List[str]]]:
    """
    Map known ATT&CK data source names to suggested DDM operations.

    Returns a list of (operation_name, [contributing_source_names]) tuples.
    DS#### codes are filtered out before matching.
    """
    clean_sources = _filter_ds_codes(data_sources)
    ds_lower = ' '.join(clean_sources).lower()

    mappings = [
        ('process', 'Create/Terminate Process'),
        ('command', 'Execute Command'),
        ('network traffic', 'Establish Network Connection'),
        ('file', 'Read/Write File'),
        ('registry', 'Read/Write Registry Key'),
        ('windows event log', 'Write Windows Event Log Entry'),
        ('active directory', 'Query Active Directory'),
        ('logon session', 'Authenticate / Create Logon Session'),
        ('named pipe', 'Open/Write Named Pipe'),
        ('service', 'Create/Modify Service'),
        ('scheduled task', 'Create/Modify Scheduled Task'),
        ('module', 'Load DLL/Module'),
        ('driver', 'Load Kernel Driver'),
        ('cloud storage', 'Access Cloud Storage Object'),
        ('email', 'Send/Receive Email Message'),
        ('dns', 'Send DNS Query / Receive DNS Response'),
        ('web credential', 'Access Stored Web Credentials'),
        ('user account', 'Query/Modify User Account'),
        ('kernel', 'Invoke Kernel / System Call'),
        ('script', 'Execute Script'),
        ('wmi', 'Create WMI Subscription / Execute WMI Query'),
        ('certificate', 'Access/Create Digital Certificate'),
        ('application log', 'Review Application Logs'),
    ]

    hints = []
    for keyword, operation in mappings:
        if keyword in ds_lower:
            matched = [ds for ds in clean_sources if keyword in ds.lower()]
            hints.append((operation, matched))

    return hints


def _generate_research_summary(
    technique_info: Optional[Dict],
    atomic_tests: List[Dict],
    existing_trrs: List[Dict],
    existing_ddms: List[Dict],
    search_results: Dict[str, List[Dict]],
    config: 'ConfigManager',
    no_ddg: bool = False,
    platform_filter: str = "",
    trr_id: str = "",
) -> List[str]:
    """Generate a compact Research Summary table with DDM starting points."""
    lines = []
    lines.append("## Research Summary")
    lines.append("")
    lines.append("| | |")
    lines.append("|---|---|")

    # Tactics
    tactics = ', '.join(technique_info.get('tactics', [])) if technique_info else 'Unknown'
    lines.append(f"| **Tactics** | {tactics} |")

    # Platforms
    platforms = ', '.join(technique_info.get('platforms', [])) if technique_info else 'Unknown'
    lines.append(f"| **Platforms** | {platforms} |")

    # Platform filter (when --platform is set)
    if platform_filter:
        lines.append(f"| **Platform Filter** | `{platform_filter}` |")

    # TRR ID (when --trr-id is set)
    if trr_id:
        lines.append(f"| **TRR ID** | {trr_id} |")

    # Atomic tests
    if atomic_tests:
        n = len(atomic_tests)
        word = "test" if n == 1 else "tests"
        lines.append(f"| **Atomic Tests** | {n} {word} ([see below](#atomic-red-team-emulation-tests)) |")
    else:
        lines.append("| **Atomic Tests** | None found |")

    # Existing TRRs
    if existing_trrs:
        # Build breakdown by match_type
        type_counts: Dict[str, int] = {}
        for trr in existing_trrs:
            mt = trr.get('match_type', 'unknown')
            type_counts[mt] = type_counts.get(mt, 0) + 1
        breakdown = ', '.join(f"{count} {mtype}" for mtype, count in type_counts.items())
        lines.append(f"| **Existing TRRs** | {len(existing_trrs)} matches ({breakdown}) |")
    else:
        lines.append("| **Existing TRRs** | 0 matches |")

    # Sources found (only when DDG search was run)
    if not no_ddg:
        total_sources = sum(len(r) for r in search_results.values())
        high_priority_count = 0
        for category, results in search_results.items():
            priority = config.trusted_sources.get(category, {}).get('priority', 'medium')
            if priority == 'high':
                high_priority_count += len(results)
        lines.append(f"| **Sources Found** | {total_sources} total · {high_priority_count} high-priority |")

    lines.append("")

    # DDM Starting Points
    data_sources = technique_info.get('data_sources', []) if technique_info else []
    hints = _build_ddm_hints(data_sources)

    if hints:
        lines.append("**DDM Starting Points** (from ATT&CK data sources):")
        lines.append("")
        for operation, source_names in hints:
            sources_str = ', '.join(source_names) if source_names else '(no specific component)'
            lines.append(f"- `{operation}` ← {sources_str}")
        lines.append("")
    else:
        lines.append("**DDM Starting Points:** Identify essential operations from the technique description and ATT&CK data sources.")
        lines.append("")

    lines.append("---")
    lines.append("")

    return lines


def _truncate_code_block(text: str, max_lines: int, max_chars: int = 600) -> Tuple[str, bool]:
    """Truncate a code block to max_lines and max_chars, returning (text, was_truncated)."""
    code_lines = text.split('\n')
    truncated = False
    if len(code_lines) > max_lines:
        code_lines = code_lines[:max_lines]
        truncated = True
    result = '\n'.join(code_lines)
    if len(result) > max_chars:
        result = result[:max_chars]
        truncated = True
    return result, truncated


def _generate_atomic_section(
    atomic_tests: List[Dict],
    technique_id: str,
    platform: str = "",
) -> List[str]:
    """Generate the Atomic Red Team tests section of the report."""
    lines = []
    lines.append("## Atomic Red Team Emulation Tests")
    lines.append("")

    if not atomic_tests:
        lines.append(f"> No Atomic Red Team tests exist for {technique_id} in the official repository.")
        lines.append(">")
        lines.append("> Consider searching GitHub for community tests, or building one to validate your DDM:")
        lines.append(f"> `https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/{technique_id}/`")
    else:
        github_url = atomic_tests[0].get('github_url', '')
        n_tests = len(atomic_tests)
        tests_word = "test" if n_tests == 1 else "tests"
        lines.append(f"Found **{n_tests} {tests_word}** in the Atomic Red Team repository.")
        if github_url:
            lines.append(f"Full file: [{technique_id}.yaml]({github_url})")
        lines.append("")

        for i, test in enumerate(atomic_tests, 1):
            lines.append(f"### Test {i}: {test.get('name', 'Unnamed')}")
            lines.append("")
            platforms = test.get('platforms', [])
            executor = test.get('executor', 'unknown')
            guid = test.get('auto_generated_guid', '')

            # Platform annotation when --platform is active
            platform_note = ""
            if platform and platforms:
                test_plats = [p.lower() for p in platforms]
                if platform.lower() in test_plats:
                    platform_note = " ✅"
                else:
                    platform_note = " ⚠️ *(off-platform)*"

            if platforms:
                lines.append(f"**Platforms:** {', '.join(platforms)}{platform_note}")
            lines.append(f"**Executor:** `{executor}`")
            if guid:
                lines.append(f"**GUID:** `{guid}`")
            lines.append("")

            desc = test.get('description', '').strip()
            if desc:
                lines.append(f"**Description:** {clean_text(desc, 400)}")
                lines.append("")

            # Input arguments table
            args = test.get('input_arguments', [])
            if args:
                lines.append("**Arguments:**")
                lines.append("")
                lines.append("| Name | Default |")
                lines.append("|------|---------|")
                for arg in args:
                    name = arg.get('name', '')
                    default = clean_text(arg.get('default', ''), 80)
                    lines.append(f"| `{name}` | `{default}` |")
                lines.append("")

            # Command block
            command = test.get('command', '')
            if command:
                # Map executor names to markdown code fence language hints
                lang_map = {
                    'command_prompt': 'cmd',
                    'powershell': 'powershell',
                    'bash': 'bash',
                    'sh': 'bash',
                    'manual': '',
                }
                lang = lang_map.get(executor, executor)
                cmd_text, was_truncated = _truncate_code_block(command, 8, 600)
                lines.append("**Command:**")
                lines.append("")
                lines.append(f"```{lang}")
                lines.append(cmd_text)
                if was_truncated:
                    lines.append("# [truncated — see full test on GitHub]")
                lines.append("```")
                lines.append("")
            elif executor == 'manual':
                lines.append("*(no commands defined — manual test)*")
                lines.append("")

            # Cleanup command block
            cleanup = test.get('cleanup_command', '')
            if cleanup:
                lang_map = {
                    'command_prompt': 'cmd',
                    'powershell': 'powershell',
                    'bash': 'bash',
                    'sh': 'bash',
                    'manual': '',
                }
                lang = lang_map.get(executor, executor)
                cleanup_text, was_truncated = _truncate_code_block(cleanup, 4, 600)
                lines.append("**Cleanup:**")
                lines.append("")
                lines.append(f"```{lang}")
                lines.append(cleanup_text)
                if was_truncated:
                    lines.append("# [truncated]")
                lines.append("```")
                lines.append("")

    lines.append("")
    lines.append("---")
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Source type classification (Improvement 6)
# ---------------------------------------------------------------------------

_DETECTION_SIGNALS = {
    'domain_patterns': [
        'elastic.co/docs/reference/security',
        'elastic.co/guide/en/security/',
        'github.com/SigmaHQ',
        'github.com/splunk/security_content',
    ],
    'url_keywords': ['prebuilt-rule', 'detection-rule', 'hunting-query',
                     'sigma', 'alert-reference', 'alerts-'],
    'title_keywords': ['detection rule', 'hunting query', 'sigma rule',
                       'prebuilt rule', 'attack surface reduction',
                       'sysmon', 'event id', 'kql', 'kusto'],
}

_THREAT_INTEL_SIGNALS = {
    'domain_patterns': [
        'thedfirreport.com',
        'mandiant.com/resources',
        'unit42.paloaltonetworks.com',
    ],
    'url_keywords': ['threat-intelligence', 'threat-research', 'apt-',
                     'campaign', 'intrusion-set', 'exploitation-leads'],
    'title_keywords': ['intrusion', 'campaign', 'apt', 'threat actor',
                       'exploitation leads to', 'exploits', 'unveiling',
                       'malware analysis', 'incident response'],
}

_REFERENCE_SIGNALS = {
    'url_keywords': ['learn.microsoft.com/en-us/windows/',
                     'learn.microsoft.com/en-us/iis/',
                     'learn.microsoft.com/en-us/dotnet/',
                     'learn.microsoft.com/en-us/openspecs/',
                     'learn.microsoft.com/en-us/previous-versions/'],
    'title_keywords': ['api reference', 'documentation', 'architecture',
                       'protocol', 'specification'],
}


def _classify_source_type(result: Dict) -> Optional[str]:
    """
    Classify a search result into Detection, Threat Intel, or Reference.
    Returns a short label string or None if no strong signal.
    """
    title = (result.get('title') or '').lower()
    url = (result.get('url') or '').lower()
    text = f"{title} {url}"

    # Check detection signals
    for pattern in _DETECTION_SIGNALS.get('domain_patterns', []):
        if pattern in url:
            return 'Detection'
    for kw in _DETECTION_SIGNALS.get('url_keywords', []):
        if kw in url:
            return 'Detection'
    for kw in _DETECTION_SIGNALS.get('title_keywords', []):
        if kw in title:
            return 'Detection'

    # Check threat intel signals
    for pattern in _THREAT_INTEL_SIGNALS.get('domain_patterns', []):
        if pattern in url:
            return 'Threat Intel'
    for kw in _THREAT_INTEL_SIGNALS.get('url_keywords', []):
        if kw in url:
            return 'Threat Intel'
    for kw in _THREAT_INTEL_SIGNALS.get('title_keywords', []):
        if kw in title:
            return 'Threat Intel'

    # Check reference signals
    for kw in _REFERENCE_SIGNALS.get('url_keywords', []):
        if kw in url:
            return 'Reference'
    for kw in _REFERENCE_SIGNALS.get('title_keywords', []):
        if kw in title:
            return 'Reference'

    return None


def _normalize_search_result(result: Dict) -> Dict:
    """Ensure every search result has a consistent set of fields."""
    return {
        "title": result.get("title", ""),
        "url": result.get("url", ""),
        "description": result.get("description", ""),
        "domain": result.get("domain", extract_domain(result.get("url", ""))),
        "date": result.get("date"),
        "relevance_score": result.get("relevance_score", 0.0),
        "link_status": result.get("link_status"),
        "source_type": _classify_source_type(result),
        "enrichment_status": result.get("_enrichment_status", "not_enriched"),
        "analysis_confidence": result.get("_analysis_confidence", "not_enriched"),
        "penalties": result.get("_penalties", []),
        # Content analysis fields (empty defaults when not enriched)
        "word_count": result.get("word_count", 0),
        "depth": result.get("depth", ""),
        "code_blocks": result.get("code_blocks", 0),
        "technical_markers": result.get("technical_markers", {}),
        "content_focus": result.get("content_focus", []),
        "marker_summary": result.get("marker_summary", ""),
    }


def _normalize_atomic_test(test: Dict) -> Dict:
    """Ensure every atomic test has a consistent set of fields."""
    return {
        "name": test.get("name", "Unnamed Test"),
        "description": test.get("description", ""),
        "platforms": test.get("platforms", []),
        "executor": test.get("executor", "unknown"),
        "auto_generated_guid": test.get("auto_generated_guid", ""),
        "github_url": test.get("github_url", ""),
        "command": test.get("command", ""),
        "cleanup_command": test.get("cleanup_command", ""),
        "input_arguments": test.get("input_arguments", []),
    }


def _normalize_existing_trr(trr: Dict) -> Dict:
    """Ensure every existing TRR entry has a consistent set of fields."""
    return {
        "file_name": trr.get("file_name", ""),
        "file_path": trr.get("file_path", ""),
        "trr_id": trr.get("trr_id", ""),
        "title": trr.get("title", ""),
        "techniques": trr.get("techniques", []),
        "match_type": trr.get("match_type", ""),
        "match_score": trr.get("match_score", 0),
        "github_url": trr.get("github_url", ""),
        "references": trr.get("references", []),
    }


def _normalize_existing_ddm(ddm: Dict) -> Dict:
    """Ensure every existing DDM entry has a consistent set of fields."""
    return {
        "file_name": ddm.get("file_name", ""),
        "file_path": ddm.get("file_path", ""),
        "technique_id": ddm.get("technique_id", ""),
        "github_url": ddm.get("github_url", ""),
    }


def _render_search_result(
    lines: List[str],
    index: int,
    result: Dict,
    config: 'ConfigManager',
    extra_note: str = "",
) -> None:
    """Render a single search result as markdown, appending to lines."""
    title = result.get('title', 'Untitled')
    url = result.get('url', '')
    description = result.get('description', '')
    date = result.get('date')
    domain = result.get('domain', '')

    link_dead = result.get('link_status') == 'dead'
    dead_tag = " (link may be broken)" if link_dead else ""

    # Content focus tags (from body analysis, falling back to URL-based)
    content_focus = result.get('content_focus', [])
    if not content_focus:
        source_tag = _classify_source_type(result)
        content_focus = [source_tag] if source_tag else []

    tag_str = ''.join(f' `{t}`' for t in content_focus) if content_focus else ""

    # Title line
    lines.append(f"### {index}. [{title}]({url}){dead_tag}{tag_str}")
    lines.append("")

    if extra_note:
        lines.append(f"> {extra_note}")

    # Metadata line: source | date | depth | code
    meta_parts = []
    if domain:
        meta_parts.append(domain)
    if date:
        meta_parts.append(format_date(date))

    depth = result.get('depth')
    word_count = result.get('word_count', 0)
    if depth and depth != 'Unknown':
        meta_parts.append(f"~{word_count:,} words ({depth})")

    code_blocks = result.get('code_blocks', 0)
    if code_blocks > 0:
        label = "code sample" if code_blocks == 1 else "code samples"
        meta_parts.append(f"{code_blocks} {label}")

    # Analysis confidence warning for problematic results
    confidence = result.get('_analysis_confidence', '')
    if confidence in ('empty', 'low', 'failed', 'not_fetched'):
        meta_parts.append(f"\u26a0 {confidence}")

    if meta_parts:
        lines.append(f"> {' \u00b7 '.join(meta_parts)}")
        lines.append("")

    # Technical markers (compact one-liner if present)
    marker_summary = result.get('marker_summary', '')
    if marker_summary:
        lines.append(f"**Markers:** {marker_summary}")
        lines.append("")

    # Excerpt
    if description:
        excerpt_len = config.output_settings.get('excerpt_length', 200)
        lines.append(f"**Excerpt:** {clean_text(description, excerpt_len)}")
        lines.append("")

    # Relevance score
    score = result.get('relevance_score', 0)
    if score >= 0.60:
        relevance_label = "Strong Match"
    elif score >= 0.40:
        relevance_label = "Likely Relevant"
    elif score >= 0.25:
        relevance_label = "Possible Match"
    else:
        relevance_label = "Weak Match"
    lines.append(f"**Relevance:** {relevance_label} ({score:.0%})")
    lines.append("")


_CATEGORY_DISPLAY_NAMES = {
    'security_research': 'Security Research Blogs',
    'microsoft_docs': 'Microsoft Documentation',
    'github': 'GitHub Repositories',
    'sigma_rules': 'Sigma Detection Rules',
    'conferences': 'Conference Talks',
    'lolbas_gtfobins': 'LOLBAS / GTFOBins',
    'academic': 'Academic Papers',
}


def _compute_coverage_gaps(
    search_results: Dict[str, List[Dict]],
    config: 'ConfigManager',
) -> List[Dict]:
    """
    Identify source categories with poor or missing coverage.

    Returns list of dicts:
      {'category': str, 'status': str, 'detail': str}

    Status values:
      'empty'    -- category returned 0 results after filtering
      'weak'     -- all results scored below 40% (Possible Match only)
      'shallow'  -- results exist but none had content analysis
    """
    gaps = []

    for category in config.trusted_sources:
        results = search_results.get(category, [])
        display_name = _CATEGORY_DISPLAY_NAMES.get(category, category.replace('_', ' ').title())

        if not results:
            gaps.append({
                'category': display_name,
                'status': 'empty',
                'detail': 'No results found in this category',
            })
            continue

        # Check if all results are weak (below 40%)
        all_weak = all(r.get('relevance_score', 0) < 0.40 for r in results)
        if all_weak:
            gaps.append({
                'category': display_name,
                'status': 'weak',
                'detail': f'{len(results)} results found but all scored below 40%',
            })
            continue

        # Check if none could be content-analyzed
        poor_confidence = {'empty', 'low', 'failed', 'not_fetched', 'not_enriched'}
        all_shallow = all(
            r.get('_analysis_confidence', 'not_enriched') in poor_confidence
            for r in results
        )
        if all_shallow:
            gaps.append({
                'category': display_name,
                'status': 'shallow',
                'detail': f'{len(results)} results found but none could be content-analyzed (likely JS-rendered)',
            })

    return gaps


def generate_research_checklist(
    technique_id: str,
    technique_name: str,
    search_results: Dict[str, List[Dict]],
    atomic_tests: List[Dict],
    existing_trrs: List[Dict],
    min_score: float = 0.25,
    top_n: int = 20,
    platform: str = "",
    trr_id: str = "",
) -> str:
    """
    Generate a markdown research checklist — a prioritized action-items view
    of the top sources for the researcher to review.
    """
    lines = []
    timestamp = datetime.now().strftime("%Y-%m-%d")

    # Header
    title_parts = [f"# Research Checklist — {technique_id} {technique_name}"]
    if trr_id:
        title_parts[0] += f" ({trr_id})"
    lines.append(title_parts[0])
    lines.append("")

    meta = f"**Generated:** {timestamp}"
    if platform:
        meta += f" \u00b7 **Platform:** {platform.title()}"
    meta += f" \u00b7 **Top {top_n} sources by relevance**"
    lines.append(meta)
    lines.append("")

    # Flatten all results, sort by score, take top N
    all_results = []
    for cat_results in search_results.values():
        for r in cat_results:
            if r.get('relevance_score', 0) >= min_score:
                all_results.append(r)
    all_results.sort(key=lambda r: r.get('relevance_score', 0), reverse=True)
    top_results = all_results[:top_n]

    # Group into tiers
    strong = [r for r in top_results if r.get('relevance_score', 0) >= 0.60]
    review = [r for r in top_results if 0.40 <= r.get('relevance_score', 0) < 0.60]
    check = [r for r in top_results if r.get('relevance_score', 0) < 0.40]

    def _render_checklist_item(r: Dict) -> List[str]:
        """Render a single checklist item."""
        item_lines = []
        title = r.get('title', 'Untitled')
        url = r.get('url', '')
        score = r.get('relevance_score', 0)
        domain = r.get('domain', '')
        date = r.get('date', '')

        item_lines.append(f"- [ ] [{title}]({url}) — {score:.0%}")

        # Metadata sub-line
        meta_parts = []
        if domain:
            meta_parts.append(domain)
        if date:
            meta_parts.append(format_date(date))
        word_count = r.get('word_count', 0)
        depth = r.get('depth', '')
        if word_count and depth and depth != 'Unknown':
            meta_parts.append(f"~{word_count:,} words ({depth})")

        # Content focus tags
        content_focus = r.get('content_focus', [])
        if content_focus:
            meta_parts.append(' '.join(content_focus))

        code_blocks = r.get('code_blocks', 0)
        if code_blocks > 0:
            label = "code sample" if code_blocks == 1 else "code samples"
            meta_parts.append(f"{code_blocks} {label}")

        confidence = r.get('_analysis_confidence', '')
        if confidence in ('empty', 'low', 'failed', 'not_fetched'):
            meta_parts.append(f"\u26a0 {confidence}")

        if meta_parts:
            item_lines.append(f"  > {' \u00b7 '.join(meta_parts)}")

        # Marker summary (if present)
        marker_summary = r.get('marker_summary', '')
        if marker_summary:
            item_lines.append(f"  > Markers: {marker_summary}")

        return item_lines

    # Render tiers
    if strong:
        lines.append(f"## Priority Sources (Strong Match \u226560%)")
        lines.append("")
        for r in strong:
            lines.extend(_render_checklist_item(r))
            lines.append("")

    if review:
        lines.append(f"## Review Sources (Likely Relevant 40-59%)")
        lines.append("")
        for r in review:
            lines.extend(_render_checklist_item(r))
            lines.append("")

    if check:
        lines.append(f"## Check Sources (Possible Match 25-39%)")
        lines.append("")
        for r in check:
            lines.extend(_render_checklist_item(r))
            lines.append("")

    if not top_results:
        lines.append("*No sources passed the relevance threshold.*")
        lines.append("")

    # Existing Coverage
    lines.append("## Existing Coverage")
    lines.append("")
    if existing_trrs:
        for trr in existing_trrs:
            trr_label = trr.get('trr_id', '') or trr.get('file_name', 'Unknown')
            title = trr.get('title', '')
            detail = f" — {title}" if title else " (existing TRR found)"
            lines.append(f"- [x] {trr_label}{detail}")
    else:
        lines.append("- [ ] No existing TRRs found for this technique")

    if atomic_tests:
        n = len(atomic_tests)
        word = "test" if n == 1 else "tests"
        lines.append(f"- [ ] {n} Atomic Red Team {word} available ({technique_id})")
    else:
        lines.append("- [ ] No Atomic Red Team tests available")

    lines.append("")

    # Notes section
    lines.append("## Notes")
    lines.append("")
    lines.append("_Use this space for research notes as you review sources._")
    lines.append("")
    lines.append("---")
    lines.append(f"*Generated by TRR Source Scraper v{REPORT_VERSION}*")

    return '\n'.join(lines)


def generate_markdown_report(
    technique_id: str,
    technique_info: Optional[Dict],
    existing_trrs: List[Dict],
    existing_ddms: List[Dict],
    atomic_tests: List[Dict],
    search_results: Dict[str, List[Dict]],
    config: ConfigManager,
    no_enrich: bool = False,
    no_ddg: bool = False,
    filtered_count: int = 0,
    min_score: float = 0.25,
    trr_id: str = "",
    platform: str = "",
    search_focus_terms: Optional[List[str]] = None,
) -> str:
    """
    Generate a markdown report with all gathered information.

    Args:
        technique_id: MITRE ATT&CK technique ID
        technique_info: Information from MITRE ATT&CK
        existing_trrs: List of existing TRRs found
        existing_ddms: List of existing DDMs found
        atomic_tests: Emulation tests from Atomic Red Team
        search_results: Search results organized by category
        config: Configuration manager
        no_enrich: Whether metadata enrichment was skipped
        no_ddg: Whether DuckDuckGo search was skipped
        trr_id: Optional TRR identifier for report header
        platform: Optional platform filter for off-platform result separation

    Returns:
        Markdown formatted string
    """
    lines = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Header
    technique_name = technique_info.get('name', 'Unknown') if technique_info else 'Unknown'
    # For sub-techniques, use the short name after the colon for search queries.
    # "Server Software Component: Web Shell" → "Web Shell"
    common_name = (
        technique_name.split(":")[-1].strip()
        if ":" in technique_name
        else technique_name
    )
    lines.append(f"# TRR Research Brief: {technique_id} — {technique_name}")
    lines.append("")
    lines.append(f"**Generated:** {timestamp}")
    lines.append(f"**Report Version:** {REPORT_VERSION}")
    lines.append(f"**Technique:** [{technique_id}](https://attack.mitre.org/techniques/{technique_id.replace('.', '/')})")

    if no_ddg:
        scan_mode = "Offline (--no-ddg: MITRE + Atomic Red Team only)"
    elif no_enrich:
        scan_mode = "Quick Scan (--no-enrich: metadata enrichment skipped)"
    else:
        scan_mode = "Full Enriched Run"
    lines.append(f"**Scan Mode:** {scan_mode}")
    if trr_id:
        lines.append(f"**TRR ID:** {trr_id}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Research Summary (compact table replacing the old checklist)
    lines.extend(_generate_research_summary(
        technique_info=technique_info,
        atomic_tests=atomic_tests,
        existing_trrs=existing_trrs,
        existing_ddms=existing_ddms,
        search_results=search_results,
        config=config,
        no_ddg=no_ddg,
        platform_filter=platform,
        trr_id=trr_id,
    ))

    # Search focus terms (shown when broad-technique keyword extraction was used)
    if search_focus_terms:
        lines.append(f"> **Search focus terms:** {', '.join(search_focus_terms)}")
        lines.append("")

    # Coverage Gaps (only when DDG search was run)
    if not no_ddg:
        gaps = _compute_coverage_gaps(search_results, config)
        if gaps:
            lines.append("## Coverage Gaps")
            lines.append("")
            lines.append("The following source categories may need manual research:")
            lines.append("")
            for gap in gaps:
                lines.append(f"- **{gap['category']}** — {gap['detail']}")
            lines.append("")
            lines.append("---")
            lines.append("")

    # MITRE ATT&CK Reference
    if technique_info:
        lines.append("## MITRE ATT&CK Reference")
        lines.append("")
        lines.append(f"### [{technique_id} — {technique_info.get('name', 'Unknown')}]({technique_info.get('url', '')})")
        lines.append("")
        description = technique_info.get('description', '')
        if description:
            lines.append(f"> {clean_text(description, 500)}")
            lines.append("")

        if technique_info.get('data_sources'):
            clean_ds = _filter_ds_codes(technique_info['data_sources'])
            if clean_ds:
                lines.append(f"**Data Sources:** {', '.join(clean_ds)}")
                lines.append("")

        if technique_info.get('permissions_required'):
            lines.append(f"**Permissions Required:** {', '.join(technique_info['permissions_required'])}")
            lines.append("")

        if technique_info.get('effective_permissions'):
            lines.append(f"**Effective Permissions:** {', '.join(technique_info['effective_permissions'])}")
            lines.append("")

        if technique_info.get('defense_bypassed'):
            lines.append(f"**Defenses Bypassed:** {', '.join(technique_info['defense_bypassed'])}")
            lines.append("")

        if technique_info.get('references'):
            lines.append("**MITRE References:**")
            lines.append("")
            for ref in technique_info['references'][:8]:
                name = ref.get('name', 'Reference')
                url = ref.get('url', '')
                if url:
                    lines.append(f"- [{name}]({url})")
            lines.append("")

        lines.append("---")
        lines.append("")

    # Atomic Red Team section
    lines.extend(_generate_atomic_section(atomic_tests, technique_id, platform=platform))

    # Existing TRRs
    if existing_trrs:
        lines.append("## Existing TRRs in Repository")
        lines.append("")
        lines.append("The following existing TRRs may contain relevant information:")
        lines.append("")

        for trr in sorted(existing_trrs, key=lambda x: x.get('match_score', 0), reverse=True):
            match_label = {
                'exact': 'Exact Match',
                'parent': 'Parent Technique',
                'name': 'Name Match'
            }.get(trr.get('match_type', ''), 'Related')

            lines.append(f"### {trr.get('file_name', 'Unknown')}")
            lines.append("")
            if trr.get('trr_id'):
                lines.append(f"**TRR ID:** {trr['trr_id']}")
            lines.append(f"**Match Type:** {match_label}")
            if trr.get('title'):
                lines.append(f"**Title:** {trr['title']}")
            if trr.get('techniques'):
                lines.append(f"**Techniques:** {', '.join(trr['techniques'])}")
            lines.append("")

            if trr.get('references'):
                lines.append("**References from TRR:**")
                for ref in trr['references'][:5]:
                    lines.append(f"- [{ref.get('name', 'Reference')}]({ref.get('url', '')})")
                lines.append("")

            lines.append(f"**File:** `{trr.get('file_path', '')}`")
            lines.append("")

        lines.append("---")
        lines.append("")

    # Existing DDMs (cross-reference with TRR titles when available)
    if existing_ddms:
        lines.append("## Existing DDMs in Repository")
        lines.append("")
        # Build TRR-ID -> title lookup from existing TRRs
        trr_title_map: Dict[str, str] = {}
        for trr in existing_trrs:
            tid = trr.get('trr_id', '')
            ttitle = trr.get('title', '')
            if tid and ttitle:
                trr_title_map[tid.lower()] = ttitle
        for ddm in existing_ddms:
            fname = ddm.get('file_name', '')
            # Extract TRR ID from filename: ddm_trr0011_ad_a.json -> trr0011
            trr_match = _re.search(r'(trr\d+)', fname, _re.IGNORECASE)
            parent_title = ""
            if trr_match:
                parent_title = trr_title_map.get(trr_match.group(1).lower(), "")
            if parent_title:
                lines.append(f"- `{fname}` — {parent_title}")
            else:
                lines.append(f"- `{fname}`")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Search Results by Category
    category_labels = {
        'security_research': 'Security Research Blogs',
        'microsoft_docs': 'Microsoft Documentation',
        'conferences': 'Conference Presentations',
        'github': 'GitHub Resources',
        'sigma_rules': 'Sigma Detection Rules',
        'lolbas_gtfobins': 'Living Off The Land References',
        'academic': 'Academic Papers',
    }

    priority_order = [
        'security_research', 'microsoft_docs', 'conferences',
        'github', 'sigma_rules', 'lolbas_gtfobins', 'academic'
    ]

    total_sources = 0
    high_priority_count = 0

    if no_ddg:
        lines.append("## Search Results")
        lines.append("")
        lines.append("> **Note:** DuckDuckGo search was skipped (`--no-ddg`). No web sources were gathered.")
        lines.append("> Run without `--no-ddg` to include search results.")
        lines.append("")
        lines.append("---")
        lines.append("")
    else:
        off_platform_results = []  # Collect results that target a different platform

        for category in priority_order:
            results = search_results.get(category, [])
            if not results:
                continue

            total_sources += len(results)
            priority = config.trusted_sources.get(category, {}).get('priority', 'medium')
            if priority == 'high':
                high_priority_count += len(results)

            # Split into on-platform and off-platform when --platform is set
            on_platform = []
            for result in results:
                detected_plat = _is_off_platform(result, platform) if platform else None
                if detected_plat:
                    result['_detected_platform'] = detected_plat
                    off_platform_results.append(result)
                else:
                    on_platform.append(result)

            if not on_platform:
                continue

            label = category_labels.get(category, category.replace('_', ' ').title())
            lines.append(f"## {label}")
            lines.append("")

            if no_enrich:
                lines.append("> **Quick Scan Mode:** Page metadata (titles, publication dates) was not fetched.")
                lines.append("> Descriptions shown are DuckDuckGo snippets only. Re-run without `--no-enrich` for full detail.")
                lines.append("")

            for i, result in enumerate(on_platform, 1):
                _render_search_result(lines, i, result, config)

            lines.append("---")
            lines.append("")

        # Render off-platform results in a separate section
        if off_platform_results:
            lines.append("## Other Platforms")
            lines.append("")
            lines.append(
                f"*{len(off_platform_results)} result(s) moved here — "
                f"appear to target a different platform than `{platform}`.*"
            )
            lines.append("")
            for i, result in enumerate(off_platform_results, 1):
                detected = result.get('_detected_platform', 'unknown')
                _render_search_result(lines, i, result, config,
                                     extra_note=f"Likely platform: **{detected}**")
            lines.append("---")
            lines.append("")

    # Manual search queries — dynamically generated from HIGH priority domains
    lines.append("## Additional Search Queries")
    lines.append("")
    lines.append("Use these queries for deeper manual research:")
    lines.append("")

    # Core queries
    lines.append(f'- `"{common_name}" {technique_id} detection`')
    lines.append(f'- `site:github.com/SigmaHQ/sigma {technique_id}`')
    lines.append(f'- `site:github.com/redcanaryco/atomic-red-team {technique_id}`')
    lines.append("")

    # Dynamically add site-specific queries for HIGH priority domains
    lines.append("High-priority source queries (generated from config):")
    lines.append("")
    for category, cat_config in config.trusted_sources.items():
        if cat_config.get('priority') == 'high':
            for domain in cat_config.get('domains', [])[:6]:
                lines.append(f'- `site:{domain} "{common_name}"`')

    lines.append("")
    lines.append("---")
    lines.append("")

    # Footer summary
    lines.append(f"*Total sources found: {total_sources} | High priority: {high_priority_count} | Atomic tests: {len(atomic_tests)}*")
    if filtered_count > 0:
        filtered_word = "result" if filtered_count == 1 else "results"
        lines.append("")
        lines.append(
            f"> **Relevance filtering:** {filtered_count} {filtered_word} below the "
            f"{min_score:.0%} threshold were excluded. Use `--min-score 0.0` to include all results."
        )

    return '\n'.join(lines)


def main():
    """Main entry point for the TRR Source Scraper."""
    args = parse_args()
    quiet = args.quiet
    verbose = args.verbose

    # Validate technique ID
    technique_id = normalize_technique_id(args.technique_id)
    if not validate_technique_id(technique_id):
        print(f"Error: Invalid technique ID format: {args.technique_id}")
        print("Expected format: T1003 or T1003.006")
        sys.exit(1)

    if not quiet:
        print(f"TRR Source Scraper — Researching {technique_id}")
        print("=" * 55)

    # Load configuration
    config = ConfigManager()
    max_per_category = args.max_per_category or config.search_settings.get('max_results_per_category', 10)
    user_agent = config.search_settings.get('user_agent', 'TRR-Source-Scraper/1.0')

    # Step 1: Fetch MITRE ATT&CK information
    print_progress("Step 1/6 — Fetching MITRE ATT&CK data...", always=True, quiet=quiet)
    technique_info = fetch_mitre_technique(technique_id, user_agent)

    if technique_info:
        print_progress(f"         Technique: {technique_info.get('name', 'Unknown')}", always=True, quiet=quiet)
        if technique_info.get('tactics'):
            print_progress(f"         Tactics:   {', '.join(technique_info['tactics'])}", always=True, quiet=quiet)
        if technique_info.get('platforms'):
            print_progress(f"         Platforms: {', '.join(technique_info['platforms'])}", always=True, quiet=quiet)
    else:
        print_progress("         Warning: Could not fetch MITRE ATT&CK page. Continuing with limited info.", always=True, quiet=quiet)

    # Get technique name
    technique_name = args.name
    if not technique_name and technique_info:
        technique_name = technique_info.get('name', '')
    if not technique_name:
        technique_name = technique_id

    # Step 2: Check for existing TRRs
    trr_cfg = config.trr_repository
    github_repo = args.trr_repo or trr_cfg.get("github_repo", "")
    branch = trr_cfg.get("branch", "main")
    reports_path = trr_cfg.get("reports_path", "reports")

    if github_repo:
        print_progress(f"Step 2/6 — Checking {github_repo} for existing TRRs and DDMs...", always=True, quiet=quiet)
    else:
        print_progress("Step 2/6 — No TRR repository configured — skipping", always=True, quiet=quiet)

    existing_trrs, existing_ddms = scan_for_existing_trrs(
        technique_id,
        technique_name,
        github_repo=github_repo,
        branch=branch,
        reports_path=reports_path,
        user_agent=user_agent,
    )

    if existing_trrs:
        print_progress(f"         Found {len(existing_trrs)} existing TRR(s)", always=True, quiet=quiet)
    if existing_ddms:
        print_progress(f"         Found {len(existing_ddms)} existing DDM(s)", always=True, quiet=quiet)
    if github_repo and not existing_trrs and not existing_ddms:
        print_progress("         No existing TRRs or DDMs found — this is a new technique to research", always=True, quiet=quiet)

    # Step 3: Fetch Atomic Red Team tests
    print_progress("Step 3/6 — Fetching Atomic Red Team emulation tests...", always=True, quiet=quiet)
    atomic_tests = fetch_atomic_tests(technique_id, user_agent)

    if atomic_tests:
        print_progress(f"         Found {len(atomic_tests)} Atomic Red Team test(s)", always=True, quiet=quiet)
        for test in atomic_tests:
            platforms = ', '.join(test.get('platforms', []))
            print_progress(f"         - {test['name']} [{platforms}]", verbose=verbose, quiet=quiet)
    else:
        print_progress("         No Atomic Red Team tests found for this technique", always=True, quiet=quiet)

    # Step 4: Search for sources (skippable with --no-ddg)
    if args.no_ddg:
        print_progress("Step 4/6 — Skipping DuckDuckGo search (--no-ddg)", always=True, quiet=quiet)
        search_results: Dict[str, List[Dict]] = {}
    else:
        print_progress("Step 4/6 — Searching for research sources...", always=True, quiet=quiet)
        t1_count = len(config.tier1_domains)
        print_progress(f"         Running {t1_count} focused queries for high-value sources...", always=True, quiet=quiet)
        print_progress(f"         Plus sweep queries across {len(config.trusted_sources)} categories...", always=True, quiet=quiet)

        reset_cache_stats()  # Scope cache stats to DDG search queries only
        search_results = search_technique_sources(
            technique_id=technique_id,
            technique_name=technique_name,
            categories=config.trusted_sources,
            max_per_category=max_per_category,
            user_agent=user_agent,
            extra_terms=args.extra_terms,
            verbose=verbose,
            mitre_refs=technique_info.get('references', []) if technique_info else None,
            use_cache=not args.no_cache,
            tier1_domains=config.tier1_domains,
            technique_description=technique_info.get('description', '') if technique_info else '',
        )

        total_results = sum(len(r) for r in search_results.values())
        print_progress(f"         Found {total_results} potential sources across all categories", always=True, quiet=quiet)

        # Cache performance summary
        cache_stats = get_cache_stats()
        if cache_stats['hits'] > 0 or cache_stats['expired'] > 0:
            print_progress(
                f"         Cache: {cache_stats['hits']} hits, "
                f"{cache_stats['misses']} misses, "
                f"{cache_stats['expired']} expired",
                always=True, quiet=quiet,
            )

    # Step 5: Enrich results with metadata (optional)
    total_results = sum(len(r) for r in search_results.values())
    if not args.no_enrich and not args.no_ddg and total_results > 0:
        print_progress("Step 5/6 — Enriching results with page metadata...", always=True, quiet=quiet)
        js_domains = [] if args.no_playwright else config.js_rendered_domains

        # Create a shared Playwright fetcher (if available) to reuse one
        # browser instance across all categories rather than launching
        # a new Chromium per category.
        pw_fetcher = None
        if js_domains:
            try:
                from scrapers.playwright_fetcher import PLAYWRIGHT_AVAILABLE, PlaywrightFetcher
                if PLAYWRIGHT_AVAILABLE:
                    pw_fetcher = PlaywrightFetcher()
            except Exception:
                pass  # Playwright import or init failed — proceed without it

        try:
            for category, results in search_results.items():
                if results:
                    search_results[category] = enrich_search_results(
                        results, user_agent,
                        js_rendered_domains=js_domains,
                        verbose=verbose,
                        pw_fetcher=pw_fetcher,
                    )
        finally:
            if pw_fetcher:
                pw_fetcher.close()
        # Report enrichment stats
        enriched_count = sum(
            1 for cat_results in search_results.values()
            for r in cat_results if r.get('_enrichment_status') == 'enriched'
        )
        analyzed_count = sum(
            1 for cat_results in search_results.values()
            for r in cat_results if r.get('word_count', 0) > 0
        )
        print_progress(
            f"         Metadata enriched: {enriched_count} · "
            f"Content analyzed: {analyzed_count} of {total_results}",
            always=True, quiet=quiet,
        )
        # Playwright stats
        playwright_count = sum(
            1 for cat_results in search_results.values()
            for r in cat_results if r.get('_enrichment_status') in ('playwright', 'playwright_analyzed')
        )
        if playwright_count:
            print_progress(
                f"         Playwright rendered: {playwright_count}",
                always=True, quiet=quiet,
            )
    elif args.validate_links and not args.no_ddg and total_results > 0:
        print_progress("Step 5/6 — Validating links (HEAD requests only)...", always=True, quiet=quiet)
        for category, results in search_results.items():
            if results:
                search_results[category] = validate_search_result_links(results, user_agent)
    else:
        reason = "--no-ddg" if args.no_ddg else "--no-enrich" if args.no_enrich else "no results"
        print_progress(f"Step 5/6 — Skipping metadata enrichment ({reason})", always=True, quiet=quiet)

    # Step 6: Score, sort, and filter results by relevance
    # (Runs AFTER enrichment so body-content signals are available)
    filtered_count = 0
    min_score = (
        args.min_score
        if args.min_score is not None
        else config.search_settings.get('min_relevance_score', 0.25)
    )
    if search_results:
        print_progress("Step 6/6 — Scoring and filtering results by relevance...", always=True, quiet=quiet)
        mitre_ref_domains = set()
        if technique_info:
            for ref in technique_info.get('references', []):
                d = extract_domain(ref.get('url', ''))
                if d:
                    mitre_ref_domains.add(d)

        pre_filter_total = 0
        for category, results in search_results.items():
            pre_filter_total += len(results)
            for r in results:
                r['relevance_score'] = compute_relevance_score(
                    r, technique_id, technique_name, mitre_ref_domains,
                    trusted_sources=config.trusted_sources,
                    noise_patterns=config.noise_patterns,
                )
                # Results from category-scoped queries (e.g. site:github.com/SigmaHQ)
                # are already pre-filtered to be relevant; give them a boost
                if r.get('_scoped_query'):
                    r['relevance_score'] = min(r['relevance_score'] + 0.20, 1.0)
                # Show penalty breakdown in verbose mode
                if verbose and r.get('_penalties'):
                    for ptype, pval, preason in r['_penalties']:
                        print(f"    [-{pval:.0%} {ptype}] {preason}: {r.get('title', '')[:60]}")
            # Sort by relevance score descending, then filter
            results.sort(key=lambda r: r.get('relevance_score', 0), reverse=True)
            search_results[category] = [
                r for r in results if r.get('relevance_score', 0) >= min_score
            ]

        filtered_total = sum(len(r) for r in search_results.values())
        filtered_count = pre_filter_total - filtered_total
        print_progress(
            f"         {filtered_total} sources passed relevance filtering "
            f"(min score: {min_score:.0%}, {filtered_count} excluded)",
            always=True, quiet=quiet,
        )

    # Deduplicate across categories (GitHub forks, academic paper formats, etc.)
    if search_results:
        pre_dedup_total = sum(len(r) for r in search_results.values())
        search_results = deduplicate_results(search_results, verbose=verbose)
        post_dedup_total = sum(len(r) for r in search_results.values())
        dedup_removed = pre_dedup_total - post_dedup_total
        if dedup_removed > 0:
            print_progress(
                f"         Removed {dedup_removed} duplicate(s) across categories",
                always=True, quiet=quiet,
            )

    # Compute search focus terms for the report (broad technique keyword extraction)
    search_focus_terms = []
    if technique_info and is_broad_technique(technique_name):
        search_focus_terms = extract_attack_keywords(
            technique_info.get('description', '')
        )

    # Generate report
    report = generate_markdown_report(
        technique_id=technique_id,
        technique_info=technique_info,
        existing_trrs=existing_trrs,
        existing_ddms=existing_ddms,
        atomic_tests=atomic_tests,
        search_results=search_results,
        config=config,
        no_enrich=args.no_enrich,
        no_ddg=args.no_ddg,
        filtered_count=filtered_count,
        min_score=min_score,
        trr_id=args.trr_id,
        platform=args.platform or "",
        search_focus_terms=search_focus_terms,
    )

    # Determine output filename suffix
    if args.no_ddg:
        filename_suffix = "offline_scan"
    elif args.no_enrich:
        filename_suffix = "quick_scan"
    else:
        filename_suffix = "research_brief"

    # Save markdown report
    output_dir = args.output or Path(config.output_settings.get('default_output_dir', 'output'))
    output_dir.mkdir(parents=True, exist_ok=True)
    if args.trr_id:
        output_file = output_dir / f"{args.trr_id}_{filename_suffix}.md"
    else:
        output_file = output_dir / f"{technique_id}_{filename_suffix}.md"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)

    # Optionally save JSON
    if args.json:
        json_base = args.trr_id if args.trr_id else technique_id
        json_file = output_dir / f"{json_base}_{filename_suffix}.json"

        # Normalize technique_info — guarantee consistent shape even on fetch failure
        safe_technique_info = dict(technique_info) if technique_info else {}
        for key, default in DEFAULT_TECHNIQUE_INFO.items():
            safe_technique_info.setdefault(key, default)

        # Normalize all collection types for consistent downstream consumption
        normalized_results = {
            category: [_normalize_search_result(r) for r in results]
            for category, results in search_results.items()
        }
        normalized_tests = [_normalize_atomic_test(t) for t in atomic_tests]
        normalized_trrs = [_normalize_existing_trr(t) for t in existing_trrs]
        normalized_ddms = [_normalize_existing_ddm(d) for d in existing_ddms]

        raw_data = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "platform": args.platform or "",
            "generated": datetime.now().isoformat(),
            "report_version": REPORT_VERSION,
            "scan_mode": filename_suffix,
            "technique_info": safe_technique_info,
            "existing_trrs": normalized_trrs,
            "existing_ddms": normalized_ddms,
            "atomic_tests": normalized_tests,
            "search_results": normalized_results,
        }
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(raw_data, f, indent=2, ensure_ascii=False)
        print(f"JSON saved to:  {json_file}")

    # Optionally generate research checklist
    if args.checklist and not search_results:
        print("Checklist skipped: no search results (use without --no-ddg)")
    elif args.checklist and search_results:
        checklist = generate_research_checklist(
            technique_id=technique_id,
            technique_name=technique_name,
            search_results=search_results,
            atomic_tests=atomic_tests,
            existing_trrs=existing_trrs,
            min_score=min_score,
            top_n=20,
            platform=args.platform or "",
            trr_id=args.trr_id,
        )
        json_base = args.trr_id if args.trr_id else technique_id
        checklist_file = output_dir / f"{json_base}_research_checklist.md"
        with open(checklist_file, 'w', encoding='utf-8') as f:
            f.write(checklist)
        print(f"Checklist saved: {checklist_file}")

    print("")
    print("=" * 55)
    print(f"Report saved to: {output_file}")
    print(f"Sources found:  {sum(len(r) for r in search_results.values())}")
    print(f"ART tests:      {len(atomic_tests)}")
    print("")
    if not quiet:
        print("Next step: Open the report and review the Research Summary and DDM Starting Points.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
