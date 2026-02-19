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
from typing import Dict, List, Optional

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
    fetch_atomic_tests,
)
from utils import (
    ConfigManager,
    RateLimiter,
    validate_technique_id,
    normalize_technique_id,
    clean_text,
    format_date,
    get_category_for_domain,
)

REPORT_VERSION = "1.1"


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


def _build_ddm_hints(data_sources: List[str]) -> List[str]:
    """
    Map known ATT&CK data source names to suggested DDM operations.
    Returns a list of suggested starting operations for the DDM.
    """
    hints = []
    ds_lower = ' '.join(data_sources).lower()

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
    ]

    for keyword, operation in mappings:
        if keyword in ds_lower:
            hints.append(f'`[E][I][O]` {operation}')

    return hints if hints else ['`[?]` (Identify essential operations from the technique description above)']


def _generate_research_checklist(
    technique_id: str,
    technique_info: Optional[Dict],
    atomic_tests: List[Dict],
    search_results: Dict[str, List[Dict]],
) -> List[str]:
    """Generate a quick-start research checklist for novice researchers."""
    lines = []
    lines.append("## Quick-Start Research Checklist")
    lines.append("")
    lines.append("> **How to use this:** Work through each phase in order. Complete all")
    lines.append("> stop-checks before advancing. Mark items `[x]` as you finish them.")
    lines.append("")

    # Phase 1
    lines.append("### Phase 1 — Technique Overview")
    lines.append("")
    if technique_info:
        lines.append(f"- [x] Official ATT&CK page fetched: [{technique_id}]({technique_info.get('url', '')})")
        lines.append("- [ ] Read the description and summarize the technique in 2–3 sentences **without naming any tool**")
        if technique_info.get('tactics'):
            lines.append(f"- [x] Tactics identified: {', '.join(technique_info['tactics'])}")
        else:
            lines.append("- [ ] Identify which tactic(s) this technique supports")
        if technique_info.get('platforms'):
            lines.append(f"- [x] Platforms in scope: {', '.join(technique_info['platforms'])}")
        else:
            lines.append("- [ ] Identify affected platforms")
    else:
        lines.append("- [ ] Fetch the official ATT&CK page (MITRE fetch failed — check your connection)")
        lines.append("- [ ] Summarize the technique in 2–3 sentences without naming any tool")
        lines.append("- [ ] Identify tactics and platforms")
    lines.append("")

    # Phase 2
    lines.append("### Phase 2 — Technical Background")
    lines.append("")
    ms_count = len(search_results.get('microsoft_docs', []))
    if ms_count > 0:
        lines.append(f"- [ ] Review the {ms_count} Microsoft documentation source(s) found below")
    else:
        lines.append("- [ ] Search Microsoft documentation for the underlying technology")
    lines.append("- [ ] Identify the Windows APIs, protocols, or OS services involved")
    lines.append("- [ ] Understand what prerequisites the attacker must satisfy")
    lines.append("- [ ] Document which security controls this technique bypasses or abuses")
    lines.append("- [ ] **Stop check:** Can you explain *why* this technique works without referencing a tool?")
    lines.append("")

    # Phase 3
    lines.append("### Phase 3 — DDM Construction")
    lines.append("")
    lines.append("Suggested starting operations based on ATT&CK data sources:")
    lines.append("")
    data_sources = technique_info.get('data_sources', []) if technique_info else []
    hints = _build_ddm_hints(data_sources)
    for hint in hints:
        lines.append(f"- [ ] {hint}")
    lines.append("")
    lines.append("For each operation, classify it:")
    lines.append("  - `[E]` Essential — must happen for the technique to work")
    lines.append("  - `[I]` Immutable — attacker cannot change it")
    lines.append("  - `[O]` Observable — visible through available telemetry")
    lines.append("- [ ] **Stop check:** No unresolved `[?]` markers remain")
    lines.append("")

    # Phase 4
    lines.append("### Phase 4 — Emulation Tests")
    lines.append("")
    if atomic_tests:
        lines.append(f"- [x] {len(atomic_tests)} Atomic Red Team test(s) found — see section below")
        lines.append("- [ ] Review each test to validate your DDM covers the operations it performs")
    else:
        lines.append("- [ ] No Atomic Red Team tests found for this technique")
        lines.append("- [ ] Check GitHub for any community-contributed tests or POCs")
        lines.append("- [ ] Consider creating an atomic test to validate your DDM")
    lines.append("")

    # Phase 5
    lines.append("### Phase 5 — Detection & TRR Documentation")
    lines.append("")
    github_count = len(search_results.get('github', []))
    sigma_count = len(search_results.get('sigma_rules', []))
    lines.append(f"- [ ] Review {github_count} GitHub resource(s) and {sigma_count} Sigma rule source(s) found below")
    lines.append("- [ ] Map each essential operation to an available telemetry source")
    lines.append("- [ ] Identify detection gaps (essential operations with no telemetry)")
    lines.append("- [ ] Write procedure narratives (not step lists — explain *why* each step works)")
    lines.append("- [ ] Assemble the TRR document following the TIRED Labs template")
    lines.append("")
    lines.append("---")
    lines.append("")

    return lines


def _generate_atomic_section(atomic_tests: List[Dict], technique_id: str) -> List[str]:
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
        lines.append(f"Found **{len(atomic_tests)} test(s)** in the Atomic Red Team repository.")
        if github_url:
            lines.append(f"Full file: [{technique_id}.yaml]({github_url})")
        lines.append("")

        for i, test in enumerate(atomic_tests, 1):
            lines.append(f"### Test {i}: {test.get('name', 'Unnamed')}")
            lines.append("")
            platforms = test.get('platforms', [])
            executor = test.get('executor', 'unknown')
            guid = test.get('auto_generated_guid', '')

            if platforms:
                lines.append(f"**Platforms:** {', '.join(platforms)}")
            lines.append(f"**Executor:** `{executor}`")
            if guid:
                lines.append(f"**GUID:** `{guid}`")
            lines.append("")
            desc = test.get('description', '').strip()
            if desc:
                lines.append(f"**Description:** {clean_text(desc, 400)}")
                lines.append("")

    lines.append("")
    lines.append("---")
    lines.append("")
    return lines


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

    Returns:
        Markdown formatted string
    """
    lines = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Header
    technique_name = technique_info.get('name', 'Unknown') if technique_info else 'Unknown'
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

    if technique_info:
        if technique_info.get('tactics'):
            lines.append(f"**Tactics:** {', '.join(technique_info.get('tactics', []))}")
        if technique_info.get('platforms'):
            lines.append(f"**Platforms:** {', '.join(technique_info.get('platforms', []))}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Quick-start research checklist
    lines.extend(_generate_research_checklist(technique_id, technique_info, atomic_tests, search_results))

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
            lines.append(f"**Data Sources:** {', '.join(technique_info['data_sources'])}")
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
    lines.extend(_generate_atomic_section(atomic_tests, technique_id))

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

    # Existing DDMs
    if existing_ddms:
        lines.append("## Existing DDMs in Repository")
        lines.append("")
        for ddm in existing_ddms:
            lines.append(f"- `{ddm.get('file_name', '')}`")
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
        quick_scan_note = (
            no_enrich and
            "> **Quick Scan Mode:** Page metadata (titles, publication dates) was not fetched.\n"
            "> Descriptions shown are DuckDuckGo snippets only. Re-run without `--no-enrich` for full detail."
        )

        for category in priority_order:
            results = search_results.get(category, [])
            if not results:
                continue

            total_sources += len(results)
            priority = config.trusted_sources.get(category, {}).get('priority', 'medium')
            if priority == 'high':
                high_priority_count += len(results)

            label = category_labels.get(category, category.replace('_', ' ').title())
            lines.append(f"## {label}")
            lines.append("")

            if no_enrich:
                lines.append("> **Quick Scan Mode:** Page metadata (titles, publication dates) was not fetched.")
                lines.append("> Descriptions shown are DuckDuckGo snippets only. Re-run without `--no-enrich` for full detail.")
                lines.append("")

            for i, result in enumerate(results, 1):
                title = result.get('title', 'Untitled')
                url = result.get('url', '')
                description = result.get('description', '')
                date = result.get('date')
                domain = result.get('domain', '')

                lines.append(f"### {i}. [{title}]({url})")
                lines.append("")

                if domain:
                    lines.append(f"> **Source:** {domain}")
                if date:
                    lines.append(f"> **Published:** {format_date(date)}")
                lines.append("")

                if description:
                    excerpt_len = config.output_settings.get('excerpt_length', 200)
                    lines.append(f"**Excerpt:** {clean_text(description, excerpt_len)}")
                    lines.append("")

                lines.append(f"**Relevance:** {priority.title()}")
                lines.append("")

            lines.append("---")
            lines.append("")

    # Manual search queries — dynamically generated from HIGH priority domains
    lines.append("## Additional Search Queries")
    lines.append("")
    lines.append("Use these queries for deeper manual research:")
    lines.append("")

    # Core queries
    lines.append(f'- `"{technique_name}" {technique_id} detection`')
    lines.append(f'- `site:github.com/SigmaHQ/sigma {technique_id}`')
    lines.append(f'- `site:github.com/redcanaryco/atomic-red-team {technique_id}`')
    lines.append("")

    # Dynamically add site-specific queries for HIGH priority domains
    lines.append("High-priority source queries (generated from config):")
    lines.append("")
    for category, cat_config in config.trusted_sources.items():
        if cat_config.get('priority') == 'high':
            for domain in cat_config.get('domains', [])[:6]:
                lines.append(f'- `site:{domain} "{technique_name}"`')

    lines.append("")
    lines.append("---")
    lines.append("")

    # Footer summary
    lines.append(f"*Total sources found: {total_sources} | High priority: {high_priority_count} | Atomic tests: {len(atomic_tests)}*")

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
    print_progress("Step 1/5 — Fetching MITRE ATT&CK data...", always=True, quiet=quiet)
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
    print_progress("Step 2/5 — Checking for existing TRRs and DDMs...", always=True, quiet=quiet)
    existing_trrs, existing_ddms = scan_for_existing_trrs(technique_id, technique_name)

    if existing_trrs:
        print_progress(f"         Found {len(existing_trrs)} existing TRR(s)", always=True, quiet=quiet)
    if existing_ddms:
        print_progress(f"         Found {len(existing_ddms)} existing DDM(s)", always=True, quiet=quiet)
    if not existing_trrs and not existing_ddms:
        print_progress("         No existing TRRs or DDMs found — this is a new technique to research", always=True, quiet=quiet)

    # Step 3: Fetch Atomic Red Team tests
    print_progress("Step 3/5 — Fetching Atomic Red Team emulation tests...", always=True, quiet=quiet)
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
        print_progress("Step 4/5 — Skipping DuckDuckGo search (--no-ddg)", always=True, quiet=quiet)
        search_results: Dict[str, List[Dict]] = {}
    else:
        print_progress("Step 4/5 — Searching for research sources...", always=True, quiet=quiet)
        print_progress(f"         Searching across {len(config.trusted_sources)} source categories...", always=True, quiet=quiet)
        print_progress("         (This takes ~30–60 seconds due to rate limiting)", always=True, quiet=quiet)

        search_results = search_technique_sources(
            technique_id=technique_id,
            technique_name=technique_name,
            categories=config.trusted_sources,
            max_per_category=max_per_category,
            user_agent=user_agent,
            extra_terms=args.extra_terms,
            verbose=verbose,
        )

        total_results = sum(len(r) for r in search_results.values())
        print_progress(f"         Found {total_results} potential sources across all categories", always=True, quiet=quiet)

    # Step 5: Enrich results with metadata (optional)
    total_results = sum(len(r) for r in search_results.values())
    if not args.no_enrich and not args.no_ddg and total_results > 0:
        print_progress("Step 5/5 — Enriching results with page metadata...", always=True, quiet=quiet)
        print_progress("         Fetching page titles and descriptions (this may take a moment)...", always=True, quiet=quiet)
        for category, results in search_results.items():
            if results:
                search_results[category] = enrich_search_results(results, user_agent)
    else:
        reason = "--no-ddg" if args.no_ddg else "--no-enrich" if args.no_enrich else "no results"
        print_progress(f"Step 5/5 — Skipping metadata enrichment ({reason})", always=True, quiet=quiet)

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
    output_file = output_dir / f"{technique_id}_{filename_suffix}.md"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)

    # Optionally save JSON
    if args.json:
        json_file = output_dir / f"{technique_id}_{filename_suffix}.json"
        raw_data = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "generated": datetime.now().isoformat(),
            "report_version": REPORT_VERSION,
            "scan_mode": filename_suffix,
            "technique_info": technique_info,
            "existing_trrs": existing_trrs,
            "existing_ddms": existing_ddms,
            "atomic_tests": atomic_tests,
            "search_results": search_results,
        }
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(raw_data, f, indent=2, ensure_ascii=False)
        print(f"JSON saved to:  {json_file}")

    print("")
    print("=" * 55)
    print(f"Report saved to: {output_file}")
    print(f"Sources found:  {total_results}")
    print(f"ART tests:      {len(atomic_tests)}")
    print("")
    if not quiet:
        print("Next step: Open the report and work through the Quick-Start Checklist.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
