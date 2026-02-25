# TRR Source Scraper

Automated research source discovery for MITRE ATT&CK techniques. Gathers sources from MITRE ATT&CK, Atomic Red Team, and DuckDuckGo (security blogs, Microsoft docs, Sigma rules, GitHub, academic papers, conference talks), and outputs a structured markdown research brief with optional JSON and source analysis.

No API keys required.

## Quick Start

```bash
cd tools/trr-source-scraper
pip install -r requirements.txt

# Basic run
python trr_scraper.py T1003.006 --name "DCSync"

# Quick scan (skip metadata enrichment)
python trr_scraper.py T1505.003 --no-enrich

# Offline (MITRE + Atomic only, no web search)
python trr_scraper.py T1003.006 --no-ddg

# Full run with JSON + source analysis
python trr_scraper.py T1505.003 --name "Web Shell" --platform windows --json --source-analysis
```

Output is written to `output/` as a markdown report. Add `--json` for machine-readable output and `--source-analysis` for a prioritized source analysis.

### Optional: Playwright for JS-Rendered Sites

Some high-value security blogs (Elastic, Red Canary, TechCommunity, SpecterOps) use JavaScript to render content. Without Playwright, these pages return empty content and are flagged with `⚠ empty` in reports. With Playwright installed, the scraper renders these pages in a headless browser and extracts full content.

```bash
pip install playwright
playwright install chromium
```

Playwright is fully optional. The scraper works without it — JS-heavy results are flagged so the researcher knows to check them manually. Use `--no-playwright` to disable it even when installed.

## Flags

| Flag | Effect |
|------|--------|
| `--name "DCSync"` | Technique name for better search precision |
| `--no-enrich` | Skip page metadata fetching (faster) |
| `--no-ddg` | Skip web search entirely (offline mode) |
| `--json` | Write structured JSON alongside markdown |
| `--source-analysis` | Generate a prioritized source analysis alongside the report |
| `--no-cache` | Force fresh queries (default: 1-day cache) |
| `--no-playwright` | Skip Playwright rendering even if installed |
| `--extra-terms "mimikatz"` | Append terms to every search query |
| `--min-score 0.5` | Raise relevance threshold (default: 0.25) |
| `--min-score 0.0` | Include all results regardless of score |
| `--max-per-category 5` | Cap results per source category |
| `--platform windows` | Soft-filter; moves off-platform results to a separate section |
| `--trr-id TRR0001` | Use TRR ID in output filenames instead of technique ID |
| `--validate-links` | Check for dead links (HEAD requests only, use with `--no-enrich`) |
| `--verbose` | Show per-category search diagnostics, cache stats, penalty details |
| `--quiet` | Suppress all output except the final save confirmation |

## What the Report Contains

The markdown brief includes:

- **Research Summary** table — tactics, platforms, test counts, DDM starting points
- **Search focus terms** — ATT&CK-derived keywords used to narrow broad techniques (when applicable)
- **Coverage Gaps** — source categories with poor or missing results, flagging where manual research is needed
- **MITRE ATT&CK reference** data
- **Atomic Red Team tests** with inline commands and arguments
- **Categorized search results** sorted by relevance with source type tags (`Detection`, `Threat Intel`, `Reference`)

Each result includes:

- Relevance score with label (Strong Match ≥60%, Likely Relevant 40-59%, Possible Match 25-39%)
- Content analysis: word count, depth label, code block count
- Technical markers: event IDs, processes, APIs, registry paths, detection syntax
- Content focus tags: Detection, Execution, Technical, Threat Intel, General
- Analysis confidence: `analyzed`, `partial`, `low`, `empty`, `failed`, or `not_fetched`
- Noise penalties (when applied) visible in `--verbose` mode

### Source Analysis (`--source-analysis`)

Generates a separate markdown file with prioritized sources for review:

```markdown
## Priority Sources (Strong Match ≥60%)

- [IIS Raid – Backdooring IIS](https://example.com/...) — 82%
  > specterops.io · ~3,200 words (Long-form) · 4 code samples
  > Markers: event_ids: 4688, Sysmon 1; processes: w3wp.exe

## Review Sources (Likely Relevant 40-59%)
...
```

Sources that couldn't be content-analyzed are flagged with `⚠ empty`, `⚠ low`, or `⚠ failed` so the researcher knows which ones need manual inspection.

## How Search Works

### Two-Tier Search Strategy

- **Tier 1** — Individual `site:domain` queries against high-value domains (DFIR Report, Elastic, Red Canary, SpecterOps, CrowdStrike, Microsoft Learn, Microsoft Tech Community, Mandiant). Max 2 results each. Configurable via `tier1_domains` in `sources.json`.
- **Tier 2** — Batched OR queries across remaining domains in each category (groups of 5). Category-specific queries target Sigma rules, LOLBAS/GTFOBins, and academic papers with tailored search terms.

Tier-1 results sort first within each category.

### Broad Technique Detection

For techniques with generic names (e.g., "PowerShell", "Windows Management Instrumentation"), the scraper automatically extracts high-signal keywords from the ATT&CK description and appends them to search queries. This reduces noise from generic forum posts and documentation pages. Keywords are shown in the report under **Search focus terms**.

Narrow techniques (e.g., "DCSync", "Kerberoasting", "Web Shell") use standard queries unchanged.

### Relevance Scoring

Results are scored 0–100% using a combination of positive signals and noise penalties:

**Positive signals** (from metadata — always available):
- Title contains technique ID (+30%) or name (+25%)
- Description contains technique ID (+15%) or name (+10%)
- URL path contains technique ID (+10%)
- Domain cited in MITRE's own references (+10%)
- Trusted domain tier: high (+15%), medium (+5%)

**Bonus signals** (from content analysis — after enrichment):
- Long-form content (+10%), Standard (+5%)
- ≥2 code blocks (+5%)
- ≥3 technical marker categories (+10%), 1-2 (+5%)

**Noise penalties** (configurable in `sources.json`):
- .NET API reference pages, MDN docs, NuGet/PyPI listings
- API class/namespace reference pages
- Package install instructions, boilerplate legal pages
- Penalties are per-category (URL, title, content) — worst match per category applies

Results below 25% are filtered by default (configurable via `--min-score`).

### Content Analysis

Every fetched page undergoes content analysis that extracts:

- **Word count and depth** — Minimal (<500), Brief (500-1000), Standard (1000-3000), Long-form (3000+)
- **Code blocks** — count of `<pre>`, `<code>`, and fenced code blocks
- **Technical markers** — event IDs, process names, Windows APIs, registry paths, network protocols, file paths, detection query syntax (Sigma, KQL, SPL, YARA)
- **Content focus tags** — Detection, Execution, Technical, Threat Intel, General
- **Analysis confidence** — distinguishes between "analyzed and found nothing" vs "couldn't analyze the page"

GitHub blob URLs are automatically rewritten to `raw.githubusercontent.com` for direct text analysis. Sigma YAML, ART test files, and hunt guides all get full content analysis.

### JS-Rendered Page Support (Playwright)

When Playwright is installed, pages from configured JS-heavy domains are rendered in a headless Chromium browser before content analysis. This recovers article text from sites that serve empty HTML via static fetch.

Domains are configured in `js_rendered_domains` in `sources.json`. Playwright is only invoked for these domains — all other pages use fast static HTTP fetch. A single browser instance is reused across all Playwright fetches in a run.

### Source Type Tags

Results are classified with inline tags when there's a strong signal:

- `Detection` — Detection rules, hunting queries, alert references
- `Threat Intel` — Intrusion reports, campaign analysis, APT write-ups
- `Reference` — Vendor documentation, API docs, protocol specs

### Search Result Caching

DuckDuckGo search results are cached for 1 day in `output/.cache/`. MITRE ATT&CK data is cached for 7 days. Use `--no-cache` to force fresh queries. Cache hit/miss statistics are shown with `--verbose`.

## Configuration

All settings live in `config/sources.json`. The defaults work well — only edit if you need to add domains or change thresholds.

### Key Configuration Sections

**`tier1_domains`** — Which domains get individual targeted queries. Add domains here if they consistently produce high-quality content.

**`trusted_sources`** — Each category has a domain list, priority level, and optional search suffix. Add new categories or domains as needed.

**`noise_patterns`** — URL, title, and content patterns that trigger score penalties. Tune these if specific noise sources keep appearing in your results.

**`js_rendered_domains`** — Domains that require Playwright for content extraction. Only relevant if Playwright is installed.

**`search_settings`** / **`output_settings`** — Rate limiting, timeouts, relevance thresholds, excerpt length.

## Project Structure

```
trr-source-scraper/
├── trr_scraper.py              # Entry point, report generation, source analysis generation
├── scrapers/
│   ├── mitre_attack.py         # ATT&CK API fetch
│   ├── duckduckgo.py           # Search with tier-1/tier-2 strategy + broad technique queries
│   ├── site_fetcher.py         # Page enrichment, content analysis, Playwright integration
│   ├── playwright_fetcher.py   # Optional headless browser for JS-rendered sites
│   └── atomic_red_team.py      # Atomic Red Team YAML fetcher
├── utils/
│   ├── helpers.py              # Scoring (with penalties), filtering, keyword extraction
│   ├── content_analysis.py     # Marker extraction, text extraction, confidence assessment
│   └── cache.py                # File-based JSON cache with TTL and stats
├── config/
│   └── sources.json            # Domains, noise patterns, JS domains, settings
├── output/                     # Reports, source analysis, JSON, and search cache
│   └── .cache/                 # Cached search results (auto-managed)
├── requirements.txt
└── README.md
```

## Ethical Scraping

This tool follows ethical scraping practices:

- **Rate Limiting** — Built-in delays between requests (configurable)
- **Caching** — Search results cached for 1 day to reduce unnecessary requests
- **User-Agent** — Identifies the scraper in all requests
- **Conservative Limits** — Caps results per category to avoid overwhelming sources
- **Selective Playwright** — Only renders JS for configured domains, not every URL

## Troubleshooting

**No search results** — Add `--name` with the technique's common name. Some techniques have limited public research.

**Rate limiting (429 errors)** — Normal on uncached runs. The 1-day cache prevents this on re-runs. Wait a few minutes between fresh runs.

**Slow performance** — Playwright adds 3-8 seconds per JS-rendered page. Use `--no-enrich` to skip all page fetching, `--no-playwright` to skip only JS rendering, or reduce `--max-per-category`.

**JS sites showing ⚠ empty** — Install Playwright (`pip install playwright && playwright install chromium`). Some sites (notably CrowdStrike) may still show empty due to bot detection.

**MITRE fetch failures** — The tool continues with limited info. Technique data is cached for 7 days after a successful fetch.

**Too much noise for broad techniques** — The scraper auto-detects broad techniques and adds ATT&CK keywords to queries. You can also add `--extra-terms` to focus searches further, or raise `--min-score`.

## Version History

**v1.6** (current) — Broad technique query intelligence, noise penalty scoring, content analysis confidence flags, coverage gap detection, source analysis export, Playwright integration for JS-rendered sites, cache diagnostics, enrichment status in JSON output.

**v1.5** — Content analysis (word count, depth, code blocks, technical markers, content focus tags). Relevance scoring runs after enrichment. GitHub raw file analysis.

**v1.4** — Quality filters (relevance scoring, deduplication, platform filtering, trusted source tiers, dead link detection).

**v1.3** — Two-tier search strategy, Atomic Red Team integration.
