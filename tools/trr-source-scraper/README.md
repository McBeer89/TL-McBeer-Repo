# TRR Source Scraper

Automated research source discovery for MITRE ATT&CK techniques. Gathers sources from MITRE ATT&CK, Atomic Red Team, the [TIRED Labs TRR library](https://github.com/tired-labs/techniques), DuckDuckGo (security blogs, Microsoft docs, Sigma rules, GitHub, academic papers, conference talks), and outputs a structured markdown research brief with optional JSON.

No API keys required.

## Quick Start

```bash
cd tools/trr-source-scraper
pip install -r requirements.txt

# Basic run
python trr_scraper.py T1003.006 --name "DCSync"

# Quick scan (skip metadata enrichment)
python trr_scraper.py T1505.003 --no-enrich

# Offline (MITRE + Atomic + existing TRRs only, no web search)
python trr_scraper.py T1003.006 --no-ddg
```

Output is written to `output/` as a markdown report. Add `--json` for machine-readable output alongside the markdown.

## Flags

| Flag | Effect |
|------|--------|
| `--name "DCSync"` | Technique name for better search precision |
| `--no-enrich` | Skip page metadata fetching (faster) |
| `--no-ddg` | Skip web search entirely (offline mode) |
| `--json` | Write structured JSON alongside markdown |
| `--no-cache` | Force fresh queries (default: 1-day cache) |
| `--extra-terms "mimikatz"` | Append terms to every search query |
| `--min-score 0.5` | Raise relevance threshold (default: 0.25) |
| `--min-score 0.0` | Include all results regardless of score |
| `--max-per-category 5` | Cap results per source category |
| `--platform windows` | Soft-filter; moves off-platform results to a separate section |
| `--trr-id TRR0001` | Use TRR ID in output filenames instead of technique ID |
| `--trr-repo org/repo` | Override the TRR repository (default: `tired-labs/techniques`) |
| `--validate-links` | Check for dead links (HEAD requests only, use with `--no-enrich`) |
| `--verbose` | Show per-category search diagnostics |
| `--checklist` | Generate a markdown research checklist alongside the report |
| `--no-playwright` | Skip Playwright rendering even for JS-heavy sites |

## What the Report Contains

The markdown brief includes a **Research Summary** table (tactics, platforms, test counts, DDM starting points), **MITRE ATT&CK reference** data, **Atomic Red Team tests** with inline commands and arguments, **existing TRR/DDM matches** from the TIRED Labs library, and **categorized search results** sorted by relevance with source type tags (`Detection`, `Threat Intel`, `Reference`).

A **Coverage Gaps** section flags source categories that returned no results, only weak matches, or couldn't be content-analyzed (likely JS-rendered). A content **analysis confidence** indicator warns when page content couldn't be extracted.

Results scoring below 25% relevance are filtered by default. Relevance is computed from technique ID/name presence in titles, descriptions, and URLs, with boosts for trusted domains and MITRE-cited sources, and penalties for known noise patterns (API reference pages, package listings, legal boilerplate).

Use `--checklist` to generate a prioritized **research checklist** (`_research_checklist.md`) — a checkbox-formatted action list of the top 20 sources grouped by relevance tier (Strong Match, Likely Relevant, Possible Match) with metadata sub-lines and marker summaries.

## How Search Works

**Tier 1** — Individual `site:domain` queries against 8 high-value domains (DFIR Report, Elastic, Red Canary, SpecterOps, CrowdStrike, Microsoft Learn, Microsoft Tech Community, Mandiant). Max 2 results each.

**Tier 2** — Batched OR queries across remaining domains in each category (groups of 5). Category-specific queries target Sigma rules, LOLBAS/GTFOBins, and academic papers with tailored search terms.

Results are deduplicated across categories, GitHub forks are collapsed to canonical repos, and noise filters remove off-topic pages (e.g., PowerShell cmdlet docs for non-PowerShell techniques, non-English locale pages, author/tag index pages, Sigma PRs and coverage maps).

For **broad techniques** (PowerShell, Scheduled Task, etc.), the scraper extracts keywords from the ATT&CK description and generates enhanced search queries to surface more specific results. Search focus terms are shown in the report header.

Search results are cached for 1 day in `output/.cache/`.

## Configuration

All settings live in `config/sources.json`. The defaults work well — only edit if you need to add domains or change thresholds.

**Tier-1 domains** (`tier1_domains`): Which domains get individual targeted queries. Add domains here if they consistently produce high-quality content for your research.

**Source categories** (`trusted_sources`): Each category has a domain list, priority level, and optional search suffix. Add new categories or domains as needed.

**Search/output settings** (`search_settings`, `output_settings`): Rate limiting, timeouts, relevance thresholds, excerpt length. Defaults are conservative.

**TRR repository** (`trr_repository`): GitHub repo for existing TRR/DDM matching. Default: `tired-labs/techniques`.

**Noise patterns** (`noise_patterns`): URL, title, and content patterns that penalize irrelevant results (e.g., .NET API reference, NuGet package pages, legal boilerplate). Penalties are subtracted from relevance scores. Only the worst match per category is applied.

**JS-rendered domains** (`js_rendered_domains`): Domains that require Playwright for content extraction. Static HTTP fetches return empty HTML for these sites. See [Troubleshooting](#troubleshooting) for install instructions.

## Project Structure

```
trr-source-scraper/
├── trr_scraper.py           # Entry point and report generation
├── scrapers/
│   ├── mitre_attack.py      # ATT&CK page scraper
│   ├── duckduckgo.py        # Search with tier-1/tier-2 strategy
│   ├── existing_trr.py      # GitHub TRR/DDM scanner
│   ├── site_fetcher.py      # Page metadata enrichment
│   ├── playwright_fetcher.py # Optional JS rendering via Playwright
│   └── atomic_red_team.py   # Atomic Red Team YAML fetcher
├── utils/
│   ├── helpers.py           # Scoring, filtering, URL validation
│   ├── cache.py             # File-based JSON cache with TTL
│   └── content_analysis.py  # Word count, technical markers, focus tags
├── config/
│   └── sources.json         # Domains, settings, TRR repo config
└── output/                  # Reports and search cache
```

## Troubleshooting

**No search results**: Add `--name` with the technique's common name. Some techniques have limited public research.

**Rate limiting (429 errors)**: Normal on uncached runs. The 1-day cache prevents this on re-runs. Wait a few minutes between fresh runs.

**Slow performance**: Use `--no-enrich` to skip metadata fetching, or reduce `--max-per-category`.

**MITRE fetch failures**: The tool continues with limited info. Technique data is cached for 7 days after a successful fetch.

**JS-rendered sites show empty content**: Install Playwright for full content extraction from CrowdStrike, Elastic, Red Canary, and other JS-heavy sites:

```bash
pip install playwright && playwright install chromium
```

The scraper works without Playwright — JS-heavy pages will fall back to static fetch with reduced content analysis. Use `--no-playwright` to disable rendering even when installed.
