# TRR Source Scraper

A Python tool for scraping the web to find potential research sources for MITRE ATT&CK techniques when creating Technique Research Reports (TRRs).

## Purpose

When creating a Technique Research Report, researchers need to gather information from multiple sources to understand an attack technique thoroughly. This tool automates the discovery of relevant sources, including:

- **MITRE ATT&CK** - Official technique documentation and curated references
- **Existing TRRs & DDMs** - Previously completed reports in the [tired-labs/techniques](https://github.com/tired-labs/techniques) repository
- **Atomic Red Team** - Emulation tests from Red Canary's open-source library
- **Security Research Blogs** - SpecterOps, Red Canary, CrowdStrike, Elastic, etc.
- **Microsoft Documentation** - Official Windows/Azure docs
- **Conference Presentations** - Black Hat, DEF CON, BSides
- **GitHub Resources** - Detection rules, Sigma rules, POC code
- **Academic Papers** - Research publications

## Installation

```bash
# Navigate to the tool directory
cd tools/trr-source-scraper

# Install dependencies
pip install -r requirements.txt
```

No API keys or authentication tokens are required. All data sources (GitHub, MITRE, DuckDuckGo) are accessed via public endpoints.

## Usage

### Basic Usage

```bash
# Search for sources on a technique
python trr_scraper.py T1003.006

# With technique name for better search results
python trr_scraper.py T1003.006 --name "DCSync"
```

### Scan Modes

```bash
# Full enriched run (default) — web search + page metadata
python trr_scraper.py T1003.006 --name "DCSync"

# Quick scan — web search but skip metadata fetching (faster)
python trr_scraper.py T1003.006 --no-enrich

# Offline scan — MITRE + Atomic Red Team + existing TRRs only (no web search)
python trr_scraper.py T1003.006 --no-ddg

# Quick scan with link validation — check for broken links without full metadata
python trr_scraper.py T1003.006 --no-enrich --validate-links
```

### Advanced Options

```bash
# Add extra search terms to every query
python trr_scraper.py T1003.006 --extra-terms "mimikatz lsass"

# Limit results per category
python trr_scraper.py T1003.006 --max-per-category 5

# Also write raw JSON output alongside the markdown report
python trr_scraper.py T1003.006 --json

# Force fresh search results (bypass 1-day cache)
python trr_scraper.py T1003.006 --no-cache

# Override the GitHub repo for TRR/DDM lookup
python trr_scraper.py T1003.006 --trr-repo my-org/my-techniques

# Verbose mode for debugging
python trr_scraper.py T1003.006 --verbose

# Suppress all output except the final save confirmation
python trr_scraper.py T1003.006 --quiet
```

### Command-Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `technique_id` | - | MITRE ATT&CK technique ID (required, e.g., `T1003.006`) |
| `--name` | `-n` | Technique name for better search results (e.g., `"DCSync"`) |
| `--output` | `-o` | Output directory for the markdown report (default: `./output/`) |
| `--max-per-category` | `-m` | Maximum number of results per category (default: 10) |
| `--no-enrich` | - | Skip fetching page metadata (saves as `_quick_scan.md`) |
| `--no-ddg` | - | Skip DuckDuckGo search entirely (saves as `_offline_scan.md`) |
| `--extra-terms` | `-e` | Additional search terms appended to every query |
| `--json` | - | Also write a JSON file with all raw collected data |
| `--no-cache` | - | Bypass search result cache and force fresh queries |
| `--validate-links` | - | Check link liveness via HEAD requests |
| `--trr-repo` | - | Override GitHub repo for TRR/DDM lookup |
| `--verbose` | `-v` | Print detailed progress and diagnostic information |
| `--quiet` | `-q` | Suppress all output except the final save confirmation |

## Existing TRR/DDM Lookup

The tool automatically checks the [tired-labs/techniques](https://github.com/tired-labs/techniques) GitHub repository for existing TRRs and DDMs that relate to the technique being researched. This uses public GitHub API endpoints — no authentication token is required.

The repository is configured in `config/sources.json`:

```json
{
  "trr_repository": {
    "github_repo": "tired-labs/techniques",
    "branch": "main",
    "reports_path": "reports"
  }
}
```

To use a different repository, either edit the config or pass `--trr-repo`:

```bash
python trr_scraper.py T1003.006 --trr-repo my-org/my-techniques
```

The scanner matches TRRs using technique ID (exact match), parent technique ID, and technique name keywords, and assigns a match confidence score.

## Output

The tool generates a markdown report containing:

1. **Quick-Start Research Checklist** - Phased workflow guide for researchers
2. **MITRE ATT&CK Reference** - Technique summary, tactics, platforms, data sources
3. **Atomic Red Team Emulation Tests** - Available test cases with execution details
4. **Existing TRRs** - Previously completed reports matching this technique
5. **Existing DDMs** - Detection Data Models related to the technique
6. **Categorized Sources** - Research sources organized by type, sorted by relevance score:
   - Security Research Blogs (High Priority)
   - Microsoft Documentation (High Priority)
   - Conference Presentations (Medium Priority)
   - GitHub Resources (Medium Priority)
   - Sigma Rules (Medium Priority)
   - LOLBAS/GTFOBins (Medium Priority)
   - Academic Papers (Low Priority)
7. **Additional Search Queries** - Suggested queries for manual research

### Relevance Scoring

Each source link is scored 0-100% based on how likely it is to contain substantive content about the technique. Scoring factors include whether the technique ID or name appears in the page title, description, URL, and whether the domain is cited by MITRE's own references. Results are labeled:

- **Strong Match** (50%+) - Technique ID and name prominently featured
- **Likely Relevant** (25-49%) - Clear technique references found
- **Possible Match** (10-24%) - Indirect or partial references
- Results below 10% are filtered out (configurable via `min_relevance_score`)

### Search Result Caching

DuckDuckGo search results are cached for 1 day in `output/.cache/` to avoid rate limiting on repeated runs. Use `--no-cache` to force fresh queries. MITRE ATT&CK data is cached for 7 days.

## Configuration

The tool's behavior is customized via `config/sources.json`:

### Source Categories

Add or modify trusted sources in the `trusted_sources` section:

```json
{
  "trusted_sources": {
    "security_research": {
      "priority": "high",
      "domains": ["specterops.io", "redcanary.com", "..."],
      "search_suffix": "security research analysis detection"
    }
  }
}
```

### Search Settings

```json
{
  "search_settings": {
    "max_results_per_category": 10,
    "delay_between_requests": 2,
    "timeout": 15,
    "max_retries": 3,
    "user_agent": "TRR-Source-Scraper/1.0 (Educational Research Tool)",
    "min_relevance_score": 0.10
  }
}
```

### Output Settings

```json
{
  "output_settings": {
    "default_output_dir": "output",
    "include_excerpts": true,
    "excerpt_length": 200,
    "include_dates": true
  }
}
```

## Project Structure

```
trr-source-scraper/
├── trr_scraper.py           # Main entry point
├── scrapers/
│   ├── __init__.py
│   ├── mitre_attack.py      # MITRE ATT&CK page scraper
│   ├── duckduckgo.py        # DuckDuckGo search with caching
│   ├── existing_trr.py      # GitHub TRR/DDM scanner
│   ├── site_fetcher.py      # Page metadata & link validation
│   └── atomic_red_team.py   # Atomic Red Team YAML fetcher
├── utils/
│   ├── __init__.py
│   ├── helpers.py           # Rate limiting, URL validation, relevance scoring
│   └── cache.py             # File-based JSON cache with TTL
├── config/
│   └── sources.json         # Trusted sources, search settings, TRR repo config
├── output/                  # Generated reports and cache
│   └── .cache/              # Cached search results (auto-managed)
├── requirements.txt         # Python dependencies
└── README.md
```

## Ethical Scraping

This tool follows ethical scraping practices:

- **Rate Limiting**: Built-in delays between requests (configurable)
- **Caching**: Search results cached for 1 day to reduce unnecessary requests
- **User-Agent**: Identifies the scraper in all requests
- **Conservative Limits**: Caps results per category to avoid overwhelming sources

## Extending the Tool

### Adding New Source Categories

1. Edit `config/sources.json`
2. Add a new category with domains and search settings:

```json
{
  "my_new_category": {
    "priority": "medium",
    "domains": ["example-security-blog.com"],
    "search_suffix": "analysis"
  }
}
```

### Adding New Scrapers

1. Create a new scraper in `scrapers/`
2. Import and use the `RateLimiter` and helper utilities
3. Register in `scrapers/__init__.py`
4. Call from `trr_scraper.py` main function

## Troubleshooting

### "Could not fetch MITRE ATT&CK page"

- Check your internet connection
- The MITRE ATT&CK site may be temporarily unavailable
- The tool will continue with limited information

### No search results found

- Try adding the `--name` parameter with the technique name
- Some techniques may have limited public research
- Check if DuckDuckGo is accessible from your network

### Rate limiting / 429 errors

- This is normal when running multiple searches in quick succession
- The tool caches results for 1 day — re-running will use cached data
- Use `--no-cache` only when you need fresh results
- Wait a few minutes between uncached runs

### Slow performance

- Use `--no-enrich` to skip metadata fetching
- Reduce `--max-per-category` to fewer results
- Cached runs (second run onward) are significantly faster

## License

This tool is part of the Tired Labs project. See the main repository for license information.
