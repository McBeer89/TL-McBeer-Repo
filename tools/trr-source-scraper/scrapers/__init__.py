"""
Scraper modules for the TRR Source Scraper.
"""

from scrapers.mitre_attack import MitreAttackScraper, fetch_mitre_technique
from scrapers.duckduckgo import DuckDuckGoScraper, search_technique_sources
from scrapers.site_fetcher import SiteFetcher, enrich_search_results, validate_search_result_links
from scrapers.atomic_red_team import fetch_atomic_tests

__all__ = [
    'MitreAttackScraper',
    'fetch_mitre_technique',
    'DuckDuckGoScraper',
    'search_technique_sources',
    'SiteFetcher',
    'enrich_search_results',
    'validate_search_result_links',
    'fetch_atomic_tests',
]