"""
Scanner for finding existing TRRs related to a technique.

Supports two backends:
  - GitHubTRRScanner: fetches from tired-labs/techniques (or any configured repo)
  - ExistingTRRScanner: local filesystem fallback (legacy)
"""

import re
import urllib.parse
from pathlib import Path
from typing import Dict, Optional, List, Tuple
import json

import requests

from utils import create_session


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RAW_BASE = "https://raw.githubusercontent.com/{repo}/{branch}/{path}"
TREE_API = "https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"

# Words that appear frequently in ATT&CK technique names but carry
# little discriminative value for name-based matching against TRR content.
ATTACK_STOPWORDS = frozenset({
    "server", "software", "component", "system", "service",
    "access", "execution", "remote", "credential", "valid",
    "local", "external", "application", "protocol", "domain",
    "trusted", "native", "scheduled", "windows", "create",
    "modify", "default", "network", "use", "abuse",
    "data", "account", "code", "file", "cloud",
    "signed", "binary", "process", "command", "scripts",
    "user", "logon", "event", "traffic", "object",
    "registry", "stored", "manipulation", "discovery",
    "collection", "impact", "resource", "exploit",
    "compromise", "obtain", "establish", "develop",
    "stage", "gather", "phishing",
})


# ---------------------------------------------------------------------------
# Shared content-matching logic (used by both scanner backends)
# ---------------------------------------------------------------------------

def _match_trr_content(
    content: str,
    file_path: str,
    technique_id: str,
    parent_id: str,
    technique_name: str,
) -> Optional[Dict]:
    """
    Return a match-info dict if the file content relates to the technique, else None.

    Match tiers (highest wins):
      exact  (score 100) — technique ID appears verbatim
      parent (score  75) — parent technique ID appears
      name   (score  50) — 2+ meaningful words from the technique name appear
    """
    technique_pattern = rf'\b{re.escape(technique_id)}\b'
    parent_pattern = rf'\b{re.escape(parent_id)}(?:\.\d+)?\b'

    match_type = None
    match_score = 0

    if re.search(technique_pattern, content, re.IGNORECASE):
        match_type = 'exact'
        match_score = 100
    elif re.search(parent_pattern, content, re.IGNORECASE):
        match_type = 'parent'
        match_score = 75
    elif technique_name:
        # For sub-techniques ("Parent: Sub"), focus on the sub-technique name
        matching_name = (
            technique_name.split(":")[-1].strip()
            if ":" in technique_name
            else technique_name
        )

        # Extract distinctive words: >= 3 chars and not in the stopword set
        name_words = [
            w for w in matching_name.lower().split()
            if len(w) >= 3 and w not in ATTACK_STOPWORDS
        ]

        content_lower = content.lower()
        if len(name_words) >= 2:
            # For short names (2-3 words), require the phrase to appear
            # as a unit to avoid matching documents that happen to use each
            # word in unrelated contexts.
            phrase = matching_name.lower()
            if len(name_words) <= 3 and re.search(
                rf'\b{re.escape(phrase)}\b', content_lower
            ):
                match_type = 'name'
                match_score = 50
            elif len(name_words) > 3:
                # Longer names: use whole-word matching with >50% threshold
                word_matches = sum(
                    1 for word in name_words
                    if re.search(rf'\b{re.escape(word)}\b', content_lower)
                )
                threshold = max(2, (len(name_words) + 1) // 2)
                if word_matches >= threshold:
                    match_type = 'name'
                    match_score = 50
        elif len(name_words) == 1:
            # Single distinctive word — require whole-word match to avoid
            # substring false positives (e.g., "shell" in "powershell")
            word = name_words[0]
            if re.search(rf'\b{re.escape(word)}\b', content_lower):
                match_type = 'name'
                match_score = 40

    if match_type is None:
        return None

    file_name = file_path.split("/")[-1] if "/" in file_path else Path(file_path).name
    return {
        'file_path': file_path,
        'file_name': file_name,
        'match_type': match_type,
        'match_score': match_score,
        'trr_id': _extract_trr_id(content),
        'techniques': _extract_technique_ids(content),
        'references': _extract_references(content),
        'title': _extract_title(content),
    }


def _extract_trr_id(content: str) -> Optional[str]:
    """Extract TRR ID from content."""
    patterns = [
        r'TRR\s*ID[:\s]+(TRR\d+)',
        r'\*\*ID\*\*[:\s]*(TRR\d+)',
        r'\|\s*ID\s*\|\s*(TRR\d+)',
        r'(TRR\d{4})',
    ]
    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1).upper()
    return None


def _extract_technique_ids(content: str) -> List[str]:
    """Extract all MITRE ATT&CK technique IDs from content."""
    pattern = r'\b(T\d{4}(?:\.\d{3})?)\b'
    matches = re.findall(pattern, content, re.IGNORECASE)
    return list(set(m.upper() for m in matches))


def _extract_references(content: str) -> List[Dict]:
    """Extract markdown links from the References section."""
    references = []
    ref_pattern = r'##\s*References\s*\n(.*?)(?=##|$)'
    match = re.search(ref_pattern, content, re.IGNORECASE | re.DOTALL)
    if match:
        ref_section = match.group(1)
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        for link_match in re.finditer(link_pattern, ref_section):
            references.append({
                'name': link_match.group(1).strip(),
                'url': link_match.group(2).strip(),
            })
        if not references:
            for url_match in re.finditer(r'https?://[^\s\)]+', ref_section):
                references.append({'name': 'Reference', 'url': url_match.group(0)})
    return references


def _extract_title(content: str) -> str:
    """Extract the first H1 header as the title."""
    match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    return match.group(1).strip() if match else ""


# ---------------------------------------------------------------------------
# GitHub backend
# ---------------------------------------------------------------------------

class GitHubTRRScanner:
    """
    Fetches TRR and DDM files from a public GitHub repository.

    Uses the Git Trees API (one API call) to enumerate files, then fetches
    content via raw.githubusercontent.com (no rate-limit impact).

    Expected repo structure:
        reports/
          trr0011/
            <technique-slug>/
              README.md        ← TRR document
              ddms/
                ddm_*.json     ← DDM files
    """

    def __init__(
        self,
        github_repo: str,
        branch: str = "main",
        reports_path: str = "reports",
        user_agent: str = "",
    ):
        self.github_repo = github_repo
        self.branch = branch
        self.reports_path = reports_path.rstrip("/")
        self.session = create_session(user_agent or "TRR-Source-Scraper/1.0")
        self.session.headers.update({"Accept": "application/vnd.github.v3+json"})
        self._tree: Optional[List[Dict]] = None  # cached after first fetch

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_tree(self) -> List[Dict]:
        """Fetch the full repo file tree (cached for the lifetime of this instance)."""
        if self._tree is not None:
            return self._tree
        url = TREE_API.format(repo=self.github_repo, branch=self.branch)
        try:
            r = self.session.get(url, timeout=15)
            r.raise_for_status()
            self._tree = r.json().get("tree", [])
        except Exception as e:
            print(f"  [warn] Could not fetch repo tree from GitHub ({e})")
            self._tree = []
        return self._tree

    def _raw_url(self, path: str) -> str:
        encoded = urllib.parse.quote(path, safe="/")
        return RAW_BASE.format(repo=self.github_repo, branch=self.branch, path=encoded)

    def _github_url(self, path: str) -> str:
        encoded = urllib.parse.quote(path, safe="/")
        return f"https://github.com/{self.github_repo}/blob/{self.branch}/{encoded}"

    def _fetch_text(self, path: str) -> Optional[str]:
        try:
            r = self.session.get(self._raw_url(path), timeout=15)
            r.raise_for_status()
            return r.text
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Public interface (mirrors ExistingTRRScanner)
    # ------------------------------------------------------------------

    def find_related_trrs(self, technique_id: str, technique_name: str = "") -> List[Dict]:
        """
        Find TRR README.md files that match the technique.

        Looks for files at depth: reports/<trr_id>/<slug>/README.md
        (exactly 3 forward-slashes after the prefix).
        """
        tree = self._get_tree()
        technique_id = technique_id.upper().strip()
        parent_id = technique_id.split(".")[0]

        prefix = self.reports_path + "/"
        readme_paths = [
            e["path"] for e in tree
            if e.get("type") == "blob"
            and e["path"].startswith(prefix)
            and e["path"].endswith("/README.md")
            and e["path"].count("/") == 3  # reports / trr#### / slug / README.md
        ]

        results = []
        for path in readme_paths:
            content = self._fetch_text(path)
            if content is None:
                continue
            match = _match_trr_content(content, path, technique_id, parent_id, technique_name)
            if match:
                match["github_url"] = self._github_url(path)
                results.append(match)

        return results

    def find_ddm_files(
        self,
        technique_id: str,
        matched_trr_prefixes: Optional[set] = None,
    ) -> List[Dict]:
        """
        Find DDM JSON files related to the technique.

        If matched_trr_prefixes is provided (set of 'reports/trr####/slug' strings
        from a prior find_related_trrs call), DDMs are found by path prefix alone —
        no content fetch needed.

        Otherwise, falls back to fetching each DDM JSON and checking for the
        technique ID in the content.
        """
        tree = self._get_tree()
        technique_id = technique_id.upper().strip()

        prefix = self.reports_path + "/"
        ddm_paths = [
            e["path"] for e in tree
            if e.get("type") == "blob"
            and e["path"].startswith(prefix)
            and "/ddms/" in e["path"]
            and e["path"].endswith(".json")
        ]

        results = []
        for path in ddm_paths:
            matched = False

            if matched_trr_prefixes:
                # e.g. path = "reports/trr0011/ad/ddms/ddm_trr0011_ad_a.json"
                # trr_prefix  = "reports/trr0011/ad"
                trr_prefix = path.rsplit("/ddms/", 1)[0]
                matched = trr_prefix in matched_trr_prefixes
            else:
                content = self._fetch_text(path)
                matched = content is not None and technique_id in content

            if matched:
                results.append({
                    "file_path": path,
                    "file_name": path.split("/")[-1],
                    "technique_id": technique_id,
                    "github_url": self._github_url(path),
                })

        return results


# ---------------------------------------------------------------------------
# Legacy local filesystem backend (kept for completeness)
# ---------------------------------------------------------------------------

class ExistingTRRScanner:
    """
    Scans a local Completed TRRs directory for existing reports.
    Used only when no GitHub repo is configured.
    """

    def __init__(self, trr_directory: Optional[Path] = None):
        if trr_directory is None:
            script_dir = Path(__file__).parent
            project_root = script_dir.parent.parent.parent
            trr_directory = project_root / "Completed TRRs"
        self.trr_directory = Path(trr_directory)

    def find_related_trrs(self, technique_id: str, technique_name: str = "") -> List[Dict]:
        if not self.trr_directory.exists():
            return []
        technique_id = technique_id.upper().strip()
        parent_id = technique_id.split(".")[0]
        results = []
        for trr_file in self.trr_directory.glob("*.md"):
            try:
                content = trr_file.read_text(encoding="utf-8")
            except Exception:
                continue
            match = _match_trr_content(
                content, str(trr_file), technique_id, parent_id, technique_name
            )
            if match:
                results.append(match)
        return results

    def find_ddm_files(self, technique_id: str) -> List[Dict]:
        if not self.trr_directory.exists():
            return []
        ddm_dir = self.trr_directory.parent / "Completed DDMs"
        if not ddm_dir.exists():
            return []
        results = []
        for ddm_file in ddm_dir.glob("*.json"):
            try:
                content = json.loads(ddm_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            if self._ddm_matches_technique(ddm_file.name, content, technique_id):
                results.append({
                    "file_path": str(ddm_file),
                    "file_name": ddm_file.name,
                    "technique_id": technique_id,
                })
        return results

    def _ddm_matches_technique(self, filename: str, content: Dict, technique_id: str) -> bool:
        if technique_id.replace(".", "_") in filename:
            return True
        return technique_id in json.dumps(content)


# ---------------------------------------------------------------------------
# Convenience function (called from trr_scraper.py)
# ---------------------------------------------------------------------------

def scan_for_existing_trrs(
    technique_id: str,
    technique_name: str = "",
    trr_directory: Optional[Path] = None,
    github_repo: str = "",
    branch: str = "main",
    reports_path: str = "reports",
    user_agent: str = "",
) -> Tuple[List[Dict], List[Dict]]:
    """
    Scan for existing TRRs and DDMs, using GitHub if configured.

    Args:
        technique_id:    MITRE ATT&CK technique ID
        technique_name:  Human-readable name for fuzzy matching
        trr_directory:   Local directory (legacy, ignored when github_repo is set)
        github_repo:     GitHub repo slug, e.g. 'tired-labs/techniques'
        branch:          Branch to use (default: main)
        reports_path:    Path within the repo where reports live (default: reports)
        user_agent:      HTTP user-agent string

    Returns:
        Tuple of (trr_list, ddm_list)
    """
    if github_repo:
        scanner = GitHubTRRScanner(github_repo, branch, reports_path, user_agent)
        trrs = scanner.find_related_trrs(technique_id, technique_name)
        # Derive TRR prefixes so DDM lookup is path-based (no extra network fetches)
        matched_prefixes = {
            t["file_path"].rsplit("/ddms/", 1)[0]  # won't split README paths; safe
            if "/ddms/" in t["file_path"]
            else "/".join(t["file_path"].split("/")[:3])  # reports/trr####/slug
            for t in trrs
        }
        # Build prefixes from the README paths: reports/trr####/slug/README.md → reports/trr####/slug
        matched_prefixes = {
            t["file_path"].rsplit("/README.md", 1)[0] for t in trrs
        }
        ddms = scanner.find_ddm_files(technique_id, matched_trr_prefixes=matched_prefixes)
        return trrs, ddms
    else:
        scanner = ExistingTRRScanner(trr_directory)
        return (
            scanner.find_related_trrs(technique_id, technique_name),
            scanner.find_ddm_files(technique_id),
        )
