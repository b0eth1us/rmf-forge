"""
Loads the bundled ASD STIG XCCDF and provides lookup by Vuln ID.
Also holds the curated Fortify/ZAP category -> ASD Vuln ID + CCI mapping table.
Zero network calls.
"""
import os
import re
from functools import lru_cache
from lxml import etree
from typing import Any

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")

# Curated mapping: Fortify/ZAP vulnerability category -> ASD STIG Vuln ID + CCI
# Format: { category_keyword: { "vuln_ids": [...], "cci_ids": [...] } }
VULN_MAPPING: dict[str, dict] = {
    "sql injection":                 {"vuln_ids": ["V-222604"], "cci_ids": ["CCI-001310", "CCI-002754"]},
    "command injection":             {"vuln_ids": ["V-222607"], "cci_ids": ["CCI-001310"]},
    "cross-site scripting":          {"vuln_ids": ["V-222602"], "cci_ids": ["CCI-001310", "CCI-002602"]},
    "xss":                           {"vuln_ids": ["V-222602"], "cci_ids": ["CCI-001310", "CCI-002602"]},
    "path manipulation":             {"vuln_ids": ["V-222612"], "cci_ids": ["CCI-001310"]},
    "privacy violation":             {"vuln_ids": ["V-222642"], "cci_ids": ["CCI-000196"]},
    "insecure randomness":           {"vuln_ids": ["V-222579"], "cci_ids": ["CCI-002450"]},
    "weak cryptographic hash":       {"vuln_ids": ["V-222576"], "cci_ids": ["CCI-002450"]},
    "weak encryption":               {"vuln_ids": ["V-222576"], "cci_ids": ["CCI-002450"]},
    "password management":           {"vuln_ids": ["V-222647"], "cci_ids": ["CCI-000196"]},
    "hardcoded password":            {"vuln_ids": ["V-222647"], "cci_ids": ["CCI-000196", "CCI-002742"]},
    "hardcoded credential":          {"vuln_ids": ["V-222647"], "cci_ids": ["CCI-002742"]},
    "unreleased resource":           {"vuln_ids": ["V-222667"], "cci_ids": ["CCI-001163"]},
    "null dereference":              {"vuln_ids": ["V-222667"], "cci_ids": ["CCI-001163"]},
    "log forging":                   {"vuln_ids": ["V-222554"], "cci_ids": ["CCI-001312"]},
    "trust boundary violation":      {"vuln_ids": ["V-222609"], "cci_ids": ["CCI-001310"]},
    "xml external entity":           {"vuln_ids": ["V-222608"], "cci_ids": ["CCI-001310"]},
    "xxe":                           {"vuln_ids": ["V-222608"], "cci_ids": ["CCI-001310"]},
    "csrf":                          {"vuln_ids": ["V-222603"], "cci_ids": ["CCI-001310", "CCI-001664"]},
    "cross-site request forgery":    {"vuln_ids": ["V-222603"], "cci_ids": ["CCI-001310", "CCI-001664"]},
    "open redirect":                 {"vuln_ids": ["V-222618"], "cci_ids": ["CCI-001310"]},
    "server-side request forgery":   {"vuln_ids": ["V-222618"], "cci_ids": ["CCI-001310"]},
    "ssrf":                          {"vuln_ids": ["V-222618"], "cci_ids": ["CCI-001310"]},
    "insecure deserialization":      {"vuln_ids": ["V-222609"], "cci_ids": ["CCI-001310"]},
    "improper input validation":     {"vuln_ids": ["V-222604"], "cci_ids": ["CCI-001310"]},
    "buffer overflow":               {"vuln_ids": ["V-222667"], "cci_ids": ["CCI-001163"]},
    "integer overflow":              {"vuln_ids": ["V-222667"], "cci_ids": ["CCI-001163"]},
    "race condition":                {"vuln_ids": ["V-222579"], "cci_ids": ["CCI-001163"]},
    "cleartext":                     {"vuln_ids": ["V-222576"], "cci_ids": ["CCI-002450"]},
    "unencrypted":                   {"vuln_ids": ["V-222576"], "cci_ids": ["CCI-002450"]},
    "session fixation":              {"vuln_ids": ["V-222603"], "cci_ids": ["CCI-001664"]},
    "missing authentication":        {"vuln_ids": ["V-222596"], "cci_ids": ["CCI-000764"]},
    "broken authentication":         {"vuln_ids": ["V-222596"], "cci_ids": ["CCI-000764"]},
    "access control":                {"vuln_ids": ["V-222609"], "cci_ids": ["CCI-000213"]},
    "authorization":                 {"vuln_ids": ["V-222609"], "cci_ids": ["CCI-000213"]},
    "directory listing":             {"vuln_ids": ["V-222612"], "cci_ids": ["CCI-001310"]},
    "information disclosure":        {"vuln_ids": ["V-222642"], "cci_ids": ["CCI-000196"]},
    "error handling":                {"vuln_ids": ["V-222554"], "cci_ids": ["CCI-001312"]},
    "exception":                     {"vuln_ids": ["V-222554"], "cci_ids": ["CCI-001312"]},
}

@lru_cache(maxsize=1)
def load_asd_stig() -> dict[str, dict[str, Any]]:
    """
    Returns {normalized_vuln_id: {title, severity, description, fix_text, raw_id}}
    Normalizes IDs like 'SV-222604r961080_rule' -> 'V-222604'
    """
    stig_file = os.path.join(DATA_DIR, "stig", "ASD_STIG.xml")
    if not os.path.exists(stig_file):
        return {}

    try:
        tree = etree.parse(stig_file)
        root = tree.getroot()
    except Exception:
        return {}

    # Try multiple known XCCDF namespaces
    namespaces_to_try = [
        {"xccdf": "http://checklists.nist.gov/xccdf/1.1"},
        {"xccdf": "http://checklists.nist.gov/xccdf/1.2"},
        {},
    ]

    rules = []
    for ns in namespaces_to_try:
        if ns:
            rules = root.findall(".//xccdf:Rule", ns)
        else:
            rules = root.findall(".//{http://checklists.nist.gov/xccdf/1.1}Rule")
            if not rules:
                rules = root.findall(".//Rule")
        if rules:
            break

    index = {}
    for rule in rules:
        raw_id = rule.get("id", "")
        # Normalize SV-222604r961080_rule -> V-222604
        normalized = _normalize_vuln_id(raw_id)

        ns_used = namespaces_to_try[0] if rules else {}
        if ns_used:
            title = rule.findtext("xccdf:title", namespaces=ns_used) or ""
            severity = rule.get("severity", "")
            desc = rule.findtext("xccdf:description", namespaces=ns_used) or ""
            fix = rule.findtext("xccdf:fixtext", namespaces=ns_used) or ""
            # Extract CCI references
            cci_refs = [
                ident.text for ident in
                rule.findall("xccdf:ident", ns_used)
                if ident.text and ident.text.startswith("CCI-")
            ]
        else:
            title = rule.findtext("title") or ""
            severity = rule.get("severity", "")
            desc = rule.findtext("description") or ""
            fix = rule.findtext("fixtext") or ""
            cci_refs = []

        entry = {
            "title": title,
            "severity": severity,
            "description": desc,
            "fix_text": fix,
            "raw_id": raw_id,
            "cci_ids": cci_refs,
        }
        index[normalized] = entry
        # Also index by raw ID for direct lookups
        index[raw_id] = entry

    return index


def _normalize_vuln_id(raw: str) -> str:
    """
    Normalize STIG rule IDs to V-XXXXXX format.
    SV-222604r961080_rule -> V-222604
    V-222604 -> V-222604
    """
    match = re.search(r'V-(\d+)', raw, re.IGNORECASE)
    if match:
        return f"V-{match.group(1)}"
    return raw


def map_finding_to_stig(title: str, description: str = "") -> dict:
    """
    Given a finding title and description, return the best matching
    Vuln IDs and CCI IDs from the curated mapping table.
    Returns {"vuln_ids": [...], "cci_ids": [...]} or empty lists if no match.
    """
    combined = f"{title} {description}".lower()

    best_match = None
    best_score = 0

    for keyword, mapping in VULN_MAPPING.items():
        if keyword in combined:
            # Prefer longer/more specific keyword matches
            score = len(keyword)
            if score > best_score:
                best_score = score
                best_match = mapping

    if best_match:
        return best_match

    return {"vuln_ids": [], "cci_ids": []}


def map_fortify_to_vuln_ids(category: str) -> list[str]:
    """Legacy function — maps a Fortify category string to Vuln IDs."""
    result = map_finding_to_stig(category)
    return result.get("vuln_ids", [])
