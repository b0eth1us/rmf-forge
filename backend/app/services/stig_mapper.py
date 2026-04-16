"""
Loads the bundled ASD STIG XCCDF and provides lookup by Vuln ID.
Also holds the curated Fortify category -> ASD Vuln ID mapping table.
Zero network calls.
"""
import os
import json
from functools import lru_cache
from lxml import etree
from typing import Any

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")

# Curated mapping: Fortify vulnerability category -> ASD STIG Vuln ID(s)
FORTIFY_TO_ASD: dict[str, list[str]] = {
    "SQL Injection":                    ["V-222604"],
    "Command Injection":                ["V-222607"],
    "Cross-Site Scripting":             ["V-222602"],
    "Path Manipulation":                ["V-222612"],
    "Privacy Violation":                ["V-222642"],
    "Insecure Randomness":              ["V-222579"],
    "Weak Cryptographic Hash":          ["V-222576"],
    "Password Management":              ["V-222647"],
    "Hardcoded Password":               ["V-222647"],
    "Unreleased Resource":              ["V-222667"],
    "Null Dereference":                 ["V-222667"],
    "Log Forging":                      ["V-222554"],
    "Trust Boundary Violation":         ["V-222609"],
    "XML External Entity Injection":    ["V-222608"],
    "CSRF":                             ["V-222603"],
    "Open Redirect":                    ["V-222618"],
    "Server-Side Request Forgery":      ["V-222618"],
}

@lru_cache(maxsize=1)
def load_asd_stig() -> dict[str, dict[str, Any]]:
    """Returns {vuln_id: {title, severity, description, fix_text, ...}}"""
    stig_file = os.path.join(DATA_DIR, "stig", "ASD_STIG.xml")
    if not os.path.exists(stig_file):
        return {}
    tree = etree.parse(stig_file)
    root = tree.getroot()
    ns = {"xccdf": "http://checklists.nist.gov/xccdf/1.1"}
    index = {}
    for rule in root.findall(".//xccdf:Rule", ns):
        vuln_id = rule.get("id", "")
        title = rule.findtext("xccdf:title", namespaces=ns) or ""
        severity = rule.get("severity", "")
        desc = rule.findtext("xccdf:description", namespaces=ns) or ""
        fix = rule.findtext("xccdf:fixtext", namespaces=ns) or ""
        index[vuln_id] = {"title": title, "severity": severity, "description": desc, "fix_text": fix}
    return index

def map_fortify_to_vuln_ids(category: str) -> list[str]:
    return FORTIFY_TO_ASD.get(category, [])
