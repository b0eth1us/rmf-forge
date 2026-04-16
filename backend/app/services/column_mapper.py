"""
Fuzzy column mapper — no AI, no network calls.
Uses Levenshtein distance + a curated alias table to suggest
column merges across Fortify, ZAP, and arbitrary CSV/Excel inputs.
"""
from Levenshtein import distance as levenshtein
from typing import Any

# Curated alias groups: canonical name -> list of known aliases
ALIAS_GROUPS: dict[str, list[str]] = {
    "severity":      ["severity", "risk level", "criticality", "priority", "risk rating", "cvss score"],
    "title":         ["title", "name", "vulnerability name", "finding name", "issue name", "check name"],
    "description":   ["description", "details", "summary", "finding details", "issue description"],
    "plugin_id":     ["plugin id", "rule id", "check id", "vuln id", "issue id", "finding id"],
    "cwe_id":        ["cwe", "cwe id", "cwe number", "weakness id"],
    "cve_id":        ["cve", "cve id", "cve number"],
    "host":          ["host", "hostname", "ip address", "target", "system", "asset"],
    "port":          ["port", "port number", "service port"],
    "solution":      ["solution", "remediation", "fix", "recommendation", "mitigation"],
    "source_tool":   ["source", "tool", "scanner", "source tool"],
}

def _normalize(s: str) -> str:
    return s.lower().strip().replace("_", " ").replace("-", " ")

def suggest_mapping(columns: list[str], threshold: int = 3) -> dict[str, list[dict[str, Any]]]:
    """
    Given a list of raw column headers, return suggested canonical mappings.
    Returns: { canonical_name: [{"original": col, "confidence": 0-1}, ...] }
    """
    suggestions: dict[str, list[dict]] = {k: [] for k in ALIAS_GROUPS}
    unmatched: list[str] = []

    for col in columns:
        norm = _normalize(col)
        best_canonical = None
        best_score = float("inf")

        for canonical, aliases in ALIAS_GROUPS.items():
            for alias in aliases:
                d = levenshtein(norm, alias)
                if d < best_score:
                    best_score = d
                    best_canonical = canonical

        if best_score <= threshold:
            confidence = max(0.0, 1.0 - (best_score / max(len(norm), 1)))
            suggestions[best_canonical].append({
                "original": col,
                "confidence": round(confidence, 2),
                "distance": best_score,
            })
        else:
            unmatched.append(col)

    # Remove empty canonical slots
    suggestions = {k: v for k, v in suggestions.items() if v}
    suggestions["__unmatched__"] = [{"original": c, "confidence": 0.0, "distance": -1} for c in unmatched]
    return suggestions
