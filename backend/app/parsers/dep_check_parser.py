"""
OWASP Dependency Check parser.
Handles both XML (dependency-check-report.xml) and JSON output formats.
"""
import json
from lxml import etree
from typing import Any


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"


def parse_dep_check_xml(file_bytes: bytes) -> list[dict[str, Any]]:
    try:
        root = etree.fromstring(file_bytes)
    except etree.XMLSyntaxError as e:
        raise ValueError(f"Invalid Dependency Check XML: {e}")

    # Detect namespace
    ns_candidates = [
        {"dc": "https://jeremylong.github.io/DependencyCheck/dependency-check.2.5.xsd"},
        {"dc": "https://jeremylong.github.io/DependencyCheck/dependency-check.2.4.xsd"},
        {},
    ]

    dependencies = []
    ns_used = {}
    for ns in ns_candidates:
        deps = root.findall(".//dc:dependency", ns) if ns else root.findall(".//dependency")
        if deps:
            dependencies = deps
            ns_used = ns
            break

    findings = []
    for dep in dependencies:
        if ns_used:
            dep_name = dep.findtext("dc:fileName", namespaces=ns_used) or ""
            dep_version = dep.findtext("dc:version", namespaces=ns_used) or ""
            vulns = dep.findall(".//dc:vulnerability", ns_used)
        else:
            dep_name = dep.findtext("fileName") or ""
            dep_version = dep.findtext("version") or ""
            vulns = dep.findall(".//vulnerability")

        for vuln in vulns:
            if ns_used:
                name = vuln.findtext("dc:name", namespaces=ns_used) or ""
                desc = vuln.findtext("dc:description", namespaces=ns_used) or ""
                cvss_score_str = vuln.findtext(".//dc:cvssV3/dc:baseScore", namespaces=ns_used) or \
                                 vuln.findtext(".//dc:cvssV2/dc:score", namespaces=ns_used) or "0"
                cwe_raw = vuln.findtext("dc:cwe", namespaces=ns_used) or ""
            else:
                name = vuln.findtext("name") or ""
                desc = vuln.findtext("description") or ""
                cvss_score_str = vuln.findtext(".//cvssV3/baseScore") or \
                                 vuln.findtext(".//cvssV2/score") or "0"
                cwe_raw = vuln.findtext("cwe") or ""

            try:
                cvss_score = float(cvss_score_str)
            except (ValueError, TypeError):
                cvss_score = 0.0

            # Extract bare CWE number
            cwe_id = ""
            if cwe_raw:
                import re
                m = re.search(r'CWE-(\d+)', cwe_raw, re.IGNORECASE)
                cwe_id = m.group(1) if m else cwe_raw.strip()

            findings.append({
                "source_tool": "dep_check",
                "plugin_id": name,
                "title": f"{dep_name}: {name}",
                "severity": _cvss_to_severity(cvss_score),
                "description": desc,
                "cwe_id": cwe_id,
                "cve_id": name if name.startswith("CVE-") else "",
                "dependency_name": dep_name,
                "dependency_version": dep_version,
                "affected_url": "",
            })

    return findings


def parse_dep_check_json(file_bytes: bytes) -> list[dict[str, Any]]:
    try:
        data = json.loads(file_bytes)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid Dependency Check JSON: {e}")

    findings = []
    for dep in data.get("dependencies", []):
        dep_name = dep.get("fileName", dep.get("filePath", ""))
        dep_version = dep.get("version", "")
        for vuln in dep.get("vulnerabilities", []):
            name = vuln.get("name", "")
            desc = vuln.get("description", "")
            cvss = float(
                vuln.get("cvssv3", {}).get("baseScore") or
                vuln.get("cvssv2", {}).get("score") or 0
            )
            cwe_raw = " ".join(c.get("cweId", "") for c in vuln.get("cwes", []))

            import re
            m = re.search(r'CWE-(\d+)', cwe_raw, re.IGNORECASE)
            cwe_id = m.group(1) if m else ""

            findings.append({
                "source_tool": "dep_check",
                "plugin_id": name,
                "title": f"{dep_name}: {name}",
                "severity": _cvss_to_severity(cvss),
                "description": desc,
                "cwe_id": cwe_id,
                "cve_id": name if name.startswith("CVE-") else "",
                "dependency_name": dep_name,
                "dependency_version": dep_version,
                "affected_url": "",
            })

    return findings
