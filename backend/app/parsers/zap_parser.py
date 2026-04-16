"""
Parses OWASP ZAP XML and JSON report exports.
"""
import json
from lxml import etree
from typing import Any

def parse_zap_xml(file_bytes: bytes) -> list[dict[str, Any]]:
    findings = []
    root = etree.fromstring(file_bytes)
    for alert in root.findall(".//alertitem"):
        findings.append({
            "source_tool": "zap",
            "plugin_id": alert.findtext("pluginid") or "",
            "title": alert.findtext("name") or "",
            "severity": alert.findtext("riskdesc") or "",
            "description": alert.findtext("desc") or "",
            "cwe_id": alert.findtext("cweid") or "",
            "cve_id": "",
            "solution": alert.findtext("solution") or "",
        })
    return findings

def parse_zap_json(file_bytes: bytes) -> list[dict[str, Any]]:
    data = json.loads(file_bytes)
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            findings.append({
                "source_tool": "zap",
                "plugin_id": alert.get("pluginid", ""),
                "title": alert.get("name", ""),
                "severity": alert.get("riskdesc", ""),
                "description": alert.get("desc", ""),
                "cwe_id": str(alert.get("cweid", "")),
                "cve_id": "",
                "solution": alert.get("solution", ""),
            })
    return findings
