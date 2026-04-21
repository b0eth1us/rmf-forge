"""
OWASP ZAP report parser.
Handles both XML and JSON export formats from ZAP 2.x and 2.14+.
"""
import json
import re
from lxml import etree
from typing import Any


def parse_zap_xml(file_bytes: bytes) -> list[dict[str, Any]]:
    try:
        root = etree.fromstring(file_bytes)
    except etree.XMLSyntaxError as e:
        raise ValueError(f"Invalid ZAP XML: {e}")

    findings = []
    alert_items = (
        root.findall(".//alertitem") or
        root.findall(".//alert") or
        root.findall(".//OWASPZAPReport/site/alerts/alertitem")
    )

    for alert in alert_items:
        findings.append({
            "source_tool": "zap",
            "plugin_id": alert.findtext("pluginid") or alert.findtext("pluginId") or "",
            "title": alert.findtext("name") or alert.findtext("alert") or "",
            "severity": _normalize_severity(
                alert.findtext("riskdesc") or alert.findtext("riskDesc") or
                alert.findtext("risk") or ""
            ),
            "description": _strip_html(alert.findtext("desc") or alert.findtext("description") or ""),
            "cwe_id": (alert.findtext("cweid") or alert.findtext("cweId") or "").strip(),
            "cve_id": (alert.findtext("cveid") or alert.findtext("cveId") or "").strip(),
            "solution": _strip_html(alert.findtext("solution") or ""),
            "affected_url": alert.findtext("uri") or alert.findtext("url") or "",
        })
    return findings


def parse_zap_json(file_bytes: bytes) -> list[dict[str, Any]]:
    try:
        data = json.loads(file_bytes)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid ZAP JSON: {e}")

    findings = []
    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    if sites:
        for site in sites:
            for alert in site.get("alerts", []):
                findings.append(_alert_to_dict(alert))
    elif "alerts" in data:
        for alert in data["alerts"]:
            findings.append(_alert_to_dict(alert))
    elif isinstance(data, list):
        for alert in data:
            findings.append(_alert_to_dict(alert))

    return findings


def _alert_to_dict(alert: dict) -> dict[str, Any]:
    return {
        "source_tool": "zap",
        "plugin_id": str(alert.get("pluginid", alert.get("pluginId", ""))),
        "title": alert.get("name", alert.get("alert", "")),
        "severity": _normalize_severity(
            alert.get("riskdesc", alert.get("riskDesc", alert.get("risk", "")))
        ),
        "description": _strip_html(alert.get("desc", alert.get("description", ""))),
        "cwe_id": str(alert.get("cweid", alert.get("cweId", ""))).strip(),
        "cve_id": str(alert.get("cveid", alert.get("cveId", ""))).strip(),
        "solution": _strip_html(alert.get("solution", "")),
        "affected_url": alert.get("uri", alert.get("url", "")),
    }


def _normalize_severity(raw: str) -> str:
    mapping = {
        "high": "High", "3": "High",
        "medium": "Medium", "2": "Medium",
        "low": "Low", "1": "Low",
        "informational": "Informational", "info": "Informational", "0": "Informational",
        "critical": "Critical",
    }
    key = (raw or "").lower().split()[0]
    return mapping.get(key, raw or "Unknown")


def _strip_html(text: str) -> str:
    if not text:
        return ""
    try:
        from lxml.html import fromstring
        return fromstring(text).text_content().strip()
    except Exception:
        return re.sub(r"<[^>]+>", "", text).strip()
