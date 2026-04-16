"""
Parses Fortify .fpr files (which are ZIP archives containing FVDL XML)
and Fortify CSV exports into a normalized list of finding dicts.
"""
import zipfile
import io
from lxml import etree
from typing import Any

def parse_fpr(file_bytes: bytes) -> list[dict[str, Any]]:
    findings = []
    with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
        fvdl_name = next((n for n in zf.namelist() if n.endswith(".fvdl")), None)
        if not fvdl_name:
            raise ValueError("No .fvdl found inside .fpr archive")
        fvdl_bytes = zf.read(fvdl_name)

    root = etree.fromstring(fvdl_bytes)
    ns = {"fvdl": "xmlns://www.fortifysoftware.com/schema/fvdl"}

    for vuln in root.findall(".//fvdl:Vulnerability", ns):
        cid = vuln.findtext("fvdl:ClassInfo/fvdl:Type", namespaces=ns) or ""
        kingdom = vuln.findtext("fvdl:ClassInfo/fvdl:Kingdom", namespaces=ns) or ""
        severity = vuln.findtext("fvdl:InstanceInfo/fvdl:Confidence", namespaces=ns) or ""
        findings.append({
            "source_tool": "fortify",
            "plugin_id": cid,
            "title": f"{kingdom}: {cid}",
            "severity": severity,
            "description": "",
            "raw": etree.tostring(vuln, encoding="unicode"),
        })
    return findings
