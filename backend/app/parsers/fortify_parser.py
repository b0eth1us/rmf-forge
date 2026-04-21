"""
Fortify .fpr parser.

A .fpr file is a ZIP archive containing:
  - *.fvdl         — vulnerability data (findings, snippets, taint traces)
  - audit.xml      — developer comments and audit decisions
  - (other files)

This parser:
1. Reads both fvdl and audit.xml from the ZIP
2. Parses audit.xml for developer comments and audit actions (Not an Issue, Suppressed)
3. Parses FVDL for vulnerabilities, code snippets, and taint traces
4. Joins audit data to findings by InstanceID
"""
import zipfile
import io
import re
from lxml import etree
from typing import Any


# Fortify confidence (0.0-5.0) -> severity label
def _confidence_to_severity(val: str) -> str:
    try:
        f = float(val)
        if f >= 4.0: return "Critical"
        if f >= 3.0: return "High"
        if f >= 2.0: return "Medium"
        return "Low"
    except (ValueError, TypeError):
        return val or "Unknown"


def _try_ns(root: etree._Element, xpath: str, namespaces: dict) -> list:
    """Try xpath with namespace, fall back to no-namespace version."""
    results = root.findall(xpath, namespaces)
    if not results:
        # Strip namespace prefix and try bare
        bare = re.sub(r'\w+:', '', xpath)
        results = root.findall(bare)
    return results


def parse_audit_xml(audit_bytes: bytes) -> dict[str, dict]:
    """
    Parse audit.xml and return {instance_id: {comment, action}} mapping.
    audit.xml structure:
      <IssueList>
        <Issue iid="...">
          <Tag id="...">
            <Value>comment text</Value>
          </Tag>
          <Suppressed>true</Suppressed>
          <NotAnIssue>true</NotAnIssue>
        </Issue>
      </IssueList>
    """
    audit_map: dict[str, dict] = {}
    try:
        root = etree.fromstring(audit_bytes)
    except etree.XMLSyntaxError:
        return audit_map

    # audit.xml may or may not have a namespace
    issues = root.findall(".//Issue")
    if not issues:
        issues = root.findall(".//{http://www.fortifysoftware.com/schema/audit}Issue")

    for issue in issues:
        iid = issue.get("iid", "")
        if not iid:
            continue

        # Extract comment — stored in Tag/Value elements
        comment_parts = []
        for tag in issue.findall(".//Tag"):
            for val in tag.findall(".//Value"):
                if val.text and val.text.strip():
                    comment_parts.append(val.text.strip())
        comment = " | ".join(comment_parts) if comment_parts else ""

        # Determine audit action
        action = ""
        suppressed = issue.findtext(".//Suppressed") or issue.findtext("Suppressed") or ""
        not_an_issue = issue.findtext(".//NotAnIssue") or issue.findtext("NotAnIssue") or ""
        if suppressed.lower() == "true":
            action = "Suppressed"
        elif not_an_issue.lower() == "true":
            action = "Not an Issue"

        audit_map[iid] = {"comment": comment, "action": action}

    return audit_map


def _parse_snippets(root: etree._Element, ns: dict) -> dict[str, dict]:
    """
    Extract code snippets from FVDL <Snippets> section.
    Returns {snippet_id: {file, start_line, end_line, text}}
    """
    snippets: dict[str, dict] = {}
    snippet_elements = _try_ns(root, ".//fvdl:Snippets/fvdl:Snippet", ns)
    if not snippet_elements:
        snippet_elements = root.findall(".//Snippets/Snippet")

    for snip in snippet_elements:
        sid = snip.get("id", "")
        if ns:
            file_el = snip.find("fvdl:File", ns)
            start_el = snip.find("fvdl:StartLine", ns)
            end_el = snip.find("fvdl:EndLine", ns)
            text_el = snip.find("fvdl:Text", ns)
        else:
            file_el = snip.find("File")
            start_el = snip.find("StartLine")
            end_el = snip.find("EndLine")
            text_el = snip.find("Text")

        snippets[sid] = {
            "file": file_el.text if file_el is not None else "",
            "start_line": int(start_el.text) if start_el is not None and start_el.text else 0,
            "end_line": int(end_el.text) if end_el is not None and end_el.text else 0,
            "text": text_el.text if text_el is not None else "",
        }
    return snippets


def _parse_node_pool(root: etree._Element, ns: dict) -> dict[str, dict]:
    """
    Extract NodePool entries (used to reconstruct taint traces).
    Returns {node_id: {file, line, snippet_id}}
    """
    nodes: dict[str, dict] = {}
    node_elements = _try_ns(root, ".//fvdl:NodePool/fvdl:Node", ns)
    if not node_elements:
        node_elements = root.findall(".//NodePool/Node")

    for node in node_elements:
        nid = node.get("id", "")
        if ns:
            loc = node.find("fvdl:SourceLocation", ns)
        else:
            loc = node.find("SourceLocation")

        if loc is not None:
            nodes[nid] = {
                "file": loc.get("path", ""),
                "line": int(loc.get("line", 0) or 0),
                "snippet_id": loc.get("snippet", ""),
            }
    return nodes


def _build_taint_trace(trace_el: etree._Element, ns: dict, node_pool: dict) -> str:
    """
    Build a human-readable taint trace string from a <Trace> element.
    e.g. "login.py:42 → session.py:88 → db.py:107"
    """
    steps = []
    if ns:
        entries = trace_el.findall(".//fvdl:NodeRef", ns)
    else:
        entries = trace_el.findall(".//NodeRef")

    for entry in entries:
        nid = entry.get("id", "")
        node = node_pool.get(nid)
        if node and node.get("file"):
            fname = node["file"].split("/")[-1]  # basename only
            line = node.get("line", "?")
            step = f"{fname}:{line}"
            if not steps or steps[-1] != step:
                steps.append(step)

    return " → ".join(steps) if steps else ""


def parse_fpr(file_bytes: bytes) -> list[dict[str, Any]]:
    """
    Parse a Fortify .fpr file. Returns list of normalized finding dicts.
    Each dict includes audit comments, code snippets, and taint traces.
    """
    # --- Read ZIP contents ---
    try:
        zf_obj = zipfile.ZipFile(io.BytesIO(file_bytes))
    except zipfile.BadZipFile:
        raise ValueError("Invalid .fpr file — not a valid ZIP archive")

    with zf_obj as zf:
        names = zf.namelist()

        fvdl_name = next((n for n in names if n.endswith(".fvdl")), None)
        if not fvdl_name:
            raise ValueError("No .fvdl found inside .fpr archive")
        fvdl_bytes = zf.read(fvdl_name)

        audit_bytes = None
        audit_name = next((n for n in names if n.endswith("audit.xml")), None)
        if audit_name:
            audit_bytes = zf.read(audit_name)

    # --- Parse audit.xml ---
    audit_map: dict[str, dict] = {}
    if audit_bytes:
        audit_map = parse_audit_xml(audit_bytes)

    # --- Parse FVDL ---
    try:
        fvdl_root = etree.fromstring(fvdl_bytes)
    except etree.XMLSyntaxError as e:
        raise ValueError(f"Could not parse FVDL XML: {e}")

    # Detect namespace
    ns: dict = {}
    for candidate in [
        {"fvdl": "xmlns://www.fortifysoftware.com/schema/fvdl"},
        {"fvdl": "http://www.fortifysoftware.com/schema/fvdl"},
        {"fvdl": "http://www.fortify.com/schema/fvdl"},
    ]:
        if fvdl_root.findall(".//fvdl:Vulnerability", candidate):
            ns = candidate
            break

    # Extract supporting structures
    snippets = _parse_snippets(fvdl_root, ns)
    node_pool = _parse_node_pool(fvdl_root, ns)

    # Get vulnerabilities
    if ns:
        vulns = fvdl_root.findall(".//fvdl:Vulnerability", ns)
    else:
        vulns = fvdl_root.findall(".//Vulnerability")

    findings: list[dict[str, Any]] = []

    for vuln in vulns:
        def t(path: str) -> str:
            el = vuln.find(path, ns) if ns else vuln.find(re.sub(r'\w+:', '', path))
            return (el.text or "").strip() if el is not None else ""

        # Core fields
        instance_id = t("fvdl:InstanceInfo/fvdl:InstanceID") or t("InstanceInfo/InstanceID")
        cid = t("fvdl:ClassInfo/fvdl:Type") or t("ClassInfo/Type")
        kingdom = t("fvdl:ClassInfo/fvdl:Kingdom") or t("ClassInfo/Kingdom")
        confidence = t("fvdl:InstanceInfo/fvdl:Confidence") or t("InstanceInfo/Confidence")
        analyzer = t("fvdl:ClassInfo/fvdl:AnalyzerName") or t("ClassInfo/AnalyzerName")

        # Primary source location
        if ns:
            src_locs = vuln.findall(".//fvdl:SourceLocation", ns)
        else:
            src_locs = vuln.findall(".//SourceLocation")

        file_path = ""
        line_number = 0
        code_snippet_text = ""
        if src_locs:
            loc = src_locs[0]
            file_path = loc.get("path", "")
            try:
                line_number = int(loc.get("line", 0) or 0)
            except (ValueError, TypeError):
                line_number = 0
            snippet_id = loc.get("snippet", "")
            if snippet_id and snippet_id in snippets:
                code_snippet_text = snippets[snippet_id].get("text", "")

        # Taint trace
        taint_trace_str = ""
        if ns:
            trace_els = vuln.findall(".//fvdl:Trace", ns)
        else:
            trace_els = vuln.findall(".//Trace")
        if trace_els:
            taint_trace_str = _build_taint_trace(trace_els[0], ns, node_pool)

        # Join audit data
        audit_data = audit_map.get(instance_id, {})

        findings.append({
            "source_tool": "fortify",
            "plugin_id": instance_id or cid,
            "title": f"{kingdom}: {cid}" if kingdom else cid,
            "severity": _confidence_to_severity(confidence),
            "description": f"Fortify {analyzer} finding: {cid}" + (f" in {kingdom}" if kingdom else ""),
            "cwe_id": "",
            "file_path": file_path,
            "line_number": line_number,
            "code_snippet": code_snippet_text,
            "taint_trace": taint_trace_str,
            "audit_comment": audit_data.get("comment", ""),
            "audit_action": audit_data.get("action", ""),
        })

    return findings
