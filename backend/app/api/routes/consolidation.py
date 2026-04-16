from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Form
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.project import Project
from app.models.finding import Finding, FindingStatus
from app.models.import_log import ImportLog
from app.services.column_mapper import suggest_mapping
from app.services.finding_hasher import stable_key
from app.parsers.fortify_parser import parse_fpr
from app.parsers.zap_parser import parse_zap_xml, parse_zap_json
import hashlib, json, io, uuid
from openpyxl import load_workbook
import csv as csvlib

router = APIRouter()

def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _parse_csv(data: bytes) -> list[dict]:
    text = data.decode("utf-8-sig", errors="replace")
    reader = csvlib.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]

def _parse_xlsx(data: bytes) -> list[dict]:
    wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        return []
    headers = [str(h) if h is not None else f"col_{i}" for i, h in enumerate(rows[0])]
    return [dict(zip(headers, row)) for row in rows[1:]]

def _detect_tool(filename: str, data: bytes) -> str:
    fn = filename.lower()
    if fn.endswith(".fpr"):
        return "fortify"
    if fn.endswith(".json"):
        return "zap_json"
    if fn.endswith(".xml"):
        # peek for ZAP signature
        if b"<OWASPZAPReport" in data[:512] or b"<report>" in data[:512]:
            return "zap_xml"
        return "xml_generic"
    if fn.endswith(".csv"):
        return "csv"
    if fn.endswith((".xlsx", ".xls")):
        return "xlsx"
    return "unknown"

def _normalize_finding(raw: dict, tool: str, column_map: dict[str, str]) -> dict:
    """Apply approved column mapping to a raw row dict."""
    out: dict = {"source_tool": tool}
    reverse = {v: k for k, v in column_map.items()}
    for orig_col, value in raw.items():
        canonical = reverse.get(orig_col, orig_col)
        out[canonical] = str(value) if value is not None else ""
    return out

@router.post("/preview")
async def preview_columns(
    file: UploadFile = File(...),
):
    """Step 1: upload a file, get back column mapping suggestions."""
    data = await file.read()
    tool = _detect_tool(file.filename or "", data)

    if tool == "fortify":
        rows = parse_fpr(data)
        columns = list(rows[0].keys()) if rows else []
    elif tool == "zap_xml":
        rows = parse_zap_xml(data)
        columns = list(rows[0].keys()) if rows else []
    elif tool == "zap_json":
        rows = parse_zap_json(data)
        columns = list(rows[0].keys()) if rows else []
    elif tool == "csv":
        rows = _parse_csv(data)
        columns = list(rows[0].keys()) if rows else []
    elif tool == "xlsx":
        rows = _parse_xlsx(data)
        columns = list(rows[0].keys()) if rows else []
    else:
        raise HTTPException(400, f"Unsupported file type: {file.filename}")

    suggestions = suggest_mapping(columns)
    return {
        "filename": file.filename,
        "tool": tool,
        "row_count": len(rows),
        "columns": columns,
        "suggestions": suggestions,
        "file_hash": _hash(data),
    }


@router.post("/import/{project_id}")
async def import_file(
    project_id: uuid.UUID,
    file: UploadFile = File(...),
    column_map: str = Form(...),   # JSON string: {canonical: original_col}
    db: Session = Depends(get_db),
):
    """Step 2: submit approved column mapping, import findings into project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    data = await file.read()
    file_hash = _hash(data)
    tool = _detect_tool(file.filename or "", data)
    col_map: dict[str, str] = json.loads(column_map)

    # Parse raw rows
    if tool == "fortify":
        raw_rows = parse_fpr(data)
    elif tool == "zap_xml":
        raw_rows = parse_zap_xml(data)
    elif tool == "zap_json":
        raw_rows = parse_zap_json(data)
    elif tool == "csv":
        raw_rows = _parse_csv(data)
    elif tool == "xlsx":
        raw_rows = _parse_xlsx(data)
    else:
        raise HTTPException(400, f"Unsupported file type")

    added = updated = unchanged = 0

    for row in raw_rows:
        norm = _normalize_finding(row, tool, col_map)
        key = stable_key(tool, norm.get("plugin_id"), norm.get("title"))

        existing = db.query(Finding).filter(
            Finding.project_id == project_id,
            Finding.stable_key == key,
        ).first()

        if existing:
            # Preserve justification and status — only update scan data
            existing.severity = norm.get("severity", existing.severity)
            existing.description = norm.get("description", existing.description)
            existing.last_seen = __import__("datetime").datetime.utcnow()
            if existing.justification:
                unchanged += 1
            else:
                updated += 1
        else:
            finding = Finding(
                project_id=project_id,
                stable_key=key,
                source_tool=tool,
                severity=norm.get("severity"),
                title=norm.get("title"),
                description=norm.get("description"),
                plugin_id=norm.get("plugin_id"),
                cwe_id=norm.get("cwe_id"),
                cve_id=norm.get("cve_id"),
                status=FindingStatus.not_reviewed,
                raw_data=json.dumps(row),
            )
            db.add(finding)
            added += 1

    log = ImportLog(
        project_id=project_id,
        filename=file.filename,
        file_hash=file_hash,
        source_tool=tool,
        findings_added=added,
        findings_updated=updated,
        findings_unchanged=unchanged,
    )
    db.add(log)
    db.commit()

    return {
        "status": "ok",
        "findings_added": added,
        "findings_updated": updated,
        "findings_unchanged": unchanged,
    }
