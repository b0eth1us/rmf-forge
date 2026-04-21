from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.finding import Finding, FindingStatus
from app.parsers.zap_parser import parse_zap_xml, parse_zap_json
from app.services.cci_mapper import map_cwe_to_ccis
from app.services.finding_hasher import stable_key
import uuid, json

router = APIRouter()

@router.post("/map/{project_id}")
async def map_zap_to_cci(
    project_id: uuid.UUID,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    from app.models.project import Project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        data = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read file: {e}")

    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    fn = (file.filename or "").lower()

    try:
        if fn.endswith(".json"):
            rows = parse_zap_json(data)
        elif fn.endswith(".xml"):
            rows = parse_zap_xml(data)
        else:
            # Try JSON first, fall back to XML
            try:
                rows = parse_zap_json(data)
            except Exception:
                rows = parse_zap_xml(data)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Could not parse ZAP file: {str(e)}")

    if not rows:
        raise HTTPException(status_code=422, detail="No alerts found in ZAP report")

    mapped, unmapped = [], []

    for row in rows:
        cwe = str(row.get("cwe_id", "")).strip().lstrip("CWE-").lstrip("cwe-")
        ccis = map_cwe_to_ccis(cwe) if cwe and cwe not in ("", "0", "None") else []

        entry = {
            "plugin_id": row.get("plugin_id", ""),
            "title": row.get("title", ""),
            "severity": row.get("severity", ""),
            "cwe_id": cwe,
            "description": row.get("description", ""),
            "solution": row.get("solution", ""),
        }

        if ccis:
            mapped.append({**entry, "ccis": ccis})
        else:
            unmapped.append(entry)

    # Persist findings to the project
    added = 0
    import json as json_lib
    from datetime import datetime
    for row in rows:
        cwe = str(row.get("cwe_id", "")).strip().lstrip("CWE-")
        key = stable_key("zap", row.get("plugin_id"), row.get("title"))
        existing = db.query(Finding).filter(
            Finding.project_id == project_id,
            Finding.stable_key == key,
        ).first()
        if not existing:
            finding = Finding(
                project_id=project_id,
                stable_key=key,
                source_tool="zap",
                severity=row.get("severity"),
                title=row.get("title"),
                description=row.get("description"),
                plugin_id=row.get("plugin_id"),
                cwe_id=cwe,
                status=FindingStatus.not_reviewed,
                raw_data=json_lib.dumps(row),
            )
            # Auto-assign first CCI if available
            ccis = map_cwe_to_ccis(cwe) if cwe else []
            if ccis:
                finding.cci_id = ccis[0].get("cci_id", "")
            db.add(finding)
            added += 1

    db.commit()

    return {
        "total": len(rows),
        "mapped_count": len(mapped),
        "unmapped_count": len(unmapped),
        "findings_added": added,
        "mapped": mapped,
        "unmapped": unmapped,
    }
