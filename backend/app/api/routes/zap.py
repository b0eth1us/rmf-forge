from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.finding import Finding
from app.parsers.zap_parser import parse_zap_xml, parse_zap_json
from app.services.cci_mapper import map_cwe_to_ccis
import uuid

router = APIRouter()

@router.post("/map/{project_id}")
async def map_zap_to_cci(
    project_id: uuid.UUID,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Ingest a ZAP report, map each alert's CWE to CCIs,
    store as findings, and return mapping results.
    """
    from app.models.project import Project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    data = await file.read()
    fn = (file.filename or "").lower()

    if fn.endswith(".json"):
        rows = parse_zap_json(data)
    elif fn.endswith(".xml"):
        rows = parse_zap_xml(data)
    else:
        raise HTTPException(400, "ZAP file must be .xml or .json")

    mapped, unmapped = [], []

    for row in rows:
        cwe = row.get("cwe_id", "").strip().lstrip("CWE-")
        ccis = map_cwe_to_ccis(cwe) if cwe else []

        if ccis:
            mapped.append({
                "plugin_id": row.get("plugin_id"),
                "title": row.get("title"),
                "severity": row.get("severity"),
                "cwe_id": cwe,
                "ccis": ccis,
            })
        else:
            unmapped.append({
                "plugin_id": row.get("plugin_id"),
                "title": row.get("title"),
                "cwe_id": cwe or "unknown",
            })

    return {
        "total": len(rows),
        "mapped_count": len(mapped),
        "unmapped_count": len(unmapped),
        "mapped": mapped,
        "unmapped": unmapped,
    }
