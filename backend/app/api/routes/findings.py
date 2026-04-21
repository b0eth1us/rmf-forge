from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.finding import Finding, FindingStatus
from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import date

router = APIRouter()

class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    justification: Optional[str] = None
    vuln_id: Optional[str] = None
    cci_id: Optional[str] = None
    nist_control: Optional[str] = None
    scheduled_completion_date: Optional[date] = None
    milestone_description: Optional[str] = None

class FindingResponse(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    source_tool: str
    severity: Optional[str]
    title: Optional[str]
    description: Optional[str]
    plugin_id: Optional[str]
    cwe_id: Optional[str]
    cve_id: Optional[str]
    cci_id: Optional[str]
    nist_control: Optional[str]
    vuln_id: Optional[str]
    status: FindingStatus
    justification: Optional[str]
    audit_comment: Optional[str]
    audit_action: Optional[str]
    file_path: Optional[str]
    line_number: Optional[int]
    code_snippet: Optional[str]
    taint_trace: Optional[str]
    affected_url: Optional[str]
    dependency_name: Optional[str]
    dependency_version: Optional[str]
    scheduled_completion_date: Optional[date]
    milestone_description: Optional[str]
    class Config:
        from_attributes = True

@router.get("/project/{project_id}", response_model=list[FindingResponse])
def list_findings(
    project_id: uuid.UUID,
    status: Optional[str] = Query(None),
    source_tool: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Finding).filter(Finding.project_id == project_id)
    if status:
        q = q.filter(Finding.status == status)
    if source_tool:
        q = q.filter(Finding.source_tool == source_tool)
    return q.order_by(Finding.severity, Finding.title).all()

@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: uuid.UUID,
    data: FindingUpdate,
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    for field, value in data.model_dump(exclude_none=True).items():
        setattr(finding, field, value)
    db.commit()
    db.refresh(finding)
    return finding

@router.get("/project/{project_id}/summary")
def findings_summary(project_id: uuid.UUID, db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    summary = {"total": len(findings), "by_status": {}, "by_tool": {}, "by_severity": {}}
    for f in findings:
        summary["by_status"][f.status.value] = summary["by_status"].get(f.status.value, 0) + 1
        summary["by_tool"][f.source_tool] = summary["by_tool"].get(f.source_tool, 0) + 1
        sev = f.severity or "Unknown"
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
    return summary

@router.get("/project/{project_id}/unmapped")
def unmapped_findings(project_id: uuid.UUID, db: Session = Depends(get_db)):
    """Findings with no CCI assignment — surface for manual review."""
    findings = db.query(Finding).filter(
        Finding.project_id == project_id,
        Finding.cci_id == None,
    ).all()
    return [{"id": str(f.id), "title": f.title, "source_tool": f.source_tool,
             "cwe_id": f.cwe_id, "severity": f.severity} for f in findings]

@router.post("/project/{project_id}/remap")
def remap_findings(project_id: uuid.UUID, db: Session = Depends(get_db)):
    """Re-run auto-mapping on all findings missing vuln_id or cci_id."""
    from app.services.stig_mapper import map_finding_to_stig
    from app.services.cci_mapper import map_cwe_to_ccis

    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    updated = 0

    for f in findings:
        changed = False
        if not f.cci_id and f.cwe_id:
            import re
            bare = re.sub(r'[^0-9]', '', f.cwe_id)
            ccis = map_cwe_to_ccis(bare)
            if ccis:
                f.cci_id = ccis[0].get("cci_id")
                f.nist_control = ccis[0].get("nist_control")
                changed = True
        if not f.vuln_id or not f.cci_id:
            match = map_finding_to_stig(f.title or "", f.description or "")
            if not f.vuln_id and match.get("vuln_ids"):
                f.vuln_id = match["vuln_ids"][0]
                changed = True
            if not f.cci_id and match.get("cci_ids"):
                f.cci_id = match["cci_ids"][0]
                changed = True
        if changed:
            updated += 1

    db.commit()
    return {"remapped": updated, "total": len(findings)}
