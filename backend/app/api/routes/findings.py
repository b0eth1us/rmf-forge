from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.finding import Finding, FindingStatus
from pydantic import BaseModel
from typing import Optional
import uuid

router = APIRouter()

class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    justification: Optional[str] = None
    vuln_id: Optional[str] = None
    cci_id: Optional[str] = None

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
    vuln_id: Optional[str]
    status: FindingStatus
    justification: Optional[str]
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
