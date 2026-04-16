from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.finding import Finding, FindingStatus
from app.services.stig_mapper import load_asd_stig, map_fortify_to_vuln_ids
from lxml import etree
from datetime import datetime
import uuid, json

router = APIRouter()

STATUS_MAP = {
    FindingStatus.open:           "Open",
    FindingStatus.not_a_finding:  "NotAFinding",
    FindingStatus.not_applicable: "Not_Applicable",
    FindingStatus.not_reviewed:   "Not_Reviewed",
}

def _build_ckl(findings: list[Finding], project_name: str) -> bytes:
    root = etree.Element("CHECKLIST")
    asset = etree.SubElement(root, "ASSET")
    etree.SubElement(asset, "ROLE").text = "None"
    etree.SubElement(asset, "HOST_NAME").text = project_name
    etree.SubElement(asset, "HOST_IP").text = ""
    etree.SubElement(asset, "HOST_MAC").text = ""
    etree.SubElement(asset, "HOST_FQDN").text = ""
    etree.SubElement(asset, "TECH_AREA").text = "Application Review"
    etree.SubElement(asset, "TARGET_KEY").text = ""
    etree.SubElement(asset, "WEB_OR_DATABASE").text = "false"

    si_data = etree.SubElement(root, "STIGS")
    istig = etree.SubElement(si_data, "iSTIG")
    stig_info = etree.SubElement(istig, "STIG_INFO")
    for k, v in [
        ("version", "6"), ("classification", "UNCLASSIFIED"),
        ("customname", ""), ("stigid", "ASD_STIG"),
        ("description", "Application Security and Development STIG"),
        ("filename", "ASD_STIG.xml"), ("releaseinfo", ""),
        ("title", "Application Security and Development Security Technical Implementation Guide"),
        ("uuid", str(uuid.uuid4())), ("notice", ""), ("source", ""),
    ]:
        si = etree.SubElement(stig_info, "SI_DATA")
        etree.SubElement(si, "SID_NAME").text = k
        etree.SubElement(si, "SID_DATA").text = v

    stig_data = load_asd_stig()

    for f in findings:
        vuln_ids = []
        if f.vuln_id:
            vuln_ids = [f.vuln_id]
        elif f.title:
            # Try to map from Fortify category
            for cat, vids in __import__("app.services.stig_mapper", fromlist=["FORTIFY_TO_ASD"]).FORTIFY_TO_ASD.items():
                if cat.lower() in (f.title or "").lower():
                    vuln_ids = vids
                    break

        if not vuln_ids:
            vuln_ids = ["V-222400"]  # generic unmapped placeholder

        for vid in vuln_ids:
            stig_ref = stig_data.get(vid, {})
            vuln = etree.SubElement(istig, "VULN")

            for sname, sdata in [
                ("Vuln_Num", vid),
                ("Severity", f.severity or stig_ref.get("severity", "medium")),
                ("Group_Title", stig_ref.get("title", f.title or "")),
                ("Rule_ID", f"{vid}_rule"),
                ("Rule_Ver", vid),
                ("Rule_Title", stig_ref.get("title", f.title or "")),
                ("Vuln_Discuss", stig_ref.get("description", f.description or "")),
                ("Check_Content", ""),
                ("Fix_Text", stig_ref.get("fix_text", "")),
                ("CCI_REF", f.cci_id or "CCI-001310"),
            ]:
                sd = etree.SubElement(vuln, "STIG_DATA")
                etree.SubElement(sd, "VULN_ATTRIBUTE").text = sname
                etree.SubElement(sd, "ATTRIBUTE_DATA").text = sdata

            etree.SubElement(vuln, "STATUS").text = STATUS_MAP.get(f.status, "Not_Reviewed")
            etree.SubElement(vuln, "FINDING_DETAILS").text = f.description or ""
            etree.SubElement(vuln, "COMMENTS").text = f.justification or ""
            etree.SubElement(vuln, "SEVERITY_OVERRIDE").text = ""
            etree.SubElement(vuln, "SEVERITY_JUSTIFICATION").text = ""

    return etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="UTF-8")


def _build_xccdf(findings: list[Finding], project_name: str) -> bytes:
    XCCDF_NS = "http://checklists.nist.gov/xccdf/1.1"
    root = etree.Element(f"{{{XCCDF_NS}}}TestResult", nsmap={"xccdf": XCCDF_NS})
    root.set("id", f"xccdf_rmfforge_testresult_{uuid.uuid4().hex[:8]}")
    root.set("start-time", datetime.utcnow().isoformat())
    root.set("end-time", datetime.utcnow().isoformat())

    title = etree.SubElement(root, f"{{{XCCDF_NS}}}title")
    title.text = f"RMF Forge — {project_name}"

    benchmark = etree.SubElement(root, f"{{{XCCDF_NS}}}benchmark")
    benchmark.set("href", "ASD_STIG.xml")

    for f in findings:
        rr = etree.SubElement(root, f"{{{XCCDF_NS}}}rule-result")
        rr.set("idref", f.vuln_id or "V-222400")
        rr.set("severity", f.severity or "medium")
        result = etree.SubElement(rr, f"{{{XCCDF_NS}}}result")
        result.text = "fail" if f.status == FindingStatus.open else "pass"
        if f.justification:
            msg = etree.SubElement(rr, f"{{{XCCDF_NS}}}message")
            msg.text = f.justification

    return etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="UTF-8")


@router.get("/export/ckl/{project_id}")
def export_ckl(project_id: uuid.UUID, db: Session = Depends(get_db)):
    from app.models.project import Project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    ckl_bytes = _build_ckl(findings, project.name)
    return Response(
        content=ckl_bytes,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{project.name}.ckl"'},
    )


@router.get("/export/xccdf/{project_id}")
def export_xccdf(project_id: uuid.UUID, db: Session = Depends(get_db)):
    from app.models.project import Project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    xccdf_bytes = _build_xccdf(findings, project.name)
    return Response(
        content=xccdf_bytes,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{project.name}_xccdf.xml"'},
    )


@router.get("/unmapped/{project_id}")
def unmapped_findings(project_id: uuid.UUID, db: Session = Depends(get_db)):
    """Return findings with no vuln_id assigned yet."""
    findings = db.query(Finding).filter(
        Finding.project_id == project_id,
        Finding.vuln_id == None,
    ).all()
    return [{"id": str(f.id), "title": f.title, "source_tool": f.source_tool} for f in findings]
