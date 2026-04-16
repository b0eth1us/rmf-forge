from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.finding import Finding, FindingStatus
from app.services.cci_mapper import map_cwe_to_ccis
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
import io, uuid

router = APIRouter()

SEVERITY_COLORS = {
    "critical": "C00000", "high": "FF0000",
    "medium": "FFC000", "low": "FFFF00", "informational": "D9D9D9",
}

def _col_letter(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s

def _style_header(ws, row: int, cols: list[str]):
    for i, h in enumerate(cols, 1):
        cell = ws.cell(row=row, column=i, value=h)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="1F3864")
        cell.alignment = Alignment(wrap_text=True)
    ws.row_dimensions[row].height = 30


@router.get("/consolidated/{project_id}")
def export_consolidated(project_id: uuid.UUID, db: Session = Depends(get_db)):
    """Export all findings as eMASS-ready Excel workbook."""
    from app.models.project import Project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    findings = db.query(Finding).filter(Finding.project_id == project_id)\
        .order_by(Finding.severity, Finding.title).all()

    wb = Workbook()
    ws = wb.active
    ws.title = "Findings"

    headers = [
        "Finding ID", "Source Tool", "Severity", "Title", "Description",
        "Plugin ID", "CWE", "CVE", "CCI", "STIG Vuln ID",
        "Status", "Justification", "First Seen", "Last Seen",
    ]
    _style_header(ws, 1, headers)

    for row_num, f in enumerate(findings, 2):
        values = [
            str(f.id)[:8], f.source_tool, f.severity, f.title, f.description,
            f.plugin_id, f.cwe_id, f.cve_id, f.cci_id, f.vuln_id,
            f.status.value, f.justification,
            f.first_seen.strftime("%Y-%m-%d") if f.first_seen else "",
            f.last_seen.strftime("%Y-%m-%d") if f.last_seen else "",
        ]
        for col_num, val in enumerate(values, 1):
            cell = ws.cell(row=row_num, column=col_num, value=val or "")
            if col_num == 3:  # severity color coding
                sev_key = (val or "").lower()
                color = SEVERITY_COLORS.get(sev_key)
                if color:
                    cell.fill = PatternFill("solid", fgColor=color)

    # Column widths
    widths = [10, 12, 10, 40, 50, 15, 10, 15, 15, 15, 18, 50, 12, 12]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[_col_letter(i)].width = w

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{_col_letter(len(headers))}1"

    # Summary sheet
    ws2 = wb.create_sheet("Summary")
    _style_header(ws2, 1, ["Metric", "Value"])
    from collections import Counter
    status_counts = Counter(f.status.value for f in findings)
    tool_counts = Counter(f.source_tool for f in findings)
    summary_rows = [
        ("Total Findings", len(findings)),
        ("", ""),
        *[(f"Status: {k}", v) for k, v in status_counts.items()],
        ("", ""),
        *[(f"Tool: {k}", v) for k, v in tool_counts.items()],
    ]
    for i, (k, v) in enumerate(summary_rows, 2):
        ws2.cell(row=i, column=1, value=k)
        ws2.cell(row=i, column=2, value=v)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    safe_name = project.name.replace(" ", "_")
    return Response(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}_findings.xlsx"'},
    )


@router.get("/emass-zap/{project_id}")
def export_emass_zap(project_id: uuid.UUID, db: Session = Depends(get_db)):
    """Export ZAP findings as eMASS bulk upload template."""
    from app.models.project import Project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    findings = db.query(Finding).filter(
        Finding.project_id == project_id,
        Finding.source_tool.in_(["zap", "zap_xml", "zap_json"]),
    ).all()

    wb = Workbook()
    ws = wb.active
    ws.title = "eMASS Import"

    headers = [
        "Control Number", "CCI", "Implementation Status",
        "Implementation Narrative", "Finding", "Risk Description",
        "Mitigation", "Severity", "Relevance of Threat",
    ]
    _style_header(ws, 1, headers)

    for row_num, f in enumerate(findings, 2):
        ccis = map_cwe_to_ccis(f.cwe_id or "")
        for cci_info in (ccis or [{}]):
            controls = ", ".join(cci_info.get("controls", []))
            ws.append([
                controls,
                cci_info.get("cci_id", ""),
                f.status.value,
                f.justification or "",
                f.title or "",
                f.description or "",
                "",
                f.severity or "",
                "",
            ])

    # Unmapped sheet
    ws2 = wb.create_sheet("Unmapped CWEs")
    _style_header(ws2, 1, ["Title", "CWE ID", "Severity", "Notes"])
    for f in findings:
        if not map_cwe_to_ccis(f.cwe_id or ""):
            ws2.append([f.title, f.cwe_id, f.severity, "No CCI mapping found — review manually"])

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    safe_name = project.name.replace(" ", "_")
    return Response(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}_emass.xlsx"'},
    )
