"""Zero Trust assessment workbook from the last stored canonical run."""

from __future__ import annotations

import os

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from services import timeutil
from services import zero_trust_store
from services.assessment_service import EXCEL_DIR, NO_STORED_ASSESSMENT, NoStoredAssessmentError

BRAND_NAVY = "0F172A"
BRAND_ACCENT = "6366F1"
SLATE = "475569"
BORDER_GRAY = "E2E8F0"
LIGHT_BG = "F8FAFC"

PILLARS = ("identity", "devices", "network", "data", "infrastructure")

STATUS_COLORS = {
    "PASSED": {"text": "16A34A", "fill": "DCFCE7"},
    "FAILED": {"text": "E4002B", "fill": "FEE2E2"},
    "INVESTIGATE": {"text": "D97706", "fill": "FEF3C7"},
}

RISK_COLORS = {
    "CRITICAL": "B91C1C",
    "HIGH": "EA580C",
    "MEDIUM": "D97706",
    "LOW": "16A34A",
}


def _solid(hex_color):
    return PatternFill(start_color=hex_color, end_color=hex_color, fill_type="solid")


def _thin_border():
    side = Side(style="thin", color=BORDER_GRAY)
    return Border(left=side, right=side, top=side, bottom=side)


def _style_header_row(ws, row_index, columns):
    for col_index in range(1, columns + 1):
        cell = ws.cell(row=row_index, column=col_index)
        cell.font = Font(bold=True, color="FFFFFF", size=10)
        cell.fill = _solid(BRAND_NAVY)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = _thin_border()
    ws.row_dimensions[row_index].height = 22


def _autofit(ws, min_width=10, max_width=46):
    for column_cells in ws.columns:
        length = 0
        letter = get_column_letter(column_cells[0].column)
        for cell in column_cells:
            if cell.value is None:
                continue
            length = max(length, len(str(cell.value)))
        ws.column_dimensions[letter].width = max(min_width, min(max_width, length + 3))


def _append_row(ws, values, start_row=None):
    row_index = start_row or (ws.max_row + 1)
    for col_index, value in enumerate(values, start=1):
        ws.cell(row=row_index, column=col_index, value=value)
    return row_index


def _tests(assessment):
    out = []
    for key in PILLARS:
        bucket = (assessment or {}).get(key) or {}
        out.extend(bucket.get("tests") or [])
    return out


def _write_kv(ws, row, label, value):
    label_cell = ws.cell(row=row, column=1, value=label)
    label_cell.font = Font(bold=True, color=SLATE)
    label_cell.fill = _solid(LIGHT_BG)
    label_cell.border = _thin_border()
    value_cell = ws.cell(row=row, column=2, value=value if value not in (None, "") else "—")
    value_cell.border = _thin_border()
    ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=4)
    return row + 1


def _build_overview(workbook, assessment):
    ws = workbook.active
    ws.title = "Overview"
    ws.sheet_view.showGridLines = False
    tenant = assessment.get("tenant") or {}
    title = ws.cell(row=1, column=1, value="ZERO TRUST CLOUD SECURITY ASSESSMENT")
    title.font = Font(bold=True, color="FFFFFF", size=16)
    title.fill = _solid(BRAND_NAVY)
    title.alignment = Alignment(horizontal="left", vertical="center")
    ws.merge_cells("A1:D1")
    ws.row_dimensions[1].height = 34
    subtitle = ws.cell(row=2, column=1, value="HeimDRIX AI Agentic Security Platform — Cloud Security Assessment Report")
    subtitle.font = Font(color=SLATE, size=10, italic=True)
    ws.merge_cells("A2:D2")
    row = 4
    row = _write_kv(ws, row, "Assessment ID", assessment.get("assessmentId"))
    row = _write_kv(ws, row, "Completed", assessment.get("completedAt") or assessment.get("startedAt"))
    row = _write_kv(ws, row, "Tenant", tenant.get("tenantName") or tenant.get("name") or tenant.get("primaryDomain"))
    row = _write_kv(ws, row, "Score", assessment.get("score") if assessment.get("score") is not None else assessment.get("weightedScore"))
    row = _write_kv(ws, row, "Generated", timeutil.ist_now().strftime("%Y-%m-%d %H:%M IST"))
    row += 1
    header = ws.cell(row=row, column=1, value="PILLAR SNAPSHOT")
    header.font = Font(bold=True, color="FFFFFF", size=11)
    header.fill = _solid(BRAND_ACCENT)
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=4)
    row += 1
    _append_row(ws, ["Pillar", "Passed", "Total", "Score"], start_row=row)
    _style_header_row(ws, row, 4)
    row += 1
    for key in PILLARS:
        bucket = assessment.get(key) or {}
        summary = bucket.get("summary") or {}
        _append_row(
            ws,
            [
                key.title(),
                summary.get("passed", 0),
                summary.get("total", 0),
                summary.get("score"),
            ],
            start_row=row,
        )
        for col in range(1, 5):
            ws.cell(row=row, column=col).border = _thin_border()
        row += 1
    ws.column_dimensions["A"].width = 22
    for letter in ("B", "C", "D"):
        ws.column_dimensions[letter].width = 18


def _write_tests(ws, tests):
    headers = ["Control ID", "Name", "Pillar", "Category", "Status", "Risk", "Recommendation"]
    _append_row(ws, headers, start_row=1)
    _style_header_row(ws, 1, len(headers))
    ws.freeze_panes = "A2"
    for test in tests:
        status = str(test.get("status") or "").upper()
        risk = str(test.get("risk") or "").upper()
        row_index = _append_row(
            ws,
            [
                test.get("id"),
                test.get("name"),
                test.get("area"),
                test.get("category"),
                status,
                risk,
                test.get("recommendation") or "",
            ],
        )
        status_style = STATUS_COLORS.get(status, {})
        if status_style:
            cell = ws.cell(row=row_index, column=5)
            cell.font = Font(bold=True, color=status_style["text"])
            cell.fill = _solid(status_style["fill"])
        risk_color = RISK_COLORS.get(risk)
        if risk_color:
            ws.cell(row=row_index, column=6).font = Font(bold=True, color=risk_color)
        for col in range(1, len(headers) + 1):
            cell = ws.cell(row=row_index, column=col)
            cell.border = _thin_border()
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    if tests:
        ws.auto_filter.ref = ws.dimensions
    _autofit(ws)


def generate_zero_trust_excel(filename=None):
    results = zero_trust_store.latest_results()
    assessment = (results or {}).get("assessment") if results else None
    if not assessment:
        raise NoStoredAssessmentError(NO_STORED_ASSESSMENT)

    os.makedirs(EXCEL_DIR, exist_ok=True)
    month = timeutil.ist_now().strftime("%b_%Y")
    filename = filename or "Zero_Trust_Assessment_Workbook_{0}.xlsx".format(month)
    filename = os.path.basename(filename)
    if not filename.lower().endswith(".xlsx"):
        filename = filename + ".xlsx"
    output_file = os.path.join(EXCEL_DIR, filename)

    workbook = Workbook()
    _build_overview(workbook, assessment)
    all_sheet = workbook.create_sheet("All Controls")
    tests = _tests(assessment)
    _write_tests(all_sheet, tests)
    for key in PILLARS:
        bucket = assessment.get(key) or {}
        sheet = workbook.create_sheet(key.title()[:31])
        _write_tests(sheet, bucket.get("tests") or [])
    workbook.save(output_file)

    return {
        "status": "SUCCESS",
        "message": "Zero Trust workbook generated successfully.",
        "local_file": output_file,
        "download_url": "reports/{0}".format(filename),
        "filename": filename,
        "assessment_id": assessment.get("assessmentId"),
        "security_domain": "zero_trust",
        "_source": "stored",
    }
