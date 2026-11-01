"""Professional PDF rendering for the executive summary."""

import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

BRAND_NAVY = colors.HexColor("#0f172a")
BRAND_SLATE = colors.HexColor("#475569")
BRAND_ACCENT = colors.HexColor("#6366f1")
LIGHT_BG = colors.HexColor("#f8fafc")
BORDER = colors.HexColor("#e2e8f0")

RISK_COLORS = {
    "CRITICAL": colors.HexColor("#b91c1c"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#16a34a"),
}


def _styles():
    base = getSampleStyleSheet()
    title = ParagraphStyle(
        "ExecTitle",
        parent=base["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=BRAND_NAVY,
        spaceAfter=4,
    )
    subtitle = ParagraphStyle(
        "ExecSubtitle",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=BRAND_SLATE,
        spaceAfter=12,
    )
    heading = ParagraphStyle(
        "ExecHeading",
        parent=base["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=BRAND_NAVY,
        spaceBefore=14,
        spaceAfter=6,
    )
    label = ParagraphStyle(
        "ExecLabel",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=BRAND_SLATE,
    )
    value = ParagraphStyle(
        "ExecValue",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=BRAND_NAVY,
    )
    body = ParagraphStyle(
        "ExecBody",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
    )
    return {
        "title": title,
        "subtitle": subtitle,
        "heading": heading,
        "label": label,
        "value": value,
        "body": body,
    }


def _risk_badge(risk):
    color = RISK_COLORS.get((risk or "").upper(), BRAND_SLATE)
    return Paragraph(
        "<font color='white'><b>{0}</b></font>".format(risk or "UNKNOWN"),
        ParagraphStyle(
            "RiskBadge",
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=14,
            alignment=TA_CENTER,
            backColor=color,
            borderPadding=8,
        ),
    )


def _meta_table(summary, styles):
    device = summary.get("device") or {}
    hostname = device.get("hostname") or "Unknown"
    model = device.get("model") or "—"
    version = device.get("version") or "—"
    collected = summary.get("_collected_at") or ""
    if collected:
        try:
            from reports.timeutil import IST
            from datetime import datetime, timezone

            parsed = datetime.fromisoformat(collected)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            collected = parsed.astimezone(IST).strftime(
                "%Y-%m-%d %H:%M IST"
            )
        except Exception:
            pass

    rows = [
        [
            Paragraph("DEVICE", styles["label"]),
            Paragraph(hostname, styles["value"]),
            Paragraph("MODEL", styles["label"]),
            Paragraph(model, styles["value"]),
        ],
        [
            Paragraph("VERSION", styles["label"]),
            Paragraph(version, styles["value"]),
            Paragraph("GENERATED", styles["label"]),
            Paragraph(collected or "—", styles["value"]),
        ],
    ]
    table = Table(rows, colWidths=[0.9 * inch, 2.6 * inch, 1.1 * inch, 2.4 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _summary_table(summary, styles):
    s = summary.get("summary") or {}
    overall = (s.get("overall_risk") or "LOW").upper()
    color = RISK_COLORS.get(overall, BRAND_SLATE)

    stats = [
        ("Total Controls", s.get("total_controls", 0), BRAND_ACCENT),
        ("Compliant", s.get("compliant", 0), RISK_COLORS["LOW"]),
        ("Non-Compliant", s.get("non_compliant", 0), RISK_COLORS["HIGH"]),
        ("Not Assessed", s.get("not_assessed", 0), BRAND_SLATE),
    ]

    rows = []
    for label, count, accent in stats:
        rows.append(
            [
                Paragraph("<b>{0}</b>".format(label), styles["body"]),
                Paragraph(
                    "<font color='{0}'><b>{1}</b></font>".format(
                        accent.hexval().replace("0x", "#"), count
                    ),
                    ParagraphStyle(
                        "StatValue",
                        parent=styles["body"],
                        alignment=TA_CENTER,
                        fontSize=12,
                    ),
                ),
            ]
        )

    table = Table(rows, colWidths=[3.4 * inch, 1.6 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    wrapper = Table(
        [
            [
                Paragraph("OVERALL RISK", styles["label"]),
                Paragraph("COMPLIANCE SNAPSHOT", styles["label"]),
            ],
            [_risk_badge(overall), table],
        ],
        colWidths=[2.2 * inch, 5.0 * inch],
    )
    wrapper.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return wrapper


def _findings_table(summary, styles):
    findings = summary.get("top_findings") or []
    if not findings:
        return None

    header = [
        Paragraph("<font color='white'><b>Control</b></font>", styles["body"]),
        Paragraph("<font color='white'><b>Risk</b></font>", styles["body"]),
        Paragraph("<font color='white'><b>Finding</b></font>", styles["body"]),
        Paragraph("<font color='white'><b>Remediation</b></font>", styles["body"]),
    ]

    rows = [header]
    for finding in findings:
        risk = (finding.get("risk") or "LOW").upper()
        rows.append(
            [
                Paragraph(
                    "<b>{0}</b>".format(finding.get("control") or "—"),
                    styles["body"],
                ),
                Paragraph(
                    "<font color='{0}'><b>{1}</b></font>".format(
                        RISK_COLORS.get(risk, BRAND_SLATE).hexval().replace("0x", "#"),
                        risk,
                    ),
                    styles["body"],
                ),
                Paragraph(finding.get("finding") or "—", styles["body"]),
                Paragraph(finding.get("remediation") or "—", styles["body"]),
            ]
        )

    table = Table(
        rows,
        colWidths=[1.4 * inch, 0.8 * inch, 2.5 * inch, 2.4 * inch],
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_NAVY),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _priorities_table(summary, styles):
    priorities = summary.get("remediation_priorities") or []
    if not priorities:
        return None

    rows = []
    for index, priority in enumerate(priorities, start=1):
        rows.append(
            [
                Paragraph(
                    "<font color='{0}'><b>{1}</b></font>".format(
                        BRAND_ACCENT.hexval().replace("0x", "#"), index
                    ),
                    styles["body"],
                ),
                Paragraph(priority, styles["body"]),
            ]
        )

    table = Table(rows, colWidths=[0.4 * inch, 6.6 * inch])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, LIGHT_BG]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(BRAND_SLATE)
    canvas.drawString(
        0.75 * inch,
        0.5 * inch,
        "HeimDRIX AI Agentic Security Platform — Network Security Assessment",
    )
    canvas.drawRightString(
        A4[0] - 0.75 * inch,
        0.5 * inch,
        "Page {0}".format(canvas.getPageNumber()),
    )
    canvas.restoreState()


def generate(summary, output_file):
    """Render ``summary`` (from ExecutiveSummary.generate) to a styled PDF."""
    summary = summary or {}
    styles = _styles()

    document = SimpleDocTemplate(
        output_file,
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="Executive Summary",
        author="HeimDRIX AI Agentic Security Platform",
    )

    story = []
    story.append(Paragraph("EXECUTIVE SUMMARY", styles["title"]))
    story.append(
        Paragraph(
            "Network Security Assessment — Palo Alto Firewall Compliance Review",
            styles["subtitle"],
        )
    )
    story.append(_meta_table(summary, styles))
    story.append(Spacer(1, 14))
    story.append(_summary_table(summary, styles))

    findings = _findings_table(summary, styles)
    if findings is not None:
        story.append(Paragraph("Top Findings", styles["heading"]))
        story.append(findings)

    priorities = _priorities_table(summary, styles)
    if priorities is not None:
        story.append(Paragraph("Remediation Priorities", styles["heading"]))
        story.append(priorities)

    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return output_file
