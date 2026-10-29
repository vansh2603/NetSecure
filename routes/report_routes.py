
from io import BytesIO
from datetime import datetime

from flask import Blueprint, jsonify, send_file
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether
)

from database.db import db
from database.models import Scan
from risk_engine.risk_calculator import get_risk_level

report_bp = Blueprint("report", __name__)


@report_bp.route("/api/reports/<int:scan_id>/pdf", methods=["GET"])
def download_pdf_report(scan_id):
    scan = db.session.get(Scan, scan_id)

    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#2563eb"),
        spaceAfter=12
    ))

    story = [
        Paragraph("NetSecure Security Scan Report", styles["ReportTitle"]),
        Paragraph(
            f"Generated: {datetime.now().strftime('%d %b %Y, %H:%M')}",
            styles["Normal"]
        ),
        Spacer(1, 10),
        Paragraph("Scan Summary", styles["Heading2"])
    ]

    try:
        risk_level = get_risk_level(scan.risk_score)
    except (TypeError, ValueError):
        risk_level = "Unknown"

    summary = [
        ["Scan ID", str(scan.id)],
        ["Target", scan.target],
        ["Status", scan.status],
        ["Risk Score", f"{scan.risk_score}/10"],
        ["Risk Level", risk_level],
        [
            "Start Time",
            scan.start_time.strftime("%d %b %Y, %H:%M")
            if scan.start_time else "N/A"
        ],
        [
            "End Time",
            scan.end_time.strftime("%d %b %Y, %H:%M")
            if scan.end_time else "N/A"
        ]
    ]

    summary_table = Table(summary, colWidths=[40 * mm, 115 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eefc")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#1e3a8a")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
    ]))

    story.extend([summary_table, Spacer(1, 16)])
    story.append(Paragraph("Open Ports and Findings", styles["Heading2"]))

    port_rows = [["Port", "Service", "State", "Finding", "Severity", "Score"]]
    has_ports = False

    for host in scan.hosts:
        for port in host.ports:
            has_ports = True

            findings = port.vulnerabilities
            if not findings:
                port_rows.append([
                    str(port.port_number),
                    port.service or "Unknown",
                    port.state or "Unknown",
                    "No matched finding",
                    "-",
                    "-"
                ])
                continue

            for finding in findings:
                port_rows.append([
                    str(port.port_number),
                    port.service or "Unknown",
                    port.state or "Unknown",
                    Paragraph(finding.name, styles["BodyText"]),
                    finding.severity or "Unknown",
                    str(finding.score if finding.score is not None else 0)
                ])

    if not has_ports:
        story.append(Paragraph("No open ports were recorded for this scan.", styles["BodyText"]))
    else:
        port_table = Table(
            port_rows,
            colWidths=[15 * mm, 28 * mm, 18 * mm, 52 * mm, 22 * mm, 15 * mm],
            repeatRows=1
        )
        port_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
        ]))
        story.extend([port_table, Spacer(1, 16)])

    story.append(Paragraph("Recommendations", styles["Heading2"]))

    recommendations = []
    for host in scan.hosts:
        for port in host.ports:
            for finding in port.vulnerabilities:
                if finding.recommendation:
                    recommendations.append(
                        f"Port {port.port_number} — {finding.name}: "
                        f"{finding.recommendation}"
                    )

    if recommendations:
        for recommendation in recommendations:
            story.append(KeepTogether([
                Paragraph(recommendation, styles["BodyText"]),
                Spacer(1, 6)
            ]))
    else:
        story.append(Paragraph(
            "No recommendations were generated by the current rule-based checks.",
            styles["BodyText"]
        ))

    story.extend([
        Spacer(1, 16),
        Paragraph("Assessment Limitations", styles["Heading2"]),
        Paragraph(
            "Findings are preliminary, rule-based indicators derived from observed "
            "open ports and service labels. They do not confirm that a vulnerability "
            "exists. Verify service versions and configurations before taking action.",
            styles["BodyText"]
        )
    ])

    doc.build(story)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"netsecure_scan_{scan.id}_report.pdf"
    )
