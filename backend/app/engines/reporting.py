from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from io import BytesIO
from datetime import datetime

def generate_board_brief_pdf(assets, rating, scan_date=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    display_date = scan_date if scan_date else datetime.now().strftime('%Y-%m-%d')

    # Header
    elements.append(Paragraph("Q-GUARDIAN | QUANTUM TRANSITION INTELLIGENCE", styles['Title']))
    elements.append(Paragraph(f"BOARD BRIEF - {display_date}", styles['Heading2']))
    elements.append(Spacer(1, 12))

    # Calculate Risk Statistics (mosca may be a partial/fallback dict)
    def _mosca(a):
        m = a.get('mosca', {})
        return m if isinstance(m, dict) else {}
    critical_assets = [a for a in assets if _mosca(a).get('risk_state') == 'CRITICAL']
    warning_assets = [a for a in assets if _mosca(a).get('risk_state') == 'WARNING']
    all_days = [d for d in (_mosca(a).get('days_remaining_worst') for a in assets) if d is not None]
    min_days = min(all_days) if all_days else 0

    # Executive Summary
    elements.append(Paragraph("EXECUTIVE SUMMARY", styles['Heading3']))
    
    if critical_assets:
        narrative = f"CRITICAL: {len(critical_assets)} asset(s) have breached the Mosca safety threshold. Immediate migration planning is required for core infrastructure."
    elif warning_assets:
        narrative = f"WARNING: The enterprise risk window opens in as little as {min_days} days. Staged migration for sensitive tiers should commence within this quarter."
    else:
        narrative = f"All discovered assets are currently within the Mosca safe zone. Continued monitoring of nation-state CRQC progress is recommended."
        
    summary_text = f"The enterprise cyber rating is currently <b>{rating['score']} ({rating['status']})</b> based on {rating['asset_count']} discovered assets. {narrative}"
    elements.append(Paragraph(summary_text, styles['Normal']))
    elements.append(Spacer(1, 12))

    # Top Risks Table
    elements.append(Paragraph("TOP 5 CRYPTOGRAPHIC RISKS", styles['Heading3']))
    data = [["Asset Hostname", "Algorithm", "QTRI Score", "Mosca Countdown"]]
    
    # Sort assets by QTRI score (lowest first)
    sorted_assets = sorted(assets, key=lambda x: x.get('qtri_score') or 0)[:5]
    for asset in sorted_assets:
        days = _mosca(asset).get('days_remaining_worst')
        countdown = f"{days} Days" if days is not None else "N/A (safe/PQC)"
        data.append([
            asset.get('hostname', 'N/A'),
            asset.get('algorithm', 'UNKNOWN'),
            str(asset.get('qtri_score', 0)),
            countdown
        ])

    t = Table(data)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.maroon),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(t)
    elements.append(Spacer(1, 24))

    # Regulatory Alignment
    elements.append(Paragraph("REGULATORY ALIGNMENT", styles['Heading3']))
    elements.append(Paragraph(
        "Findings are mapped to RBI baseline cyber-resilience controls (Cyber Security Framework in Banks, "
        "DBS.CO/CSITE/BC.11/33.01.001/2015-16, and the Master Direction on Digital Payment Security Controls, 2021), "
        "NIST IR 8547 (PQC transition; deprecate 112-bit after 2030, disallow after 2035) and FIPS 203/204/205.",
        styles['Normal']))

    # HNDL Grounding Disclaimer
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("HNDL SIMULATION ADVISORY", styles['Heading3']))
    elements.append(Paragraph(
        "<b>Weakly Grounded Notice:</b> Harvest-Now-Decrypt-Later (HNDL) exposure volumes in this brief are computed from "
        "<b>illustrative, configurable per-tier traffic baselines</b> — they are not measured and not sourced from any regulator "
        "or GRI publication. Only the CRQC arrival-probability weighting is model-derived. Without real packet-capture / network "
        "telemetry these figures are a <b>theoretical risk ceiling</b> for prioritization, not a verified exfiltration measurement.",
        styles['Normal']
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer
