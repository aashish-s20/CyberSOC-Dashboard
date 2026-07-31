import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(title, headers, data_rows, subtitle="CyberSOC Security Platform Report"):
    """
    Generates a professional PDF report containing the specified headers and table rows.
    Returns the binary PDF payload.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        name='TitleStyle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        name='SubTitleStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=15
    )
    
    body_style = ParagraphStyle(
        name='BodyStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=colors.HexColor('#334155')
    )
    
    header_style = ParagraphStyle(
        name='HeaderStyle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        textColor=colors.white
    )
    
    elements = []
    
    # Add Report Headers
    elements.append(Paragraph(title, title_style))
    elements.append(Paragraph(subtitle, subtitle_style))
    elements.append(Spacer(1, 10))
    
    # Parse Table rows
    formatted_data = []
    
    # Header row
    header_row = [Paragraph(h, header_style) for h in headers]
    formatted_data.append(header_row)
    
    # Content rows
    for row in data_rows:
        row_elements = []
        for val in row:
            val_str = str(val) if val is not None else 'N/A'
            row_elements.append(Paragraph(val_str, body_style))
        formatted_data.append(row_elements)
        
    # Table widths mapping
    col_width = (612 - 72) / len(headers)
    t = Table(formatted_data, colWidths=[col_width] * len(headers))
    
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 1), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
    ]))
    
    elements.append(t)
    doc.build(elements)
    
    buffer.seek(0)
    return buffer.getvalue()
