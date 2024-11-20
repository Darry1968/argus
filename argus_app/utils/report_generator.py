from reportlab.pdfgen import canvas
from datetime import datetime

def generate_report(data, output_path):
    """
    Generates a PDF report.

    Args:
        data (dict): Dictionary containing URL data.
        output_path (str): Path to save the generated report.
    """
    c = canvas.Canvas(output_path)
    c.setFont("Helvetica", 12)

    # Title
    c.drawString(50, 800, f"Report for URL: {data['original_url']}")
    c.drawString(50, 780, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Vulnerabilities Section
    c.drawString(50, 760, "Vulnerabilities Found:")
    vulnerabilities = data["vulnerabilities_found"]
    if vulnerabilities:
        for idx, vuln in enumerate(vulnerabilities, start=1):
            c.drawString(70, 740 - (idx * 20), f"- {vuln}")
    else:
        c.drawString(70, 740, "No vulnerabilities found.")

    # Open Endpoints Section
    c.drawString(50, 600, "Open Endpoints:")
    endpoints = data["open_endpoints"]
    for idx, endpoint in enumerate(endpoints, start=1):
        c.drawString(70, 580 - (idx * 20), f"- {endpoint}")

    c.save()
