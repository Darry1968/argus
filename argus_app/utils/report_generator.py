from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from datetime import datetime
from reportlab.lib.utils import ImageReader
import matplotlib.pyplot as plt
import os

def generate_report(data, output_path):
    """
    Generates a PDF report with enhanced layout, mitigation strategies, and graphs.

    Args:
        data (dict): Dictionary containing URL data.
        output_path (str): Path to save the generated report.
    """
    # Canvas settings
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica", 12)

    # Add Logo and Title
    logo_path = os.path.join("static", "css", "Logo.png")
    if os.path.exists(logo_path):
        logo = ImageReader(logo_path)
        c.drawImage(logo, 50, height - 100, width=100, height=50, mask="auto")
    c.setFont("Helvetica-Bold", 18)
    c.drawString(160, height - 70, "ARGUS")
    c.setFont("Helvetica", 14)
    c.drawCentredString(width / 2, height - 90, "API SCAN REPORT")

    # Timestamp and URL
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 130, f"Report for URL: {data['original_url']}")
    c.drawString(50, height - 150, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Vulnerabilities Section
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 180, "Vulnerabilities Found:")
    vulnerabilities = data["vulnerabilities_found"]
    if vulnerabilities:
        for idx, vuln in enumerate(vulnerabilities, start=1):
            c.setFont("Helvetica", 12)
            c.drawString(70, height - 200 - (idx * 20), f"- {vuln}")
    else:
        c.setFont("Helvetica", 12)
        c.drawString(70, height - 200, "No vulnerabilities found.")

    # Open Endpoints Section
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 300, "Open Endpoints:")
    endpoints = data["open_endpoints"]
    for idx, endpoint in enumerate(endpoints, start=1):
        c.setFont("Helvetica", 12)
        c.drawString(70, height - 320 - (idx * 20), f"- {endpoint}")

    # Add graphs
    graph1_path = "static/owasp_line_graph.png"
    graph2_path = "static/owasp_bar_graph.png"
    create_graphs(graph1_path, graph2_path)
    if os.path.exists(graph1_path):
        c.drawImage(graph1_path, 50, height - 550, width=250, height=150)
    if os.path.exists(graph2_path):
        c.drawImage(graph2_path, 320, height - 550, width=250, height=150)

    # Mitigation Strategies
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, 100, "Basic Mitigation Strategies:")
    mitigation_points = [
        "1. Regularly update and patch software to fix known vulnerabilities.",
        "2. Implement input validation and sanitization to prevent injection attacks.",
        "3. Use secure authentication and session management practices.",
        "4. Encrypt sensitive data in transit and at rest using strong encryption standards.",
        "5. Conduct regular vulnerability scans and penetration testing to identify risks."
    ]
    for idx, point in enumerate(mitigation_points):
        c.setFont("Helvetica", 12)
        c.drawString(70, 80 - (idx * 20), point)

    # Save the report
    c.save()

def create_graphs(graph1_path, graph2_path):
    """
    Creates OWASP Top 10 graphs and saves them as PNG files.

    Args:
        graph1_path (str): Path to save the line graph.
        graph2_path (str): Path to save the bar graph.
    """
    # Mock OWASP vulnerability data
    owasp_categories = [
        "Injection", "Broken Auth", "Sensitive Data Exposure", "XML External Entities",
        "Broken Access Control", "Security Misconfiguration", "XSS",
        "Insecure Deserialization", "Components with Known Vulnerabilities", "Insufficient Logging"
    ]
    attacks_over_time = [15, 20, 10, 5, 25, 18, 12, 8, 22, 7]  # Mock data
    attack_counts = [50, 30, 40, 20, 60, 45, 35, 25, 55, 30]  # Mock data

    # Create line graph
    plt.figure(figsize=(8, 4))
    plt.plot(owasp_categories, attacks_over_time, marker="o", color="blue")
    plt.title("OWASP Top 10 Attacks Over Time")
    plt.xlabel("Vulnerabilities")
    plt.ylabel("Number of Attacks")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(graph1_path)
    plt.close()

    # Create bar graph
    plt.figure(figsize=(8, 4))
    plt.bar(owasp_categories, attack_counts, color="green")
    plt.title("OWASP Top 10 Attack Counts")
    plt.xlabel("Vulnerabilities")
    plt.ylabel("Number of Attacks")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(graph2_path)
    plt.close()
