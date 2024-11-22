from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from datetime import datetime
from reportlab.lib.utils import ImageReader
import matplotlib.pyplot as plt
import os


def generate_report(data, output_path):
    """
    Generates a multi-page PDF report with enhanced layout, mitigation strategies, and graphs.

    Args:
        data (dict): Dictionary containing URL data.
        output_path (str): Path to save the generated report.
    """
    # Canvas settings
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    current_y = height - 50  # Initial Y-axis position

    def add_new_page():
        nonlocal current_y
        c.showPage()  # Add a new page
        c.setFont("Helvetica", 12)
        current_y = height - 50

    # Add Logo and Title
    logo_path = os.path.join("static", "css", "Logo.png")
    if os.path.exists(logo_path):
        logo = ImageReader(logo_path)
        c.drawImage(logo, 50, height - 100, width=100, height=50, mask="auto")
    c.setFont("Helvetica-Bold", 18)
    c.drawString(275, height - 70, "ARGUS")
    c.setFont("Helvetica", 14)
    c.drawCentredString(width / 2, height - 90, "API SCAN REPORT")
    current_y -= 100

    # Timestamp and URL
    c.setFont("Helvetica", 12)
    c.drawString(50, current_y, f"Report for URL: {data['original_url']}")
    current_y -= 20
    c.drawString(50, current_y, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    current_y -= 40

    # Add graphs below the timestamp
    graph1_path = "argus_app/static/css/owasp_line_graph.png"
    graph2_path = "argus_app/static/css/owasp_bar_graph.png"
    create_graphs(graph1_path, graph2_path)

    if os.path.exists(graph1_path):
        c.drawImage(graph1_path, 50, current_y - 150, width=250, height=150)
    if os.path.exists(graph2_path):
        c.drawImage(graph2_path, 320, current_y - 150, width=250, height=150)

    # Adjust current_y to immediately follow the graphs
    current_y -= 180  # Reduced the gap to align with content starting immediately below the images

    # Vulnerabilities Section
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, current_y, "Vulnerabilities Found:")
    current_y -= 20
    vulnerabilities = data["vulnerabilities_found"]
    if vulnerabilities:
        for idx, vuln in enumerate(vulnerabilities, start=1):
            if current_y < 50:
                add_new_page()
                c.drawString(50, current_y, "Vulnerabilities Found (Continued):")
                current_y -= 20
            c.setFont("Helvetica", 12)
            c.drawString(70, current_y, f"- {vuln}")
            current_y -= 20
    else:
        c.setFont("Helvetica", 12)
        c.drawString(70, current_y, "No vulnerabilities found.")
        current_y -= 20


    if current_y < 150:
        add_new_page()

    # Open Endpoints Section
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, current_y, "Open Endpoints:")
    current_y -= 20
    endpoints = data["open_endpoints"]
    for idx, endpoint in enumerate(endpoints, start=1):
        if current_y < 50:
            add_new_page()
            c.drawString(50, current_y, "Open Endpoints (Continued):")
            current_y -= 20
        c.setFont("Helvetica", 12)
        c.drawString(70, current_y, f"- {endpoint}")
        current_y -= 20

    if current_y < 150:
        add_new_page()

    # Mitigation Strategies Section
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, current_y, "Basic Mitigation Strategies:")
    current_y -= 20
    mitigation_points = [
        "1. Regularly update and patch software to fix known vulnerabilities.",
        "2. Implement input validation and sanitization to prevent injection attacks.",
        "3. Use secure authentication and session management practices.",
        "4. Encrypt sensitive data in transit and at rest using strong encryption standards.",
        "5. Conduct regular vulnerability scans and penetration testing to identify risks."
    ]
    for idx, point in enumerate(mitigation_points):
        if current_y < 50:
            add_new_page()
            c.drawString(50, current_y, "Basic Mitigation Strategies (Continued):")
            current_y -= 20
        c.setFont("Helvetica", 12)
        c.drawString(70, current_y, point)
        current_y -= 20

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
