from flask import Blueprint, request, jsonify, render_template, send_file
from .utils.scanner import APIScanner
from .utils.report_generator import generate_report
from models import db, ScanResult
from .controllers import *
import json
import os

app_blueprint = Blueprint(
    'app',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/app/static'
)

@app_blueprint.route('/')
def index():
    return render_template('argus/index.html')

@app_blueprint.route('/scanner',methods=['GET','POST'])
def scanner():
    if request.method == 'POST':
        data = request.form
        url = data.get('url')
        scanner = APIScanner()
        open_endpoints = scanner.scan_api(url)
        owasp_zap_results = [
            "mkc 1 baar",
            "mkc 2 baar",
            "mkc 3 baar",
        ]
        owasp_top_10 = {
            "name": "Darshan Soni",
            "age": 21,
            "skills": ["Python", "Cybersecurity", "PowerShell"],
            "details": {
                "email": "sonidarshan200@gmail.com",
                "location": "Pune, Maharashtra"
            }
        }
        
        return render_template(
            'argus/scanner.html',
            endpoints=open_endpoints, 
            owasp_zap_results = owasp_zap_results,
            owasp_top_10 = owasp_top_10
        )
    else:
        return render_template('argus/scanner.html')

@app_blueprint.route('/report')
def report():
    return render_template('argus/report.html')

@app_blueprint.route('/login')
def login():
    return render_template('argus/login.html')

@app_blueprint.route('/generate-report/<int:url_id>', methods=['GET'])
def generate_report_route(url_id):
    # Fetch data from the database
    url_data = db.session.query(ScanResult).filter_by(id=url_id).first()
    if url_data:
        result_data = json.loads(url_data.result)  # Convert JSON string to dictionary
        vulnerabilities = result_data.get("vulnerabilities", [])  # Extract vulnerabilities
    else:
        return {"error": "URL not found"}, 404

    # Prepare data
    report_data = {
        "original_url": url_data.original_endpoint,
        "open_endpoints": json.loads(url_data.endpoints),
        "vulnerabilities_found": json.loads(url_data.result),
        "timestamp": url_data.timestamp,
    }

    output_dir = "argus_app/static/reports"
    output_path = os.path.join(output_dir, f"report_{url_id}.pdf")

    # Create the directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    generate_report(report_data, output_path)

    # Serve the file
    return send_file(output_path, as_attachment=True)