from flask import Blueprint, request, jsonify, render_template
from .utils.scanner import APIScanner
from models import ScanResult
from .controllers import *

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