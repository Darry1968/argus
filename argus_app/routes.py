from flask import Blueprint, request, jsonify, render_template
# from .utils.scanner import scan_api
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

@app_blueprint.route('/scanner')
def scanner():
    return render_template('argus/scanner.html')

@app_blueprint.route('/report')
def report():
    return render_template('argus/report.html')
