from flask import Blueprint, request, jsonify, render_template
# from .utils.scanner import scan_api
from models import ScanResult
from .controllers import *

app_blueprint = Blueprint('app',__name__)

@app_blueprint.route('/')
def index():
    return "teri mkc"

@app_blueprint.route('/login')
def login():
    return "this is a login page"