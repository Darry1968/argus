from flask import Blueprint, request, jsonify, render_template
# from .utils.scanner import scan_api
from models import User
from .controllers import *

auth_blueprint = Blueprint('auth', __name__,url_prefix="/auth")

@auth_blueprint.route('/login')
def login():
    return "login api"

@auth_blueprint.route('signup')
def signup():
    return "signup api"