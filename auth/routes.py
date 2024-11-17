from flask import Blueprint, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from models import User  # Assuming a User model exists in models.py

from .controllers import *

login_manager = LoginManager()

auth_blueprint = Blueprint('auth', __name__,url_prefix="/auth")

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID."""
    return User.query.get(int(user_id))
    
@auth_blueprint.route('/login', methods=['POST'])
def login():
    """Handle login requests."""
    data = request.form  # Get form data
    if not data:
        flash("data is required")
    
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        login_user(user)
        flash('Logged in successfully!', 'success')
        return redirect(url_for('app.dashboard'))  # Redirect to dashboard

    flash('Invalid email or password', 'danger')
    return redirect(url_for('app.index'))  # Redirect to homepage

@auth_blueprint.route('signup')
def signup():
    """Handle signup requests."""
    data = request.form
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    cpassword = data.get('cpassword')

    # Check if user already exists
    if User.query.filter_by(email=email).first():
        flash('Email already exists', 'danger')
        return redirect(url_for('app.index'))  # Redirect to homepage

    # Create new user
    if password == cpassword:
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(email=email, password=hashed_password)
        new_user.save()  # Assuming a save method is defined in the User model

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('app.index'))
    else:
        flash("Password and confirm password does not match")
        return redirect(url_for('app.login'))

@auth_blueprint.route('/logout', methods=['POST'])
@login_required
def logout():
    """Handle logout requests."""
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('app.index'))