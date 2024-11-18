from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)

    def __repr__(self):
        return self.username


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_endpoint = db.Column(db.String(2048), nullable=False)  # Increased URL length
    endpoints = db.Column(db.Text, nullable=False)  # Store as JSON
    result = db.Column(db.Text, nullable=False)  # Store detailed results as JSON
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Ensure NOT NULL

class Endpoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    status_code = db.Column(db.Integer, nullable=True)  # Nullable if status isn't always available
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)
