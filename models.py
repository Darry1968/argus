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
    original_endpoint = db.Column(db.String(2048), nullable=False)  # Original URL scanned
    open_endpoints = db.Column(db.JSON, nullable=False)  # JSON array of open endpoints
    vulnerabilities_found = db.Column(db.JSON, nullable=False)  # JSON array of vulnerabilities
    risk_level = db.Column(db.String(50), nullable=False)  # Overall risk level: Low, Medium, High
    score = db.Column(db.Float, nullable=False)  # A numeric risk score (e.g., 0–100)
    scan_duration = db.Column(db.Float, nullable=False)  # Duration of the scan in seconds
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Scan timestamp
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # User who initiated the scan
    description = db.Column(db.Text, nullable=True)  # Optional: Description or notes about the scan

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)  # Link to ScanResult
    endpoint = db.Column(db.String(2048), nullable=False)  # Vulnerable endpoint
    vulnerability_type = db.Column(db.String(150), nullable=False)  # Type of vulnerability (e.g., XSS, SQLi)
    owasp_category = db.Column(db.String(150), nullable=False)  # OWASP Top 10 category
    severity = db.Column(db.String(50), nullable=False)  # Severity level: Low, Medium, High, Critical
    description = db.Column(db.Text, nullable=True)  # Detailed description of the vulnerability
    remediation = db.Column(db.Text, nullable=True)  # Suggested remediation steps


class Endpoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)  # Link to ScanResult
    url = db.Column(db.String(2048), nullable=False)  # Endpoint URL
    status_code = db.Column(db.Integer, nullable=True)  # HTTP status code (e.g., 200, 403)
    is_open = db.Column(db.Boolean, nullable=False, default=True)  # Whether the endpoint is accessible
    notes = db.Column(db.Text, nullable=True)  # Optional: Notes about the endpoint

