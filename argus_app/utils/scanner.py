# app.py
from flask import Flask, request, jsonify
from zapv2 import ZAPv2
import asyncio
import json
import logging
import time
import requests
from datetime import datetime
from typing import List, Dict, Optional
import threading
from concurrent.futures import ThreadPoolExecutor
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ZAPScanner:
    def _init_(self):
        """Initialize ZAP scanner with default configuration"""
        self.zap_api_url = 'http://localhost:8080'
        self.api_key = os.getenv('ZAP_API_KEY', '')  # Get API key from environment variable
        self.zap = ZAPv2(proxies={'http': self.zap_api_url, 'https': self.zap_api_url}, 
                        apikey=self.api_key)
        self.context_id = None
        self.scan_policy = 'API-Scan'

    def create_context(self, target_url: str) -> str:
        """Create a new ZAP context for scanning"""
        context_name = f"api_scan_{int(time.time())}"
        self.context_id = self.zap.context.new_context(context_name)
        
        # Include target URL in context
        self.zap.context.include_in_context(context_name, f"^{target_url}.*$")
        
        # Set up context configurations
        self.zap.context.set_context_in_scope(context_name, True)
        self.zap.context.set_context_technology_included(context_name, 'Db,Db.CouchDB,Db.Cassandra,Db.MongoDB')
        
        return self.context_id

    def setup_scan_policy(self):
        """Set up a custom scan policy for API scanning"""
        try:
            self.zap.ascan.remove_scan_policy(self.scan_policy)
        except:
            pass

        self.zap.ascan.add_scan_policy(self.scan_policy)
        
        # Configure specific scan rules for APIs
        rules = {
            '40012': 'HIGH',    # SQL Injection
            '40014': 'HIGH',    # Cross Site Scripting
            '40018': 'HIGH',    # Remote File Inclusion
            '40020': 'HIGH',    # Integer Overflow
            '90019': 'HIGH',    # Server Side Include
            '90020': 'HIGH',    # Remote OS Command Injection
            '20019': 'HIGH',    # External Redirect
            '40009': 'HIGH',    # Server Side Include
        }
        
        for rule_id, strength in rules.items():
            self.zap.ascan.set_scanner_alert_threshold(rule_id, strength, self.scan_policy)
            self.zap.ascan.set_scanner_attack_strength(rule_id, 'HIGH', self.scan_policy)

    async def discover_api_endpoints(self, target_url: str) -> List[str]:
        """Discover API endpoints using ZAP Spider"""
        logger.info(f"Starting API endpoint discovery for {target_url}")
        
        # Configure and start spider
        scan_id = self.zap.spider.scan(target_url)
        
        # Wait for spider to complete
        while int(self.zap.spider.status(scan_id)) < 100:
            await asyncio.sleep(2)
            
        # Get discovered endpoints
        urls = self.zap.spider.results(scan_id)
        
        # Filter for API endpoints
        api_endpoints = [
            url for url in urls 
            if any(pattern in url.lower() for pattern in ['/api/', '/v1/', '/v2/', '/rest/'])
        ]
        
        logger.info(f"Discovered {len(api_endpoints)} API endpoints")
        return api_endpoints

    async def validate_endpoint(self, endpoint: str) -> bool:
        """Validate if endpoint returns 200 status code"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(endpoint) as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"Error validating endpoint {endpoint}: {str(e)}")
            return False

    async def scan_endpoint(self, endpoint: str) -> Dict:
        """Perform vulnerability scan on an endpoint"""
        logger.info(f"Scanning endpoint: {endpoint}")
        
        # Start active scan
        scan_id = self.zap.ascan.scan(
            endpoint,
            scanpolicyname=self.scan_policy
        )
        
        # Monitor scan progress
        while int(self.zap.ascan.status(scan_id)) < 100:
            await asyncio.sleep(5)
            
        # Get scan results
        alerts = self.zap.core.alerts(baseurl=endpoint)
        return self.process_alerts(endpoint, alerts)

    def process_alerts(self, endpoint: str, alerts: List) -> Dict:
        """Process and categorize vulnerability alerts"""
        processed_results = {
            'endpoint': endpoint,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': []
        }
        
        for alert in alerts:
            vulnerability = {
                'name': alert.get('name'),
                'risk_level': alert.get('risk'),
                'confidence': alert.get('confidence'),
                'description': alert.get('description'),
                'solution': alert.get('solution'),
                'reference': alert.get('reference'),
                'cwe_id': alert.get('cweid'),
                'wasc_id': alert.get('wascid'),
                'evidence': alert.get('evidence', ''),
                'parameter': alert.get('param', ''),
                'attack': alert.get('attack', ''),
                'url': alert.get('url')
            }
            processed_results['vulnerabilities'].append(vulnerability)
        
        return processed_results

class ScanManager:
    def _init_(self):
        self.scanner = ZAPScanner()
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.active_scans = {}

    async def start_scan(self, target_url: str) -> str:
        """Start a new scan session"""
        scan_id = str(int(time.time()))
        self.active_scans[scan_id] = {
            'status': 'starting',
            'target': target_url,
            'results': None,
            'start_time': datetime.now().isoformat()
        }
        
        # Start scan in background
        self.executor.submit(self._run_scan, scan_id, target_url)
        
        return scan_id

    async def _run_scan(self, scan_id: str, target_url: str):
        """Execute the complete scan workflow"""
        try:
            self.active_scans[scan_id]['status'] = 'discovering_endpoints'
            
            # Create context and setup policy
            self.scanner.create_context(target_url)
            self.scanner.setup_scan_policy()
            
            # Discover endpoints
            endpoints = await self.scanner.discover_api_endpoints(target_url)
            
            # Validate endpoints
            valid_endpoints = []
            for endpoint in endpoints:
                if await self.scanner.validate_endpoint(endpoint):
                    valid_endpoints.append(endpoint)
            
            self.active_scans[scan_id]['status'] = 'scanning'
            
            # Scan valid endpoints
            scan_results = []
            for endpoint in valid_endpoints:
                result = await self.scanner.scan_endpoint(endpoint)
                scan_results.append(result)
            
            # Prepare final report
            report = {
                'scan_id': scan_id,
                'target_url': target_url,
                'scan_summary': {
                    'total_endpoints': len(endpoints),
                    'valid_endpoints': len(valid_endpoints),
                    'start_time': self.active_scans[scan_id]['start_time'],
                    'end_time': datetime.now().isoformat()
                },
                'results': scan_results
            }
            
            self.active_scans[scan_id]['status'] = 'completed'
            self.active_scans[scan_id]['results'] = report
            
        except Exception as e:
            logger.error(f"Error during scan {scan_id}: {str(e)}")
            self.active_scans[scan_id]['status'] = 'error'
            self.active_scans[scan_id]['error'] = str(e)

# Initialize scan manager
scan_manager = ScanManager()

# API Routes
@app.route('/api/scan', methods=['POST'])
async def start_scan():
    """Start a new API scan"""
    data = request.get_json()
    target_url = data.get('target_url')
    
    if not target_url:
        return jsonify({'error': 'target_url is required'}), 400
    
    scan_id = await scan_manager.start_scan(target_url)
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'target_url': target_url
    })

@app.route('/api/scan/<scan_id>', methods=['GET'])
async def get_scan_status(scan_id):
    """Get status of a specific scan"""
    scan_info = scan_manager.active_scans.get(scan_id)
    
    if not scan_info:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'scan_id': scan_id,
        'status': scan_info['status'],
        'target': scan_info['target'],
        'results': scan_info['results'] if scan_info['status'] == 'completed' else None
    })

@app.route('/api/scans', methods=['GET'])
async def list_scans():
    """List all scans"""
    scans = []
    for scan_id, info in scan_manager.active_scans.items():
        scans.append({
            'scan_id': scan_id,
            'status': info['status'],
            'target': info['target'],
            'start_time': info.get('start_time')
        })
    
    return jsonify({'scans': scans})
