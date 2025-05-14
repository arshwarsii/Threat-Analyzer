# app.py
from flask import Flask, render_template, request, jsonify, session
import hashlib
import requests
import os
import sqlite3
from datetime import datetime
import time
import socket

app = Flask(__name__)
app.secret_key = os.urandom(24)

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = "a8237004a0fa0c6be08a85ddfa214167ed8c80b7c8331c2624fc7e71a7f3df2d"  # Replace with your actual API key
API_URL = "https://www.virustotal.com/vtapi/v2"

# Database Setup
def init_db():
    conn = sqlite3.connect('scan_history.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT NOT NULL,
        resource TEXT NOT NULL,
        positives INTEGER,
        total INTEGER,
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        verdict TEXT
    )
    ''')
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Helper Functions
def get_file_hash(file_data):
    """Calculate SHA-256 hash for the uploaded file"""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_data)
    return sha256_hash.hexdigest()

def save_to_history(scan_type, resource, positives, total, verdict):
    """Save scan results to database"""
    conn = sqlite3.connect('scan_history.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (scan_type, resource, positives, total, verdict) VALUES (?, ?, ?, ?, ?)",
        (scan_type, resource, positives, total, verdict)
    )
    conn.commit()
    conn.close()

def generate_verdict(report):
    """Generate a verdict based on scan results"""
    if report['positives'] == 0:
        return "This file/URL appears safe with no detections."
    elif report['positives'] <= 3:
        return "Low-risk alert: Some vendors flagged this as suspicious."
    elif 4 <= report['positives'] <= 10:
        return "Moderate risk: Multiple security vendors detected potential threats."
    else:
        return "High risk: Widespread detection as malicious. Avoid using!"

def check_api_quota():
    """Simple implementation of API quota management"""
    current_time = time.time()
    
    if 'last_request_time' not in session:
        session['last_request_time'] = []
    
    # Keep track of the last 4 request times (for 4 requests/minute limit)
    last_requests = session['last_request_time']
    
    # Remove requests older than 60 seconds
    while last_requests and current_time - last_requests[0] > 60:
        last_requests.pop(0)
    
    # Check if we've made 4 or more requests in the last minute
    if len(last_requests) >= 4:
        return False
    
    # Add current request time
    last_requests.append(current_time)
    session['last_request_time'] = last_requests
    
    return True
# Helper function to find an available port
def find_available_port(start_port=5000):
    port = start_port
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                port += 1

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze_file', methods=['POST'])
def analyze_file():
    if not check_api_quota():
        return jsonify({
            'success': False,
            'error': 'API rate limit reached (4 requests/minute). Please try again later.'
        })
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'})
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    # Check file size (32MB limit)
    file_data = file.read()
    if len(file_data) > 32 * 1024 * 1024:  # 32MB in bytes
        return jsonify({'success': False, 'error': 'File exceeds 32MB size limit'})
    
    # Calculate hash
    file_hash = get_file_hash(file_data)
    
    # Query VirusTotal API
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    response = requests.get(f"{API_URL}/file/report", params=params)
    
    if response.status_code == 200:
        report = response.json()
        
        # Check if the file is found in VirusTotal database
        if report.get('response_code') == 0:
            return jsonify({
                'success': False, 
                'error': 'File not found in VirusTotal database. Consider submitting the file for analysis first.'
            })
        
        # Generate verdict
        verdict = generate_verdict(report)
        
        # Save to history
        save_to_history('file', file_hash, report.get('positives', 0), report.get('total', 0), verdict)
        
        return jsonify({
            'success': True,
            'result': {
                'resource': file_hash,
                'scan_date': report.get('scan_date'),
                'positives': report.get('positives', 0),
                'total': report.get('total', 0),
                'permalink': report.get('permalink', ''),
                'scan_id': report.get('scan_id', ''),
                'community_score': calculate_community_score(report),
                'first_seen': report.get('first_seen', 'N/A'),
                'community_votes': extract_community_votes(report),
                'threat_categories': extract_threat_categories(report),
                'verdict': verdict
            }
        })
    else:
        return jsonify({
            'success': False,
            'error': f"API Error: {response.status_code} - {response.text}"
        })

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    if not check_api_quota():
        return jsonify({
            'success': False,
            'error': 'API rate limit reached (4 requests/minute). Please try again later.'
        })
    
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'success': False, 'error': 'No URL provided'})
    
    # Query VirusTotal API
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    response = requests.get(f"{API_URL}/url/report", params=params)
    
    if response.status_code == 200:
        report = response.json()
        
        # Check if the URL is found in VirusTotal database
        if report.get('response_code') == 0:
            return jsonify({
                'success': False, 
                'error': 'URL not found in VirusTotal database. Consider submitting the URL for analysis first.'
            })
        
        # Generate verdict
        verdict = generate_verdict(report)
        
        # Save to history
        save_to_history('url', url, report.get('positives', 0), report.get('total', 0), verdict)
        
        return jsonify({
            'success': True,
            'result': {
                'resource': url,
                'scan_date': report.get('scan_date'),
                'positives': report.get('positives', 0),
                'total': report.get('total', 0),
                'permalink': report.get('permalink', ''),
                'scan_id': report.get('scan_id', ''),
                'community_score': calculate_community_score(report),
                'first_seen': report.get('first_seen', 'N/A'),
                'community_votes': extract_community_votes(report),
                'threat_categories': extract_threat_categories(report),
                'verdict': verdict
            }
        })
    else:
        return jsonify({
            'success': False,
            'error': f"API Error: {response.status_code} - {response.text}"
        })

@app.route('/history', methods=['GET'])
def get_history():
    conn = sqlite3.connect('scan_history.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_history ORDER BY scan_date DESC LIMIT 20")
    rows = cursor.fetchall()
    history = [dict(row) for row in rows]
    conn.close()
    
    return jsonify({'success': True, 'history': history})

# Helper functions for parsing VirusTotal response
def calculate_community_score(report):
    """Calculate a normalized community score from 0-100"""
    total = report.get('total', 0)
    positives = report.get('positives', 0)
    
    if total == 0:
        return 100  # No detections
    
    # Invert the score (fewer detections = higher score)
    score = 100 - (positives / total * 100)
    return round(score, 1)

def extract_community_votes(report):
    """Extract community voting information"""
    votes = report.get('votes', {})
    return {
        'harmless': votes.get('harmless', 0),
        'malicious': votes.get('malicious', 0)
    }

def extract_threat_categories(report):
    """Extract threat categories from scan results"""
    categories = set()
    
    # Extract from scan results if available
    scans = report.get('scans', {})
    for vendor, result in scans.items():
        if result.get('detected'):
            category = result.get('result', '').lower()
            
            # Map common keywords to categories
            if any(x in category for x in ['trojan', 'virus', 'worm', 'backdoor']):
                categories.add('malware')
            if any(x in category for x in ['phish', 'fraud', 'fake']):
                categories.add('phishing')
            if any(x in category for x in ['pua', 'pup', 'unwanted', 'adware']):
                categories.add('potentially_unwanted')
            if any(x in category for x in ['suspicious', 'heuristic']):
                categories.add('suspicious')
            if any(x in category for x in ['exploit', 'cve']):
                categories.add('exploit')
            if any(x in category for x in ['ransom']):
                categories.add('ransomware')
    
    # If no specific categories were found but there are detections, add generic 'suspicious'
    if not categories and report.get('positives', 0) > 0:
        categories.add('suspicious')
    
    return list(categories)

if __name__ == '__main__':
    init_db()
    port = find_available_port()
    print(f"Server running on http://127.0.0.1:{port}")
    app.run(debug=True, port=port)