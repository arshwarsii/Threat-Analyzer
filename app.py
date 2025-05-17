from flask import Flask, render_template, request, jsonify, session
import hashlib
import requests
import os
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = "a8237004a0fa0c6be08a85ddfa214167ed8c80b7c8331c2624fc7e71a7f3df2d"  # Replace with your actual API key
API_URL = "https://www.virustotal.com/vtapi/v2"

# Helper Functions
def get_file_hash(file_data):
    """Calculate SHA-256 hash for the uploaded file"""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_data)
    return sha256_hash.hexdigest()

def generate_verdict(report):
    """Generate a verdict based on scan results"""
    if report['positives'] == 0:
        return "✅ This file/URL appears safe with no detections."
    elif report['positives'] <= 3:
        return "⚠️ Low-risk alert: Some vendors flagged this as suspicious."
    elif 4 <= report['positives'] <= 10:
        return "⚠️⚠️ Moderate risk: Multiple security vendors detected potential threats."
    else:
        return "❌ High risk: Widespread detection as malicious. Avoid using!"

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
    
    # Check file size
    file_data = file.read()
    file_size = len(file_data)
    
    if file_size < 1:  # Minimum 1 byte
        return jsonify({'success': False, 'error': 'File is too small to analyze'})
    
    if file_size > 32 * 1024 * 1024:  # 32MB
        return jsonify({'success': False, 'error': 'File exceeds 32MB size limit'})
    
    # Calculate hash
    file_hash = get_file_hash(file_data)
    
    # First try to get existing report
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    response = requests.get(f"{API_URL}/file/report", params=params)
    
    if response.status_code == 200:
        report = response.json()
        
        if report.get('response_code') == 0:
            # File not found, submit for analysis
            file.seek(0)  # Rewind file pointer after reading
            files = {'file': (file.filename, file.stream, file.mimetype)}
            headers = {"Accept-Encoding": "gzip, deflate"}
            
            try:
                submit_response = requests.post(
                    f"{API_URL}/file/scan",
                    files=files,
                    params={'apikey': VIRUSTOTAL_API_KEY},
                    headers=headers,
                    timeout=30
                )
                
                if submit_response.status_code == 200:
                    submit_data = submit_response.json()
                    if submit_data.get('response_code') == 1:
                        return jsonify({
                            'success': False,
                            'error': 'File submitted for analysis. Please try again in a few minutes.'
                        })
                    else:
                        return jsonify({
                            'success': False,
                            'error': 'Submission failed: ' + submit_data.get('verbose_msg', 'Unknown error')
                        })
                else:
                    return jsonify({
                        'success': False,
                        'error': f"Submission API Error: {submit_response.status_code}"
                    })
            except requests.exceptions.RequestException as e:
                return jsonify({
                    'success': False,
                    'error': f"Connection error: {str(e)}"
                })
        
        # Process existing report
        if not report.get('scans'):
            return jsonify({
                'success': False,
                'error': 'Analysis not complete yet. Please try again later.'
            })
            
        verdict = generate_verdict(report)
        
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
                'first_seen': report.get('first_seen') or report.get('creation_date') or 'N/A',
                'last_seen': report.get('last_seen') or report.get('last_analysis_date') or 'N/A',
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
    app.run(debug=True)
