from flask import Flask, render_template, request, jsonify, session
import hashlib
import requests
import os
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = "a8237004a0fa0c6be08a85ddfa214167ed8c80b7c8331c2624fc7e71a7f3df2d"
API_URL = "https://www.virustotal.com/vtapi/v2"

# Helper Functions
def get_file_hash(file_data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_data)
    return sha256_hash.hexdigest()

def generate_verdict(report):
    if report['positives'] == 0:
        return "✅ This file/URL appears safe with no detections."
    elif report['positives'] <= 3:
        return "⚠️ Low-risk alert: Some vendors flagged this as suspicious."
    elif 4 <= report['positives'] <= 10:
        return "⚠️⚠️ Moderate risk: Multiple security vendors detected potential threats."
    else:
        return "❌ High risk: Widespread detection as malicious. Avoid using!"

def check_api_quota():
    current_time = time.time()
    
    if 'last_request_time' not in session:
        session['last_request_time'] = []
    
    last_requests = session['last_request_time']
    
    while last_requests and current_time - last_requests[0] > 60:
        last_requests.pop(0)
    
    if len(last_requests) >= 4:
        return False
    
    last_requests.append(current_time)
    session['last_request_time'] = last_requests
    
    return True

def calculate_community_score(report):
    total = report.get('total', 0)
    positives = report.get('positives', 0)
    
    if total == 0:
        return 100
    
    score = 100 - (positives / total * 100)
    return round(score, 1)

def extract_community_votes(report):
    votes = report.get('votes', {})
    return {
        'harmless': votes.get('harmless', 0),
        'malicious': votes.get('malicious', 0)
    }

def extract_threat_categories(report):
    categories = set()
    scans = report.get('scans', {})
    
    for vendor, result in scans.items():
        if result.get('detected'):
            category = result.get('result', '').lower()
            
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
    
    if not categories and report.get('positives', 0) > 0:
        categories.add('suspicious')
    
    return list(categories)

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

    # Handle initial file submission
    if 'file' in request.files:
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        try:
            file_data = file.read()
            file_size = len(file_data)
            
            if file_size < 1:
                return jsonify({'success': False, 'error': 'File is too small to analyze'})
            
            if file_size > 200 * 1024 * 1024:
                return jsonify({'success': False, 'error': 'File exceeds 32MB size limit'})
            
            file_hash = get_file_hash(file_data)
            params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
            response = requests.get(f"{API_URL}/file/report", params=params)
            
            if response.status_code == 204:
                return jsonify({
                    'success': False,
                    'error': 'VirusTotal API is currently unavailable. Please try again later.'
                })
                
            if response.status_code != 200:
                return jsonify({
                    'success': False,
                    'error': f"API Error: {response.status_code} - {response.text}"
                })
                
            report = response.json()
            response_code = report.get('response_code')

            if response_code == 0:
                # File not in dataset, submit it
                file.seek(0)
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
                    
                    if submit_response.status_code == 204:
                        return jsonify({
                            'success': False,
                            'error': 'VirusTotal API is currently unavailable. Please try again later.'
                        })
                        
                    if submit_response.status_code != 200:
                        return jsonify({
                            'success': False,
                            'error': f"Submission API Error: {submit_response.status_code}"
                        })
                        
                    submit_data = submit_response.json()
                    if submit_data.get('response_code') == 1:
                        return jsonify({
                            'success': False,
                            'scan_id': submit_data.get('scan_id'),
                            'message': 'File submitted for analysis. Please wait...',
                            'requires_polling': True
                        })
                    else:
                        return jsonify({
                            'success': False,
                            'error': 'Submission failed: ' + submit_data.get('verbose_msg', 'Unknown error')
                        })
                        
                except requests.exceptions.RequestException as e:
                    return jsonify({
                        'success': False,
                        'error': f"Connection error: {str(e)}"
                    })
            
            elif response_code == -2:
                # Analysis in progress
                return jsonify({
                    'success': False,
                    'scan_id': report.get('scan_id'),
                    'message': 'Analysis in progress. Please wait...',
                    'requires_polling': True
                })
            
            elif response_code == 1:
                # Analysis complete
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
                    'error': 'Unexpected response code from VirusTotal'
                })
                
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f"Unexpected error: {str(e)}"
            })
    
    # Handle polling with scan_id
    elif 'scan_id' in request.form:
        scan_id = request.form['scan_id']
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_id}
        try:
            response = requests.get(f"{API_URL}/file/report", params=params)
            
            if response.status_code == 204:
                return jsonify({
                    'success': False,
                    'error': 'VirusTotal API is currently unavailable. Please try again later.'
                })
                
            if response.status_code != 200:
                return jsonify({
                    'success': False,
                    'error': f"API Error: {response.status_code} - {response.text}"
                })
                
            report = response.json()
            response_code = report.get('response_code')
            
            if response_code == 1:
                verdict = generate_verdict(report)
                return jsonify({
                    'success': True,
                    'result': {
                        'resource': report.get('resource', scan_id),
                        'scan_date': report.get('scan_date', 'N/A'),
                        'positives': report.get('positives', 0),
                        'total': report.get('total', 0),
                        'permalink': report.get('permalink', ''),
                        'scan_id': scan_id,
                        'community_score': calculate_community_score(report),
                        'first_seen': report.get('first_seen', 'N/A'),
                        'community_votes': extract_community_votes(report),
                        'threat_categories': extract_threat_categories(report),
                        'verdict': verdict
                    }
                })
            
            elif response_code == -2:
                return jsonify({
                    'success': False,
                    'scan_id': scan_id,
                    'message': 'Analysis in progress. Please wait...',
                    'requires_polling': True
                })
            
            else:
                return jsonify({
                    'success': False,
                    'error': 'Invalid scan_id or analysis failed'
                })
                
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f"Polling error: {str(e)}"
            })
    
    return jsonify({
        'success': False,
        'error': 'No file or scan_id provided'
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
    scan_id = data.get('scan_id')
    
    if not url:
        return jsonify({'success': False, 'error': 'No URL provided'})
    
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    if scan_id:
        params['scan_id'] = scan_id
    
    response = requests.get(f"{API_URL}/url/report", params=params)
    
    if response.status_code == 200:
        report = response.json()
        
        if report.get('response_code') == 0:
            submit_params = {'apikey': VIRUSTOTAL_API_KEY, 'url': url}
            submit_response = requests.post(f"{API_URL}/url/scan", data=submit_params)
            
            if submit_response.status_code == 200:
                submit_data = submit_response.json()
                return jsonify({
                    'success': False,
                    'scan_id': submit_data.get('scan_id'),
                    'message': 'URL submitted for analysis. Please wait...',
                    'requires_polling': True
                })
        
        elif report.get('response_code') == -2:
            return jsonify({
                'success': False,
                'scan_id': report.get('scan_id'),
                'message': 'Analysis in progress. Please wait...',
                'requires_polling': True
            })
        
        else:
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
    
    return jsonify({
        'success': False,
        'error': f"API Error: {response.status_code} - {response.text}"
    })

if __name__ == '__main__':
    app.run(debug=True)
