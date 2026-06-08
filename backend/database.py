import sqlite3
import json
import os
from datetime import datetime, timedelta
import random

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scans.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Scans Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL,
            overall_score INTEGER DEFAULT 0,
            overall_severity TEXT DEFAULT 'OK',
            overall_emoji TEXT DEFAULT '🟢',
            results_json TEXT
        )
    ''')
    
    # 2. Threat Intelligence Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            country TEXT NOT NULL,
            country_code TEXT NOT NULL,
            attacks_detected INTEGER NOT NULL,
            risk_percentage REAL NOT NULL,
            source_ips TEXT NOT NULL
        )
    ''')
    
    # 3. Vulnerabilities Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            severity TEXT NOT NULL,
            cvss_score REAL NOT NULL,
            description TEXT NOT NULL,
            impact TEXT NOT NULL,
            component TEXT NOT NULL,
            remediation TEXT NOT NULL,
            status TEXT NOT NULL,
            discovered_at TEXT NOT NULL
        )
    ''')
    
    # 4. Audit Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            user TEXT NOT NULL,
            details TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    
    # Check if we need to seed the tables
    cursor.execute("SELECT COUNT(*) FROM threat_intel")
    if cursor.fetchone()[0] == 0:
        seed_db(cursor)
        conn.commit()
        
    conn.close()

def seed_db(cursor):
    print("🌱 Seeding enterprise database datasets...")
    
    # 1. Seed Threat Intelligence
    countries = [
        ("United States", "US", 3450, 32.8, ["192.168.4.12", "172.56.21.90", "98.137.11.23"]),
        ("China", "CN", 2980, 28.3, ["220.181.38.148", "111.206.22.12", "180.149.132.8"]),
        ("Russian Federation", "RU", 1840, 17.5, ["95.108.19.122", "87.250.250.242", "213.180.204.3"]),
        ("Germany", "DE", 850, 8.1, ["46.137.92.100", "78.47.125.180", "193.99.144.80"]),
        ("Brazil", "BR", 540, 5.1, ["200.221.2.45", "186.202.153.220", "201.54.195.12"]),
        ("India", "IN", 420, 4.0, ["125.21.246.33", "202.54.30.22", "59.177.100.12"])
    ]
    for c in countries:
        cursor.execute('''
            INSERT INTO threat_intel (country, country_code, attacks_detected, risk_percentage, source_ips)
            VALUES (?, ?, ?, ?, ?)
        ''', (c[0], c[1], c[2], c[3], json.dumps(c[4])))
        
    # 2. Seed Vulnerabilities
    vulns = [
        ("CVE-2026-4431", "CRITICAL", 9.8, 
         "Remote Code Execution (RCE) via deserialization block in main load balancer config.", 
         "Complete system compromise. Attacker can execute commands with superuser permissions.", 
         "Load Balancer Engine v2.4", 
         "Upgrade Load Balancer service to version 2.5 or apply serialization class validation filter.", 
         "OPEN", (datetime.now() - timedelta(days=2)).isoformat()),
         
        ("CVE-2026-1024", "HIGH", 8.4, 
         "SQL Injection (SQLi) vulnerability in user session management module.", 
         "Unauthorized data read of session tables. Potential account takeover.", 
         "Authentication Gateway Service", 
         "Implement parameterized prepared queries in db session retrieval driver.", 
         "IN_PROGRESS", (datetime.now() - timedelta(days=5)).isoformat()),
         
        ("CVE-2025-9981", "HIGH", 7.5, 
         "Cross-Site Scripting (Stored XSS) in administrative support chat portal.", 
         "Execution of malicious scripts in admin browsers. Cookie/JWT token extraction.", 
         "Support Chat Widget UI", 
         "Sanitize comment text payloads using DOMPurify libraries prior to UI injection.", 
         "OPEN", (datetime.now() - timedelta(days=12)).isoformat()),
         
        ("CVE-2025-5021", "MEDIUM", 6.1, 
         "Lack of Strict-Transport-Security (HSTS) configuration on API domains.", 
         "SSL Stripping attacks. Interception of login credentials on untrusted networks.", 
         "HTTP Router Gateway", 
         "Configure HTTP headers filter to emit Strict-Transport-Security with max-age=31536000.", 
         "PATCHED", (datetime.now() - timedelta(days=18)).isoformat()),
         
        ("CVE-2025-3210", "MEDIUM", 5.3, 
         "Open network diagnostic endpoints exposed to public DNS routing.", 
         "Information disclosure of internal cluster node architectures.", 
         "Kubernetes Diagnostic Panel", 
         "Enforce security group rules to restrict diagnostic endpoints to VPN internal subnets.", 
         "PATCHED", (datetime.now() - timedelta(days=25)).isoformat()),
         
        ("CVE-2025-0144", "LOW", 3.8, 
         "Suboptimal Clickjacking protections via missing X-Frame-Options (XFO) header.", 
         "Potential frame styling UI spoofing attacks targeting authenticated users.", 
         "Static Landing Assets", 
         "Emit X-Frame-Options: SAMEORIGIN header filter across landing domains.", 
         "PATCHED", (datetime.now() - timedelta(days=40)).isoformat())
    ]
    for v in vulns:
        cursor.execute('''
            INSERT INTO vulnerabilities (id, severity, cvss_score, description, impact, component, remediation, status, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', v)

    # 3. Seed Audit Logs
    logs = [
        ((datetime.now() - timedelta(minutes=5)).isoformat(), "USER_LOGIN", "SUCCESS", "admin@cybershield.io", "User log-in session verified successfully from IP 192.168.2.140."),
        ((datetime.now() - timedelta(minutes=15)).isoformat(), "SCAN_COMPLETED", "SUCCESS", "SYSTEM_DAEMON", "Security audit completed for target domain: github.com. Overall score: 92%."),
        ((datetime.now() - timedelta(minutes=20)).isoformat(), "SCAN_INITIATED", "STARTED", "admin@cybershield.io", "Manual scan triggered for target domain: github.com."),
        ((datetime.now() - timedelta(hours=2)).isoformat(), "VULNERABILITY_DISCOVERED", "ALERT", "SYSTEM_DAEMON", "Critical risk RCE (CVE-2026-4431) discovered in load balancer configuration during nightly audit."),
        ((datetime.now() - timedelta(hours=6)).isoformat(), "REPORT_GENERATED", "SUCCESS", "security-officer@cybershield.io", "Compliance Report SOC2 downloaded by user session."),
        ((datetime.now() - timedelta(days=1)).isoformat(), "SETTINGS_CHANGED", "UPDATED", "admin@cybershield.io", "Enforced Multi-Factor Authentication (MFA) enforcement threshold globally."),
        ((datetime.now() - timedelta(days=2)).isoformat(), "SCAN_COMPLETED", "SUCCESS", "SYSTEM_DAEMON", "Security audit completed for target domain: api.cybershield.internal. Overall score: 54%."),
        ((datetime.now() - timedelta(days=3)).isoformat(), "DATABASE_BACKUP", "SUCCESS", "SYSTEM_DAEMON", "Scheduled database backup uploaded to secure S3 storage bucket."),
        ((datetime.now() - timedelta(days=5)).isoformat(), "USER_ROLE_UPDATED", "SUCCESS", "admin@cybershield.io", "Upgraded security-officer@cybershield.io privileges to Policy Admin.")
    ]
    for l in logs:
        cursor.execute('''
            INSERT INTO audit_logs (timestamp, action, status, user, details)
            VALUES (?, ?, ?, ?, ?)
        ''', l)

    # 4. Seed some completed scans in scans table to provide instant historical values
    dummy_scans = [
        ("scan_github_20260608", "github.com", (datetime.now() - timedelta(hours=1)).isoformat(), "complete", 92, "OK", "🟢", 
         {'target': 'github.com', 'timestamp': (datetime.now() - timedelta(hours=1)).isoformat(), 'status': 'complete', 'overall_score': 92, 'overall_severity': 'OK', 'overall_emoji': '🟢', 
          'checks': {
              'ports': {'status': 'success', 'open_ports': [{'port': 443, 'service': 'HTTPS', 'severity': 'OK', 'desc': 'Hypertext Transfer Protocol Secure', 'banner': ''}], 'total_open': 1, 'severity': 'OK'},
              'ssl': {'status': 'success', 'protocol': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384 (256 bits)', 'subject': 'github.com', 'issuer': 'DigiCert SHA2 High Assurance Server CA', 'days_left': 185, 'issues': [{'issue': 'Certificate valid for 185 more days', 'severity': 'OK', 'icon': '✅'}, {'issue': 'Strong Protocol: TLSv1.3', 'severity': 'OK', 'icon': '✅'}], 'severity': 'OK'},
              'headers': {'status': 'success', 'http_status': 200, 'present_headers': [{'header': 'Content-Security-Policy', 'value': "default-src 'self'", 'points': 25, 'icon': '✅'}, {'header': 'Strict-Transport-Security', 'value': 'max-age=31536000', 'points': 25, 'icon': '✅'}, {'header': 'X-Content-Type-Options', 'value': 'nosniff', 'points': 15, 'icon': '✅'}, {'header': 'X-Frame-Options', 'value': 'deny', 'points': 20, 'icon': '✅'}], 'missing_headers': [{'header': 'Referrer-Policy', 'description': 'Missing header', 'points': 10}, {'header': 'Permissions-Policy', 'description': 'Missing header', 'points': 5}], 'score': '85%', 'score_num': 85, 'severity': 'LOW'},
              'dns': {'status': 'success', 'present_records': [{'type': 'A', 'values': ['140.82.112.4']}], 'issues': [], 'severity': 'OK'}
          }}),
          
        ("scan_api_20260606", "api.cybershield.internal", (datetime.now() - timedelta(days=2)).isoformat(), "complete", 54, "MEDIUM", "🟠", 
         {'target': 'api.cybershield.internal', 'timestamp': (datetime.now() - timedelta(days=2)).isoformat(), 'status': 'complete', 'overall_score': 54, 'overall_severity': 'MEDIUM', 'overall_emoji': '🟠', 
          'checks': {
              'ports': {'status': 'success', 'open_ports': [{'port': 80, 'service': 'HTTP', 'severity': 'MEDIUM', 'desc': 'Cleartext HTTP service', 'banner': ''}, {'port': 3306, 'service': 'MySQL', 'severity': 'HIGH', 'desc': 'Exposed database', 'banner': ''}], 'total_open': 2, 'severity': 'HIGH'},
              'ssl': {'status': 'error', 'error': 'Connection refused', 'protocol': 'None', 'issues': [{'issue': 'SSL port closed', 'severity': 'HIGH', 'icon': '❌'}], 'severity': 'HIGH'},
              'headers': {'status': 'success', 'http_status': 200, 'present_headers': [], 'missing_headers': [{'header': 'Content-Security-Policy', 'description': 'Missing CSP', 'points': 25}, {'header': 'Strict-Transport-Security', 'description': 'Missing HSTS', 'points': 25}], 'score': '0%', 'score_num': 0, 'severity': 'HIGH'},
              'dns': {'status': 'success', 'present_records': [{'type': 'A', 'values': ['10.0.4.15']}], 'issues': [{'issue': 'No SPF record found. Vulnerable to email spoofing!', 'severity': 'MEDIUM', 'icon': '⚠️'}], 'severity': 'MEDIUM'}
          }})
    ]
    for s in dummy_scans:
        cursor.execute('''
            INSERT INTO scans (id, target, timestamp, status, overall_score, overall_severity, overall_emoji, results_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (s[0], s[1], s[2], s[3], s[4], s[5], s[6], json.dumps(s[7])))


def save_scan(scan_id, target, timestamp, status, overall_score=0, overall_severity='OK', overall_emoji='🟢', results_dict=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    results_json = json.dumps(results_dict) if results_dict else None
    
    cursor.execute('''
        INSERT INTO scans (id, target, timestamp, status, overall_score, overall_severity, overall_emoji, results_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            status=excluded.status,
            overall_score=excluded.overall_score,
            overall_severity=excluded.overall_severity,
            overall_emoji=excluded.overall_emoji,
            results_json=excluded.results_json
    ''', (scan_id, target, timestamp, status, overall_score, overall_severity, overall_emoji, results_json))
    
    # Save a corresponding audit log automatically on scan completions
    if status == 'complete':
        log_detail = f"Security audit completed for target domain: {target}. Score: {overall_score}%."
        cursor.execute('''
            INSERT INTO audit_logs (timestamp, action, status, user, details)
            VALUES (?, 'SCAN_COMPLETED', 'SUCCESS', 'SYSTEM_DAEMON', ?)
        ''', (timestamp, log_detail))
    elif status == 'error':
        log_detail = f"Security audit failed for target domain: {target}."
        cursor.execute('''
            INSERT INTO audit_logs (timestamp, action, status, user, details)
            VALUES (?, 'SCAN_FAILED', 'FAILURE', 'SYSTEM_DAEMON', ?)
        ''', (timestamp, log_detail))
    elif status == 'scanning':
        log_detail = f"Security audit triggered for target domain: {target}."
        cursor.execute('''
            INSERT INTO audit_logs (timestamp, action, status, user, details)
            VALUES (?, 'SCAN_INITIATED', 'STARTED', 'admin@cybershield.io', ?)
        ''', (timestamp, log_detail))
        
    conn.commit()
    conn.close()

def get_scans():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, target, timestamp, status, overall_score, overall_severity, overall_emoji FROM scans ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def get_scan(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        data = dict(row)
        if data['results_json']:
            data['results'] = json.loads(data['results_json'])
        else:
            data['results'] = None
        del data['results_json']
        return data
    return None

def delete_scan(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()

def get_threat_intel():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM threat_intel ORDER BY attacks_detected DESC')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_vulnerabilities():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vulnerabilities ORDER BY cvss_score DESC')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_audit_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
