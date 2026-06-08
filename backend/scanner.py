import socket
import ssl
import requests
import urllib3
from datetime import datetime
import concurrent.futures
import dns.resolver

# Disable SSL warnings for unverified requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMMON_PORTS = {
    21: {'service': 'FTP', 'severity': 'HIGH', 'desc': 'File Transfer Protocol - unencrypted auth'},
    22: {'service': 'SSH', 'severity': 'MEDIUM', 'desc': 'Secure Shell - remote access'},
    23: {'service': 'Telnet', 'severity': 'CRITICAL', 'desc': 'Telnet - unencrypted remote access (severe risk!)'},
    25: {'service': 'SMTP', 'severity': 'HIGH', 'desc': 'Simple Mail Transfer Protocol - email relay'},
    53: {'service': 'DNS', 'severity': 'MEDIUM', 'desc': 'Domain Name System - potential zone transfers'},
    80: {'service': 'HTTP', 'severity': 'MEDIUM', 'desc': 'Hypertext Transfer Protocol - cleartext web server'},
    443: {'service': 'HTTPS', 'severity': 'OK', 'desc': 'Hypertext Transfer Protocol Secure - encrypted web server'},
    3306: {'service': 'MySQL', 'severity': 'HIGH', 'desc': 'MySQL Database - exposing data store'},
    5432: {'service': 'PostgreSQL', 'severity': 'HIGH', 'desc': 'PostgreSQL Database - exposing data store'},
    8080: {'service': 'HTTP-Alt', 'severity': 'MEDIUM', 'desc': 'Alternative HTTP port - potential dev server'},
    8443: {'service': 'HTTPS-Alt', 'severity': 'MEDIUM', 'desc': 'Alternative HTTPS port - secondary SSL endpoint'}
}

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        result = sock.connect_ex((target, port))
        
        # Try banner grabbing for open ports
        banner = ""
        if result == 0:
            try:
                if port in [21, 22, 25]:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                pass
            sock.close()
            return {
                'port': port,
                'open': True,
                'service': COMMON_PORTS[port]['service'],
                'severity': COMMON_PORTS[port]['severity'],
                'desc': COMMON_PORTS[port]['desc'],
                'banner': banner
            }
        sock.close()
    except Exception:
        pass
    return {'port': port, 'open': False}

def scan_common_ports(target):
    open_ports = []
    ports_to_scan = list(COMMON_PORTS.keys())
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports_to_scan)) as executor:
        futures = {executor.submit(scan_port, target, p): p for p in ports_to_scan}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res['open']:
                open_ports.append(res)
                
    # Sort open ports
    open_ports.sort(key=lambda x: x['port'])
    
    severity = 'OK'
    if any(p['severity'] == 'CRITICAL' for p in open_ports):
        severity = 'CRITICAL'
    elif any(p['severity'] == 'HIGH' for p in open_ports):
        severity = 'HIGH'
    elif any(p['severity'] == 'MEDIUM' for p in open_ports):
        severity = 'MEDIUM'
    elif open_ports:
        severity = 'LOW'
        
    return {
        'status': 'success',
        'open_ports': open_ports,
        'total_open': len(open_ports),
        'severity': severity
    }

def get_ssl_info(hostname):
    # Try verified context first
    verified = True
    context = ssl.create_default_context()
    
    try:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.settimeout(3.0)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        cipher = conn.cipher()
        protocol = conn.version()
        conn.close()
    except Exception as e_verify:
        verified = False
        # Retry with unverified context to get cert details anyway
        try:
            unverified_context = ssl._create_unverified_context()
            conn = unverified_context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
            conn.settimeout(3.0)
            conn.connect((hostname, 443))
            # getpeercert(binary_form=True) since unverified getpeercert() returns empty dict
            der_cert = conn.getpeercert(binary_form=True)
            cipher = conn.cipher()
            protocol = conn.version()
            conn.close()
            # Parse binary cert
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())
            
            # Extract basic details manually from cryptography object
            cert = {
                'subject': ((('commonName', x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value),),) if x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else (),
                'issuer': ((('commonName', x509_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value),),) if x509_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME) else (),
                'notBefore': x509_cert.not_valid_before_utc.strftime('%b %d %H:%M:%S %Y GMT'),
                'notAfter': x509_cert.not_valid_after_utc.strftime('%b %d %H:%M:%S %Y GMT')
            }
        except Exception as e_unverified:
            return {
                'status': 'error',
                'error': f"Could not establish SSL connection: {str(e_verify)}",
                'protocol': 'None',
                'issues': [{'issue': 'SSL port closed or inaccessible', 'severity': 'HIGH', 'icon': '❌'}],
                'severity': 'HIGH'
            }

    issues = []
    severity = 'OK'
    
    # Check if certificate verification passed
    if not verified:
        issues.append({
            'issue': 'Certificate validation failed (Self-signed or untrusted Certificate Authority)',
            'severity': 'HIGH',
            'icon': '❌'
        })
        severity = 'HIGH'
    else:
        issues.append({
            'issue': 'Certificate is trusted by system root store',
            'severity': 'OK',
            'icon': '✅'
        })
        
    # Parse cert subject and issuer
    subject_cn = "Unknown"
    issuer_cn = "Unknown"
    try:
        for sub in cert.get('subject', []):
            for item in sub:
                if item[0] == 'commonName':
                    subject_cn = item[1]
        for iss in cert.get('issuer', []):
            for item in iss:
                if item[0] == 'commonName':
                    issuer_cn = item[1]
    except Exception:
        pass

    # Parse dates
    days_left = -1
    try:
        # Expected formats: "Apr 15 12:00:00 2026 GMT" or similar
        not_after_str = cert.get('notAfter')
        # Standard ssl module outputs like: 'May  9 18:29:43 2026 GMT'
        # Let's clean multiple spaces
        clean_date_str = ' '.join(not_after_str.split())
        expiry_date = datetime.strptime(clean_date_str, '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry_date - datetime.utcnow()).days
        
        if days_left < 0:
            issues.append({'issue': f'Certificate is EXPIRED (expired {abs(days_left)} days ago)', 'severity': 'HIGH', 'icon': '❌'})
            severity = 'HIGH'
        elif days_left < 30:
            issues.append({'issue': f'Certificate is expiring soon ({days_left} days left)', 'severity': 'MEDIUM', 'icon': '⚠️'})
            if severity != 'HIGH':
                severity = 'MEDIUM'
        else:
            issues.append({'issue': f'Certificate valid for {days_left} more days', 'severity': 'OK', 'icon': '✅'})
    except Exception as e_date:
        issues.append({'issue': f'Could not determine certificate expiry: {str(e_date)}', 'severity': 'LOW', 'icon': '⚠️'})
        if severity == 'OK':
            severity = 'LOW'

    # Check protocol version
    if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
        issues.append({'issue': f'Legacy protocol in use: {protocol}', 'severity': 'HIGH', 'icon': '❌'})
        severity = 'HIGH'
    else:
        issues.append({'issue': f'Strong Protocol: {protocol}', 'severity': 'OK', 'icon': '✅'})

    # Check cipher strength
    try:
        cipher_name = cipher[0]
        cipher_bits = cipher[2]
        if cipher_bits < 128:
            issues.append({'issue': f'Weak cipher suite key length: {cipher_name} ({cipher_bits} bits)', 'severity': 'HIGH', 'icon': '❌'})
            severity = 'HIGH'
        else:
            issues.append({'issue': f'Strong Cipher Suite: {cipher_name} ({cipher_bits} bits)', 'severity': 'OK', 'icon': '✅'})
    except Exception:
        cipher_name = "Unknown"
        cipher_bits = 0

    return {
        'status': 'success',
        'protocol': protocol,
        'cipher': f"{cipher_name} ({cipher_bits} bits)",
        'subject': subject_cn,
        'issuer': issuer_cn,
        'days_left': days_left,
        'issues': issues,
        'severity': severity
    }

def get_headers_info(hostname):
    # Try fetching with HTTPS, fallback to HTTP
    urls = [f"https://{hostname}", f"http://{hostname}"]
    resp = None
    final_url = None
    
    for url in urls:
        try:
            resp = requests.get(url, timeout=3.0, verify=False, allow_redirects=True)
            final_url = resp.url
            break
        except Exception:
            continue
            
    if not resp:
        return {
            'status': 'error',
            'error': 'Could not connect to target via HTTP/HTTPS to check headers',
            'severity': 'HIGH'
        }

    headers = resp.headers
    
    # We will evaluate these specific headers:
    security_headers = {
        'Content-Security-Policy': {
            'desc': 'Prevents Cross-Site Scripting (XSS) and code injection attacks',
            'points': 25
        },
        'Strict-Transport-Security': {
            'desc': 'Enforces HTTPS connections to protect authentication tokens',
            'points': 25
        },
        'X-Frame-Options': {
            'desc': 'Prevents Clickjacking attacks by controlling page framing',
            'points': 20
        },
        'X-Content-Type-Options': {
            'desc': 'Prevents MIME-sniffing vulnerability (forces browser to respect content-type)',
            'points': 15
        },
        'Referrer-Policy': {
            'desc': 'Controls how much referrer info is sent with requests',
            'points': 10
        },
        'Permissions-Policy': {
            'desc': 'Controls browser features (camera, location, APIs) allowed on the site',
            'points': 5
        }
    }

    present = []
    missing = []
    score = 0
    max_score = sum(h['points'] for h in security_headers.values())

    # Case-insensitive headers search
    lower_headers = {k.lower(): v for k, v in headers.items()}
    
    for header_name, info in security_headers.items():
        lower_name = header_name.lower()
        if lower_name in lower_headers:
            val = lower_headers[lower_name]
            present.append({
                'header': header_name,
                'value': val,
                'points': info['points'],
                'icon': '✅'
            })
            score += info['points']
        else:
            missing.append({
                'header': header_name,
                'description': info['desc'],
                'points': info['points'],
                'icon': '❌'
            })

    # Normalized score
    normalized_score = int((score / max_score) * 100)
    
    severity = 'OK'
    if normalized_score < 40:
        severity = 'HIGH'
    elif normalized_score < 75:
        severity = 'MEDIUM'
    elif normalized_score < 90:
        severity = 'LOW'
        
    return {
        'status': 'success',
        'http_status': resp.status_code,
        'final_url': final_url,
        'present_headers': present,
        'missing_headers': missing,
        'score': f"{normalized_score}%",
        'score_num': normalized_score,
        'severity': severity
    }

def get_dns_info(hostname):
    present_records = []
    issues = []
    severity = 'OK'
    
    # Clean host to ignore schema/path
    clean_host = hostname
    if '://' in clean_host:
        clean_host = clean_host.split('://')[1]
    clean_host = clean_host.split('/')[0]

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    
    try:
        # Standard IP resolution test
        socket.gethostbyname(clean_host)
    except Exception:
        return {
            'status': 'success',
            'present_records': [],
            'issues': [{'issue': f'DNS resolution failed for hostname {clean_host}', 'severity': 'HIGH', 'icon': '❌'}],
            'severity': 'HIGH'
        }

    for record in record_types:
        try:
            answers = dns.resolver.resolve(clean_host, record)
            values = []
            for rdata in answers:
                values.append(str(rdata))
            
            present_records.append({
                'type': record,
                'values': values,
                'icon': '✅'
            })
        except Exception:
            # Not found is normal for things like AAAA or TXT, just omit or note it
            pass

    # Basic checklist for DNS health
    has_a = any(r['type'] == 'A' for r in present_records)
    has_mx = any(r['type'] == 'MX' for r in present_records)
    has_ns = any(r['type'] == 'NS' for r in present_records)
    
    if not has_a:
        issues.append({'issue': 'No IPv4 address records (A records) found', 'severity': 'HIGH', 'icon': '❌'})
        severity = 'HIGH'
        
    if not has_ns:
        issues.append({'issue': 'No Name Servers (NS records) found', 'severity': 'MEDIUM', 'icon': '⚠️'})
        if severity != 'HIGH':
            severity = 'MEDIUM'
            
    if not has_mx:
        issues.append({'issue': 'No Mail Servers (MX records) configured', 'severity': 'LOW', 'icon': 'ℹ️'})
        
    # Check TXT for SPF (basic security configuration)
    has_spf = False
    for r in present_records:
        if r['type'] == 'TXT':
            for val in r['values']:
                if 'v=spf1' in val:
                    has_spf = True
                    break
                    
    if not has_spf:
        issues.append({'issue': 'No SPF (Sender Policy Framework) record found. Vulnerable to email spoofing!', 'severity': 'MEDIUM', 'icon': '⚠️'})
        if severity == 'OK':
            severity = 'LOW'
    else:
        issues.append({'issue': 'SPF record is present', 'severity': 'OK', 'icon': '✅'})

    return {
        'status': 'success',
        'present_records': present_records,
        'issues': issues,
        'severity': severity
    }

def run_complete_scan(target):
    # Strip protocol prefix if entered
    hostname = target.strip()
    if '://' in hostname:
        hostname = hostname.split('://')[1]
    hostname = hostname.split('/')[0]
    
    checks = {}
    
    # Run all scanners
    checks['ports'] = scan_common_ports(hostname)
    checks['ssl'] = get_ssl_info(hostname)
    checks['headers'] = get_headers_info(hostname)
    checks['dns'] = get_dns_info(hostname)
    
    # Calculate Overall Score (from 0 to 100)
    # 4 metrics:
    # 1. Ports (Open unsafe ports = deductions)
    # 2. SSL/TLS (validity, protocol quality)
    # 3. HTTP Headers (points based on presence)
    # 4. DNS (SPF presence, records configured)
    
    # 1. Port Score (max 25)
    # Start at 25, subtract based on open vulnerabilities
    port_score = 25
    open_vuln_ports = [p for p in checks['ports']['open_ports'] if p['severity'] in ['CRITICAL', 'HIGH']]
    open_med_ports = [p for p in checks['ports']['open_ports'] if p['severity'] == 'MEDIUM']
    port_score -= len(open_vuln_ports) * 10
    port_score -= len(open_med_ports) * 3
    port_score = max(0, port_score)
    
    # 2. SSL Score (max 25)
    ssl_score = 25
    if checks['ssl']['status'] == 'error':
        ssl_score = 0
    else:
        ssl_sev = checks['ssl']['severity']
        if ssl_sev == 'HIGH':
            ssl_score = 5
        elif ssl_sev == 'MEDIUM':
            ssl_score = 15
        elif ssl_sev == 'LOW':
            ssl_score = 20

    # 3. Headers Score (max 25)
    # We take the 0-100 headers score and divide by 4
    headers_pct = 0
    if checks['headers']['status'] == 'success':
        headers_pct = checks['headers'].get('score_num', 0)
    headers_score = int((headers_pct / 100) * 25)

    # 4. DNS Score (max 25)
    dns_score = 25
    if checks['dns']['severity'] == 'HIGH':
        dns_score = 5
    elif checks['dns']['severity'] == 'MEDIUM':
        dns_score = 15
    elif checks['dns']['severity'] == 'LOW':
        dns_score = 20
        
    overall_score = port_score + ssl_score + headers_score + dns_score
    overall_score = min(100, max(0, overall_score))
    
    # Establish overall severity level
    severities = [
        checks['ports']['severity'],
        checks['ssl']['severity'],
        checks['headers']['severity'],
        checks['dns']['severity']
    ]
    
    if 'CRITICAL' in severities:
        overall_severity = 'CRITICAL'
        overall_emoji = '🔴'
    elif 'HIGH' in severities:
        overall_severity = 'HIGH'
        overall_emoji = '🔴'
    elif 'MEDIUM' in severities:
        overall_severity = 'MEDIUM'
        overall_emoji = '🟠'
    elif 'LOW' in severities or overall_score < 90:
        overall_severity = 'LOW'
        overall_emoji = '🟡'
    else:
        overall_severity = 'OK'
        overall_emoji = '🟢'

    return {
        'target': hostname,
        'timestamp': datetime.now().isoformat(),
        'status': 'complete',
        'overall_score': overall_score,
        'overall_severity': overall_severity,
        'overall_emoji': overall_emoji,
        'checks': checks
    }
