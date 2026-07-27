import re
import socket
import ssl
import subprocess
import platform
from datetime import datetime, timezone
import whois
import dns.resolver

# 1. Input Validators
def is_valid_ipv4(ip_str):
    """Validate if a string is a standard IPv4 address."""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not pattern.match(ip_str):
        return False
    return all(0 <= int(part) < 256 for part in ip_str.split('.'))

def is_valid_domain(domain_str):
    """Validate if a string is a valid hostname/domain name."""
    pattern = re.compile(
        r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])"
        r"(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$"
    )
    return bool(pattern.match(domain_str))

# 2. Host Reachability
def check_host_reachability(target):
    """Check if target host is reachable using ICMP ping or TCP port connection fallback."""
    # Resolve hostname to IP first if it's a domain
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return False, "Unable to resolve hostname."

    # Try standard ICMP Ping based on Platform
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
    
    cmd = ['ping', param, '1', timeout_param, timeout_val, ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return True, f"Reachable (Ping response from {ip})"
    except Exception:
        pass

    # Fallback to TCP handshake test on port 80 or 443
    for port in [80, 443, 22]:
        try:
            with socket.create_connection((ip, port), timeout=1.0) as sock:
                return True, f"Reachable (TCP Handshake succeeded on port {port})"
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue

    return False, f"Host {ip} did not respond to ICMP ping or TCP requests."

# 3. TCP Port Scanner
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "Microsoft-DS",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT"
}

def scan_ports(target, port_range_str=None):
    """Scan target IP/Domain for open ports. Supports default common ports or custom range (e.g. 1-100)."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"error": "Unable to resolve target host."}

    ports_to_scan = []
    if port_range_str:
        # Parse custom range e.g. "20-80"
        match = re.match(r"^(\d+)-(\d+)$", port_range_str.strip())
        if not match:
            return {"error": "Invalid port range format. Use 'start-end' (e.g. 20-80)."}
        start, end = int(match.group(1)), int(match.group(2))
        if start < 1 or end > 65535 or start > end:
            return {"error": "Port numbers must be between 1 and 65535, and start <= end."}
        if (end - start) > 1000:
            return {"error": "For safety, maximum scan limit is 1000 ports."}
        ports_to_scan = list(range(start, end + 1))
    else:
        ports_to_scan = sorted(COMMON_PORTS.keys())

    results = []
    for port in ports_to_scan:
        service_name = COMMON_PORTS.get(port, "Unknown")
        if service_name == "Unknown":
            try:
                service_name = socket.getservbyport(port, "tcp")
            except OSError:
                pass
                
        # Attempt TCP socket connection
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)  # Low timeout for fast scans
                result = sock.connect_ex((ip, port))
                if result == 0:
                    status = "Open"
                else:
                    status = "Closed"
            results.append({
                "port": port,
                "service": service_name,
                "status": status
            })
        except Exception:
            results.append({
                "port": port,
                "service": service_name,
                "status": "Closed"
            })
            
    return {"target": target, "ip": ip, "results": results}

# 4. DNS Lookup
def perform_dns_lookup(domain):
    """Fetch DNS records (A, AAAA, MX, NS, CNAME) for target domain."""
    if not is_valid_domain(domain):
        return {"error": "Invalid domain format."}

    record_types = ['A', 'AAAA', 'MX', 'NS', 'CNAME']
    results = {}
    
    # Initialize resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    for r_type in record_types:
        results[r_type] = []
        try:
            answers = resolver.resolve(domain, r_type)
            for rdata in answers:
                if r_type == 'MX':
                    results[r_type].append(f"{rdata.preference} {rdata.exchange}")
                else:
                    results[r_type].append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
        except Exception as e:
            continue
            
    return {"domain": domain, "records": results}

# 5. WHOIS Lookup
def perform_whois_lookup(domain):
    """Retrieve WHOIS details for domain."""
    if not is_valid_domain(domain):
        return {"error": "Invalid domain format."}

    try:
        w = whois.whois(domain)
        # Parse Dates safely
        def parse_date(date_val):
            if isinstance(date_val, list):
                return str(date_val[0])
            return str(date_val) if date_val else "Unknown"

        creation_date = parse_date(w.creation_date)
        expiration_date = parse_date(w.expiration_date)
        
        # Name servers formatting
        ns = w.name_servers
        if isinstance(ns, list):
            ns_str = ", ".join(ns)
        else:
            ns_str = str(ns) if ns else "Unknown"

        # Status formatting
        status = w.status
        if isinstance(status, list):
            status_str = status[0]
        else:
            status_str = str(status) if status else "Unknown"

        return {
            "domain": domain,
            "registrar": w.registrar or "Unknown",
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "name_servers": ns_str,
            "status": status_str
        }
    except Exception as e:
        return {"error": f"WHOIS query failed: {str(e)}"}

# 6. SSL Certificate Viewer
def get_ssl_details(hostname):
    """Fetch and decode SSL Certificate parameters from target host on port 443."""
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {"error": "Unable to resolve target hostname."}

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Enable self-signed retrieval

    try:
        with socket.create_connection((ip, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Retrieve certificate in binary (DER) form
                bin_cert = ssock.getpeercert(binary_form=True)
                # Convert to dict format using ssl.DER_cert_to_PEM_cert and custom loaders
                pem_cert = ssl.DER_cert_to_PEM_cert(bin_cert)
                
                # Retrieve parsed details with verify_mode CERT_REQUIRED fallback if possible
                # Or parsing elements manually/from standard dictionary if valid
                cert_dict = None
                try:
                    # Try getting full dict with standard context load
                    ctx_verify = ssl.create_default_context()
                    with socket.create_connection((ip, 443), timeout=2.0) as sock_v:
                        with ctx_verify.wrap_socket(sock_v, server_hostname=hostname) as ssock_v:
                            cert_dict = ssock_v.getpeercert()
                except Exception:
                    pass

                # If verification failed (e.g. self-signed), retrieve details safely from connections
                if not cert_dict:
                    # Return basic stats
                    return {
                        "issuer": "Verification failed (Self-Signed / Untrusted Certificate)",
                        "subject": hostname,
                        "valid_from": "Unknown",
                        "valid_until": "Unknown",
                        "days_remaining": "Unknown",
                        "warning": "SSL Certificate verification failed, could not decode details."
                    }

                # Helper to format name fields
                def get_common_name(name_struct):
                    if not name_struct:
                        return "Unknown"
                    for rdn in name_struct:
                        for entry in rdn:
                            if entry[0] == 'commonName':
                                return entry[1]
                    return "Unknown"

                issuer = get_common_name(cert_dict.get('issuer'))
                subject = get_common_name(cert_dict.get('subject'))
                
                # Parse validity timestamps
                # Format: 'May 21 00:00:00 2026 GMT'
                date_fmt = "%b %d %H:%M:%S %Y %Z"
                not_before = datetime.strptime(cert_dict['notBefore'], date_fmt).replace(tzinfo=timezone.utc)
                not_after = datetime.strptime(cert_dict['notAfter'], date_fmt).replace(tzinfo=timezone.utc)
                
                now = datetime.now(timezone.utc)
                days_remaining = (not_after - now).days

                return {
                    "issuer": issuer,
                    "subject": subject,
                    "valid_from": not_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "valid_until": not_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "days_remaining": max(0, days_remaining)
                }
    except Exception as e:
        return {"error": f"Failed to retrieve SSL details: {str(e)}"}

# 7. Password Strength Checker
def check_password_strength(password):
    """Evaluate password strength parameters without saving input."""
    if not password:
        return {"error": "Empty password input."}

    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    # Scoring out of 5 criteria
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1 # Extra point for length
    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_symbol: score += 1

    # Map score to labels
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    elif score == 5:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return {
        "length": length,
        "has_uppercase": has_upper,
        "has_lowercase": has_lower,
        "has_numbers": has_digit,
        "has_symbols": has_symbol,
        "score": min(5, score),
        "strength": strength
    }
