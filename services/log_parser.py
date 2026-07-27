import re
import csv
from datetime import datetime, timezone
from io import StringIO

# Log parsing regex patterns
SYSLOG_PATTERN = re.compile(
    r'^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+([\w\.\-]+)\s+([\w\/\-]+)(?:\[\d+\])?:\s+(.*)$'
)
CLF_PATTERN = re.compile(
    r'^([\d\.]+) \- \- \[([^\]]+)\] "([^"]+)" (\d+) (\d+)(?: "([^"]+)" "([^"]+)")?$'
)
GENERIC_DATE_PATTERN = re.compile(
    r'^(\d{4}\-\d{2}\-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)'
)

def parse_timestamp(time_str):
    """Utility to try parsing log timestamps with different formats."""
    time_str = time_str.strip()
    formats = [
        ("%Y-%m-%d %H:%M:%S", False),
        ("%Y-%m-%dT%H:%M:%S", False),
        ("%Y-%m-%dT%H:%M:%SZ", False),
        ("%d/%b/%Y:%H:%M:%S %z", False),
        ("%b %d %H:%M:%S", True), # Syslog date doesn't have a year
    ]
    
    for fmt, needs_year in formats:
        try:
            if needs_year:
                # Prepend current year
                year = datetime.now(timezone.utc).year
                dt = datetime.strptime(f"{year} {time_str}", f"%Y {fmt}")
                return dt.replace(tzinfo=timezone.utc)
            else:
                dt = datetime.strptime(time_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
        except ValueError:
            continue
            
    # Fallback to current UTC time if unparseable
    return datetime.now(timezone.utc)

def classify_threat_and_severity(message):
    """Scans message for signatures, determining threat flags, category labels, and severity levels."""
    import urllib.parse
    msg_lower = urllib.parse.unquote(message.lower())
    
    # SQL Injection
    if any(sig in msg_lower for sig in ["union select", "select * from", "' or 1=1", "sql injection", "sqli", "select pass"]):
        return True, "Injection Attack", "Critical"
    
    # XSS
    if any(sig in msg_lower for sig in ["<script>", "javascript:", "onerror=", "xss", "alert("]):
        return True, "Cross-Site Scripting", "Critical"
        
    # Privilege Escalation
    if any(sig in msg_lower for sig in ["privilege escalation", "sudo su", "root access", "chmod +x"]):
        return True, "Privilege Escalation", "Critical"
        
    # Brute Force
    if "brute force" in msg_lower or "bruteforce" in msg_lower:
        return True, "Intrusion Attempt", "High"
        
    # Malware
    if any(sig in msg_lower for sig in ["malware", "virus", "trojan", "ransomware", "backdoor"]):
        return True, "Malware Detection", "High"
        
    # Failed Login & Auth Failures
    if any(sig in msg_lower for sig in ["failed login", "login failed", "authentication failure", "auth failure", "invalid password"]):
        return True, "Auth Event", "High"
        
    # Port Scan
    if "port scan" in msg_lower or "portscan" in msg_lower or "nmap scan" in msg_lower:
        return True, "Reconnaissance", "High"
        
    # Access Denied
    if "access denied" in msg_lower or "permission denied" in msg_lower:
        return True, "Access Violation", "Medium"
        
    # Suspicious Activity
    if "suspicious activity" in msg_lower or "suspicious connection" in msg_lower:
        return True, "Security Warning", "Medium"
        
    # General Info severity matches
    if any(sig in msg_lower for sig in ["critical", "fatal", "panic"]):
        return False, "System Alert", "Critical"
    if any(sig in msg_lower for sig in ["error", "fail", "err"]):
        return False, "System Error", "High"
    if any(sig in msg_lower for sig in ["warn", "warning"]):
        return False, "System Warning", "Medium"
        
    # Default fallback
    return False, "System Info", "Low"

def parse_log_content(content, filename):
    """Ingests log contents, detects structure format, and yields parsed event dictionaries."""
    events = []
    
    # 1. Try parsing as CSV first
    if filename.endswith('.csv'):
        try:
            reader = csv.DictReader(StringIO(content))
            headers = [h.lower() for h in reader.fieldnames] if reader.fieldnames else []
            
            # Map headers
            timestamp_col = next((h for h in reader.fieldnames if 'time' in h.lower() or 'date' in h.lower()), None)
            source_col = next((h for h in reader.fieldnames if 'src' in h.lower() or 'source' in h.lower() or 'host' in h.lower() or 'ip' in h.lower()), None)
            event_col = next((h for h in reader.fieldnames if 'event' in h.lower() or 'type' in h.lower() or 'cat' in h.lower()), None)
            severity_col = next((h for h in reader.fieldnames if 'sev' in h.lower() or 'level' in h.lower() or 'priority' in h.lower()), None)
            msg_col = next((h for h in reader.fieldnames if 'msg' in h.lower() or 'message' in h.lower() or 'desc' in h.lower() or 'info' in h.lower()), None)
            
            for row in reader:
                msg_val = row.get(msg_col, "") if msg_col else str(row)
                is_threat, event_type, calculated_sev = classify_threat_and_severity(msg_val)
                
                # Use row severity if calculated is low
                row_sev = row.get(severity_col, calculated_sev) if severity_col else calculated_sev
                final_sev = row_sev if row_sev in ["Critical", "High", "Medium", "Low"] else calculated_sev
                
                events.append({
                    "timestamp": parse_timestamp(row.get(timestamp_col, "")) if timestamp_col else datetime.now(timezone.utc),
                    "source": row.get(source_col, "CSV Source") if source_col else "Unknown",
                    "event_type": row.get(event_col, event_type) if event_col else event_type,
                    "severity": final_sev,
                    "message": msg_val,
                    "is_threat": is_threat
                })
            return events
        except Exception:
            # Fall back to text parsing if CSV parsing fails
            pass

    # 2. Text / Log parsing line by line
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Try Syslog matching
        sys_match = SYSLOG_PATTERN.match(line)
        if sys_match:
            time_raw, source, daemon, msg = sys_match.groups()
            is_threat, event_type, severity = classify_threat_and_severity(msg)
            events.append({
                "timestamp": parse_timestamp(time_raw),
                "source": source,
                "event_type": f"Syslog: {daemon}",
                "severity": severity,
                "message": msg,
                "is_threat": is_threat
            })
            continue

        # Try Web server (CLF) matching
        clf_match = CLF_PATTERN.match(line)
        if clf_match:
            client_ip, time_raw, request, status, size = clf_match.groups()[:5]
            is_threat, event_type, severity = classify_threat_and_severity(request)
            
            # Label web query
            web_event_type = f"Web Request: {request.split()[0]}" if request.split() else "Web Request"
            
            events.append({
                "timestamp": parse_timestamp(time_raw),
                "source": client_ip,
                "event_type": web_event_type,
                "severity": severity,
                "message": f'Request: "{request}" | Status: {status} | Size: {size} Bytes',
                "is_threat": is_threat
            })
            continue

        # Generic line fallback
        date_match = GENERIC_DATE_PATTERN.match(line)
        if date_match:
            time_raw = date_match.group(1)
            msg = line[len(time_raw):].strip(" -:")
            ts = parse_timestamp(time_raw)
        else:
            msg = line
            ts = datetime.now(timezone.utc)
            
        is_threat, event_type, severity = classify_threat_and_severity(msg)
        events.append({
            "timestamp": ts,
            "source": "System",
            "event_type": event_type,
            "severity": severity,
            "message": msg,
            "is_threat": is_threat
        })
        
    return events
