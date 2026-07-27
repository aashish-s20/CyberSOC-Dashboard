import csv
import json
import os
from io import StringIO
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, Response, abort, flash
from flask_login import login_required, current_user
from models.db import db
from models.user import User
from models.scan import NetworkScan, PortResult, DNSResult
from models.monitor import MonitoringSession, CapturedPacket
from models.analyzer import LogFile, LogEvent
from models.vault import VaultFile, IntegrityCheck
from models.threat import ThreatIndicator, ThreatIntelHistory
from models.alert import Alert
from models.incident import Incident, IncidentNote
from models.audit import AuditLog
from services.threat_service import lookup_threat_intel
from services.monitor_service import sniffer_manager
from services.log_parser import parse_log_content
from services.vault_service import encrypt_file_data, decrypt_file_data, calculate_sha256
from services.scanner_utils import (
    is_valid_ipv4,
    is_valid_domain,
    check_host_reachability,
    scan_ports,
    perform_dns_lookup,
    perform_whois_lookup,
    get_ssl_details,
    check_password_strength
)

main_bp = Blueprint('main', __name__)

from functools import wraps
def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return abort(401)
            if current_user.role not in roles:
                return abort(403)
            if current_user.status != 'Active':
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@main_bp.before_request
def check_rbac_limits():
    if not request.endpoint:
        return

    # Exclude public endpoints
    if request.endpoint in ['main.landing']:
        return

    # Only enforce for main blueprint
    if not request.endpoint.startswith('main.'):
        return

    # If guest user, let @login_required decorators do redirect to login page
    if not current_user.is_authenticated:
        return

    # Block any disabled user account
    if current_user.status != 'Active':
        return abort(403)

    role = current_user.role

    # 1. Administrator gets full administrative access to everything
    if role == 'Administrator':
        return

    endpoint = request.endpoint

    # 2. SOC Manager access policy
    manager_allowed = [
        'main.dashboard',
        'main.scanner', 'main.scan_detail', 'main.export_scans',
        'main.monitor', 'main.monitor_detail', 'main.export_monitor_session',
        'main.analyzer', 'main.analyzer_session', 'main.analyzer_export',
        'main.vault', 'main.vault_download_raw', 'main.vault_export',
        'main.threats', 'main.threat_search', 'main.threat_export_history',
        'main.alerts', 'main.alert_acknowledge', 'main.alert_close', 'main.alerts_export',
        'main.incidents', 'main.incident_create', 'main.incident_detail', 'main.incident_update', 'main.incident_add_note', 'main.incidents_export',
        'main.reports',
        'main.admin_audit', 'main.admin_audit_export'
    ]
    if role == 'SOC Manager':
        if endpoint not in manager_allowed:
            return abort(403)
        return

    # 3. Security Engineer access policy
    if role == 'Security Engineer':
        # Deny Admin Panel & User Management & Audit Logs (starts with main.admin_)
        if endpoint.startswith('main.admin_'):
            return abort(403)
        return

    # 4. SOC Analyst access policy
    analyst_allowed = [
        'main.dashboard',
        'main.threats', 'main.threat_search', 'main.threat_export_history',
        'main.alerts', 'main.alerts_export',
        'main.incidents', 'main.incident_detail', 'main.incident_update', 'main.incident_add_note', 'main.incidents_export',
        'main.reports'
    ]
    if role == 'SOC Analyst':
        if endpoint not in analyst_allowed:
            return abort(403)
        return

    # Lock down any other unknown role status
    return abort(403)

@main_bp.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('landing.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    total_scans = NetworkScan.query.count()
    last_scan = NetworkScan.query.order_by(NetworkScan.timestamp.desc()).first()
    recent_scans = NetworkScan.query.order_by(NetworkScan.timestamp.desc()).limit(5).all()

    # Phase 4 Monitor Metrics
    packets_captured = CapturedPacket.query.count()
    last_session = MonitoringSession.query.order_by(MonitoringSession.start_time.desc()).first()
    
    tcp_count = CapturedPacket.query.filter_by(protocol='TCP').count()
    udp_count = CapturedPacket.query.filter_by(protocol='UDP').count()
    icmp_count = CapturedPacket.query.filter_by(protocol='ICMP').count()
    arp_count = CapturedPacket.query.filter_by(protocol='ARP').count()
    other_count = CapturedPacket.query.filter(~CapturedPacket.protocol.in_(['TCP', 'UDP', 'ICMP', 'ARP'])).count()
    protocol_data = [tcp_count, udp_count, icmp_count, arp_count, other_count]

    # Phase 5 Log Analyzer Metrics
    total_logs_analysed = LogFile.query.count()
    critical_events_count = LogEvent.query.filter_by(severity='Critical').count()
    recent_log_upload = LogFile.query.order_by(LogFile.upload_time.desc()).first()
    recent_logs = LogFile.query.order_by(LogFile.upload_time.desc()).limit(5).all()

    # Phase 6 SecureVault Metrics
    files_protected = VaultFile.query.count()
    recent_vault_upload = VaultFile.query.order_by(VaultFile.upload_time.desc()).first()
    integrity_checks_count = IntegrityCheck.query.count()
    recent_vault_files = VaultFile.query.order_by(VaultFile.upload_time.desc()).limit(5).all()

    # Phase 7 Threat Intelligence Metrics
    total_ioc_searches = ThreatIntelHistory.query.count()
    high_risk_findings = ThreatIntelHistory.query.filter(ThreatIntelHistory.risk_level.in_(['High', 'Critical'])).count()
    recent_ioc_lookup = ThreatIntelHistory.query.order_by(ThreatIntelHistory.search_time.desc()).first()

    # Phase 8 Alert & Incident Metrics
    active_alerts_count = Alert.query.filter(Alert.status.in_(['New', 'Acknowledged'])).count()
    open_incidents_count = Incident.query.filter(Incident.status.in_(['Open', 'In Progress'])).count()
    critical_alerts_count = Alert.query.filter_by(severity='Critical').count()
    
    # Weekly Incident Trend Data
    from datetime import date, timedelta
    today = date.today()
    incident_trend_labels = []
    incident_trend_data = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_str = day.strftime('%Y-%m-%d')
        count = Incident.query.filter(db.func.strftime('%Y-%m-%d', Incident.created_date) == day_str).count()
        incident_trend_labels.append(day.strftime('%b %d'))
        incident_trend_data.append(count)

    return render_template(
        'dashboard.html',
        user=current_user,
        total_scans=total_scans,
        last_scan=last_scan,
        recent_scans=recent_scans,
        packets_captured=packets_captured,
        last_session=last_session,
        protocol_data=protocol_data,
        total_logs_analysed=total_logs_analysed,
        critical_events_count=critical_events_count,
        recent_log_upload=recent_log_upload,
        recent_logs=recent_logs,
        files_protected=files_protected,
        recent_vault_upload=recent_vault_upload,
        integrity_checks_count=integrity_checks_count,
        recent_vault_files=recent_vault_files,
        total_ioc_searches=total_ioc_searches,
        high_risk_findings=high_risk_findings,
        recent_ioc_lookup=recent_ioc_lookup,
        active_alerts_count=active_alerts_count,
        open_incidents_count=open_incidents_count,
        critical_alerts_count=critical_alerts_count,
        incident_trend_labels=incident_trend_labels,
        incident_trend_data=incident_trend_data
    )

@main_bp.route('/scanner')
@login_required
def scanner():
    scans = NetworkScan.query.filter_by(user_id=current_user.id).order_by(NetworkScan.timestamp.desc()).all()
    return render_template('scanner.html', scans=scans)

@main_bp.route('/scanner/scan', methods=['POST'])
@login_required
def run_scan():
    scan_type = request.form.get('scan_type')
    target = request.form.get('target', '').strip()
    port_range = request.form.get('port_range', '').strip()

    if not scan_type:
        return jsonify({"success": False, "error": "Scan type is required."}), 400

    if scan_type != 'Password Strength' and not target:
        return jsonify({"success": False, "error": "Target IP/Domain is required."}), 400

    # Validate inputs
    import re
    if scan_type in ['Host Discovery', 'Port Scan']:
        is_ip = re.match(r'^[0-9.]+$', target)
        if is_ip:
            valid = is_valid_ipv4(target)
        else:
            valid = is_valid_domain(target)
        if not valid:
            return jsonify({"success": False, "error": "Target must be a valid IPv4 address or domain name."}), 400
    elif scan_type in ['DNS Lookup', 'WHOIS', 'SSL Certificate']:
        if not is_valid_domain(target) or re.match(r'^[0-9.]+$', target):
            return jsonify({"success": False, "error": "Target must be a valid domain name."}), 400
    elif scan_type == 'Password Strength':
        if not target:
            return jsonify({"success": False, "error": "Password input cannot be empty."}), 400

    results = {}
    try:
        if scan_type == 'Host Discovery':
            reachable, msg = check_host_reachability(target)
            results = {"target": target, "reachable": reachable, "message": msg}
        elif scan_type == 'Port Scan':
            results = scan_ports(target, port_range if port_range else None)
            if "error" in results:
                return jsonify({"success": False, "error": results["error"]}), 400
        elif scan_type == 'DNS Lookup':
            results = perform_dns_lookup(target)
            if "error" in results:
                return jsonify({"success": False, "error": results["error"]}), 400
        elif scan_type == 'WHOIS':
            results = perform_whois_lookup(target)
            if "error" in results:
                return jsonify({"success": False, "error": results["error"]}), 400
        elif scan_type == 'SSL Certificate':
            results = get_ssl_details(target)
            if "error" in results:
                return jsonify({"success": False, "error": results["error"]}), 400
        elif scan_type == 'Password Strength':
            results = check_password_strength(target)
            if "error" in results:
                return jsonify({"success": False, "error": results["error"]}), 400
            # Redact password for database target entry
            target = "[Redacted Password]"
        else:
            return jsonify({"success": False, "error": "Unsupported scan type."}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Internal scan execution failed: {str(e)}"}), 500

    # Save to database
    try:
        new_scan = NetworkScan(
            user_id=current_user.id,
            target=target,
            scan_type=scan_type,
            results_json=json.dumps(results)
        )
        db.session.add(new_scan)
        db.session.flush()

        if scan_type == 'Port Scan' and "results" in results:
            for item in results["results"]:
                p_res = PortResult(
                    scan_id=new_scan.id,
                    port=item["port"],
                    service=item["service"],
                    status=item["status"]
                )
                db.session.add(p_res)
            
            # Alert generation: Port Scan identified open ports
            open_ports = [item["port"] for item in results["results"] if item["status"] == "Open"]
            if open_ports:
                alert_desc = f"Port scan on target '{target}' identified open ports: {', '.join(map(str, open_ports))}."
                alert = Alert(
                    source_module='Network Scanner',
                    alert_type='Open Port Detected',
                    severity='Medium',
                    description=alert_desc,
                    status='New'
                )
                db.session.add(alert)
        elif scan_type == 'DNS Lookup' and "records" in results:
            for record_type, records in results["records"].items():
                for value in records:
                    dns_res = DNSResult(
                        scan_id=new_scan.id,
                        record_type=record_type,
                        value=value
                    )
                    db.session.add(dns_res)
        elif scan_type == 'Host Discovery' and results.get("reachable"):
            alert_desc = f"Target host '{target}' responded to reachability discovery checks successfully."
            alert = Alert(
                source_module='Network Scanner',
                alert_type='Host Responding',
                severity='Low',
                description=alert_desc,
                status='New'
            )
            db.session.add(alert)

        log_audit_entry('Scanner Run', f"Ran {scan_type} scan targeting {target}.")
        db.session.commit()
        return jsonify({"success": True, "scan_id": new_scan.id, "results": results})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"Failed to save scan record: {str(e)}"}), 500

@main_bp.route('/scanner/history/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = db.session.get(NetworkScan, scan_id)
    if not scan:
        abort(404)
    results = json.loads(scan.results_json) if scan.results_json else {}
    return render_template('scan_detail.html', scan=scan, results=results)

@main_bp.route('/scanner/export')
@login_required
def export_scans():
    scans = NetworkScan.query.order_by(NetworkScan.timestamp.desc()).all()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Scan ID', 'User', 'Target', 'Scan Type', 'Timestamp'])
    for s in scans:
        cw.writerow([s.id, s.user.username, s.target, s.scan_type, s.timestamp.strftime('%Y-%m-%d %H:%M:%S')])
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=scan_history.csv"}
    )

@main_bp.route('/monitor')
@login_required
def monitor():
    sessions = MonitoringSession.query.filter_by(user_id=current_user.id).order_by(MonitoringSession.start_time.desc()).all()
    return render_template('monitor.html', sessions=sessions)

@main_bp.route('/monitor/interfaces')
@login_required
def monitor_interfaces():
    ifaces = sniffer_manager.get_interfaces()
    return jsonify({"success": True, "interfaces": ifaces})

@main_bp.route('/monitor/start', methods=['POST'])
@login_required
def monitor_start():
    interface = request.form.get('interface', '').strip()
    if not interface:
        return jsonify({"success": False, "error": "Network interface selection is required."}), 400

    if sniffer_manager.is_monitoring:
        return jsonify({"success": False, "error": "A packet monitoring session is already active."}), 400

    from datetime import datetime, timezone
    try:
        session = MonitoringSession(
            user_id=current_user.id,
            interface=interface,
            start_time=datetime.now(timezone.utc)
        )
        db.session.add(session)
        db.session.commit()

        # Start thread
        sniffer_manager.start_monitoring(interface, session.id)
        log_audit_entry('Monitor Capture Started', f"Started packet capture session #{session.id} on interface '{interface}'.")
        return jsonify({
            "success": True,
            "session_id": session.id,
            "warning": sniffer_manager.permission_warning
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"Failed to start monitoring session: {str(e)}"}), 500

@main_bp.route('/monitor/stop', methods=['POST'])
@login_required
def monitor_stop():
    if not sniffer_manager.is_monitoring:
        return jsonify({"success": False, "error": "No active monitoring session found."}), 400

    from datetime import datetime, timezone
    session_id = sniffer_manager.active_session_id
    
    try:
        # Stop thread
        sniffer_manager.stop_monitoring()
        
        # Final drain of buffer
        final_packets = sniffer_manager.retrieve_new_packets()
        for p in final_packets:
            pkt = CapturedPacket(
                session_id=session_id,
                timestamp=datetime.fromisoformat(p["timestamp"]),
                source_ip=p["src"],
                destination_ip=p["dst"],
                protocol=p["protocol"],
                length=p["length"]
            )
            db.session.add(pkt)
        db.session.commit()

        # Update session totals
        session = db.session.get(MonitoringSession, session_id)
        if session:
            session.end_time = datetime.now(timezone.utc)
            session.total_packets = CapturedPacket.query.filter_by(session_id=session_id).count()
            db.session.commit()
            total_pkts = session.total_packets
            ifaces = session.interface
            
            # Generate alert
            severity = 'Medium' if total_pkts > 50 else 'Low'
            alert_desc = f"Network monitor session completed on interface '{ifaces}'. Captured {total_pkts} packets."
            alert = Alert(
                source_module='Network Monitor',
                alert_type='Traffic Capture Summary',
                severity=severity,
                description=alert_desc,
                status='New'
            )
            db.session.add(alert)
            db.session.commit()
        else:
            total_pkts = 0
            ifaces = "Unknown"

        log_audit_entry('Monitor Capture Stopped', f"Stopped packet capture session #{session_id}. Captured {total_pkts} packets.")
        return jsonify({
            "success": True,
            "session_id": session_id,
            "total_packets": total_pkts,
            "interface": ifaces
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"Failed to gracefully close monitoring: {str(e)}"}), 500

@main_bp.route('/monitor/live-data')
@login_required
def monitor_live_data():
    if not sniffer_manager.is_monitoring:
        return jsonify({"success": False, "error": "Sniffer is inactive."}), 400

    from datetime import datetime, timezone
    try:
        new_packets = sniffer_manager.retrieve_new_packets()
        
        # Save to DB in real-time
        for p in new_packets:
            pkt = CapturedPacket(
                session_id=sniffer_manager.active_session_id,
                timestamp=datetime.fromisoformat(p["timestamp"]),
                source_ip=p["src"],
                destination_ip=p["dst"],
                protocol=p["protocol"],
                length=p["length"]
            )
            db.session.add(pkt)
        if new_packets:
            db.session.commit()
            
        return jsonify({
            "success": True,
            "packets": new_packets,
            "warning": sniffer_manager.permission_warning,
            "use_simulation": sniffer_manager.use_simulation
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"Error gathering live data feed: {str(e)}"}), 500

@main_bp.route('/monitor/session/<int:session_id>')
@login_required
def monitor_detail(session_id):
    session = db.session.get(MonitoringSession, session_id)
    if not session:
        abort(404)
        
    packets = CapturedPacket.query.filter_by(session_id=session_id).order_by(CapturedPacket.timestamp.asc()).all()
    
    # Calculate stats
    tcp_count = CapturedPacket.query.filter_by(session_id=session_id, protocol='TCP').count()
    udp_count = CapturedPacket.query.filter_by(session_id=session_id, protocol='UDP').count()
    icmp_count = CapturedPacket.query.filter_by(session_id=session_id, protocol='ICMP').count()
    arp_count = CapturedPacket.query.filter_by(session_id=session_id, protocol='ARP').count()
    other_count = CapturedPacket.query.filter(CapturedPacket.session_id == session_id, ~CapturedPacket.protocol.in_(['TCP', 'UDP', 'ICMP', 'ARP'])).count()
    
    # Top talkers
    from sqlalchemy import func
    top_sources = db.session.query(
        CapturedPacket.source_ip, func.count(CapturedPacket.id).label('cnt')
    ).filter_by(session_id=session_id).group_by(CapturedPacket.source_ip).order_by(func.count(CapturedPacket.id).desc()).limit(5).all()
    
    top_destinations = db.session.query(
        CapturedPacket.destination_ip, func.count(CapturedPacket.id).label('cnt')
    ).filter_by(session_id=session_id).group_by(CapturedPacket.destination_ip).order_by(func.count(CapturedPacket.id).desc()).limit(5).all()

    stats = {
        "TCP": tcp_count,
        "UDP": udp_count,
        "ICMP": icmp_count,
        "ARP": arp_count,
        "Other": other_count
    }
    
    return render_template(
        'monitor_detail.html',
        session=session,
        packets=packets,
        stats=stats,
        top_sources=top_sources,
        top_destinations=top_destinations
    )

@main_bp.route('/monitor/export/<int:session_id>')
@login_required
def export_monitor_session(session_id):
    session = db.session.get(MonitoringSession, session_id)
    if not session:
        abort(404)
        
    packets = CapturedPacket.query.filter_by(session_id=session_id).order_by(CapturedPacket.timestamp.asc()).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Packet ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length (Bytes)'])
    for p in packets:
        cw.writerow([p.id, p.timestamp.strftime('%Y-%m-%d %H:%M:%S'), p.source_ip, p.destination_ip, p.protocol, p.length])
        
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename=session_packets_{session_id}.csv"}
    )

@main_bp.route('/analyzer')
@login_required
def analyzer():
    files = LogFile.query.filter_by(user_id=current_user.id).order_by(LogFile.upload_time.desc()).all()
    return render_template('analyzer.html', files=files)

@main_bp.route('/analyzer/upload', methods=['POST'])
@login_required
def analyzer_upload():
    if 'logfile' not in request.files:
        return jsonify({"success": False, "error": "No log file part in the request."}), 400
        
    file = request.files['logfile']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected."}), 400
        
    # Check extension
    allowed_exts = {'.log', '.txt', '.csv'}
    filename_lower = file.filename.lower()
    if not any(filename_lower.endswith(ext) for ext in allowed_exts):
        return jsonify({"success": False, "error": "Unsupported file format. Please upload .log, .txt, or .csv files."}), 400
        
    # Check size (max 5MB)
    try:
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        if file_size > 5 * 1024 * 1024:
            return jsonify({"success": False, "error": "File size exceeds 5MB limit."}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to check file specifications: {str(e)}"}), 400

    # Ingest content
    try:
        content = file.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return jsonify({"success": False, "error": f"File decoding failure: {str(e)}"}), 400
        
    # Parse logs
    try:
        events = parse_log_content(content, file.filename)
        if not events:
            return jsonify({"success": False, "error": "No logs could be parsed from the file."}), 400
            
        total_events = len(events)
        threat_count = sum(1 for e in events if e["is_threat"])
        
        # Save LogFile meta record
        logfile_record = LogFile(
            user_id=current_user.id,
            filename=file.filename,
            total_events=total_events,
            threat_count=threat_count
        )
        db.session.add(logfile_record)
        db.session.flush() # Yields logfile_record.id
        
        # Save each LogEvent
        for e in events:
            evt = LogEvent(
                logfile_id=logfile_record.id,
                timestamp=e["timestamp"],
                source=e["source"],
                event_type=e["event_type"],
                severity=e["severity"],
                message=e["message"],
                is_threat=e["is_threat"]
            )
            db.session.add(evt)
            
            # Generate alert for threat events (especially Critical/High severity ones)
            if e["is_threat"]:
                alert = Alert(
                    source_module='Log Analyzer',
                    alert_type='Threat Log Event',
                    severity=e["severity"],
                    description=f"Log file '{file.filename}' contains threat signature: {e['message']} (Source: {e['source']}).",
                    status='New'
                )
                db.session.add(alert)
            
        log_audit_entry('Log Ingestion', f"Ingested log file '{file.filename}' containing {total_events} events with {threat_count} threats.")
        db.session.commit()
        return jsonify({"success": True, "file_id": logfile_record.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"Failed to parse or save log data: {str(e)}"}), 500

@main_bp.route('/analyzer/session/<int:file_id>')
@login_required
def analyzer_session(file_id):
    logfile = db.session.get(LogFile, file_id)
    if not logfile:
        abort(404)
        
    # Query parameters for filtering
    severity = request.args.get('severity', '').strip()
    keyword = request.args.get('keyword', '').strip()
    start_date_str = request.args.get('start_date', '').strip()
    end_date_str = request.args.get('end_date', '').strip()
    
    query = LogEvent.query.filter_by(logfile_id=file_id)
    
    if severity:
        query = query.filter_by(severity=severity)
        
    if keyword:
        query = query.filter(LogEvent.message.ilike(f'%{keyword}%'))
        
    from datetime import datetime
    if start_date_str:
        try:
            start_dt = datetime.strptime(start_date_str, '%Y-%m-%d')
            query = query.filter(LogEvent.timestamp >= start_dt)
        except ValueError:
            pass
            
    if end_date_str:
        try:
            end_dt = datetime.strptime(end_date_str, '%Y-%m-%d')
            # include entire end day
            query = query.filter(LogEvent.timestamp <= end_dt.replace(hour=23, minute=59, second=59))
        except ValueError:
            pass

    events = query.order_by(LogEvent.timestamp.asc()).all()
    
    # Calculate stats for the current filtered/unfiltered list
    # Let's calculate base stats for the entire file (unfiltered) to show overall file statistics
    total_count = LogEvent.query.filter_by(logfile_id=file_id).count()
    threat_count = LogEvent.query.filter_by(logfile_id=file_id, is_threat=True).count()
    
    # Severity counts
    critical_count = LogEvent.query.filter_by(logfile_id=file_id, severity='Critical').count()
    high_count = LogEvent.query.filter_by(logfile_id=file_id, severity='High').count()
    medium_count = LogEvent.query.filter_by(logfile_id=file_id, severity='Medium').count()
    low_count = LogEvent.query.filter_by(logfile_id=file_id, severity='Low').count()
    
    # Timeline daily aggregation (max 10 days) for Chart.js
    from sqlalchemy import func
    daily_stats = db.session.query(
        func.date(LogEvent.timestamp).label('day'), func.count(LogEvent.id).label('cnt')
    ).filter_by(logfile_id=file_id).group_by(func.date(LogEvent.timestamp)).order_by(func.date(LogEvent.timestamp).asc()).limit(10).all()
    
    daily_labels = [str(row.day) for row in daily_stats]
    daily_counts = [row.cnt for row in daily_stats]
    
    # Event types counts (top 5)
    type_stats = db.session.query(
        LogEvent.event_type, func.count(LogEvent.id).label('cnt')
    ).filter_by(logfile_id=file_id).group_by(LogEvent.event_type).order_by(func.count(LogEvent.id).desc()).limit(5).all()
    
    type_labels = [row.event_type for row in type_stats]
    type_counts = [row.cnt for row in type_stats]

    stats = {
        "total": total_count,
        "threats": threat_count,
        "Critical": critical_count,
        "High": high_count,
        "Medium": medium_count,
        "Low": low_count,
        "daily_labels": daily_labels,
        "daily_counts": daily_counts,
        "type_labels": type_labels,
        "type_counts": type_counts
    }
    
    return render_template(
        'analyzer_detail.html',
        logfile=logfile,
        events=events,
        stats=stats,
        filters={
            "severity": severity,
            "keyword": keyword,
            "start_date": start_date_str,
            "end_date": end_date_str
        }
    )

@main_bp.route('/analyzer/export/<int:file_id>')
@login_required
def export_analyzer_session(file_id):
    logfile = db.session.get(LogFile, file_id)
    if not logfile:
        abort(404)
        
    events = LogEvent.query.filter_by(logfile_id=file_id).order_by(LogEvent.timestamp.asc()).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Event ID', 'Timestamp', 'Source', 'Event Type', 'Severity', 'Message', 'Is Threat'])
    for e in events:
        cw.writerow([e.id, e.timestamp.strftime('%Y-%m-%d %H:%M:%S'), e.source, e.event_type, e.severity, e.message, 'Yes' if e.is_threat else 'No'])
        
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename=parsed_events_{file_id}.csv"}
    )

from werkzeug.security import generate_password_hash, check_password_hash
from flask import send_file, current_app
import io

@main_bp.route('/vault')
@login_required
def vault():
    keyword = request.args.get('keyword', '').strip()
    date_str = request.args.get('date', '').strip()
    owner_str = request.args.get('owner', '').strip()
    
    query = VaultFile.query
    
    if keyword:
        query = query.filter(VaultFile.filename.ilike(f"%{keyword}%"))
    if date_str:
        query = query.filter(db.func.strftime('%Y-%m-%d', VaultFile.upload_time) == date_str)
    if owner_str:
        query = query.join(VaultFile.user).filter(User.username.ilike(f"%{owner_str}%"))
        
    files = query.order_by(VaultFile.upload_time.desc()).all()
    checks = IntegrityCheck.query.order_by(IntegrityCheck.check_time.desc()).limit(20).all()
    
    return render_template(
        'vault.html',
        files=files,
        checks=checks,
        filters={'keyword': keyword, 'date': date_str, 'owner': owner_str}
    )

@main_bp.route('/vault/upload', methods=['POST'])
@login_required
def vault_upload():
    if 'vault_file' not in request.files or 'password' not in request.form:
        flash("Upload error: File and encryption password are required.", "error")
        return redirect(url_for('main.vault'))
        
    file = request.files['vault_file']
    password = request.form['password']
    
    if file.filename == '' or not password:
        flash("Upload error: File name and password cannot be empty.", "error")
        return redirect(url_for('main.vault'))
        
    # Validate extension
    allowed_exts = {'pdf', 'docx', 'txt', 'csv', 'png', 'jpg'}
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if ext not in allowed_exts:
        flash("Upload error: Unsupported file type. Only PDF, DOCX, TXT, CSV, PNG, JPG allowed.", "error")
        return redirect(url_for('main.vault'))
        
    # Prevent duplicate filenames globally
    existing = VaultFile.query.filter_by(filename=file.filename).first()
    if existing:
        flash(f"Upload error: A file with name '{file.filename}' already exists in the SecureVault.", "error")
        return redirect(url_for('main.vault'))
        
    # Read data
    file_bytes = file.read()
    
    # Validate size (Max 5MB)
    if len(file_bytes) > 5 * 1024 * 1024:
        flash("Upload error: File size exceeds the maximum limit of 5MB.", "error")
        return redirect(url_for('main.vault'))
        
    try:
        encrypted_data, salt, iv = encrypt_file_data(file_bytes, password)
        original_hash = calculate_sha256(file_bytes)
        
        # Save file to disk
        vault_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'vault')
        os.makedirs(vault_dir, exist_ok=True)
        
        secure_uuid_name = os.urandom(16).hex() + ".enc"
        encrypted_path = os.path.join(vault_dir, secure_uuid_name)
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
            
        # Save to DB
        vault_file = VaultFile(
            filename=file.filename,
            encrypted_filename=secure_uuid_name,
            user_id=current_user.id,
            sha256_hash=original_hash,
            salt=salt.hex(),
            iv=iv.hex(),
            password_hash=generate_password_hash(password)
        )
        db.session.add(vault_file)
        log_audit_entry('Vault File Encryption', f"Successfully encrypted and stored file '{file.filename}' (SHA-256: {original_hash}).")
        db.session.commit()
        flash(f"File '{file.filename}' encrypted and stored successfully in the SecureVault.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Cryptography failed: {str(e)}", "error")
        
    return redirect(url_for('main.vault'))

@main_bp.route('/vault/decrypt/<int:file_id>', methods=['POST'])
@login_required
def vault_decrypt(file_id):
    vault_file = db.session.get(VaultFile, file_id)
    if not vault_file:
        abort(404)
        
    password = request.form.get('password', '')
    if not password:
        flash("Decryption error: Password is required.", "error")
        return redirect(url_for('main.vault'))
        
    # Verify password hash
    if not check_password_hash(vault_file.password_hash, password):
        flash("Decryption error: Incorrect encryption key password.", "error")
        return redirect(url_for('main.vault'))
        
    # Read encrypted file
    vault_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'vault')
    encrypted_path = os.path.join(vault_dir, vault_file.encrypted_filename)
    
    if not os.path.exists(encrypted_path):
        flash("File error: Encrypted payload file missing from storage.", "error")
        return redirect(url_for('main.vault'))
        
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
        
    try:
        salt = bytes.fromhex(vault_file.salt)
        iv = bytes.fromhex(vault_file.iv)
        decrypted_data = decrypt_file_data(encrypted_data, password, salt, iv)
        
        # Verify decrypted data hash matches original stored hash
        decrypted_hash = calculate_sha256(decrypted_data)
        if decrypted_hash != vault_file.sha256_hash:
            flash("Integrity warning: Decrypted payload checksum mismatch.", "error")
            
        log_audit_entry('Vault File Decryption', f"Successfully decrypted and downloaded file '{vault_file.filename}'.")
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=vault_file.filename,
            as_attachment=True
        )
    except Exception as e:
        flash(f"Decryption failed: {str(e)}", "error")
        return redirect(url_for('main.vault'))

@main_bp.route('/vault/download/<int:file_id>')
@login_required
def vault_download_raw(file_id):
    vault_file = db.session.get(VaultFile, file_id)
    if not vault_file:
        abort(404)
        
    vault_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'vault')
    encrypted_path = os.path.join(vault_dir, vault_file.encrypted_filename)
    
    if not os.path.exists(encrypted_path):
        flash("File error: Encrypted payload file missing from storage.", "error")
        return redirect(url_for('main.vault'))
        
    return send_file(
        encrypted_path,
        download_name=vault_file.filename + ".enc",
        as_attachment=True
    )

@main_bp.route('/vault/verify/<int:file_id>', methods=['POST'])
@login_required
def vault_verify(file_id):
    vault_file = db.session.get(VaultFile, file_id)
    if not vault_file:
        abort(404)
        
    if 'check_file' not in request.files:
        flash("Verification error: No file uploaded to compare.", "error")
        return redirect(url_for('main.vault'))
        
    file = request.files['check_file']
    if file.filename == '':
        flash("Verification error: No file selected.", "error")
        return redirect(url_for('main.vault'))
        
    file_bytes = file.read()
    computed_hash = calculate_sha256(file_bytes)
    
    is_verified = (computed_hash == vault_file.sha256_hash)
    status = "Integrity Verified" if is_verified else "Integrity Failed"
    
    check = IntegrityCheck(
        vault_file_id=vault_file.id,
        checked_by_id=current_user.id,
        uploaded_filename=file.filename,
        computed_hash=computed_hash,
        status=status
    )
    db.session.add(check)
    
    if not is_verified:
        alert_desc = f"File integrity check FAILED for secure file '{vault_file.filename}'. Checked file: '{file.filename}'. Checksum mismatch detected."
        alert = Alert(
            source_module='SecureVault',
            alert_type='Integrity Violation',
            severity='Critical',
            description=alert_desc,
            status='New'
        )
        db.session.add(alert)
        
    log_audit_entry('Vault Integrity Check', f"Performed integrity verification on file '{vault_file.filename}'. Result: {status}.")
    db.session.commit()
    
    if is_verified:
        flash(f"Integrity Check: Verified! File '{file.filename}' matches the secure original '{vault_file.filename}'.", "success")
    else:
        flash(f"Integrity Check: FAILED! File '{file.filename}' does NOT match the secure original '{vault_file.filename}'.", "error")
        
    return redirect(url_for('main.vault'))

@main_bp.route('/vault/export')
@login_required
def vault_export_history():
    files = VaultFile.query.order_by(VaultFile.upload_time.asc()).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['File ID', 'Filename', 'Upload Time', 'Owner', 'Encryption Status', 'SHA-256 Hash'])
    for f in files:
        cw.writerow([f.id, f.filename, f.upload_time.strftime('%Y-%m-%d %H:%M:%S'), f.user.username, f.encryption_status, f.sha256_hash])
        
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=secure_vault_history.csv"}
    )

@main_bp.route('/threats')
@login_required
def threats():
    # 1. Fetch search history
    history = ThreatIntelHistory.query.order_by(ThreatIntelHistory.search_time.desc()).all()
    
    # 2. Get last search result context to show in the UI console
    last_search = ThreatIntelHistory.query.filter_by(user_id=current_user.id).order_by(ThreatIntelHistory.search_time.desc()).first()
    last_result = None
    if last_search:
        indicator = ThreatIndicator.query.filter(ThreatIndicator.ioc.ilike(last_search.ioc)).first()
        desc = indicator.description if indicator else "No threat signatures found in threat intelligence feeds. The IOC appears to be safe."
        last_result = {
            'ioc': last_search.ioc,
            'ioc_type': last_search.ioc_type,
            'reputation_score': last_search.reputation_score,
            'risk_level': last_search.risk_level,
            'status': last_search.status,
            'category': last_search.category,
            'description': desc,
            'timestamp': last_search.search_time
        }
        
    # 3. Chart Metrics: Risk Level Distribution
    risk_levels = ['Low', 'Medium', 'High', 'Critical']
    risk_data = [ThreatIntelHistory.query.filter_by(risk_level=r).count() for r in risk_levels]
    
    # 4. Chart Metrics: IOC Type Distribution
    ioc_types = ['IPv4 Address', 'Domain Name', 'URL', 'SHA-256 Hash']
    type_data = [ThreatIntelHistory.query.filter_by(ioc_type=t).count() for t in ioc_types]
    
    # 5. Chart Metrics: Daily Searches (Last 7 Days)
    from datetime import date, timedelta
    today = date.today()
    daily_labels = []
    daily_counts = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_str = day.strftime('%Y-%m-%d')
        count = ThreatIntelHistory.query.filter(db.func.strftime('%Y-%m-%d', ThreatIntelHistory.search_time) == day_str).count()
        daily_labels.append(day.strftime('%b %d'))
        daily_counts.append(count)
        
    return render_template(
        'threats.html',
        history=history,
        last_result=last_result,
        risk_data=risk_data,
        type_data=type_data,
        daily_labels=daily_labels,
        daily_counts=daily_counts
    )

@main_bp.route('/threats/search', methods=['POST'])
@login_required
def threat_search():
    query = request.form.get('ioc', '').strip()
    if not query:
        flash("Search error: Threat query cannot be empty.", "error")
        return redirect(url_for('main.threats'))
        
    try:
        result = lookup_threat_intel(query, current_user.id)
        log_audit_entry('IOC Query', f"Queried threat intelligence for IOC '{query}'. Status: {result['status']}, Risk: {result['risk_level']}.")
        if result['status'] == 'Malicious':
            flash(f"Threat Flagged: IOC '{query}' is classified as Malicious ({result['category']}) with risk level: {result['risk_level']}.", "error")
            # Generate alert
            alert = Alert(
                source_module='Threat Intelligence',
                alert_type='Malicious IOC Query',
                severity=result['risk_level'],
                description=f"Analyst queried malicious IOC '{query}' ({result['ioc_type']}). Reputation: {result['reputation_score']}/100. Category: {result['category']}.",
                status='New'
            )
            db.session.add(alert)
            db.session.commit()
        elif result['status'] == 'Suspicious':
            flash(f"Warning: IOC '{query}' is classified as Suspicious ({result['category']}) with risk level: {result['risk_level']}.", "warning")
            # Generate alert
            alert = Alert(
                source_module='Threat Intelligence',
                alert_type='Malicious IOC Query',
                severity=result['risk_level'],
                description=f"Analyst queried suspicious IOC '{query}' ({result['ioc_type']}). Reputation: {result['reputation_score']}/100. Category: {result['category']}.",
                status='New'
            )
            db.session.add(alert)
            db.session.commit()
        else:
            flash(f"IOC Analysis Completed: '{query}' is classified as Safe.", "success")
    except ValueError as e:
        flash(f"Validation failed: {str(e)}", "error")
    except Exception as e:
        flash(f"Search lookup failed: {str(e)}", "error")
        
    return redirect(url_for('main.threats'))

@main_bp.route('/threats/export')
@login_required
def threat_export_history():
    history = ThreatIntelHistory.query.order_by(ThreatIntelHistory.search_time.asc()).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['History ID', 'User', 'IOC', 'IOC Type', 'Reputation Score', 'Risk Level', 'Status', 'Category', 'Search Time'])
    for h in history:
        cw.writerow([
            h.id,
            h.user.username,
            h.ioc,
            h.ioc_type,
            h.reputation_score,
            h.risk_level,
            h.status,
            h.category,
            h.search_time.strftime('%Y-%m-%d %H:%M:%S')
        ])
        
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=threat_intelligence_history.csv"}
    )

@main_bp.route('/alerts')
@login_required
def alerts():
    q = request.args.get('q', '').strip()
    severity = request.args.get('severity', '').strip()
    status = request.args.get('status', '').strip()
    sort = request.args.get('sort', 'desc').strip()
    
    query = Alert.query
    
    if q:
        query = query.filter(
            (Alert.description.ilike(f"%{q}%")) |
            (Alert.alert_type.ilike(f"%{q}%")) |
            (Alert.source_module.ilike(f"%{q}%"))
        )
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
        
    if sort == 'asc':
        query = query.order_by(Alert.timestamp.asc())
    else:
        query = query.order_by(Alert.timestamp.desc())
        
    alerts_list = query.all()
    
    return render_template(
        'alerts.html',
        alerts=alerts_list,
        current_search=q,
        current_severity=severity,
        current_status=status,
        current_sort=sort
    )

@main_bp.route('/alerts/acknowledge/<int:alert_id>', methods=['POST'])
@login_required
def alert_acknowledge(alert_id):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        abort(404)
    alert.status = 'Acknowledged'
    log_audit_entry('Alert Modification', f"Updated alert #{alert.id} status to Acknowledged.")
    db.session.commit()
    flash(f"Alert #{alert.id} acknowledged successfully.", "success")
    return redirect(url_for('main.alerts'))

@main_bp.route('/alerts/close/<int:alert_id>', methods=['POST'])
@login_required
def alert_close(alert_id):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        abort(404)
    alert.status = 'Closed'
    log_audit_entry('Alert Modification', f"Updated alert #{alert.id} status to Closed.")
    db.session.commit()
    flash(f"Alert #{alert.id} closed successfully.", "success")
    return redirect(url_for('main.alerts'))

@main_bp.route('/alerts/export')
@login_required
def alerts_export():
    alerts_list = Alert.query.order_by(Alert.timestamp.desc()).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Alert ID', 'Timestamp', 'Source Module', 'Alert Type', 'Severity', 'Description', 'Status'])
    for a in alerts_list:
        cw.writerow([
            a.id,
            a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            a.source_module,
            a.alert_type,
            a.severity,
            a.description,
            a.status
        ])
        
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=alert_history.csv"}
    )

@main_bp.route('/incidents')
@login_required
def incidents():
    priority = request.args.get('priority', '').strip()
    status = request.args.get('status', '').strip()
    
    query = Incident.query
    if priority:
        query = query.filter_by(priority=priority)
    if status:
        query = query.filter_by(status=status)
        
    incidents_list = query.order_by(Incident.created_date.desc()).all()
    users = User.query.all()
    active_alerts = Alert.query.filter(Alert.status.in_(['New', 'Acknowledged'])).all()
    
    return render_template(
        'incidents.html',
        incidents=incidents_list,
        users=users,
        active_alerts=active_alerts,
        current_priority=priority,
        current_status=status
    )

@main_bp.route('/incidents/create', methods=['POST'])
@login_required
def incident_create():
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    priority = request.form.get('priority', 'Medium').strip()
    related_alert_id = request.form.get('related_alert_id', '').strip()
    assigned_user_id = request.form.get('assigned_user_id', '').strip()
    
    if not title or not description:
        flash("Incident creation error: Title and Description are required.", "error")
        return redirect(url_for('main.incidents'))
        
    try:
        alert_id = int(related_alert_id) if related_alert_id else None
        user_id = int(assigned_user_id) if assigned_user_id else None
        
        incident = Incident(
            title=title,
            description=description,
            priority=priority,
            related_alert_id=alert_id,
            assigned_user_id=user_id,
            status='Open'
        )
        db.session.add(incident)
        db.session.flush() # Yields incident.id
        
        # Log initial history note
        note = IncidentNote(
            incident_id=incident.id,
            user_id=current_user.id,
            note="Incident created and investigation opened."
        )
        db.session.add(note)
        
        # Auto-acknowledge related alert
        if alert_id:
            alert = db.session.get(Alert, alert_id)
            if alert and alert.status == 'New':
                alert.status = 'Acknowledged'
                note_alert = IncidentNote(
                    incident_id=incident.id,
                    user_id=current_user.id,
                    note=f"Associated alert #{alert.id} ('{alert.alert_type}') status updated to Acknowledged."
                )
                db.session.add(note_alert)
                
        log_audit_entry('Incident Creation', f"Opened incident case INC-{incident.id}: '{title}' (Priority: {priority}).")
        db.session.commit()
        flash(f"Incident #{incident.id} created successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Incident creation failed: {str(e)}", "error")
        
    return redirect(url_for('main.incidents'))

@main_bp.route('/incidents/<int:incident_id>')
@login_required
def incident_detail(incident_id):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        abort(404)
    users = User.query.all()
    return render_template('incident_detail.html', incident=incident, users=users)

@main_bp.route('/incidents/update/<int:incident_id>', methods=['POST'])
@login_required
def incident_update(incident_id):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        abort(404)
        
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    priority = request.form.get('priority', '').strip()
    status = request.form.get('status', '').strip()
    assigned_user_id = request.form.get('assigned_user_id', '').strip()
    
    if not title or not description or not priority or not status:
        flash("Incident update error: Title, Description, Priority, and Status are required.", "error")
        return redirect(url_for('main.incident_detail', incident_id=incident.id))
        
    try:
        user_id = int(assigned_user_id) if assigned_user_id else None
        
        # Build update audit log note
        changes = []
        if incident.title != title:
            changes.append(f"Title changed to '{title}'")
        if incident.description != description:
            changes.append("Description updated")
        if incident.priority != priority:
            changes.append(f"Priority changed from '{incident.priority}' to '{priority}'")
        if incident.status != status:
            changes.append(f"Status changed from '{incident.status}' to '{status}'")
        if incident.assigned_user_id != user_id:
            old_name = incident.assigned_user.username if incident.assigned_user else "Unassigned"
            new_user = db.session.get(User, user_id) if user_id else None
            new_name = new_user.username if new_user else "Unassigned"
            changes.append(f"Assigned owner changed from '{old_name}' to '{new_name}'")
            
        incident.title = title
        incident.description = description
        incident.priority = priority
        
        # Handle closed date timestamping
        from datetime import datetime, timezone
        if status == 'Closed' and incident.status != 'Closed':
            incident.closed_date = datetime.now(timezone.utc)
        elif status != 'Closed':
            incident.closed_date = None
            
        incident.status = status
        incident.assigned_user_id = user_id
        
        if changes:
            note_content = "Incident parameters updated: " + ", ".join(changes) + "."
            note = IncidentNote(
                incident_id=incident.id,
                user_id=current_user.id,
                note=note_content
            )
            db.session.add(note)
            log_audit_entry('Incident Modification', f"Updated parameters for incident case INC-{incident.id}: " + ", ".join(changes) + ".")
            
        db.session.commit()
        flash(f"Incident #{incident.id} updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Incident update failed: {str(e)}", "error")
        
    return redirect(url_for('main.incident_detail', incident_id=incident.id))

@main_bp.route('/incidents/note/<int:incident_id>', methods=['POST'])
@login_required
def incident_add_note(incident_id):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        abort(404)
        
    note_text = request.form.get('note', '').strip()
    if not note_text:
        flash("Note input cannot be empty.", "error")
        return redirect(url_for('main.incident_detail', incident_id=incident.id))
        
    try:
        note = IncidentNote(
            incident_id=incident.id,
            user_id=current_user.id,
            note=note_text
        )
        db.session.add(note)
        log_audit_entry('Incident Investigation Note', f"Appended new investigation note to incident case INC-{incident.id}.")
        db.session.commit()
        flash("Investigation note appended successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to append note: {str(e)}", "error")
        
    return redirect(url_for('main.incident_detail', incident_id=incident.id))

@main_bp.route('/incidents/export')
@login_required
def incidents_export():
    incidents_list = Incident.query.order_by(Incident.created_date.desc()).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Incident ID', 'Title', 'Description', 'Priority', 'Status', 'Related Alert ID', 'Assigned User', 'Created Date', 'Closed Date'])
    for i in incidents_list:
        cw.writerow([
            i.id,
            i.title,
            i.description,
            i.priority,
            i.status,
            i.related_alert_id or 'None',
            i.assigned_user.username if i.assigned_user else 'Unassigned',
            i.created_date.strftime('%Y-%m-%d %H:%M:%S'),
            i.closed_date.strftime('%Y-%m-%d %H:%M:%S') if i.closed_date else 'Active'
        ])
        
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=incident_history.csv"}
    )

@main_bp.route('/reports')
@login_required
def reports():
    return render_template(
        'coming_soon.html',
        module_name="Reports",
        description="Generate compliance, activity, and executive SOC summary reports in PDF or JSON formats.",
        status="Coming Soon"
    )

# ==========================================
# PHASE 9 - NEW MODULES & ENDPOINTS
# ==========================================

# Helper function to write to AuditLog table
def log_audit_entry(action, details=None):
    try:
        from models.audit import AuditLog
        log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"[AUDIT LOG SYSTEM ERROR] {str(e)}")

# 1. Settings Module
@main_bp.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@main_bp.route('/settings/update', methods=['POST'])
@login_required
def settings_update():
    email = request.form.get('email', '').strip()
    if not email:
        flash("Email input cannot be empty.", "error")
        return redirect(url_for('main.settings'))
        
    try:
        # Check if email is already taken by someone else
        existing = User.query.filter(User.email == email, User.id != current_user.id).first()
        if existing:
            flash("Email address is already in use by another account.", "error")
            return redirect(url_for('main.settings'))
            
        current_user.email = email
        db.session.commit()
        
        log_audit_entry('Profile Modification', f"Analyst updated email profile parameters to: {email}.")
        flash("Profile settings updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to update profile: {str(e)}", "error")
        
    return redirect(url_for('main.settings'))

@main_bp.route('/settings/password', methods=['POST'])
@login_required
def settings_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not current_password or not new_password or not confirm_password:
        flash("Password parameters cannot be empty.", "error")
        return redirect(url_for('main.settings'))
        
    if not current_user.check_password(current_password):
        flash("Incorrect current password.", "error")
        return redirect(url_for('main.settings'))
        
    if len(new_password) < 8:
        flash("New password must be at least 8 characters long.", "error")
        return redirect(url_for('main.settings'))
        
    if new_password != confirm_password:
        flash("Passwords do not match.", "error")
        return redirect(url_for('main.settings'))
        
    try:
        current_user.set_password(new_password)
        db.session.commit()
        
        log_audit_entry('Password Update', "User successfully updated account password credentials.")
        flash("Password updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to change password: {str(e)}", "error")
        
    return redirect(url_for('main.settings'))

@main_bp.route('/settings/preferences', methods=['POST'])
@login_required
def settings_preferences():
    theme_pref = request.form.get('theme_pref', 'default')
    refresh_interval = request.form.get('refresh_interval', '10')
    email_alerts = request.form.get('email_alerts', 'off')
    
    from flask import session
    session['theme_pref'] = theme_pref
    session['refresh_interval'] = refresh_interval
    session['email_alerts'] = email_alerts
    
    log_audit_entry('Preferences Modification', f"User updated application preferences: Theme={theme_pref}, Refresh={refresh_interval}s, Email Alerts={email_alerts}.")
    flash("Application preferences updated successfully.", "success")
    return redirect(url_for('main.settings'))

# 2. Admin Panel
@main_bp.route('/admin')
@login_required
def admin_dashboard():
    total_users = User.query.count()
    active_users = User.query.filter_by(status='Active').count()
    disabled_users = User.query.filter_by(status='Disabled').count()
    total_alerts = Alert.query.count()
    total_incidents = Incident.query.count()
    total_logs = AuditLog.query.count()
    
    # Role distribution
    admins = User.query.filter_by(role='Administrator').count()
    managers = User.query.filter_by(role='SOC Manager').count()
    engineers = User.query.filter_by(role='Security Engineer').count()
    analysts = User.query.filter_by(role='SOC Analyst').count()
    
    import sys
    import platform
    app_health = {
        "db_status": "Operational",
        "db_engine": "SQLite",
        "python_version": sys.version.split()[0],
        "platform": platform.system(),
        "uploads_writeable": os.access(current_app.config['UPLOAD_FOLDER'], os.W_OK) if os.path.exists(current_app.config['UPLOAD_FOLDER']) else True,
        "sniffer_mode": "Simulation" if getattr(sniffer_manager, 'permission_warning', False) else "Operational"
    }
    
    return render_template(
        'admin/dashboard.html',
        total_users=total_users,
        active_users=active_users,
        disabled_users=disabled_users,
        total_alerts=total_alerts,
        total_incidents=total_incidents,
        total_logs=total_logs,
        admins=admins,
        managers=managers,
        engineers=engineers,
        analysts=analysts,
        app_health=app_health
    )

# 3. User Management
@main_bp.route('/admin/users')
@login_required
def admin_users():
    users = User.query.order_by(User.id.asc()).all()
    return render_template('admin/users.html', users=users)

@main_bp.route('/admin/users/add', methods=['POST'])
@login_required
def admin_user_add():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'SOC Analyst').strip()
    status = request.form.get('status', 'Active').strip()
    
    if not username or not email or not password or not role or not status:
        flash("User creation parameters cannot be empty.", "error")
        return redirect(url_for('main.admin_users'))
        
    if len(username) < 3:
        flash("Username must be at least 3 characters long.", "error")
        return redirect(url_for('main.admin_users'))
        
    if len(password) < 8:
        flash("Password must be at least 8 characters long.", "error")
        return redirect(url_for('main.admin_users'))
        
    if User.query.filter_by(username=username).first():
        flash("Username is already registered.", "error")
        return redirect(url_for('main.admin_users'))
        
    if User.query.filter_by(email=email).first():
        flash("Email address is already registered.", "error")
        return redirect(url_for('main.admin_users'))
        
    try:
        new_user = User(username=username, email=email, role=role, status=status)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        log_audit_entry('User Account Created', f"Administrator created user account '{username}' with role '{role}' and status '{status}'.")
        flash(f"User account '{username}' created successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to create user account: {str(e)}", "error")
        
    return redirect(url_for('main.admin_users'))

@main_bp.route('/admin/users/edit/<int:user_id>', methods=['POST'])
@login_required
def admin_user_edit(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
        
    email = request.form.get('email', '').strip()
    role = request.form.get('role', '').strip()
    status = request.form.get('status', '').strip()
    password = request.form.get('password', '') # Optional password reset
    
    if not email or not role or not status:
        flash("User edit parameters cannot be empty.", "error")
        return redirect(url_for('main.admin_users'))
        
    # Prevent self lockout/changes
    if user.id == current_user.id:
        if role != 'Administrator':
            flash("Self-protection check: You cannot downgrade your own administrative Administrator role.", "error")
            return redirect(url_for('main.admin_users'))
        if status != 'Active':
            flash("Self-protection check: You cannot disable your own active account.", "error")
            return redirect(url_for('main.admin_users'))
            
    try:
        # Check email duplicate
        existing = User.query.filter(User.email == email, User.id != user.id).first()
        if existing:
            flash("Email address is already in use by another user account.", "error")
            return redirect(url_for('main.admin_users'))
            
        changes = []
        if user.email != email:
            changes.append(f"Email changed to '{email}'")
        if user.role != role:
            changes.append(f"Role changed from '{user.role}' to '{role}'")
        if user.status != status:
            changes.append(f"Status changed from '{user.status}' to '{status}'")
            
        user.email = email
        user.role = role
        user.status = status
        
        if password:
            if len(password) < 8:
                flash("Reset password must be at least 8 characters long.", "error")
                return redirect(url_for('main.admin_users'))
            user.set_password(password)
            changes.append("Password reset by administrator")
            
        if changes:
            log_audit_entry('User Account Modified', f"Administrator modified user '{user.username}': " + ", ".join(changes) + ".")
            
        db.session.commit()
        flash(f"User account '{user.username}' updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to update user details: {str(e)}", "error")
        
    return redirect(url_for('main.admin_users'))

@main_bp.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_user_delete(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
        
    if user.id == current_user.id:
        flash("Self-protection check: You cannot delete your own administrative account.", "error")
        return redirect(url_for('main.admin_users'))
        
    try:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        log_audit_entry('User Account Deleted', f"Administrator deleted user account '{username}' from system databases.")
        flash(f"User account '{username}' deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete user account: {str(e)}", "error")
        
    return redirect(url_for('main.admin_users'))

@main_bp.route('/admin/users/status/<int:user_id>', methods=['POST'])
@login_required
def admin_user_status(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
        
    if user.id == current_user.id:
        flash("Self-protection check: You cannot disable your own active account.", "error")
        return redirect(url_for('main.admin_users'))
        
    try:
        new_status = 'Disabled' if user.status == 'Active' else 'Active'
        user.status = new_status
        db.session.commit()
        
        log_audit_entry('User Account Status Toggle', f"Administrator toggled status of '{user.username}' to '{new_status}'.")
        flash(f"User '{user.username}' account status updated to {new_status}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to toggle user status: {str(e)}", "error")
        
    return redirect(url_for('main.admin_users'))

# 4. Audit Logs Module
@main_bp.route('/admin/audit')
@login_required
def admin_audit():
    q = request.args.get('q', '').strip()
    action_filter = request.args.get('action_filter', '').strip()
    
    query = AuditLog.query
    
    if q:
        query = query.join(AuditLog.user, isouter=True).filter(
            (AuditLog.action.ilike(f"%{q}%")) |
            (AuditLog.details.ilike(f"%{q}%")) |
            (User.username.ilike(f"%{q}%"))
        )
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
        
    logs = query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    
    # Retrieve unique actions for filtering dropdown list
    unique_actions = db.session.query(AuditLog.action).distinct().all()
    actions_list = [a[0] for a in unique_actions]
    
    return render_template(
        'admin/audit.html',
        logs=logs,
        current_search=q,
        current_action=action_filter,
        actions_list=actions_list
    )

@main_bp.route('/admin/audit/export')
@login_required
def admin_audit_export():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Audit ID', 'Timestamp', 'User', 'Action', 'Details', 'IP Address'])
    for l in logs:
        cw.writerow([
            l.id,
            l.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            l.user.username if l.user else 'System',
            l.action,
            l.details,
            l.ip_address
        ])
        
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=audit_logs_history.csv"}
    )

