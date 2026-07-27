import csv
import json
from io import StringIO
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, Response, abort
from flask_login import login_required, current_user
from models.db import db
from models.scan import NetworkScan, PortResult, DNSResult
from models.monitor import MonitoringSession, CapturedPacket
from models.analyzer import LogFile, LogEvent
from services.monitor_service import sniffer_manager
from services.log_parser import parse_log_content
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
        recent_logs=recent_logs
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
        elif scan_type == 'DNS Lookup' and "records" in results:
            for record_type, records in results["records"].items():
                for value in records:
                    dns_res = DNSResult(
                        scan_id=new_scan.id,
                        record_type=record_type,
                        value=value
                    )
                    db.session.add(dns_res)

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
        else:
            total_pkts = 0
            ifaces = "Unknown"

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

@main_bp.route('/vault')
@login_required
def vault():
    return render_template(
        'coming_soon.html',
        module_name="SecureVault",
        description="Manage security credentials, API keys, certificates, and sensitive environment configs inside a secure key vault container.",
        status="Coming Soon"
    )

@main_bp.route('/threats')
@login_required
def threats():
    return render_template(
        'coming_soon.html',
        module_name="Threat Intelligence",
        description="Cross-reference IP reputation, DNS blacklist indexes, and local threat feeds against global open intelligence APIs.",
        status="Coming Soon"
    )

@main_bp.route('/alerts')
@login_required
def alerts():
    return render_template(
        'coming_soon.html',
        module_name="Alerts",
        description="Configure rule triggers, routing actions, and notification systems for critical system and threat events.",
        status="Coming Soon"
    )

@main_bp.route('/incidents')
@login_required
def incidents():
    return render_template(
        'coming_soon.html',
        module_name="Incidents",
        description="Track active cases, assignments, resolution notes, and investigation tasks for security breaches.",
        status="Coming Soon"
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

