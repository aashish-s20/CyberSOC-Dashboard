import csv
import json
from io import StringIO
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, Response, abort
from flask_login import login_required, current_user
from models.db import db
from models.scan import NetworkScan, PortResult, DNSResult
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
    return render_template(
        'dashboard.html',
        user=current_user,
        total_scans=total_scans,
        last_scan=last_scan,
        recent_scans=recent_scans
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
    return render_template(
        'coming_soon.html',
        module_name="Network Monitor",
        description="Analyze real-time traffic volume, bandwidth consumption, active protocol ratios, and network adapter statistics.",
        status="Coming Soon"
    )

@main_bp.route('/analyzer')
@login_required
def analyzer():
    return render_template(
        'coming_soon.html',
        module_name="Log Analyzer",
        description="Aggregate, parse, and review raw system syslog, audit log, and application logs using regex patterns.",
        status="Coming Soon"
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

