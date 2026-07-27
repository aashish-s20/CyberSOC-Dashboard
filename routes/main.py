from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('landing.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@main_bp.route('/scanner')
@login_required
def scanner():
    return render_template(
        'coming_soon.html',
        module_name="Network Scanner",
        description="Conduct automated network scanning, active host discovery, port mapping, and vulnerability assessments across configured subnets.",
        status="Coming Soon"
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

