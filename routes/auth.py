from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from models.db import db
from models.user import User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if user.status != 'Active':
                from models.audit import AuditLog
                log = AuditLog(
                    username=user.username,
                    user_role=user.role,
                    module='Authentication',
                    action='Authentication Locked',
                    status='Failure',
                    details=f"Blocked login attempt for disabled user account: {user.username}.",
                    ip_address=request.remote_addr
                )
                db.session.add(log)
                db.session.commit()
                flash('This account is disabled. Contact system administrator.', 'error')
                return redirect(url_for('auth.login'))
                
            login_user(user)
            # Update last login time
            user.last_login = datetime.now(timezone.utc)
            
            # Log successful authentication
            from models.audit import AuditLog
            log = AuditLog(
                username=user.username,
                user_role=user.role,
                module='Authentication',
                action='Authentication Success',
                status='Success',
                details=f"User {user.username} successfully logged in.",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            
            db.session.commit()
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            # Log failed authentication
            from models.audit import AuditLog
            log = AuditLog(
                username=username,
                user_role='Unknown',
                module='Authentication',
                action='Authentication Failure',
                status='Failure',
                details=f"Failed login attempt for username: {username}.",
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            flash('Invalid username or password.', 'error')
            
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        role = request.form.get('role', 'SOC Analyst')
        password = request.form.get('password', '')
        
        # Validation checks
        if len(username) < 3:
            flash('Username must be at least 3 characters.', 'error')
            return redirect(url_for('auth.register'))
            
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('auth.register'))
            
        if User.query.filter_by(username=username).first():
            flash('Username is already registered.', 'error')
            return redirect(url_for('auth.register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email address is already registered.', 'error')
            return redirect(url_for('auth.register'))
            
        # Create and save user
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.flush() # Yields new_user.id
        
        # Log self-registration
        from models.audit import AuditLog
        log = AuditLog(
            username=new_user.username,
            user_role=new_user.role,
            module='Authentication',
            action='User Self-Registration',
            status='Success',
            details=f"New user {new_user.username} registered with role: {new_user.role}.",
            ip_address=request.remote_addr
        )
        db.session.add(log)
        
        db.session.commit()
        
        flash('Account registered successfully! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    # Log logout event
    from models.audit import AuditLog
    log = AuditLog(
        username=current_user.username,
        user_role=current_user.role,
        module='Authentication',
        action='Authentication Logout',
        status='Success',
        details=f"User {current_user.username} logged out.",
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.landing'))
