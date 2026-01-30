from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import login_required, current_user, login_user, logout_user
from ..models import User, File, Feedback, AuditLog, Block, Permission
from .. import db
import datetime
import subprocess, json, psutil
from pathlib import Path
from sqlalchemy.orm import joinedload

admin_bp = Blueprint('admin', __name__, template_folder='../templates/admin')


# ==========================
# Admin access control
# ==========================
def admin_required():
    return current_user.is_authenticated and current_user.role == 'ADMIN'

@admin_bp.before_request
def check_admin():
    if request.endpoint and request.endpoint.startswith('admin.'):
        if not admin_required():
            return redirect(url_for('admin.admin_login'))


# ==========================
# Admin Authentication
# ==========================
@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email, role='ADMIN').first()
        if user and user.check_password(password):
            login_user(user)
            flash('Admin login successful')
            return redirect(url_for('admin.create_user_page'))
        flash('Invalid admin credentials')
    return render_template('admin/login.html')

@admin_bp.route('/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('admin.admin_login'))


# ==========================
# Create User
# ==========================
@admin_bp.route('/create_user', methods=['GET'])
@login_required
def create_user_page():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/create_user.html', users=users)

@admin_bp.post('/users')
@login_required
def create_user():
    email = request.form.get('email')
    username = request.form.get('username') or email.split('@')[0]
    password = request.form.get('password')
    notify_email = request.form.get('notify_email') or email

    if not email or not password:
        flash('Email and password required')
        return redirect(url_for('admin.create_user_page'))

    if User.query.filter_by(email=email).first():
        flash('Email already exists')
        return redirect(url_for('admin.create_user_page'))

    u = User(email=email, username=username, role='USER',
             active=True, notification_email=notify_email)
    u.set_password(password)

    db.session.add(u)
    db.session.add(AuditLog(actor_id=current_user.id,
                            action='ADMIN_CREATE_USER',
                            target_user_id=u.id))
    db.session.commit()

    flash('User created successfully')
    return redirect(url_for('admin.create_user_page'))


# ==========================
# Change Password
# ==========================
@admin_bp.route('/change_password', methods=['GET'])
@login_required
def change_password_page():
    users = User.query.filter(User.role != 'ADMIN').all()
    return render_template('admin/change_password.html', users=users)

@admin_bp.post('/users/<int:user_id>/password')
@login_required
def change_user_password(user_id):
    new_pw = request.form.get('new_password')
    u = User.query.get_or_404(user_id)
    u.set_password(new_pw)

    db.session.add(AuditLog(actor_id=current_user.id,
                            action='ADMIN_CHANGE_PASSWORD',
                            target_user_id=u.id))
    db.session.commit()

    flash('Password updated successfully')
    return redirect(url_for('admin.change_password_page'))


# ==========================
# All Files
# ==========================
@admin_bp.route('/all_files', methods=['GET'])
@login_required
def all_files_page():
    files = (
        db.session.query(File)
        .join(User, File.owner_id == User.id)
        .order_by(File.created_at.desc())
        .all()
    )
    return render_template('admin/all_files.html', files=files)

@admin_bp.get('/files/<int:file_id>/download')
@login_required
def admin_download(file_id):
    f = File.query.get_or_404(file_id)
    return send_file(f.storage_path, as_attachment=True, download_name=f.filename)


# ==========================
# Feedback
# ==========================
@admin_bp.route('/feedback', methods=['GET'])
@login_required
def feedback_page():
    feedbacks = (
        Feedback.query
        .options(joinedload(Feedback.user))
        .order_by(Feedback.created_at.desc())
        .all()
    )
    return render_template('admin/feedback.html', feedbacks=feedbacks)

@admin_bp.post('/feedback/<int:fb_id>/reply')
@login_required
def reply_feedback(fb_id):
    fb = Feedback.query.get_or_404(fb_id)
    reply = request.form.get('reply')

    fb.reply = reply
    fb.status = "CLOSED"

    db.session.add(fb)
    db.session.add(AuditLog(
        actor_id=current_user.id,
        action='ADMIN_REPLY_FEEDBACK',
        target_user_id=fb.user_id,
        details=reply
    ))
    db.session.commit()

    flash("Reply sent")
    return redirect(url_for('admin.feedback_page'))


# ==========================
# Analytics Page
# ==========================
@admin_bp.route('/analytics', methods=['GET'])
@login_required
def analytics_page():
    uploads = (
        db.session.query(
            db.func.date(File.created_at).label("date"),
            db.func.count(File.id).label("count")
        )
        .group_by(db.func.date(File.created_at))
        .all()
    )
    uploads = [{"date": str(r.date), "count": r.count} for r in uploads]

    downloads = (
        db.session.query(
            db.func.date(AuditLog.created_at).label("date"),
            db.func.count(AuditLog.id).label("count")
        )
        .filter(AuditLog.action == "DOWNLOAD")
        .group_by(db.func.date(AuditLog.created_at))
        .all()
    )
    downloads = [{"date": str(r.date), "count": r.count} for r in downloads]

    revokes = (
        db.session.query(
            db.func.date(Permission.revoked_at).label("date"),
            db.func.count(Permission.id).label("count")
        )
        .filter(Permission.revoked_at.isnot(None))
        .group_by(db.func.date(Permission.revoked_at))
        .all()
    )
    revokes = [{"date": str(r.date), "count": r.count} for r in revokes]

    shared_per_user = (
        db.session.query(User.email, db.func.count(Permission.id))
        .join(Permission, Permission.grantee_id == User.id)
        .group_by(User.email)
        .all()
    )
    shared_per_user = [{"email": r[0], "count": r[1]} for r in shared_per_user]

    storage_per_user = (
        db.session.query(User.email, db.func.sum(File.size_bytes))
        .join(File, File.owner_id == User.id)
        .group_by(User.email)
        .all()
    )
    storage_per_user = [{
        "email": r[0],
        "mb": round((r[1] or 0) / 1024 / 1024, 2)
    } for r in storage_per_user]

    return render_template(
        "admin/analytics.html",
        uploads=uploads,
        downloads=downloads,
        revokes=revokes,
        shared_per_user=shared_per_user,
        storage_per_user=storage_per_user
    )


# ==========================
# POW Benchmark (AJAX)
# ==========================
@admin_bp.route('/analytics/run_pow', methods=['POST'])
@login_required
def run_pow():
    """Runs pow_comparison.py externally and returns JSON."""
    script_path = Path(__file__).resolve().parent.parent.parent / "pow_comparison.py"

    if not script_path.exists():
        return jsonify({"error": "pow_comparison.py not found"}), 500

    try:
        result = subprocess.run(
            ["python", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        output = json.loads(result.stdout)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # System performance
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent

    return jsonify({
        "pow": output,
        "system": {
            "cpu": cpu,
            "ram": ram
        }
    })


# ==========================
# Logs
# ==========================
@admin_bp.route('/logs', methods=['GET'])
@login_required
def logs_page():
    logs = (
        db.session.query(AuditLog, User, File)
        .outerjoin(User, AuditLog.actor_id == User.id)
        .outerjoin(File, AuditLog.file_id == File.id)
        .order_by(AuditLog.created_at.desc())
        .all()
    )

    log_data = []
    for log, user, file in logs:
        log_data.append({
            "time": log.created_at,
            "actor": user.email if user else f"User {log.actor_id}",
            "action": log.action,
            "file": file.filename if file else "",
            "target": User.query.get(log.target_user_id).email if log.target_user_id else "",
            "details": log.details or ""
        })

    return render_template("admin/logs.html", logs=log_data)


# ==========================
# Blockchain Viewer
# ==========================
@admin_bp.route('/chain', methods=['GET'])
@login_required
def chain_page():
    blocks = Block.query.order_by(Block.index.desc()).limit(200).all()
    return render_template('admin/chain.html', blocks=blocks)
