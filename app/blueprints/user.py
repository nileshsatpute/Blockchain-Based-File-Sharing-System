from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app
from flask_login import login_required, current_user, login_user, logout_user
from ..models import User, File, Permission, Feedback, AuditLog, ShareLink, Block
from ..blockchain import append_block
from .. import db
from pathlib import Path
from datetime import datetime, timezone
import hashlib, uuid
import os


user_bp = Blueprint('user', __name__, template_folder='../templates/user')

@user_bp.before_request
def ensure_user():
    # Skip checks for login and static routes
    if request.endpoint in ('user.login', 'user.static'):
        return
    if request.endpoint and request.endpoint.startswith('user.') and not current_user.is_authenticated:
        return redirect(url_for('user.login'))
# ---------- Authentication ----------
@user_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email, role='USER').first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful')
            return redirect(url_for('user.my_files_page'))
        flash('Invalid credentials')
    return render_template('user_login.html')

@user_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('user.login'))

# ---------- File Upload & Sharing ----------
@user_bp.route('/upload', methods=['GET'])
@login_required
def upload_page():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('user/upload.html', users=users)

@user_bp.post('/upload')
@login_required
def upload():
    f = request.files.get('file')
    if not f or f.filename == '':
        flash('No file selected')
        return redirect(url_for('user.upload_page'))

    storage_dir = Path(current_app.config['UPLOAD_FOLDER'])
    storage_dir.mkdir(parents=True, exist_ok=True)

    target = storage_dir / f"{current_user.id}_{int(datetime.now(timezone.utc).timestamp())}_{f.filename}"
    f.save(target)

    # ✅ Run ClamAV scan before saving to DB
    from app.utils import scan_file_with_clamav
    is_clean, msg = scan_file_with_clamav(str(target))
    if not is_clean:
        # infected → block upload
        os.remove(target)
        flash(f"⚠️ Upload blocked: {msg}")
        return redirect(url_for('user.upload_page'))
    elif "Skipped scan" in msg:
        flash(msg)  # notify user that scan was skipped
    else:
        flash("✅ Virus scan passed: File is clean")

    size = target.stat().st_size
    sha256 = hashlib.sha256(target.read_bytes()).hexdigest()

    # Save file metadata
    file_row = File(
        owner_id=current_user.id,
        filename=f.filename,
        size_bytes=size,
        storage_path=str(target),
        sha256=sha256
    )
    db.session.add(file_row)
    db.session.commit()

    # Always log upload
    db.session.add(AuditLog(actor_id=current_user.id, action='UPLOAD', file_id=file_row.id))

    # 🔥 Handle multiple selected users from <select name="grantees" multiple>
    grantee_ids = request.form.getlist('grantees')
    for gid in grantee_ids:
        perm = Permission(file_id=file_row.id, grantee_id=int(gid), can_download=True)
        db.session.add(perm)
        db.session.add(AuditLog(
            actor_id=current_user.id,
            action="SHARE",
            file_id=file_row.id,
            target_user_id=int(gid)
        ))

    db.session.commit()

    # ---- Add Blockchain entry ----
    from app.models import Block
    import json, random

    data = {
        "action": "UPLOAD",
        "owner_id": current_user.id,
        "filename": f.filename,
        "sha256": sha256,
        "size": size,
        "shared_with": grantee_ids,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "clamav": msg  # ✅ log ClamAV result in blockchain
    }

    prev_block = Block.query.order_by(Block.index.desc()).first()
    index = (prev_block.index + 1) if prev_block else 0
    prev_hash = prev_block.block_hash if prev_block else "0"

    block_str = json.dumps(data, sort_keys=True)
    block_hash = hashlib.sha256((block_str + prev_hash).encode()).hexdigest()

    # set nonce (dummy/random for now)
    nonce = random.randint(0, 1000000)

    new_block = Block(
        index=index,
        prev_hash=prev_hash,
        nonce=nonce,
        timestamp=datetime.now(timezone.utc),
        data_json=block_str,
        block_hash=block_hash
    )

    db.session.add(new_block)
    db.session.commit()

    flash(
        f'File uploaded successfully (Scan: {msg}) & Blockchain updated. Shared with {len(grantee_ids)} users.'
        if grantee_ids else f'File uploaded successfully (Scan: {msg}) & Blockchain updated'
    )
    return redirect(url_for('user.my_files_page'))





from sqlalchemy.orm import joinedload

@user_bp.route('/my_files', methods=['GET'])
@login_required
def my_files_page():
    # Fetch only current user's files
    my_files = (
        File.query.filter_by(owner_id=current_user.id)
        .order_by(File.created_at.desc())
        .all()
    )

    # Other users for granting/revoking
    users = User.query.filter(User.id != current_user.id).all()

    # Build a dict of active permissions (exclude revoked)
    file_permissions = {}
    for f in my_files:
        active_perms = (
            Permission.query
            .filter_by(file_id=f.id)
            .filter(Permission.revoked_at.is_(None))  # only active permissions
            .all()
        )
        file_permissions[f.id] = [p.grantee_id for p in active_perms]

    return render_template(
        'user/my_files.html',
        my_files=my_files,
        users=users,
        file_permissions=file_permissions
    )




@user_bp.post('/share/<int:file_id>')
@login_required
def share(file_id):
    file_row = File.query.get_or_404(file_id)
    gid = int(request.form.get('user_id'))
    db.session.add(Permission(file_id=file_id, grantee_id=gid, can_download=True))
    db.session.add(AuditLog(actor_id=current_user.id, action='SHARE', file_id=file_id, target_user_id=gid))
    db.session.commit()
    flash('Access granted')
    return redirect(url_for('user.my_files_page'))

@user_bp.route('/shared', methods=['GET'])
@login_required
def shared_with_me_page():
    # Get all file IDs where current user has active (not revoked) permission
    shared_file_ids = [
        p.file_id
        for p in Permission.query.filter(
            Permission.grantee_id == current_user.id,
            Permission.revoked_at.is_(None)   # exclude revoked permissions
        ).all()
    ]

    if not shared_file_ids:
        shared_files = []
    else:
        # Fetch files shared with this user and preload owner relationship
        shared_files = (
            db.session.query(File)
            .join(User, File.owner_id == User.id)
            .filter(File.id.in_(shared_file_ids))
            .order_by(File.created_at.desc())
            .all()
        )

    return render_template('user/shared.html', shared_with_me=shared_files)





@user_bp.post('/revoke/<int:file_id>')
@login_required
def revoke(file_id):
    gid = int(request.form.get('user_id'))
    perm = Permission.query.filter_by(file_id=file_id, grantee_id=gid, revoked_at=None).first()
    if perm:
        perm.revoked_at = datetime.now(timezone.utc)
        db.session.add(AuditLog(actor_id=current_user.id, action='REVOKE', file_id=file_id, target_user_id=gid))
        db.session.commit()
        flash('Access revoked')
    return redirect(url_for('user.my_files_page'))

@user_bp.get('/download/<int:file_id>')
@login_required
def download(file_id):
    f = File.query.get_or_404(file_id)
    return send_file(f.storage_path, as_attachment=True, download_name=f.filename)

# ---------- Feedback ----------
@user_bp.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback_page():
    if request.method == 'POST':
        subject = request.form.get('subject')
        body = request.form.get('body')

        fb = Feedback(
            user_id=current_user.id,
            subject=subject,
            body=body,
            status='OPEN'
        )
        db.session.add(fb)
        db.session.add(
            AuditLog(
                actor_id=current_user.id,
                action='USER_FEEDBACK',
                details=subject
            )
        )
        db.session.commit()
        flash('Feedback submitted')
        return redirect(url_for('user.feedback_page'))

    # Show all feedback submitted by the logged-in user
    feedbacks = (
        Feedback.query
        .filter_by(user_id=current_user.id)
        .order_by(Feedback.created_at.desc())
        .all()
    )
    return render_template('user/feedback.html', feedbacks=feedbacks)


@user_bp.post('/feedback')
@login_required
def feedback():
    subj = request.form.get('subject') or ''
    body = request.form.get('body')
    fb = Feedback(user_id=current_user.id, subject=subj, body=body)
    db.session.add(fb); db.session.commit()
    flash('Feedback submitted')
    return redirect(url_for('user.feedback_page'))

# ---------- Blockchain ----------
@user_bp.route('/chain', methods=['GET'])
@login_required
def chain_page():
    blocks = Block.query.filter(Block.data_json.contains(f'"owner_id": {current_user.id}')).order_by(Block.index.desc()).limit(100).all()
    return render_template('user/chain.html', blocks=blocks)
