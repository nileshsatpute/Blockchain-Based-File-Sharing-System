# Run instructions (ClamAV + Email)
1. Create venv and install requirements:
   python -m venv .venv
   # activate .venv\Scripts\activate (Windows) or source .venv/bin/activate (Linux)
   pip install -r requirements.txt
   If python-clamd fails to install on Windows, install Git and try: pip install git+https://github.com/graingert/python-clamd.git

2. Install ClamAV and start clamd:
   - Ubuntu:
     sudo apt update && sudo apt install -y clamav clamav-daemon
     sudo systemctl stop clamav-freshclam.service
     sudo freshclam
     sudo systemctl start clamav-daemon
   - Windows: install ClamAV for Windows and ensure clamd is running (or use clamd service).

   Example .env:
     SECRET_KEY=supersecret
     DATABASE_URL=sqlite:///app.db
     FROM_EMAIL=you@gmail.com

4. Start the app:
   python run_app.py
   Open http://localhost:5000
   Admin seeded: email=admin@example.com, password=Admin (change in admin panel after login)

Notes:
- The app enforces ClamAV scanning: if clamd is not available uploads will be blocked with a clear error instructing to start clamd.
- Emails are sent to notification_email for users and admin email from seeded admin record.
