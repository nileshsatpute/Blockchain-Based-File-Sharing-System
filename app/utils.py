import os
import logging
import subprocess
from email.message import EmailMessage
import smtplib
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


def send_email(subject, body, to_addrs, host=None, port=587, user=None, pwd=None):
    """
    Send an email using SMTP (with TLS).
    Returns True if sent, False otherwise.
    """
    from_addr = os.environ.get("FROM_EMAIL", user)
    if not host or not from_addr:
        return False

    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, (list, tuple)) else to_addrs
        msg.set_content(body)

        with smtplib.SMTP(host, port) as s:
            s.starttls()
            if user and pwd:
                s.login(user, pwd)
            s.send_message(msg)

        logger.info("Email sent: %s -> %s", subject, to_addrs)
        return True

    except Exception as e:
        logger.exception("Failed to send email: %s", e)
        return False


import subprocess

def scan_file_with_clamav(file_path):
    """
    Scan a file using ClamAV on Windows.
    Returns (True, "Clean") if clean,
    Returns (False, "Virus detected: <name>") if infected,
    Returns (True, "Skipped scan...") if ClamAV is not available.
    """
    try:
        result = subprocess.run(
            [r"C:\clamav-1.3.1.win.x64\clamscan.exe", "--no-summary", file_path],
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()

        if "OK" in output:
            return True, "Clean"
        elif "FOUND" in output:
            # Extract virus name safely
            try:
                virus_name = output.split("FOUND")[0].split(":")[-1].strip()
            except Exception:
                virus_name = "Unknown"
            return False, f"Virus detected: {virus_name}"
        else:
            return True, f"Skipped scan (ClamAV output not recognized: {output})"

    except Exception as e:
        # If ClamAV not available, skip scan
        return True, f"Skipped scan (ClamAV not available: {e})"

