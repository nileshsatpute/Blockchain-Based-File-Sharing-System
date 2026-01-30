🔗 Blockchain-Based Cloud File Sharing System

A secure cloud file-sharing system built using Flask, SQLite, and a custom blockchain implementation to ensure file integrity, transparency, and auditability.
The system allows users to upload, share, and revoke file access, while maintaining an immutable record of all actions using blockchain concepts.

📌 Project Overview

Traditional cloud file-sharing systems focus mainly on storage and access but lack transparent auditing and tamper-proof records.
This project addresses that gap by integrating a private blockchain to log every critical file operation such as upload, share, download, and revoke.
The system is designed as a single-node, on-premise solution, suitable for academic institutions, small organizations, and controlled environments.

🚀 Key Features
👤 User Module

User registration and login
Upload files to cloud storage
Share files with specific users
Revoke file access at any time
Download shared files (permission-based)
Submit feedback to admin

🛡️ Admin Module

Admin authentication
Create and manage users
Change user passwords
View all uploaded files
View user feedback and reply
View system audit logs
View blockchain records

Analytics dashboard (graphs & statistics)

🔗 Blockchain Integration

Custom Python-based blockchain
SHA-256 hashing for block integrity
Proof of Work (PoW) mechanism
Immutable block chaining
Blockchain logs for:
File upload
File sharing
File access revocation
Downloads

📊 Analytics Dashboard

Uploads per day
Downloads per day
Revokes per day
Files shared per user
Storage usage per user

🧪 Security & Integrity

Passwords stored using secure hashing (Werkzeug / PBKDF2)
File integrity verified using SHA-256 hash
Optional ClamAV virus scanning before upload
Complete audit logging of all actions

🏗️ System Architecture

Frontend: HTML, CSS, JavaScript, Chart.js
Backend: Flask (Python)
Database: SQLite with SQLAlchemy ORM
Blockchain: Custom implementation (SHA-256 + Proof of Work)
Storage: Local file system
Virus Scan: ClamAV (optional)

🗃️ Database Tables

User – User and admin accounts
File – File metadata and ownership
Permission – File sharing permissions
AuditLog – System activity logs
Block – Blockchain data
Feedback – User feedback and admin replies

🔄 Workflow Overview

User logs in
User uploads a file
(Optional) File scanned using ClamAV
File stored on server
SHA-256 hash generated for file integrity
Blockchain block created for the action
Permissions applied if file is shared
Audit log entry recorded
Admin can view analytics, logs, and blockchain

⚙️ Installation & Setup

1️⃣ Clone the Repository
git clone https://github.com/your-username/blockchain-file-sharing.git
cd blockchain-file-sharing

2️⃣ Create Virtual Environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ Run the Application
flask run
Access the application at:

http://127.0.0.1:5000


🔮 Future Enhancements

Distributed (multi-node) blockchain
Cloud storage integration (AWS / IPFS)
End-to-end file encryption
Smart contract-based permissions
Role-based access control
Mobile application support

🎓 Academic Use Case

This project demonstrates practical implementation of:
Blockchain fundamentals
Proof of Work
Secure file handling
Access control mechanisms
Full-stack web development

👨‍💻 Author

Nilesh Satpute


