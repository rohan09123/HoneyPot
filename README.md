# 🍯 HoneyPot 🍯

HoneyPot is a **Python-based SSH and HTTP honeypot** designed to simulate real services, capture unauthorized access attempts, and log attacker behavior for security analysis and learning purposes.

This project is intended for **educational and defensive security research only**.

---

## 📌 Project Overview

The honeypot runs:
- A **fake SSH server** using a generated server key
- A **basic HTTP server** to log incoming requests

Attackers interacting with these services have their:
- IP address
- Credentials
- Commands
- HTTP requests
logged for later analysis.

---

## ⚙️ Requirements

- Python 3.8+
- Linux / macOS (recommended)
- `paramiko` library (for SSH server)

Install dependencies:
```bash
pip install -r requirements.txt
```
## 🔐 SSH Server Key Generation (IMPORTANT)
The SSH honeypot requires a server host key to funtion.
This key identifies the SSH server to connecting clients.

### 🗝️ Step 1: Generate an SSH Server Key
Run the following command in the project directory:
```bash
ssh-keygen -t rsa -b 2048 -f server.key
```
You will get:
- `server.key` -> Private key ( KEEP SECRET )
- `server.key.pub` -> Public key

📁Place both files in the root directory of the project.

The <b>Private key</b> allows your honeypot to act as a real SSH server.
The <b>Public key</b> is sent to clients during the SSH handshake.

⚠️ <b>Never expose real production SSH keys. Use only test keys.</b>

## ▶️ Running the Honeypot

Start SSH Honeypot
```bash
python3 ./honeypy.py -a 127.0.0.1 -p 2223 -u hii -pw hi --ssh
```

Start HTTP Honeypot
```bash
python3 /honey.py -p 8080 --http
```

## 🛡️ Security Warning
### ⚠️ This project intentionally attracts malicious traffic.

<b>💀 DO NOT:</b>

- Run on production systems
- Expose internal networks
- Use real SSH keys or credentials

<b>✅ Recommended:</b>

- Run inside a VM or sandbox
- Use firewall rules
- Monitor logs regularly

## 🎓 Educational Use

This project helps demonstrate:

- How SSH servers authenticate clients
- How attackers scan exposed services
- Basic defensive monitoring techniques
