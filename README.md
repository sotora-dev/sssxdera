# SSSXDERA AUTOMATED EXPLOITATION FRAMEWORK v3.2.0

![Status](https://img.shields.io/badge/Status-Active-brightgreen) ![Version](https://img.shields.io/badge/Version-3.2.0-blue) ![Author](https://img.shields.io/badge/Author-Shirokami%20Sotora-red)

**SSSXDERA** is an advanced cyber offensive operations tool designed for automated vulnerability scanning and exploitation. This framework allows for batch testing of targets against critical vulnerabilities including SQL Injection, XSS, RCE via Upload, and LFI.

---

## ⚠️ LEGAL DISCLAIMER

**PLEASE READ BEFORE USE:**

All usage of this script outside of an authorized scope (i.e., on systems you do not own or do not have explicit permission to test) is **strictly prohibited** and is the sole responsibility of the user.

The developers (Shirokami Sotora | xDera Network) assume **NO liability** and are not responsible for any misuse or damage caused by this program. This tool is designed for educational purposes and authorized security testing only.

**By downloading or running this script, you agree that you are solely responsible for your actions.**

---

## 🔥 Features

- **Reconnaissance:** Automated technology detection (Fingerprinting).
- **Unrestricted File Upload:** Checks for RCE via shell upload.
- **Local File Inclusion (LFI):** Tests for system file leakage.
- **Config Dump:** Scans for exposed configuration files (credentials/secrets).
- **Auth Bypass:** Brute-force/Bypass checks on login panels.
- **SQL Injection:** Error-based SQLi scanner.
- **Command Injection:** Tests for OS command execution.
- **SSRF:** Server-Side Request Forgery detection.
- **XSS:** Reflected Cross-Site Scripting scanner.
- **Reporting:** Auto-logs successful exploits to `report.txt`.

---

## 🛠️ Installation

Follow these steps to set up the environment and install the tool.

### 1. Update System & Install Python
```bash
apt update && apt upgrade -y
pkg install python git -y

```

### 2. Clone Repository

```bash
git clone [https://github.com/sotora-dev/sssxdera.git](https://github.com/sotora-dev/sssxdera.git)
cd sssxdera

```

### 3. Install Dependencies

```bash
pip install requests urllib3

```

---

## 🚀 Usage

Run the script using Python:

```bash
python sssxdera.py

```

You can input a single URL (e.g., `http://target.com`) or a list of targets in a text file (e.g., `targets.txt`).

---

## 🔧 Troubleshooting

If you encounter errors regarding missing modules (e.g., `ModuleNotFoundError: No module named 'requests'`), please try running the following commands in order:

**1. Upgrade PIP:**

```bash
python -m pip install --upgrade pip

```

**2. Force Install Requests:**

```bash
pip install requests

```

**3. Install to User Path (if permission denied):**

```bash
pip install --user requests

```

**4. Install via Python Module:**

```bash
python -m pip install requests

```

---


**Use this script wisely.**
Ensure you have permission before scanning any target. Stay ethical.

---

*Developed by Shirokami Sotora | xDera Network*
