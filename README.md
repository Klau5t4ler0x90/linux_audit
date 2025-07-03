# 🔍 Linux Security Audit

A lightweight, script-based security audit tool for Linux. Quickly checks common hardening measures, privilege escalation risks, running services, and best-practice configurations.

## 🚀 Features

- **🛡 Core Hardening Checks**  
  - UFW firewall status  
  - SELinux mode  
  - Unattended-Upgrades

- **🔑 Admin & Root Privilege Verification**  
  - Sudo group membership  
  - Passwordless sudo rules  
  - Root account status

- **⚡ Privilege Escalation Checks**  
  - Unsafe SUID binaries  
  - Weak `sudo` rules (`NOPASSWD`)  
  - Editable root cronjobs  
  - World-writable critical files

- **🖥 Service & Configuration Audits**  
  - **SSH Hardening**: PasswordAuthentication, PermitRootLogin, PubkeyAuthentication, MaxAuthTries  
  - **Fail2Ban**: Service status and active jails  
  - **VNC Services**: `vncserver` & `x11vnc` status  
  - **Webserver Hardening**: Apache & Nginx directory listing settings  
  - **Unwanted Services**: FTP, Telnet, RPC, and more

- **🔍 CVE Version Scans**  
  Compares installed versions of Sudo, kernel, libblockdev (if present), Mozilla VPN (example) against known patched releases for 2025 CVEs.

- **🌐 Optional Exploit-DB Lookup**  
  With `--exploit`, looks up the installed kernel version in the Exploit-DB and shows direct links for any matches.

- **🧰 LinPEAS Integration**  
  `--linpeas` streams LinPEAS live in the terminal and saves output to `results_linpeas.txt` for deeper system scanning.

- **🔒 Sudo Password Support**  
  Use `-p | --password` to pass the sudo password up front and avoid multiple prompts.

## 📦 Installation

```bash
git clone https://github.com/yourusername/Linux_Audit.git
cd Linux_Audit
chmod +x linux_audit.py
```

## ⚙️ Usage

```bash
# Basic audit
python3 linux_audit.py

# Pass sudo password
python3 linux_audit.py -p YourSudoPassword

# Enable Exploit-DB lookup
python3 linux_audit.py --exploit

# Stream LinPEAS
python3 linux_audit.py --linpeas

# Combine all options
python3 linux_audit.py -p YourPassword --exploit --linpeas
```

> **⚠ Warning:** Passing passwords via CLI can be stored in shell history. For high security, consider using a secure credential manager.

## 🤝 Contributing

Contributions, issues, and pull requests are welcome! Feel free to propose improvements or additional checks.

---

If you find this tool useful, consider buying me a coffee:  
[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/klau5t4ler0x90)
