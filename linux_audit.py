import subprocess
import argparse
import re
import sys
import requests


def run_command(command, password=None):
    """Run a shell command, optionally with sudo password, return output and exit code."""
    try:
        if password and command.strip().startswith("sudo "):
            # Remove 'sudo ' prefix and add password input
            cmd = command.strip()[5:]
            command = f"echo {password} | sudo -S {cmd}"
        proc = subprocess.run(command, shell=True, capture_output=True, text=True)
        return proc.stdout.strip(), proc.returncode
    except Exception as e:
        return f"Error: {e}", 1


def stream_linpeas():
    """Stream LinPEAS output live and save to 'results_linpeas.txt'."""
    print("\n🌐 Starting LinPEAS (requires network)...")
    # Construct the command to download and execute LinPEAS
    bash_cmd = "curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash"
    proc = subprocess.Popen(["bash", "-c", bash_cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # Open output file
    with open('results_linpeas.txt', 'w') as outfile:
        # Stream lines
        for line in proc.stdout:
            # Print to terminal
            sys.stdout.write(line)
            # Write to file
            outfile.write(line)
    proc.wait()
    # Report status
    if proc.returncode == 0:
        print(f"\n[✔] LinPEAS completed successfully with exit code {proc.returncode}.")
        print("[✔] Full output saved to 'results_linpeas.txt'.")
    else:
        print(f"\n[❌] LinPEAS failed with exit code {proc.returncode}.")
        print("[✔] Partial output saved to 'results_linpeas.txt'.")


def check_firewall():
    print("\n🔎 Checking firewall status...")
    out, _ = run_command("ufw status | grep -qi 'active' && echo ACTIVE || echo INACTIVE")
    print("[✔] UFW active" if out == "ACTIVE" else "[✘] UFW inactive or not installed")


def check_selinux():
    print("\n🔎 Checking SELinux status...")
    out, code = run_command("getenforce")
    if code == 0:
        print(f"[✔] SELinux mode: {out}")
    else:
        print("[⚠] SELinux not installed or getenforce not available.")


def check_autoupdates():
    print("\n🔎 Checking unattended upgrades...")
    out, _ = run_command("grep -E '^Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades")
    print("[✔] Unattended-Upgrades enabled" if '1' in out else "[✘] Unattended-Upgrades not enabled")


def check_admin_rights(password=None):
    print("\n🔎 Checking user privileges...")
    out, _ = run_command("groups | grep -q sudo && echo YES || echo NO")
    print("[⚠] User in sudo group" if out == "YES" else "[✔] Not in sudo group")
    out, _ = run_command("sudo -l 2>/dev/null | grep '(ALL)'", password)
    print("[⚠] Has passwordless sudo" if out else "[✔] No passwordless sudo")
    # Check if root login enabled (shadow entry not locked)
    out, _ = run_command(r"grep '^root:' /etc/shadow | grep -q ':[*!]' && echo NO || echo YES")
    print("[⚠] Root login allowed" if out == "YES" else "[✔] Root login disabled/locked")


def check_suid_binaries(password=None):
    print("\n🔎 Checking SUID binaries...")
    out, _ = run_command("find / -perm -4000 -type f 2>/dev/null", password)
    print(out if out else "[✔] No unusual SUID binaries found.")


def check_weak_sudo_rules(password=None):
    print("\n🔎 Checking weak sudo rules...")
    out, _ = run_command("sudo -l 2>/dev/null", password)
    print(out if "NOPASSWD" in out else "[✔] No NOPASSWD entries.")


def check_cron_jobs(password=None):
    print("\n🔎 Checking cron jobs...")
    out, _ = run_command("ls -l /etc/cron.* /var/spool/cron/crontabs 2>/dev/null", password)
    print(out if out else "[✔] No editable root cronjobs found.")


def check_writable_files(password=None):
    print("\n🔎 Checking world-writable files...")
    out, _ = run_command("find /etc -type f -perm -o=w 2>/dev/null", password)
    print(out if out else "[✔] No world-writable critical files.")


def check_kernel_version():
    print("\n🔎 Checking kernel version...")
    out, _ = run_command("uname -r")
    print(f"🖥 Kernel version: {out}")
    return out


def get_output(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


def version_to_tuple(v):
    nums = re.findall(r'\d+', v)
    return tuple(map(int, nums)) if nums else ()


def check_version(current, minimum, description):
    curr, minv = version_to_tuple(current), version_to_tuple(minimum)
    ok = curr and curr >= minv
    symbol = ">=" if ok else "<"
    status = "✔" if ok else "⚠"
    print(f"[{status}] {description}: {current or 'unknown'} {symbol} {minimum}")


def search_exploit_db(kernel_version):
    print("\n🔎 Exploit-DB lookup for kernel...")
    try:
        url = f"https://www.exploit-db.com/search?q={kernel_version}"
        resp = requests.get(url)
        if resp.status_code == 200 and 'No results found' not in resp.text:
            print(f"[⚠] Exploits found: {url}")
        else:
            print("[✔] No exploits in Exploit-DB.")
    except Exception as e:
        print(f"[❌] Error querying Exploit-DB: {e}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Linux Security Audit Tool")
    parser.add_argument('-p', '--password', type=str, help='sudo password')
    parser.add_argument('--exploit', action='store_true', help='Exploit-DB lookup')
    parser.add_argument('--linpeas', action='store_true', help='Stream LinPEAS')
    args = parser.parse_args()

    if args.linpeas:
        stream_linpeas()

    print("\n🔍 Linux Security Audit")
    check_firewall()
    check_selinux()
    check_autoupdates()
    check_admin_rights(args.password)
    check_suid_binaries(args.password)
    check_weak_sudo_rules(args.password)
    check_cron_jobs(args.password)
    check_writable_files(args.password)
    kv = check_kernel_version()
    check_version(get_output("sudo --version | head -n1"), "1.9.17p1", "Sudo (CVE-2025-32462/63)")
    if args.exploit:
        search_exploit_db(kv)
    print("\n✅ Audit complete!")
