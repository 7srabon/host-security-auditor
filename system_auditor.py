"""
Linux & Windows System Privilege & Security Hardening Auditor
Author: Student Portfolio Project
Description: Audits current user permissions, checks administrative elevation,
             and reports the security posture based on the Principle of Least Privilege.
"""

import os
import sys
import platform
from datetime import datetime

def check_privileges():
    current_os = platform.system()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Detect active user safely
    try:
        user = os.getlogin()
    except Exception:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown"

    # Check administrative elevation
    is_admin = False
    if current_os == "Windows":
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
    else:
        # Linux / Unix
        if hasattr(os, "geteuid"):
            is_admin = (os.geteuid() == 0)

    # Compile the audit report
    report = []
    report.append("=" * 60)
    report.append(f" SYSTEM SECURITY AUDIT REPORT - {timestamp}")
    report.append("=" * 60)
    report.append(f"Operating System : {current_os} ({platform.release()})")
    report.append(f"Active User      : {user}")
    report.append(f"Elevation Status : {'ELEVATED (Admin/Root)' if is_admin else 'RESTRICTED (Standard User)'}")
    report.append("-" * 60)

    if is_admin:
        report.append("[!] RISK RATING: HIGH")
        report.append("[!] Recommendation: Do not run daily tasks or network services")
        report.append("    as Administrator/Root. Adhere to the Principle of Least Privilege.")
    else:
        report.append("[+] RISK RATING: LOW")
        report.append("[+] Security Posture: Operating within Least Privilege boundaries.")
        report.append("    Malicious payloads cannot modify core kernel/system configurations.")
    report.append("=" * 60)

    result_text = "\n".join(report)
    print(result_text)

    # Save output to a persistent audit log
    with open("audit_log.txt", "w") as log_file:
        log_file.write(result_text)
    print("\n[+] Audit report saved successfully to 'audit_log.txt'")

if __name__ == "__main__":
    check_privileges()