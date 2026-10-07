# Host Security & Privilege Auditor

A lightweight Python defensive security tool that evaluates runtime user privileges and enforces the **Principle of Least Privilege** across Windows and Linux environments.

## Features
- Detects host operating system and execution environment dynamically.
- Verifies administrative/root privileges (`geteuid` for Linux / `IsUserAnAdmin` for Windows).
- Outputs a risk evaluation report based on blast-radius minimization.
- Automatically exports results to a local timestamped audit log.

## Installation & Usage
1. Clone the repository:
   ```bash
   git clone [https://github.com/](https://github.com/)<your-username>/host-security-auditor.git
   cd host-security-auditor