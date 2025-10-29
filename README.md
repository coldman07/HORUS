# 🛡️ HORUS - Ransomware Canary Protection

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6)
![License](https://img.shields.io/badge/license-GNU-green)

HORUS is a Windows ransomware canary system that detects threats using the Event Log, identifies the malicious **Process ID (PID)**, and executes immediate, automated mitigation.

It is designed to be an all-in-one, "run and forget" solution. It automatically configures Windows auditing, deploys canaries, and monitors for attacks in real-time.



## 📖 Introduction

Standard ransomware can encrypt thousands of files in minutes. Simple file-watching detectors are often too slow and cannot identify *which process* is responsible for the attack.

HORUS is different. It implements the professional strategy of using decoy "canary" files tied directly to the **Windows Security Auditing system**. When ransomware (or any unauthorized program) touches a canary file, Windows generates a security event that contains the exact **Process ID (PID)** of the attacker. HORUS instantly catches this event, kills the malicious process, and disconnects the computer from the network to stop the attack dead in its tracks.

## ✨ Core Features

* **PID-Based Detection:** No guesswork. HORUS identifies the *exact* malicious process PID from the Windows Event Log (Event ID 4663).
* **Automated Setup:** Automatically enables the required Windows Audit Policy (`auditpol`) and elevates its own privileges (`SeSecurityPrivilege`) to manage security rules.
* **Automated SACL Deployment:** Programmatically applies the necessary System Access Control List (SACL) audit rules to every canary file it deploys.
* **Layered Mitigation:** When a threat is detected, HORUS automatically:
    1.  **Kills** the malicious process by its PID.
    2.  **Isolates** the machine by disabling all network adapters.
    3.  (Configurable) **Logs off** the user session to stop all running user processes.
    4.  (Configurable) **Shuts down** the entire machine as a last resort.
* **Simple GUI:** A clean Tkinter interface for a 2-step "Initialize" and "Start" process.
* **Robust and Lightweight:** Uses native Windows APIs for monitoring, resulting in near-zero CPU usage while idle.

---

## ⚙️ How It Works

HORUS combines several Windows security features into a single, automated workflow.

1.  [cite_start]**Admin Check:** On launch, the script checks for Administrator privileges and attempts to re-launch itself if not elevated [cite: 26-36].
2.  **`Initialize System` Button:**
    * Enables the `SeSecurityPrivilege` for its own process, which is required to modify audit rules.
    * Runs the `auditpol` command to enable "File System" auditing for the entire OS.
    * Deploys hidden canary files (e.g., `Budget_Secret_0.xlsx`) into protected user directories.
    * Applies a **SACL** (audit rule) to each canary file. This tells Windows, "Log an event if *anyone* tries to write to or delete this specific file".
3.  **`Start Protection` Button:**
    * Starts a monitoring thread that "listens" to the Windows Security Event Log in real-time.
4.  **Attack Scenario:**
    * Ransomware starts encrypting files and eventually accesses a canary file.
    * Windows Security immediately generates **Event ID 4663** ("An attempt was made to access an object").
    * This event log entry contains the **Process ID (PID)** and name of the ransomware executable.
    * The HORUS monitor reads the event, parses the data, and checks the process name against a `trusted_processes` list.
    * If the process is not trusted, HORUS triggers the `MitigationHandler`.
5.  **Mitigation:**
    * The `MitigationHandler` instantly calls `taskkill /F /PID <PID>` (with a `wmic` fallback) to terminate the ransomware process.
    * It then runs a PowerShell command to disable all active network adapters, stopping lateral movement.
    * Finally, it displays a "RANSOMWARE DETECTED" alert to the user.

---

## 🚀 Getting Started

### Requirements

* **OS:** Windows 10, Windows 11, or Windows Server.
* **Privileges:** **Administrator** (non-negotiable). The script will try to self-elevate.
* **Python:** 3.8 or newer.
* **Dependencies:** `pywin32`

### Installation

1.  Clone this repository:
    ```bash
    git clone [https://github.com/your-username/horus-ransomware.git](https://github.com/your-username/horus-ransomware.git)
    cd horus-ransomware
    ```

2.  Install the required `pywin32` library:
    ```bash
    pip install pywin32
    ```

### Usage

You **must** run the script as an Administrator.

1.  Right-click your terminal (PowerShell or CMD) and select "Run as administrator".
2.  Navigate to the script directory and run it:
    ```bash
    python .\horusV3_claude_series.py
    ```

**Step 1: Initialize**
* Click the **`⚙️ Initialize System`** button.
* This is a one-time setup. It will enable Windows auditing and deploy the canary files. The log window will show the progress.

**Step 2: Start Protection**
* After initialization is complete, click the **`▶ Start Protection`** button.
* The status will change to "Running," and HORUS is now actively monitoring your system.
* You can minimize the window, and it will continue to run.

---

## 🔧 Configuration

All settings can be easily modified in the `HorusConfig` dataclass at the top of the script (around line 40).

```python
@dataclass
class HorusConfig:
    # --- DANGEROUS ---
    # Enable these for a more aggressive response
    auto_logoff_user: bool = False  
    auto_shutdown_system: bool = False

    # --- TUNING ---
    # Add programs here to prevent false positives
    trusted_processes: List[str] = field(default_factory=lambda: [
        "explorer.exe",
        "notepad.exe",
        # ... more processes
    ])

    # --- DEPLOYMENT ---
    # Add more folders to protect
    protected_directories: List[str] = field(default_factory=list)
    canary_count: int = 5
```

## ⚠️ CRITICAL WARNING ⚠️
This is not a toy. This is a powerful, destructive security tool.

By design, this script automatically kills processes and disables all network connectivity when triggered.

Enabling auto_logoff_user or auto_shutdown_system is even more drastic and will result in immediate session termination or system shutdown without warning.

ALWAYS test this tool in a safe, isolated virtual machine (VM) before deploying it on a real system. The authors are not responsible for any data loss, system instability, or network issues caused by its use.

## 📄 License
This project is licensed under the MIT License. See the LICENSE file for details.

## 🎓 Acknowledgments
This project is a Python implementation of the ransomware canary strategy detailed in the "Stopping Ransomware via Canary File Triggers on Windows" technical document.
