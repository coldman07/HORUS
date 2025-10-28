#!/usr/bin/env python3
"""
HORUS - Automated Canary-Based Ransomware Protection
Windows Event Log Monitoring with Real-time Response

Author: HORUS Development Team
Version: 3.0.0
License: MIT
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import platform
import ctypes
import win32evtlog
import win32evtlogutil
import win32con
import win32security
import ntsecuritycon
import win32api
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# --- Import Windows-specific libraries ---
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    import ntsecuritycon
except ImportError:
    if platform.system() == "Windows":
        print("Missing required libraries. Please run: pip install pywin32")
    sys.exit(1)


# Check if running as Administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # Re-run as admin
    if platform.system() == "Windows":
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
        except Exception as e:
            print(f"Failed to re-launch as admin: {e}")
            # Show a simple Tkinter error if re-launch fails
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Admin Rights Required", "HORUS must be run as Administrator.\nPlease restart the application with Admin privileges.")
    sys.exit(0)

# -------------------------------
# Configuration
# -------------------------------

@dataclass
class HorusConfig:
    """Main configuration for HORUS system"""
    # General Settings
    log_file: str = "horus_canary.log"
    log_level: str = "INFO"
    
    # Directories to Protect
    protected_directories: List[str] = field(default_factory=list)
    
    # Canary File Settings
    canary_count: int = 5
    canary_file_types: List[str] = field(default_factory=lambda: ['.docx', '.xlsx', '.pdf', '.txt'])
    
    # Mitigation Settings - CRITICAL ACTIONS
    auto_kill_process: bool = True
    auto_disable_network: bool = True
    auto_logoff_user: bool = False  # Disabled by default - logs off the user session [cite: 30]
    auto_shutdown_system: bool = False  # Disabled by default - shuts down the computer [cite: 33]
    
    # Trusted Processes (will be ignored)
    trusted_processes: List[str] = field(default_factory=lambda: [
        "explorer.exe",
        "notepad.exe",
        "wordpad.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "acrord32.exe",
        "chrome.exe",
        "firefox.exe",
        "msedge.exe",
        "code.exe",
        "notepad++.exe",
        "totalcmd64.exe",
        "dopus.exe"
    ])
    
    def __post_init__(self):
        if not self.protected_directories:
            user_docs = os.path.expanduser("~/Documents")
            user_desktop = os.path.expanduser("~/Desktop")
            user_downloads = os.path.expanduser("~/Downloads")
            self.protected_directories = [user_docs, user_desktop, user_downloads]

# -------------------------------
# Canary File Data Structure
# -------------------------------

@dataclass
class CanaryFile:
    """Represents a deployed canary file"""
    path: str
    filename: str
    file_hash: str
    created_at: datetime
    
    def exists(self) -> bool:
        return os.path.exists(self.path)
    
    def get_current_hash(self) -> Optional[str]:
        try:
            if not self.exists():
                return None
            with open(self.path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None

@dataclass
class ThreatEvent:
    """Threat detected from Event Log"""
    timestamp: datetime
    event_id: int
    process_id: int
    process_name: str
    file_path: str
    user_name: str
    access_mask: str
    mitigated: bool = False
    mitigation_actions: List[str] = field(default_factory=list)

# -------------------------------
# Windows Audit Configuration
# -------------------------------

class WindowsAuditManager:
    """Manages Windows audit policy and SACL configuration"""
    
    def __init__(self, config: HorusConfig):
        self.config = config
        self.logger = logging.getLogger("HORUS.AuditManager")
        self.privilege_enabled = self._enable_sacl_privilege()

    def _enable_sacl_privilege(self) -> bool:
        """Enable SeSecurityPrivilege required to read/write SACLs."""
        try:
            # Get the current process token
            hToken = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )
            
            # Look up the LUID (Locally Unique Identifier) for the privilege
            privilege_id = win32security.LookupPrivilegeValue(
                None, 
                win32security.SE_SECURITY_NAME  # This is "SeSecurityPrivilege"
            )
            
            # Prepare the new privilege state (enable it)
            new_privileges = [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)]
            
            # Apply the privilege to the process token
            win32security.AdjustTokenPrivileges(hToken, 0, new_privileges)
            win32api.CloseHandle(hToken)
            
            if win32api.GetLastError() == 0:
                self.logger.info("✓ SeSecurityPrivilege enabled for SACL operations.")
                return True
            else:
                self.logger.warning(f"Could not enable SeSecurityPrivilege: {win32api.GetLastError()}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to enable SeSecurityPrivilege: {e}")
            return False
    
    def enable_file_system_auditing(self) -> bool:
        """Enable Windows File System auditing """
        try:
            self.logger.info("Enabling Windows File System auditing...")
            result = subprocess.run(
                ['auditpol', '/set', '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}', '/success:enable'],
                capture_output=True,
                timeout=10,
                check=True
            )
            
            self.logger.info("✓ File system auditing enabled")
            return True
                
        except Exception as e:
            self.logger.error(f"Error enabling auditing (Requires Admin): {e}")
            return False
    
    def set_file_sacl(self, file_path: str) -> bool:
        """Set SACL (audit rules) on a file"""
        if not self.privilege_enabled:
            self.logger.error(f"Cannot set SACL on {file_path}: SeSecurityPrivilege is not held.")
            return False
            
        try:
            self.logger.debug(f"Setting SACL on {file_path}")
            
            # Get current ACL
            sd = win32security.GetFileSecurity(
                file_path,
                win32security.SACL_SECURITY_INFORMATION
            )
            
            # Get existing SACL or create a new one
            sacl = sd.GetSecurityDescriptorSacl()
            if not sacl:
                sacl = win32security.ACL()
            
            # Get Everyone SID
            everyone_sid = win32security.CreateWellKnownSid(
                win32security.WinWorldSid,
                None
            )
            
            # Audit flags: Write, Delete, Change Permissions [cite: 54]
            audit_flags = (
                ntsecuritycon.FILE_WRITE_DATA |
                ntsecuritycon.FILE_APPEND_DATA |
                ntsecuritycon.DELETE |
                ntsecuritycon.WRITE_DAC |
                ntsecuritycon.WRITE_OWNER |
                ntsecuritycon.FILE_WRITE_ATTRIBUTES |
                ntsecuritycon.FILE_WRITE_EA
            )
            
            
            # Add audit ACE
            sacl.AddAuditAccessAce(
                win32security.ACL_REVISION,
                audit_flags,  # Arg 2: The access rights to audit
                everyone_sid, # Arg 3: The user/group SID
                1,  # Arg 4: Audit on Success (1 = True)
                0 # Arg 5: Audit on Failure (0 = False)
            )
            
            # Set the SACL
            sd.SetSecurityDescriptorSacl(1, sacl, 0) # 1 = SACL present
            win32security.SetFileSecurity(
                file_path,
                win32security.SACL_SECURITY_INFORMATION,
                sd
            )
            
            self.logger.debug(f"✓ SACL set on {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set SACL on {file_path}: {e}")
            return False

# -------------------------------
# Canary Deployment Manager
# -------------------------------

class CanaryDeploymentManager:
    """Deploys and manages canary files"""
    
    def __init__(self, config: HorusConfig, audit_manager: WindowsAuditManager):
        self.config = config
        self.audit_manager = audit_manager
        self.logger = logging.getLogger("HORUS.Deployment")
        self.deployed_canaries: List[CanaryFile] = []
    
    def deploy_all_canaries(self) -> bool:
        """Deploy canary files to all protected directories"""
        self.logger.info(f"Deploying {self.config.canary_count} canary files...")
        
        deployed_count = 0
        
        for directory in self.config.protected_directories:
            if not os.path.exists(directory):
                self.logger.warning(f"Directory does not exist: {directory}")
                continue
            
            # Create hidden canary folder
            folder_hash = hashlib.md5(directory.encode()).hexdigest()[:8]
            canary_folder = os.path.join(directory, f".horus_canary_{folder_hash}")
            
            try:
                os.makedirs(canary_folder, exist_ok=True)
                self._set_hidden_attribute(canary_folder)
                
                # Deploy canaries in this folder
                canaries_per_dir = max(1, self.config.canary_count // len(self.config.protected_directories))
                
                for i in range(canaries_per_dir):
                    if deployed_count >= self.config.canary_count:
                        break
                    
                    canary = self._create_canary_file(canary_folder, deployed_count)
                    if canary:
                        # Set SACL on the canary file
                        if self.audit_manager.set_file_sacl(canary.path):
                            self.deployed_canaries.append(canary)
                            deployed_count += 1
                            self.logger.info(f"✓ Deployed: {canary.filename}")
                        else:
                            self.logger.error(f"Failed to set SACL on {canary.filename}")
            
            except Exception as e:
                self.logger.error(f"Failed to deploy canaries in {directory}: {e}")
        
        self.logger.info(f"✓ Successfully deployed {deployed_count} canary files")
        return deployed_count > 0
    
    def _create_canary_file(self, directory: str, index: int) -> Optional[CanaryFile]:
        """Create a single canary file"""
        import random
        
        prefixes = ["IMPORTANT", "Confidential", "Budget", "Passwords", "Backup", "Project", "Financial"]
        suffixes = ["2024", "2025", "Final", "Copy", "Secret", "Private", "Archive"]
        file_type = random.choice(self.config.canary_file_types)
        
        filename = f"{random.choice(prefixes)}_{random.choice(suffixes)}_{index}{file_type}"
        file_path = os.path.join(directory, filename)
        
        try:
            # Create file with warning content [cite: 88, 90]
            content = f"""
═══════════════════════════════════════════════════════
        ⚠️  HORUS RANSOMWARE CANARY FILE  ⚠️
═══════════════════════════════════════════════════════

DO NOT MODIFY, DELETE, OR MOVE THIS FILE

This is a decoy file monitored by the HORUS ransomware
protection system. Any unauthorized access will trigger
immediate security response including:

- Process termination
- Network isolation
- Security alert

Created: {datetime.now().isoformat()}
File ID: HORUS-CANARY-{random.randint(100000, 999999)}

═══════════════════════════════════════════════════════
"""
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Calculate hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Set attributes [cite: 91]
            self._set_hidden_attribute(file_path)
            self._set_readonly_attribute(file_path)
            
            return CanaryFile(
                path=file_path,
                filename=filename,
                file_hash=file_hash,
                created_at=datetime.now()
            )
            
        except Exception as e:
            self.logger.error(f"Failed to create canary {filename}: {e}")
            return None
    
    def _set_hidden_attribute(self, path: str) -> bool:
        """Set hidden attribute on file/folder [cite: 91]"""
        try:
            subprocess.run(['attrib', '+H', path], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _set_readonly_attribute(self, path: str) -> bool:
        """Set read-only attribute"""
        try:
            subprocess.run(['attrib', '+R', path], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def get_canary_paths(self) -> List[str]:
        """Get list of all deployed canary file paths"""
        return [c.path for c in self.deployed_canaries]

# -------------------------------
# Windows Event Log Monitor
# -------------------------------

class WindowsEventMonitor:
    """Monitors Windows Security Event Log for Event ID 4663"""
    
    def __init__(self, config: HorusConfig, canary_paths: List[str], mitigation_handler):
        self.config = config
        self.canary_paths = set(canary_paths)
        self.mitigation_handler = mitigation_handler
        self.logger = logging.getLogger("HORUS.EventMonitor")
        
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.last_record_number = 0
    
    def start(self) -> bool:
        """Start monitoring event log"""
        if self.running:
            return True
        
        try:
            self.logger.info("Starting Windows Event Log monitor...")
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            self.logger.error(f"Failed to start event monitor: {e}")
            return False
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        self.logger.info("✓ Event monitor started - watching for Event ID 4663")
        
        # Get starting position
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if events:
                self.last_record_number = events[0].RecordNumber
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            self.logger.warning(f"Could not get last event record number: {e}")
            self.last_record_number = 0 # Start from the beginning
        
        while self.running:
            try:
                self._check_for_events()
                time.sleep(0.5)  # Poll twice per second
            except Exception as e:
                self.logger.error(f"Error in event monitor loop: {e}")
                time.sleep(1)
    
    def _check_for_events(self):
        """Check for new Event ID 4663 events """
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Start reading from the last record we processed
            events = win32evtlog.ReadEventLog(hand, flags, self.last_record_number + 1)
            
            for event in events:
                if event.EventID == 4663:  # File access event 
                    self._process_event(event)
                
                self.last_record_number = max(self.last_record_number, event.RecordNumber)
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            # Ignore "no more items" errors, which are normal
            if e.args[0] != 18: # ERROR_NO_MORE_ITEMS
                self.logger.debug(f"Event check error: {e}")
    
    def _process_event(self, event):
        """Process Event ID 4663 - file access"""
        try:
            # Parse event data
            
            # Get string inserts from event
            strings = event.StringInserts
            if not strings or len(strings) < 10:
                return
            
            # Event 4663 string layout (typical):
            # 0: Subject User SID
            # 1: Subject User Name
            # 2: Subject Domain
            # 5: Object Name (file path)
            # 8: Process ID 
            # 9: Process Name
            # 10: Access Mask (what they tried to do)
            
            subject_user = strings[1]
            object_name = strings[5]
            process_id_hex = strings[8]
            process_name = strings[9]
            access_mask = strings[10]
            
            # Check if this is one of our canary files [cite: 61]
            if object_name not in self.canary_paths:
                return
            
            # Skip system accounts (machine accounts end with $) [cite: 97]
            if subject_user.endswith('$'):
                self.logger.debug(f"Ignoring system account access: {subject_user}")
                return
            
            # Skip trusted processes [cite: 98]
            process_basename = os.path.basename(process_name).lower()
            if any(trusted.lower() in process_basename for trusted in self.config.trusted_processes):
                self.logger.info(f"Ignoring trusted process: {process_basename}")
                return
            
            # THREAT DETECTED!
            try:
                pid = int(process_id_hex, 16) if process_id_hex.startswith('0x') else int(process_id_hex)
            except:
                pid = 0
            
            threat = ThreatEvent(
                timestamp=datetime.now(),
                event_id=4663,
                process_id=pid,
                process_name=process_name,
                file_path=object_name,
                user_name=subject_user,
                access_mask=access_mask
            )
            
            self.logger.critical(f"🚨 RANSOMWARE DETECTED!")
            self.logger.critical(f"   File: {os.path.basename(object_name)}")
            self.logger.critical(f"   Process: {process_basename} (PID: {pid})")
            self.logger.critical(f"   User: {subject_user}")
            
            # Trigger mitigation
            self.mitigation_handler.execute_mitigation(threat)
            
        except Exception as e:
            self.logger.error(f"Error processing event: {e}")

# -------------------------------
# Mitigation Handler
# -------------------------------

class MitigationHandler:
    """Executes mitigation actions"""
    
    def __init__(self, config: HorusConfig):
        self.config = config
        self.logger = logging.getLogger("HORUS.Mitigation")
        self.threat_log: List[ThreatEvent] = []
        self.lock = threading.Lock() # Ensure mitigation only runs once
        self.mitigation_in_progress = False
    
    def execute_mitigation(self, threat: ThreatEvent):
        """Execute all configured mitigation actions"""
        with self.lock:
            # Prevent re-entrancy if multiple events fire at once
            if self.mitigation_in_progress:
                self.logger.warning("Mitigation already in progress, skipping duplicate trigger.")
                return
            self.mitigation_in_progress = True
            
            self.logger.critical("=" * 60)
            self.logger.critical("🛡️ EXECUTING EMERGENCY MITIGATION")
            self.logger.critical("=" * 60)
            
            actions_taken = []
            
            # Action 1: Kill malicious process 
            if self.config.auto_kill_process and threat.process_id > 0:
                if self._kill_process(threat.process_id):
                    action = f"Killed process {os.path.basename(threat.process_name)} (PID: {threat.process_id})"
                    actions_taken.append(action)
                    self.logger.info(f"✓ {action}")
                else:
                    self.logger.error(f"✗ Failed to kill process {threat.process_id}")
            
            # Action 2: Disable network [cite: 36-39]
            if self.config.auto_disable_network:
                if self._disable_network():
                    actions_taken.append("Network adapters disabled")
                    self.logger.info("✓ Network isolated")
                else:
                    self.logger.error("✗ Failed to disable network")
            
            # Action 3: Log off user (if enabled) [cite: 30-31]
            if self.config.auto_logoff_user:
                actions_taken.append("User session logoff initiated")
                self.logger.warning("⚠️ Logging off user session...")
                self._logoff_user()
            
            # Action 4: Shutdown system (if enabled) [cite: 33-34]
            if self.config.auto_shutdown_system:
                actions_taken.append("System shutdown initiated")
                self.logger.critical("⚠️ SHUTTING DOWN SYSTEM...")
                self._shutdown_system()
            
            # Update threat record
            threat.mitigated = True
            threat.mitigation_actions = actions_taken
            self.threat_log.append(threat)
            
            # Save log
            self._save_threat_log()
            
            # Show alert (run in a separate thread to avoid blocking)
            threading.Thread(target=self._show_alert, args=(threat,)).start()
            
            self.logger.critical("=" * 60)
            self.logger.critical(f"✓ Mitigation complete: {len(actions_taken)} actions taken")
            self.logger.critical("=" * 60)
            
            # Allow new mitigations after a cooldown
            # (This is simple, a real system might have more complex state)
            time.sleep(10) 
            self.mitigation_in_progress = False
    
    def _kill_process(self, pid: int) -> bool:
        """Kill process by PID"""
        try:
            # Method 1: taskkill
            result = subprocess.run(
                ['taskkill', '/F', '/PID', str(pid)],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return True
            
            # Method 2: wmic (fallback)
            result = subprocess.run(
                ['wmic', 'process', 'where', f'ProcessId={pid}', 'delete'],
                capture_output=True,
                timeout=5
            )
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Failed to kill process {pid}: {e}")
            return False
    
    def _disable_network(self) -> bool:
        """Disable all active network adapters"""
        try:
            ps_cmd = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Disable-NetAdapter -Confirm:$false"
            result = subprocess.run(
                ['powershell', '-Command', ps_cmd],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Failed to disable network: {e}")
            return False
    
    def _logoff_user(self):
        """Log off the current user session"""
        try:
            subprocess.run(['shutdown', '/l', '/f'], timeout=5)
        except Exception as e:
            self.logger.error(f"Failed to log off user: {e}")
    
    def _shutdown_system(self):
        """Shutdown the system immediately"""
        try:
            subprocess.run(['shutdown', '/s', '/t', '0', '/f'], timeout=5)
        except Exception as e:
            self.logger.error(f"Failed to shutdown system: {e}")
    
    def _save_threat_log(self):
        """Save threat log to JSON file"""
        try:
            log_file = Path("horus_threats.json")
            threats_data = []
            
            for threat in self.threat_log:
                threats_data.append({
                    "timestamp": threat.timestamp.isoformat(),
                    "event_id": threat.event_id,
                    "process_id": threat.process_id,
                    "process_name": threat.process_name,
                    "file_path": threat.file_path,
                    "user_name": threat.user_name,
                    "mitigated": threat.mitigated,
                    "actions": threat.mitigation_actions
                })
            
            with open(log_file, 'w') as f:
                json.dump(threats_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save threat log: {e}")
    
    def _show_alert(self, threat: ThreatEvent):
        """Show alert dialog to user"""
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            
            message = f"""🚨 RANSOMWARE DETECTED AND MITIGATED 🚨

Canary File: {os.path.basename(threat.file_path)}

Malicious Process:
  Name: {os.path.basename(threat.process_name)}
  PID: {threat.process_id}
  User: {threat.user_name}

Actions Taken:
"""
            for action in threat.mitigation_actions:
                message += f"  ✓ {action}\n"
            
            message += f"\nTime: {threat.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            message += "\n\nCheck HORUS logs for full details."
            
            messagebox.showerror("HORUS Security Alert", message, parent=root)
            root.destroy()
            
        except Exception as e:
            self.logger.warning(f"Could not show alert dialog: {e}")

# -------------------------------
# Main HORUS System
# -------------------------------

class HorusSystem:
    """Main HORUS system coordinator"""
    
    def __init__(self, config: HorusConfig):
        self.config = config
        self.logger = self._setup_logging()
        self.running = False
        
        # Initialize components
        self.audit_manager = WindowsAuditManager(config)
        self.deployment_manager = CanaryDeploymentManager(config, self.audit_manager)
        self.mitigation_handler = MitigationHandler(config)
        self.event_monitor: Optional[WindowsEventMonitor] = None
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        # Get the root logger
        logger = logging.getLogger("HORUS")
        logger.setLevel(getattr(logging, self.config.log_level))
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Create file handler (always safe)
        file_handler = logging.FileHandler(self.config.log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Create console handler (with explicit encoding and error handling)
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        # Fix for UnicodeEncodeError on Windows console
        stream_handler.encoding = 'utf-8' 
        logger.addHandler(stream_handler)

        return logging.getLogger("HORUS.System")
    
    def initialize(self) -> bool:
        """Initialize the system (one-time setup)"""
        self.logger.info("=" * 60)
        self.logger.info("🛡️ HORUS Initialization")
        self.logger.info("=" * 60)
        
        # Step 1: Enable Windows auditing
        if not self.audit_manager.enable_file_system_auditing():
            self.logger.error("Failed to enable Windows auditing")
            return False
        
        # Step 2: Deploy canary files
        if not self.deployment_manager.deploy_all_canaries():
            self.logger.error("Failed to deploy canary files")
            return False
        
        self.logger.info("=" * 60)
        self.logger.info("✓ Initialization complete")
        self.logger.info("=" * 60)
        return True
    
    def start(self) -> bool:
        """Start monitoring"""
        if self.running:
            return True
        
        if not self.deployment_manager.deployed_canaries:
            self.logger.error("No canaries deployed. Run initialize() first.")
            return False
        
        self.logger.info("Starting HORUS monitoring...")
        
        # Start event monitor
        canary_paths = self.deployment_manager.get_canary_paths()
        self.event_monitor = WindowsEventMonitor(
            self.config,
            canary_paths,
            self.mitigation_handler
        )
        
        if not self.event_monitor.start():
            self.logger.error("Failed to start event monitor")
            return False
        
        self.running = True
        self.logger.info("✓ HORUS is now monitoring for ransomware")
        return True
    
    def stop(self):
        """Stop monitoring"""
        if not self.running:
            return
        
        self.logger.info("Stopping HORUS...")
        
        if self.event_monitor:
            self.event_monitor.stop()
        
        self.running = False
        self.logger.info("✓ HORUS stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get system status"""
        return {
            "running": self.running,
            "canaries_deployed": len(self.deployment_manager.deployed_canaries),
            "threats_detected": len(self.mitigation_handler.threat_log),
            "canary_paths": self.deployment_manager.get_canary_paths()
        }

# -------------------------------
# GUI Application (Completed)
# -------------------------------

class HorusGUI:
    """GUI for HORUS system"""
    
    def __init__(self):
        self.config = HorusConfig()
        self.horus = HorusSystem(self.config)
        self.initialized = False
        self.logged_threats = 0
        
        self.root = tk.Tk()
        self.root.title("HORUS - Ransomware Protection")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        self.setup_gui()
        self.update_status_timer()
    
    def setup_gui(self):
        """Setup GUI layout"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1) # Log row
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        title = ttk.Label(title_frame, text="🛡️ HORUS Ransomware Protection", 
                          font=("Arial", 18, "bold"))
        title.pack()
        
        subtitle = ttk.Label(title_frame, text="Windows Event-Based Canary Detection System",
                             font=("Arial", 10), foreground="gray")
        subtitle.pack()
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="System Control", padding="10")
        control_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X)
        
        self.init_btn = ttk.Button(btn_frame, text="⚙️ Initialize System", 
                                   command=self.initialize_system, width=20)
        self.init_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.start_btn = ttk.Button(btn_frame, text="▶ Start Protection", 
                                    command=self.start_protection, width=20, state=tk.DISABLED)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = ttk.Button(btn_frame, text="⏹ Stop Protection", 
                                   command=self.stop_protection, width=20, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        
        # Status Panel
        status_frame = ttk.LabelFrame(main_frame, text="System Status", padding="10")
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(1, weight=1)
        
        ttk.Label(status_frame, text="Status:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.status_label = ttk.Label(status_frame, text="⚫ Not Initialized", foreground="red", font=("Arial", 10, "bold"))
        self.status_label.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(status_frame, text="Canary Files:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.canary_label = ttk.Label(status_frame, text="0")
        self.canary_label.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(status_frame, text="Threats Detected:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10))
        self.threat_label = ttk.Label(status_frame, text="0", foreground="green")
        self.threat_label.grid(row=2, column=1, sticky=tk.W)

        # Log display
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        log_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, state=tk.DISABLED, 
                                                  font=("Consolas", 9), wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Close protocol
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def initialize_system(self):
        self.log_message("Initializing HORUS...", "blue")
        if self.horus.initialize():
            self.log_message("✓ System initialized successfully.", "green")
            self.log_message(f"✓ Deployed {self.horus.get_status()['canaries_deployed']} canary files.", "green")
            self.initialized = True
            self.init_btn.config(state=tk.DISABLED, text="✓ Initialized")
            self.start_btn.config(state=tk.NORMAL)
            self.update_status_display()
        else:
            self.log_message("✗ Initialization failed. Check logs.", "red")
            messagebox.showerror("Error", "Initialization failed. Please check horus_canary.log for details.")
    
    def start_protection(self):
        if not self.initialized:
            messagebox.showwarning("Warning", "Please initialize the system first.")
            return
            
        self.log_message("Starting protection...", "blue")
        if self.horus.start():
            self.log_message("✓ HORUS protection is now active.", "green")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
        else:
            self.log_message("✗ Failed to start protection.", "red")
    
    def stop_protection(self):
        self.log_message("Stopping protection...", "orange")
        self.horus.stop()
        self.log_message("⚫ HORUS protection stopped.", "orange")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def log_message(self, message: str, color: str = "black"):
        """Add message to log display"""
        try:
            self.log_text.config(state=tk.NORMAL)
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        except Exception:
            pass # Ignore GUI errors if window is closing
            
    def update_status_timer(self):
        """Update status display periodically"""
        self.update_status_display()
        self.root.after(1000, self.update_status_timer) # Check every 1 second
        
    def update_status_display(self):
        """Update status display widgets"""
        try:
            status = self.horus.get_status()
            
            if status["running"]:
                self.status_label.config(text="● Running", foreground="green")
            elif self.initialized:
                self.status_label.config(text="⚫ Initialized (Stopped)", foreground="orange")
            else:
                self.status_label.config(text="⚫ Not Initialized", foreground="red")
                
            self.canary_label.config(text=f"{status['canaries_deployed']}")
            
            threat_count = status['threats_detected']
            self.threat_label.config(text=f"{threat_count}")
            
            if threat_count > self.logged_threats:
                self.threat_label.config(foreground="red", font=("Arial", 10, "bold"))
                # Log new threats
                new_threats = self.horus.mitigation_handler.threat_log[self.logged_threats:]
                for threat in new_threats:
                    self.log_message(f"🚨 THREAT DETECTED!", "red")
                    self.log_message(f"   File: {os.path.basename(threat.file_path)}", "red")
                    self.log_message(f"   Process: {os.path.basename(threat.process_name)} (PID: {threat.process_id})", "red")
                    for action in threat.mitigation_actions:
                         self.log_message(f"   🛡️ Action: {action}", "blue")
                self.logged_threats = threat_count
            elif threat_count == 0:
                self.threat_label.config(foreground="green", font=("Arial", 10, "normal"))

        except Exception as e:
            self.log_message(f"Error updating status: {e}", "red")

    def on_closing(self):
        """Handle window close event"""
        if self.horus.running:
            if messagebox.askokcancel("Quit", "HORUS is running. Do you want to stop protection and quit?"):
                self.horus.stop()
                self.root.destroy()
        else:
            self.root.destroy()
            
    def start(self):
        """Start the GUI main loop"""
        self.root.mainloop()

# -------------------------------
# Main Execution
# -------------------------------

if __name__ == "__main__":
    try:
        app = HorusGUI()
        app.start()
    except Exception as e:
        logging.fatal(f"Failed to launch HORUS GUI: {e}", exc_info=True)
        # Show error in a simple TK box if GUI failed to init
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Fatal Error", f"Failed to launch HORUS:\n{e}\n\nCheck horus_canary.log for details.")
            root.destroy()
        except Exception:
            pass
        sys.exit(1)
