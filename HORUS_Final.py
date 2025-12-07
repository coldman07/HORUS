#!/usr/bin/env python3
"""
HORUS - Advanced Ransomware Protection System
Hybrid Detection: Event Log Monitoring + Hash-Based Polling
Automatic Mitigation: Process Termination + Network Isolation

Author: HORUS Security Team
Version: 4.1.0 - Directory Configuration Added
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
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog  # Added filedialog
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import traceback

# Windows-specific imports
WIN = platform.system() == "Windows"
PYWIN32_AVAILABLE = False
if WIN:
    try:
        import win32evtlog
        import win32evtlogutil
        import win32security
        import ntsecuritycon
        import win32api
        import pywintypes
        PYWIN32_AVAILABLE = True
    except ImportError:
        PYWIN32_AVAILABLE = False
        # Note: In a real deployment, a non-GUI message should be logged/printed.
        # Keeping the original warning.
        print("Warning: pywin32 not available. Install with: pip install pywin32")
else:
    PYWIN32_AVAILABLE = False

# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class HorusConfig:
    """System Configuration"""
    # Logging
    log_file: str = "horus_protection.log"
    log_level: str = "INFO"
    
    # Protected Directories
    protected_directories: List[str] = field(default_factory=list)
    
    # Canary Settings
    canary_count: int = 8
    canary_file_types: List[str] = field(default_factory=lambda: ['.txt', '.docx', '.xlsx', '.pdf'])
    
    # Detection Methods
    use_event_log_detection: bool = True   # Windows Event Log (4663)
    use_hash_detection: bool = True        # Hash-based polling (reliable fallback)
    hash_check_interval: float = 0.5       # seconds between hash checks
    
    # Mitigation Actions (CRITICAL)
    auto_kill_process: bool = True         # Terminate malicious process
    auto_disable_network: bool = True      # Isolate network adapters
    auto_logoff_user: bool = False         # Force user logoff
    auto_shutdown_system: bool = False     # Emergency shutdown
    
    # Trusted Processes (whitelist)
    trusted_processes: List[str] = field(default_factory=lambda: [
        "explorer.exe", "notepad.exe", "wordpad.exe",
        "winword.exe", "excel.exe", "powerpnt.exe",
        "acrord32.exe", "chrome.exe", "firefox.exe",
        "msedge.exe", "code.exe", "notepad++.exe",
        "powershell.exe", "cmd.exe", # Adding common admin tools
        "taskmgr.exe"
    ])
    
    def __post_init__(self):
        if not self.protected_directories:
            # Default directories only if none are provided
            defaults = [
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Downloads")
            ]
            # Ensure paths exist (helpful for cross-platform testing)
            self.protected_directories = [p for p in defaults if os.path.exists(p)]

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class CanaryFile:
    """Deployed canary file information"""
    path: str
    filename: str
    file_hash: str
    created_at: str
    
    def exists(self) -> bool:
        return os.path.exists(self.path)
    
    def compute_current_hash(self) -> Optional[str]:
        try:
            if not self.exists():
                return None
            # Need to open in binary mode ('rb') for hashing
            with open(self.path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None

@dataclass
class ThreatEvent:
    """Detected threat information"""
    timestamp: str
    detection_method: str  # "event_log" or "hash_monitor"
    process_id: int
    process_name: str
    file_path: str
    user_name: str
    mitigated: bool = False
    mitigation_actions: List[str] = field(default_factory=list)

# ============================================================================
# ADMIN PRIVILEGE CHECK
# ============================================================================

def check_admin_privileges():
    """Ensure running as Administrator on Windows"""
    if not WIN:
        return True
    
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            # Re-launch as admin
            try:
                # Use sys.argv[0] for the script name
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, f'"{sys.argv[0]}" {" ".join(sys.argv[1:])}', None, 1
                )
            except Exception as e:
                # Fallback to simple print/messagebox if re-launch fails
                print(f"Failed to elevate privileges: {e}")
                root = tk.Tk()
                root.withdraw()
                messagebox.showerror(
                    "Admin Rights Required",
                    "HORUS must be run as Administrator.\n\nPlease restart with Admin privileges."
                )
            sys.exit(0)
        return True
    except Exception:
        return False

# ============================================================================
# LOGGING SYSTEM
# ============================================================================

class HorusLogger:
    """Centralized logging system"""
    
    def __init__(self, config: HorusConfig):
        self.logger = logging.getLogger("HORUS")
        self.logger.setLevel(getattr(logging, config.log_level, logging.INFO))
        self.logger.handlers.clear()
        
        # File handler
        formatter = logging.Formatter(
            '%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler = logging.FileHandler(config.log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def get_logger(self, name: str = "HORUS") -> logging.Logger:
        # Return a child logger for modular logging
        return logging.getLogger(name)

# ============================================================================
# WINDOWS AUDIT MANAGER
# ============================================================================

class WindowsAuditManager:
    """Manages Windows Security Auditing and SACL configuration"""
    
    def __init__(self, config: HorusConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.sacl_privilege_enabled = False
        
        if WIN and PYWIN32_AVAILABLE:
            self.sacl_privilege_enabled = self._enable_sacl_privilege()
    
    def _enable_sacl_privilege(self) -> bool:
        """Enable SeSecurityPrivilege for SACL operations"""
        try:
            hToken = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )
            privilege_id = win32security.LookupPrivilegeValue(
                None, win32security.SE_SECURITY_NAME
            )
            new_privileges = [(privilege_id, win32security.SE_PRIVILEGE_ENABLED)]
            # AdjustTokenPrivileges returns the previous state, we don't need it
            win32security.AdjustTokenPrivileges(hToken, False, new_privileges)
            win32api.CloseHandle(hToken)
            
            # Check if GetLastError is 0, indicating success, though often not needed after AdjustTokenPrivileges
            if win32api.GetLastError() == 0:
                self.logger.info("✓ SeSecurityPrivilege enabled for SACL operations")
                return True
            else:
                return False
        except Exception as e:
            self.logger.warning(f"Could not enable SACL privilege: {e}")
            return False
    
    def enable_file_auditing(self) -> bool:
        """Enable Windows File System auditing policy"""
        if not WIN:
            return False
        
        # This is a good implementation, using the command line tool
        try:
            self.logger.info("Enabling Windows File System auditing...")
            # Using the GUID for File System subcategory to be robust
            result = subprocess.run(
                ['auditpol', '/set', '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}', '/success:enable'],
                capture_output=True,
                timeout=10,
                check=False # Do not raise if non-zero, check returncode manually
            )
            
            if result.returncode == 0:
                self.logger.info("✓ File system auditing enabled")
                return True
            else:
                self.logger.warning(f"Audit policy may not be enabled (requires Admin): {result.stderr.decode('utf-8').strip()}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to enable auditing: {e}")
            return False
    
    def set_file_sacl(self, file_path: str) -> bool:
        """Set SACL (audit ACL) on a specific file"""
        if not WIN or not PYWIN32_AVAILABLE or not self.sacl_privilege_enabled:
            return False
        
        try:
            # Get current security descriptor
            sd = win32security.GetFileSecurity(
                file_path, win32security.SACL_SECURITY_INFORMATION
            )
            
            # Get or create SACL
            sacl = sd.GetSecurityDescriptorSacl()
            if not sacl:
                sacl = win32security.ACL()
            
            # Get Everyone SID
            everyone_sid = win32security.CreateWellKnownSid(
                win32security.WinWorldSid, None
            )
            
            # Define audit flags (write, delete, change permissions, etc.)
            audit_flags = (
                ntsecuritycon.FILE_WRITE_DATA |
                ntsecuritycon.FILE_APPEND_DATA |
                ntsecuritycon.DELETE |
                ntsecuritycon.WRITE_DAC |
                ntsecuritycon.FILE_WRITE_ATTRIBUTES |
                ntsecuritycon.WRITE_OWNER |
                ntsecuritycon.FILE_WRITE_EA
            )
            
            # Add audit ACE (success events - 1)
            sacl.AddAuditAccessAce(
                win32security.ACL_REVISION,
                audit_flags,
                everyone_sid,
                1,  # Success
                0   # Not failure
            )
            
            # Apply SACL
            sd.SetSecurityDescriptorSacl(1, sacl, 0)
            win32security.SetFileSecurity(
                file_path, win32security.SACL_SECURITY_INFORMATION, sd
            )
            
            self.logger.debug(f"✓ SACL configured for {os.path.basename(file_path)}")
            return True
            
        except Exception as e:
            self.logger.debug(f"SACL setup failed for {file_path}: {e}")
            return False

# ============================================================================
# CANARY DEPLOYMENT MANAGER
# ============================================================================

class CanaryDeploymentManager:
    """Deploys and manages canary files"""
    
    def __init__(self, config: HorusConfig, audit_mgr: WindowsAuditManager, logger: logging.Logger):
        self.config = config
        self.audit_mgr = audit_mgr
        self.logger = logger
        # Use path.lower() as key for case-insensitive lookup
        self.deployed_canaries: Dict[str, CanaryFile] = {}
    
    def deploy_all(self) -> int:
        """Deploy canary files to all protected directories"""
        self.logger.info("=" * 70)
        self.logger.info(f"Deploying {self.config.canary_count} canary files...")
        self.logger.info("=" * 70)
        
        # Clear existing canaries state before deployment
        self.deployed_canaries.clear()
        
        deployed_count = 0
        
        # --- FIX: Filter out non-existent directories to avoid errors ---
        valid_dirs = [d for d in self.config.protected_directories if os.path.exists(d)]
        num_dirs = len(valid_dirs)
        
        if num_dirs == 0:
            self.logger.error("No valid protected directories configured.")
            return 0
        # ----------------------------------------------------------------

        # Distribute canaries as evenly as possible
        canaries_per_dir = max(1, self.config.canary_count // num_dirs)
        remaining_canaries = self.config.canary_count % num_dirs
        
        for directory in valid_dirs:
            # Calculate how many canaries to deploy in this directory
            canary_target = canaries_per_dir + (1 if remaining_canaries > 0 else 0)
            if remaining_canaries > 0:
                remaining_canaries -= 1
            
            # Create hidden canary folder
            folder_id = hashlib.md5(directory.encode()).hexdigest()[:8]
            canary_folder = os.path.join(directory, f".horus_canary_{folder_id}")
            
            try:
                os.makedirs(canary_folder, exist_ok=True)
                self._set_hidden_attribute(canary_folder)
                
                # Deploy canaries
                for i in range(canary_target):
                    if deployed_count >= self.config.canary_count:
                        break
                    
                    canary = self._create_canary(canary_folder, folder_id, deployed_count)
                    if canary:
                        # Set SACL for Event Log detection
                        self.audit_mgr.set_file_sacl(canary.path)
                        
                        # Index by lowercase path for case-insensitive matching
                        self.deployed_canaries[canary.path.lower()] = canary
                        deployed_count += 1
                        self.logger.info(f"✓ Deployed: {canary.filename}")
            
            except Exception as e:
                self.logger.error(f"Failed to deploy in {directory}: {e}")
        
        self.logger.info("=" * 70)
        self.logger.info(f"✓ Successfully deployed {deployed_count} canary files")
        self.logger.info("=" * 70)
        return deployed_count
    
    def _create_canary(self, directory: str, folder_id: str, index: int) -> Optional[CanaryFile]:
        """Create a single canary file"""
        import random
        
        # Improved randomness
        prefixes = ["CONFIDENTIAL", "IMPORTANT", "BACKUP", "PASSWORD", 
                    "FINANCIAL", "PRIVATE", "SECRET", "CRITICAL"]
        suffixes = ["2024", "2025", "FINAL", "MASTER", "ARCHIVE", "DATA"]
        
        file_type = self.config.canary_file_types[index % len(self.config.canary_file_types)]
        filename = f"{random.choice(prefixes)}_{random.choice(suffixes)}_{folder_id}_{index}{file_type}"
        file_path = os.path.join(directory, filename)
        
        try:
            # Create file with warning content
            content = f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           ⚠️  HORUS RANSOMWARE CANARY FILE  ⚠️               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

⚠️  WARNING: DO NOT MODIFY, DELETE, OR ACCESS THIS FILE  ⚠️

This is a decoy file monitored by the HORUS Ransomware Protection
System. Any unauthorized access will trigger immediate security
response including:

    • Automatic process termination
    • Network adapter isolation
    • Security incident logging
    • Alert notifications

Created: {datetime.now().isoformat()}
File ID: HORUS-CANARY-{random.randint(100000, 999999)}
Protection Level: MAXIMUM

╔══════════════════════════════════════════════════════════════╗
║  This file is part of an active security monitoring system  ║
╚══════════════════════════════════════════════════════════════╝
"""
            
            # Ensure correct encoding for file creation
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Calculate hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Set file attributes
            self._set_hidden_attribute(file_path)
            self._set_readonly_attribute(file_path)
            
            return CanaryFile(
                path=file_path,
                filename=filename,
                file_hash=file_hash,
                created_at=datetime.now().isoformat()
            )
            
        except Exception as e:
            self.logger.error(f"Failed to create canary {filename}: {e}")
            return None
    
    def _set_hidden_attribute(self, path: str):
        """Set hidden attribute (Windows)"""
        if WIN:
            try:
                # Use absolute path for robustness
                subprocess.run(['attrib', '+H', os.path.abspath(path)], 
                             capture_output=True, timeout=3, check=False)
            except Exception:
                pass
    
    def _set_readonly_attribute(self, path: str):
        """Set read-only attribute (Windows)"""
        if WIN:
            try:
                # Use absolute path for robustness
                subprocess.run(['attrib', '+R', os.path.abspath(path)], 
                             capture_output=True, timeout=3, check=False)
            except Exception:
                pass
    
    def get_canary_paths(self) -> List[str]:
        """Get list of all deployed canary paths (lowercase for comparison)"""
        return list(self.deployed_canaries.keys())

# ============================================================================
# MITIGATION HANDLER
# ============================================================================

class MitigationHandler:
    """Executes security mitigation actions"""
    
    def __init__(self, config: HorusConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.threat_log: List[ThreatEvent] = []
        self.lock = threading.Lock()
        self.mitigation_in_progress = False
    
    def execute_mitigation(self, threat: ThreatEvent):
        """Execute all configured mitigation actions"""
        with self.lock:
            if self.mitigation_in_progress:
                self.logger.warning("Mitigation already in progress, skipping duplicate")
                return
            self.mitigation_in_progress = True
        
        self.logger.critical("=" * 70)
        self.logger.critical("🚨 RANSOMWARE DETECTED - EXECUTING EMERGENCY MITIGATION 🚨")
        self.logger.critical("=" * 70)
        self.logger.critical(f"Detection Method: {threat.detection_method}")
        self.logger.critical(f"Canary File: {os.path.basename(threat.file_path)}")
        self.logger.critical(f"Process: {os.path.basename(threat.process_name)} (PID: {threat.process_id})")
        self.logger.critical(f"User: {threat.user_name}")
        self.logger.critical("=" * 70)
        
        actions_taken = []
        
        # ACTION 1: Terminate malicious process
        if self.config.auto_kill_process and threat.process_id > 0:
            if self._kill_process(threat.process_id, threat.process_name):
                action = f"Terminated process {os.path.basename(threat.process_name)} (PID: {threat.process_id})"
                actions_taken.append(action)
                self.logger.info(f"✓ {action}")
            else:
                self.logger.error(f"✗ Failed to terminate PID {threat.process_id}")
        
        # ACTION 2: Disable network adapters
        if self.config.auto_disable_network:
            if self._disable_network():
                actions_taken.append("Network adapters disabled - System isolated")
                self.logger.info("✓ Network adapters disabled")
            else:
                self.logger.error("✗ Failed to disable network")
        
        # ACTION 3: Log off user (optional)
        if self.config.auto_logoff_user:
            actions_taken.append("User session logoff initiated")
            self.logger.warning("⚠️ Logging off user session...")
            self._logoff_user()
        
        # ACTION 4: Shutdown system (optional)
        if self.config.auto_shutdown_system:
            actions_taken.append("System shutdown initiated")
            self.logger.critical("⚠️ EMERGENCY SYSTEM SHUTDOWN...")
            self._shutdown_system()
        
        # Update threat record
        threat.mitigated = True
        threat.mitigation_actions = actions_taken
        self.threat_log.append(threat)
        
        # Save threat log
        self._save_threat_log()
        
        # Show alert (non-blocking)
        threading.Thread(target=self._show_alert, args=(threat,), daemon=True).start()
        
        self.logger.critical("=" * 70)
        self.logger.critical(f"✓ Mitigation complete: {len(actions_taken)} actions executed")
        self.logger.critical("=" * 70)
        
        # Cooldown period (to prevent immediate re-trigger on the next monitor cycle)
        time.sleep(5)
        self.mitigation_in_progress = False
    
    def _kill_process(self, pid: int, process_name: str) -> bool:
        """Terminate process by PID"""
        if not WIN:
            return False
        
        try:
            # Method 1: taskkill (preferred)
            result = subprocess.run(
                ['taskkill', '/F', '/PID', str(pid)],
                capture_output=True, timeout=5, check=False
            )
            
            if result.returncode == 0:
                return True
            
            # Method 2: wmic (fallback) - often less reliable than taskkill
            # result = subprocess.run(
            #     ['wmic', 'process', 'where', f'ProcessId={pid}', 'delete'],
            #     capture_output=True, timeout=5, check=False
            # )
            # return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Process termination failed: {e}")
            return False
        
        return False # Ensure a return value if taskkill fails
    
    def _disable_network(self) -> bool:
        """Disable all active network adapters"""
        if not WIN:
            return False
        
        try:
            # PowerShell command to find all active adapters and disable them
            ps_command = (
                "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
                "Disable-NetAdapter -Confirm:$false"
            )
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True, timeout=15, check=False
            )
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Network isolation failed: {e}")
            return False
    
    def _logoff_user(self):
        """Log off current user session"""
        if WIN:
            try:
                # /l for logoff, /f for force
                subprocess.run(['shutdown', '/l', '/f'], timeout=5, check=False)
            except Exception as e:
                self.logger.error(f"Logoff failed: {e}")
    
    def _shutdown_system(self):
        """Emergency system shutdown"""
        if WIN:
            try:
                # /s for shutdown, /t 0 for immediate, /f for force
                subprocess.run(['shutdown', '/s', '/t', '0', '/f'], timeout=5, check=False)
            except Exception as e:
                self.logger.error(f"Shutdown failed: {e}")
    
    def _save_threat_log(self):
        """Save threat log to JSON file"""
        try:
            log_file = Path("horus_threats.json")
            threats_data = []
            
            for threat in self.threat_log:
                # Prepare data for JSON serialization
                threats_data.append({
                    "timestamp": threat.timestamp,
                    "detection_method": threat.detection_method,
                    "process_id": threat.process_id,
                    "process_name": threat.process_name,
                    "file_path": threat.file_path,
                    "user_name": threat.user_name,
                    "mitigated": threat.mitigated,
                    "mitigation_actions": threat.mitigation_actions
                })
            
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(threats_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save threat log: {e}")
    
    def _show_alert(self, threat: ThreatEvent):
        """Show alert dialog to user"""
        # Ensure only on Windows and TK is available
        if not WIN or 'tkinter' not in sys.modules:
            return
            
        try:
            root = tk.Tk()
            root.withdraw()
            # Force the alert window to the top
            root.attributes('-topmost', True)
            
            message = f"""🚨 RANSOMWARE ATTACK DETECTED AND MITIGATED 🚨

Canary File Accessed:
  {os.path.basename(threat.file_path)}

Malicious Process Identified:
  Name: {os.path.basename(threat.process_name)}
  PID: {threat.process_id}
  User: {threat.user_name}

Detection Method:
  {threat.detection_method.upper()}

Actions Taken:
"""
            for action in threat.mitigation_actions:
                message += f"  ✓ {action}\n"
            
            message += f"\nTimestamp: {threat.timestamp}"
            message += "\n\n⚠️ Check HORUS logs for complete details."
            
            messagebox.showerror("HORUS Security Alert", message, parent=root)
            root.destroy()
            
        except Exception as e:
            self.logger.warning(f"Could not display alert dialog: {e}")

# ============================================================================
# DETECTION SYSTEMS
# ============================================================================

class EventLogMonitor:
    """
    Monitors Windows Security Event Log for Event ID 4663 (File Access)
    - Corrected implementation to properly read and process events.
    """
    
    def __init__(self, config: HorusConfig, canary_paths: List[str], 
                 mitigation: MitigationHandler, logger: logging.Logger):
        self.config = config
        # Use set of lowercase paths for efficient, case-insensitive lookup
        self.canary_paths = set(p.lower() for p in canary_paths)
        self.mitigation = mitigation
        self.logger = logger
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.last_record_number = 0
    
    def start(self) -> bool:
        """Start event log monitoring"""
        if not WIN or not PYWIN32_AVAILABLE:
            self.logger.info("Event Log monitoring unavailable (Windows/pywin32 required)")
            return False
        
        if not self.config.use_event_log_detection:
            self.logger.info("Event Log detection disabled in config")
            return False
        
        try:
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            self.logger.info("✓ Event Log monitor started (watching Event ID 4663)")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start Event Log monitor: {e}")
            return False
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        # Get starting position: read backwards to get the last record number
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if events:
                # Start processing from the record *after* the most recent one we saw
                self.last_record_number = events[0].RecordNumber
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            self.logger.warning(f"Could not get last event record number: {e}")
            self.last_record_number = 0
        
        while self.running:
            try:
                self._check_events()
                time.sleep(0.3) # Poll Event Log frequently
            except Exception as e:
                self.logger.debug(f"Event monitor loop error: {e}")
                time.sleep(1)
    
    def _check_events(self):
        """Check for new Event ID 4663 events"""
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            # Read forwards, sequentially, starting after the last record number
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Start reading from record number + 1
            # Note: win32evtlog.ReadEventLog handles the offset from the last record internally
            # when used with EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0) # The offset param is ignored with SEQUENTIAL_READ
            
            # Need a different approach to ensure we only process new events
            while self.running:
                # Read 100 events at a time
                events = win32evtlog.ReadEventLog(
                    hand, 
                    win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 
                    0, 
                    100
                )
                if not events:
                    break # No more events
                
                new_max_record = self.last_record_number
                
                for event in events:
                    # Skip events we've already processed
                    if event.RecordNumber <= self.last_record_number:
                        new_max_record = max(new_max_record, event.RecordNumber)
                        continue
                        
                    event_id = event.EventID & 0xFFFF
                    if event_id == 4663: # Object access
                        self._process_event(event)
                    
                    new_max_record = max(new_max_record, event.RecordNumber)
                
                self.last_record_number = new_max_record
            
            win32evtlog.CloseEventLog(hand)
            
        except pywintypes.error as e:
            # Ignore "no more items" (18) errors
            if e.args[0] != 18:
                self.logger.debug(f"Event check error: {e}")
        except Exception as e:
            self.logger.debug(f"Event check error: {e}")
    
    def _process_event(self, event):
        """Process Event ID 4663 - file access event"""
        try:
            strings = event.StringInserts
            # Event 4663 structure has at least 10 string inserts
            if not strings or len(strings) < 10:
                return
            
            # Extract event data (indices from Event 4663 XML/Template)
            user_name = strings[1] if len(strings) > 1 else "Unknown"
            object_name = strings[5] if len(strings) > 5 else "" # File path
            process_id_hex = strings[8] if len(strings) > 8 else "0"
            process_name = strings[9] if len(strings) > 9 else "Unknown"
            
            # Normalize path for comparison (case-insensitive check)
            object_name_lower = os.path.normpath(object_name).lower()
            
            # 1. Check if this is a canary file
            if object_name_lower not in self.canary_paths:
                return
            
            # 2. Skip system accounts (often end with $)
            if user_name.endswith('$'):
                self.logger.debug(f"Ignoring system account: {user_name}")
                return
            
            # 3. Skip trusted processes
            process_basename = os.path.basename(process_name).lower()
            if any(trusted.lower() in process_basename for trusted in self.config.trusted_processes):
                self.logger.info(f"Ignoring trusted process: {process_basename}")
                return
            
            # 4. Parse process ID
            try:
                pid = int(process_id_hex, 16) if process_id_hex.startswith('0x') else int(process_id_hex)
            except:
                pid = 0
            
            # THREAT DETECTED!
            threat = ThreatEvent(
                timestamp=datetime.now().isoformat(),
                detection_method="event_log",
                process_id=pid,
                process_name=process_name,
                file_path=object_name,
                user_name=user_name
            )
            
            self.logger.critical(f"🚨 THREAT DETECTED via Event Log!")
            self.logger.critical(f"   File: {os.path.basename(object_name)}")
            self.logger.critical(f"   Process: {process_basename} (PID: {pid})")
            
            # Execute mitigation
            self.mitigation.execute_mitigation(threat)
            
        except Exception as e:
            self.logger.error(f"Error processing event: {e}")


class HashMonitor:
    """Hash-based canary file monitoring (reliable fallback)"""
    
    def __init__(self, config: HorusConfig, deployment: CanaryDeploymentManager,
                 mitigation: MitigationHandler, logger: logging.Logger):
        self.config = config
        self.deployment = deployment
        self.mitigation = mitigation
        self.logger = logger
        self.running = False
        self.thread: Optional[threading.Thread] = None
        # Hash state stores the known good hash for each canary file path (lowercase)
        self.hash_state: Dict[str, str] = {} 
    
    def start(self) -> bool:
        """Start hash monitoring"""
        if not self.config.use_hash_detection:
            self.logger.info("Hash monitoring disabled in config")
            return False
        
        try:
            # Initialize hash state with the current, known-good hashes
            for path, canary in self.deployment.deployed_canaries.items():
                self.hash_state[path] = canary.file_hash
            
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            self.logger.info(f"✓ Hash monitor started (checking every {self.config.hash_check_interval}s)")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start hash monitor: {e}")
            return False
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        # NOTE: The loop implementation was correct in the original file (but placed in the wrong class).
        # We are restoring it here.
        while self.running:
            try:
                # Iterate over a copy of the keys for thread safety during iteration
                for path in list(self.deployment.deployed_canaries.keys()):
                    canary = self.deployment.deployed_canaries[path]
                    
                    current_hash = canary.compute_current_hash()
                    
                    # 1. Check for deletion/inaccessibility
                    if current_hash is None:
                        if path in self.hash_state:
                            self.logger.critical(f"🚨 Canary file deleted/inaccessible: {canary.filename}")
                            self._trigger_threat(path, canary, "file_deleted")
                            # Remove from state to prevent repeated triggers from this monitor
                            del self.hash_state[path] 
                        continue
                    
                    # 2. Check for modifications
                    if path in self.hash_state:
                        if current_hash != self.hash_state[path]:
                            self.logger.critical(f"🚨 Hash mismatch detected: {canary.filename}")
                            self._trigger_threat(path, canary, "file_modified")
                            # Update hash to prevent repeated triggers on the same modification
                            self.hash_state[path] = current_hash
                    else:
                        # Should not happen if initialization is correct, but safe to add
                        self.hash_state[path] = current_hash 
                
                time.sleep(self.config.hash_check_interval)
                
            except Exception as e:
                self.logger.error(f"Hash monitor error: {e}")
                time.sleep(1)
    
    def _trigger_threat(self, path: str, canary: CanaryFile, reason: str):
        """Trigger mitigation for detected threat"""
        # Best effort to identify the process is needed here since hash monitor is blind to process
        # The internal functions to get process PID (like wmic lookup) are kept simple/disabled 
        # as finding the *currently* modifying process without a driver/filter is complex.
        pid = 0 # Cannot reliably get PID without Windows API/Driver for hash detection
        
        threat = ThreatEvent(
            timestamp=datetime.now().isoformat(),
            detection_method=f"hash_monitor ({reason})",
            process_id=pid,
            # Fallback to general process name/user
            process_name="PID/Process Unknown (Hash Detect)",
            file_path=path,
            user_name=os.getenv('USERNAME', 'Unknown')
        )
        
        self.logger.critical(f"🚨 THREAT DETECTED via Hash Monitor!")
        self.logger.critical(f"   File: {canary.filename}")
        self.logger.critical(f"   Reason: {reason}")
        
        # Execute mitigation
        self.mitigation.execute_mitigation(threat)
    
    # Note: The original _get_file_accessing_process and _get_process_name are removed
    # as they are unreliable/incomplete for real-time file access without kernel/API calls,
    # which is the limitation of a pure Python hash-monitor fallback.


# ============================================================================
# MAIN HORUS SYSTEM
# ============================================================================

class HorusSystem:
    """Main HORUS system coordinator"""
    
    def __init__(self, config: HorusConfig):
        self.config = config
        self.logger_sys = HorusLogger(config)
        self.logger = self.logger_sys.get_logger("HORUS.System")
        
        self.audit_manager = WindowsAuditManager(config, self.logger)
        self.deployment_manager = CanaryDeploymentManager(config, self.audit_manager, self.logger)
        self.mitigation_handler = MitigationHandler(config, self.logger)
        
        self.event_monitor: Optional[EventLogMonitor] = None
        self.hash_monitor: Optional[HashMonitor] = None
        
        self.initialized = False
        self.running = False
    
    def initialize(self) -> bool:
        """Initialize the protection system"""
        try:
            self.logger.info("=" * 70)
            self.logger.info("🛡️  HORUS RANSOMWARE PROTECTION SYSTEM")
            self.logger.info("=" * 70)
            self.logger.info("Initializing...")
            
            # Enable Windows auditing (only if event log detection is enabled)
            if self.config.use_event_log_detection:
                self.audit_manager.enable_file_auditing()
            
            # Deploy canary files
            deployed = self.deployment_manager.deploy_all()
            if deployed == 0:
                self.logger.warning("No canaries deployed - check protected directories")
                return False
            
            self.initialized = True
            self.logger.info("=" * 70)
            self.logger.info("✓ Initialization complete")
            self.logger.info("=" * 70)
            return True
            
        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            self.logger.error(traceback.format_exc())
            return False
    
    def start(self) -> bool:
        """Start protection monitoring"""
        if not self.initialized:
            self.logger.error("System not initialized")
            return False
        
        if self.running:
            self.logger.warning("System already running")
            return True
        
        try:
            self.logger.info("Starting protection monitors...")
            
            canary_paths = self.deployment_manager.get_canary_paths()
            
            # Start Event Log monitor
            self.event_monitor = EventLogMonitor(
                self.config, canary_paths, self.mitigation_handler, 
                self.logger_sys.get_logger("HORUS.EventMonitor") # Use dedicated logger name
            )
            self.event_monitor.start()
            
            # Start Hash monitor
            self.hash_monitor = HashMonitor(
                self.config, self.deployment_manager, 
                self.mitigation_handler, 
                self.logger_sys.get_logger("HORUS.HashMonitor") # Use dedicated logger name
            )
            self.hash_monitor.start()
            
            self.running = True
            self.logger.info("=" * 70)
            self.logger.info("✓ HORUS PROTECTION IS NOW ACTIVE")
            self.logger.info("=" * 70)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop(self):
        """Stop protection monitoring"""
        if not self.running:
            return
        
        self.logger.info("Stopping protection...")
        
        if self.event_monitor:
            self.event_monitor.stop()
        if self.hash_monitor:
            self.hash_monitor.stop()
        
        self.running = False
        self.logger.info("✓ HORUS protection stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get system status"""
        # Ensure we check the current status of all canaries
        canaries_deployed = len(self.deployment_manager.deployed_canaries)
        return {
            "initialized": self.initialized,
            "running": self.running,
            "canaries_deployed": canaries_deployed,
            "threats_detected": len(self.mitigation_handler.threat_log),
            # Return list of filenames, not full paths, for cleaner display/status
            "canary_paths": [os.path.basename(p) for p in self.deployment_manager.deployed_canaries.keys()]
        }
    
    def simulate_attack(self) -> tuple[bool, str]:
        """Simulate an attack for testing (modifies first canary)"""
        if not self.deployment_manager.deployed_canaries:
            return False, "No canaries deployed"
        
        try:
            # Get the path (the key is the lowercase path)
            path = next(iter(self.deployment_manager.deployed_canaries.keys()))
            canary = self.deployment_manager.deployed_canaries[path]
            
            # Get the original case path to ensure file operation works
            original_path = Path(path).as_posix() if not WIN else Path(path) 
            # Re-read the file in its original case from the dictionary value
            # Note: A real system might need to deal with Windows' case-insensitivity here
            # but since we store the CanaryFile object, we can use its stored path
            # Let's rely on the CanaryFile.path for the *actual* file modification.
            
            # Find the actual path from the deployed_canaries dict's value
            actual_canary = next(c for c in self.deployment_manager.deployed_canaries.values() if c.path.lower() == path)
            
            with open(actual_canary.path, 'a', encoding='utf-8') as f:
                f.write(f"\n[SIMULATED ATTACK] {datetime.now().isoformat()}\n")
            
            # Remove read-only attribute temporarily to allow modification
            if WIN:
                subprocess.run(['attrib', '-R', actual_canary.path], capture_output=True, timeout=3, check=False)
                
            with open(actual_canary.path, 'a', encoding='utf-8') as f:
                f.write(f"\n[SIMULATED ATTACK] {datetime.now().isoformat()}\n")
            
            # Re-apply read-only attribute
            if WIN:
                subprocess.run(['attrib', '+R', actual_canary.path], capture_output=True, timeout=3, check=False)
            
            self.logger.warning(f"⚠️ Simulated attack on: {actual_canary.filename}")
            return True, actual_canary.filename
        except Exception as e:
            self.logger.error(f"Simulation failed: {e}")
            return False, str(e)

# ============================================================================
# GUI APPLICATION
# ============================================================================

# --- NEW ADDITION: Configuration Dialog ---
class DirectoryConfigDialog(tk.Toplevel):
    """Dialog to configure protected directories"""
    def __init__(self, parent, config: HorusConfig, on_save_callback):
        super().__init__(parent)
        self.title("Configure Protected Directories")
        self.geometry("600x400")
        self.config = config
        self.on_save = on_save_callback
        # Working copy of directories
        self.dirs = list(config.protected_directories)
        
        # Make modal
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Select folders to protect with canary files:", 
                 font=("Arial", 10)).pack(anchor=tk.W, pady=(0, 5))
        
        # Listbox with scrollbar
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.dir_listbox = tk.Listbox(list_frame, selectmode=tk.SINGLE, height=10)
        self.dir_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.dir_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.dir_listbox.config(yscrollcommand=scrollbar.set)
        
        # Populate list
        for d in self.dirs:
            self.dir_listbox.insert(tk.END, d)
            
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="➕ Add Folder", command=self.add_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="➖ Remove Selected", command=self.remove_folder).pack(side=tk.LEFT, padx=5)
        
        # Bottom Actions
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(action_frame, text="Save & Close", command=self.save_and_close).pack(side=tk.RIGHT, padx=5)
        ttk.Button(action_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)
        
    def add_folder(self):
        folder = filedialog.askdirectory(parent=self, title="Select Folder to Protect")
        if folder:
            folder = os.path.abspath(folder)
            if folder not in self.dirs:
                self.dirs.append(folder)
                self.dir_listbox.insert(tk.END, folder)
    
    def remove_folder(self):
        sel = self.dir_listbox.curselection()
        if sel:
            idx = sel[0]
            self.dir_listbox.delete(idx)
            self.dirs.pop(idx)
            
    def save_and_close(self):
        self.config.protected_directories = self.dirs
        if self.on_save:
            self.on_save()
        self.destroy()
# ------------------------------------------

class HorusGUI:
    """Graphical user interface for HORUS"""
    
    def __init__(self):
        self.config = HorusConfig()
        self.horus = HorusSystem(self.config)
        self.last_threat_count = 0
        
        self.root = tk.Tk()
        self.root.title("HORUS - Ransomware Protection System")
        self.root.geometry("950x750")
        self.root.minsize(850, 650)
        
        # Setup GUI logger first so messages during setup are caught
        self.gui_handler = GUILogHandler(self)
        logging.getLogger("HORUS").addHandler(self.gui_handler)
        
        self._setup_ui()
        self._update_status_loop()
    
    def _setup_ui(self):
        """Setup GUI layout"""
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        title = ttk.Label(title_frame, text="🛡️ HORUS Ransomware Protection",
                         font=("Arial", 20, "bold"))
        title.pack()
        
        subtitle = ttk.Label(title_frame, 
                           text="Hybrid Detection System: Event Log + Hash Monitoring",
                           font=("Arial", 10), foreground="gray")
        subtitle.pack()
        
        # Control buttons
        control_frame = ttk.LabelFrame(main_frame, text="System Control", padding=12)
        control_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X)
        
        # --- MODIFIED: Added Configuration Button ---
        self.config_btn = ttk.Button(btn_frame, text="📂 Configure Folders",
                                     command=self._open_config, width=18)
        self.config_btn.pack(side=tk.LEFT, padx=(0, 8))
        # --------------------------------------------
        
        self.init_btn = ttk.Button(btn_frame, text="⚙️ Initialize System",
                                   command=self._on_initialize, width=18)
        self.init_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.start_btn = ttk.Button(btn_frame, text="▶️ Start Protection",
                                    command=self._on_start, width=18, state=tk.DISABLED)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.stop_btn = ttk.Button(btn_frame, text="⏹️ Stop Protection",
                                   command=self._on_stop, width=18, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.sim_btn = ttk.Button(btn_frame, text="🧪 Simulate Attack",
                                  command=self._on_simulate, width=18, state=tk.DISABLED)
        self.sim_btn.pack(side=tk.LEFT)
        
        # Status display
        status_frame = ttk.LabelFrame(main_frame, text="System Status", padding=12)
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(1, weight=1)
        
        ttk.Label(status_frame, text="Status:", font=("Arial", 10, "bold")).grid(
            row=0, column=0, sticky=tk.W, padx=(0, 15), pady=3)
        self.status_label = ttk.Label(status_frame, text="⚫ Not Initialized",
                                     foreground="red", font=("Arial", 10, "bold"))
        self.status_label.grid(row=0, column=1, sticky=tk.W, pady=3)
        
        ttk.Label(status_frame, text="Canary Files:", font=("Arial", 10)).grid(
            row=1, column=0, sticky=tk.W, padx=(0, 15), pady=3)
        self.canary_label = ttk.Label(status_frame, text="0", font=("Arial", 10))
        self.canary_label.grid(row=1, column=1, sticky=tk.W, pady=3)
        
        ttk.Label(status_frame, text="Threats Detected:", font=("Arial", 10)).grid(
            row=2, column=0, sticky=tk.W, padx=(0, 15), pady=3)
        self.threat_label = ttk.Label(status_frame, text="0", 
                                      foreground="green", font=("Arial", 10))
        self.threat_label.grid(row=2, column=1, sticky=tk.W, pady=3)
        
        ttk.Label(status_frame, text="Detection Methods:", font=("Arial", 10)).grid(
            row=3, column=0, sticky=tk.W, padx=(0, 15), pady=3)
        detection_text = []
        if self.config.use_event_log_detection:
            detection_text.append("Event Log (4663)")
        if self.config.use_hash_detection:
            detection_text.append("Hash Monitor")
        self.detection_label = ttk.Label(status_frame, text=" + ".join(detection_text),
                                        font=("Arial", 10))
        self.detection_label.grid(row=3, column=1, sticky=tk.W, pady=3)
        
        # Mitigation settings
        mitigation_frame = ttk.LabelFrame(main_frame, text="Mitigation Actions", padding=12)
        mitigation_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        actions = []
        if self.config.auto_kill_process:
            actions.append("✓ Process Termination")
        if self.config.auto_disable_network:
            actions.append("✓ Network Isolation")
        if self.config.auto_logoff_user:
            actions.append("✓ User Logoff")
        if self.config.auto_shutdown_system:
            actions.append("✓ System Shutdown")
        
        ttk.Label(mitigation_frame, text=" | ".join(actions),
                 font=("Arial", 9)).pack(anchor=tk.W)
        
        # Activity log
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding=10)
        log_frame.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=20, state=tk.NORMAL,
            font=("Consolas", 9), wrap=tk.WORD, bg="#1e1e1e", fg="#d4d4d4"
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Close protocol
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    
    # --- NEW ADDITION: Open Config Callback ---
    def _open_config(self):
        if self.horus.initialized:
            messagebox.showwarning("System Initialized", 
                "Cannot change directories while system is initialized.\n"
                "Please restart the application to change folders.")
            return
        DirectoryConfigDialog(self.root, self.config, self.update_status_display)
    # ------------------------------------------

    def _on_initialize(self):
        """Initialize system"""
        self.log_message("🔄 Initializing HORUS system...", "info")
        
        # Run initialization in a separate thread to prevent GUI freeze
        def init_thread():
            self.init_btn.config(state=tk.DISABLED) # Disable button while working
            # Disable config button after init starts
            self.config_btn.config(state=tk.DISABLED)
            
            if self.horus.initialize():
                self.root.after(0, lambda: self._post_init_success())
            else:
                self.root.after(0, lambda: self._post_init_failure())
                # Re-enable config button on failure
                self.root.after(0, lambda: self.config_btn.config(state=tk.NORMAL))
            
            self.root.after(0, lambda: self.init_btn.config(state=tk.NORMAL))

        threading.Thread(target=init_thread, daemon=True).start()

    def _post_init_success(self):
        self.log_message("✓ System initialized successfully", "success")
        self.init_btn.config(state=tk.DISABLED, text="✓ Initialized")
        self.start_btn.config(state=tk.NORMAL)
        self.sim_btn.config(state=tk.NORMAL)
        self.update_status_display()
        
    def _post_init_failure(self):
        self.log_message("✗ Initialization failed", "error")
        messagebox.showerror("Error", 
            "Initialization failed. Check logs for details.")
    
    def _on_start(self):
        """Start protection"""
        self.log_message("▶️ Starting protection...", "info")
        
        def start_thread():
            self.start_btn.config(state=tk.DISABLED)
            if self.horus.start():
                self.root.after(0, lambda: self._post_start_success())
            else:
                self.root.after(0, lambda: self._post_start_failure())
                self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
        
        threading.Thread(target=start_thread, daemon=True).start()

    def _post_start_success(self):
        self.log_message("✓ Protection is now ACTIVE", "success")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
    def _post_start_failure(self):
        self.log_message("✗ Failed to start protection", "error")
    
    def _on_stop(self):
        """Stop protection"""
        self.log_message("⏹️ Stopping protection...", "warning")
        self.horus.stop()
        self.log_message("⚫ Protection stopped", "warning")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
    
    def _on_simulate(self):
        """Simulate attack for testing"""
        # Run simulation in a thread to keep GUI responsive
        def sim_thread():
            result = messagebox.askyesno(
                "Simulate Attack",
                "This will modify a canary file to trigger detection.\n\n"
                "This will activate mitigation actions!\n\nContinue?"
            )
            
            if result:
                success, info = self.horus.simulate_attack()
                self.root.after(0, lambda: self._post_simulate_result(success, info))

        threading.Thread(target=sim_thread, daemon=True).start()

    def _post_simulate_result(self, success: bool, info: str):
        if success:
            self.log_message(f"🧪 Simulated attack on: {info}", "warning")
        else:
            self.log_message(f"✗ Simulation failed: {info}", "error")
    
    def log_message(self, message: str, level: str = "info"):
        """Add message to log display"""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Color coding (simplified tag system for tkinter ScrolledText)
            tag = level
            
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
            self.log_text.config(state=tk.DISABLED)
            
            # Scroll to end
            self.log_text.see(tk.END)
        except Exception:
            pass
    
    def _update_status_loop(self):
        """Update status display periodically"""
        try:
            self.update_status_display()
        except Exception:
            pass # Ignore errors during status update
        
        self.root.after(1000, self._update_status_loop) # Reschedule for 1 second
        
    def update_status_display(self):
        """Logic to update the status panel"""
        status = self.horus.get_status()
        
        # Update status indicator
        if status["running"]:
            self.status_label.config(text="🟢 Protection Active", foreground="green")
        elif status["initialized"]:
            self.status_label.config(text="🟡 Initialized (Stopped)", foreground="orange")
        else:
            self.status_label.config(text="⚫ Not Initialized", foreground="red")
        
        # Update canary count
        self.canary_label.config(text=str(status["canaries_deployed"]))
        
        # Update threat count
        threat_count = status["threats_detected"]
        self.threat_label.config(text=str(threat_count))
        
        if threat_count > self.last_threat_count:
            # New threat detected
            self.threat_label.config(foreground="red", font=("Arial", 10, "bold"))
            # Log new threats
            new_threats = self.horus.mitigation_handler.threat_log[self.last_threat_count:]
            for threat in new_threats:
                self.log_message(f"🚨 THREAT: {os.path.basename(threat.file_path)}", "critical")
                self.log_message(f"   Process: {os.path.basename(threat.process_name)} (PID: {threat.process_id})", "critical")
                for action in threat.mitigation_actions:
                    self.log_message(f"   🛡️ {action}", "info")
            self.last_threat_count = threat_count
        elif threat_count > 0:
            # Threats exist, keep color red/bold
            self.threat_label.config(foreground="red", font=("Arial", 10, "bold"))
        else:
            # No threats
            self.threat_label.config(foreground="green", font=("Arial", 10, "normal"))

    def _on_close(self):
        """Handle window close"""
        if self.horus.running:
            result = messagebox.askokcancel(
                "Quit",
                "HORUS protection is running.\n\n"
                "Stop protection and quit?"
            )
            if result:
                self.horus.stop()
                # Remove GUI log handler before closing to prevent errors during thread teardown
                logging.getLogger("HORUS").removeHandler(self.gui_handler)
                self.root.destroy()
        else:
            logging.getLogger("HORUS").removeHandler(self.gui_handler)
            self.root.destroy()
    
    def start(self):
        """Start GUI main loop"""
        # Define tags for coloring the log text
        self.log_text.tag_config('info', foreground='#4a9eff')
        self.log_text.tag_config('success', foreground='#4ade80')
        self.log_text.tag_config('warning', foreground='#fb923c')
        self.log_text.tag_config('error', foreground='#ef4444')
        self.log_text.tag_config('critical', foreground='#dc2626')
        
        self.root.mainloop()


class GUILogHandler(logging.Handler):
    """Custom log handler for GUI"""
    
    def __init__(self, gui: HorusGUI):
        super().__init__()
        self.gui = gui
        # Set formatter for this handler to avoid duplicates in the main log
        formatter = logging.Formatter('%(message)s')
        self.setFormatter(formatter)
    
    def emit(self, record):
        try:
            # This must be run on the main thread (using root.after)
            self.gui.root.after(0, self._log_to_gui, record)
        except Exception:
            pass

    def _log_to_gui(self, record):
        """Thread-safe function to log to GUI"""
        try:
            msg = self.format(record)
            level_map = {
                "DEBUG": "info",
                "INFO": "info",
                "WARNING": "warning",
                "ERROR": "error",
                "CRITICAL": "critical"
            }
            self.gui.log_message(msg, level_map.get(record.levelname, "info"))
        except Exception:
            pass

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    # The check_admin_privileges function handles re-launching the script
    # as admin if necessary and exits the current process.
    check_admin_privileges()
    
    try:
        # Launch GUI
        app = HorusGUI()
        app.start()
        
    except Exception as e:
        # Final catch for errors that occur outside the main loop
        logging.fatal(f"Failed to launch HORUS: {e}", exc_info=True)
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Fatal Error",
                f"Failed to launch HORUS:\n\n{e}\n\n"
                "Check horus_protection.log for details."
            )
            root.destroy()
        except Exception:
            pass
        sys.exit(1)