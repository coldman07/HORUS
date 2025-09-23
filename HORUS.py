#!/usr/bin/env python3
"""
HORUS - Advanced Ransomware Protection System
Main Framework with Modular Architecture

Author: HORUS Development Team
Version: 1.0.0
License: MIT

HORUS is designed to detect, prevent, and mitigate ransomware attacks using 
a layered defense approach combining heuristic monitoring, canary files, 
and signature-based scanning.
"""

import os
import sys
import time
import json
import logging
import threading
import signal
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# -------------------------------
# Configuration and Constants
# -------------------------------

class ThreatLevel(Enum):
    """Threat level enumeration"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class SystemStatus(Enum):
    """System status enumeration"""
    STOPPED = "Stopped"
    STARTING = "Starting"
    RUNNING = "Running"
    STOPPING = "Stopping"
    ERROR = "Error"

@dataclass
class HorusConfig:
    """Main configuration for HORUS system"""
    # General Settings
    log_file: str = "horus.log"
    log_level: str = "INFO"
    config_file: str = "horus_config.json"
    
    # Risk Scoring Thresholds
    low_risk_threshold: int = 30
    medium_risk_threshold: int = 60
    high_risk_threshold: int = 80
    critical_risk_threshold: int = 95
    
    # Component Enable/Disable
    enable_heuristic_engine: bool = True
    enable_canary_manager: bool = True
    enable_clamav_integration: bool = False  # Optional component
    
    # Performance Settings
    scan_interval: int = 5  # seconds
    max_threads: int = 4
    memory_limit_mb: int = 512
    
    # Directories to Protect
    protected_directories: List[str] = None
    
    def __post_init__(self):
        if self.protected_directories is None:
            self.protected_directories = []

# -------------------------------
# Risk Assessment System
# -------------------------------

@dataclass
class RiskEvent:
    """Individual risk event"""
    timestamp: datetime
    source: str  # Which component detected it
    event_type: str
    description: str
    risk_score: int
    details: Dict[str, Any]

class RiskCalculator:
    """Calculates overall system risk score"""
    
    def __init__(self, config: HorusConfig):
        self.config = config
        self.recent_events: List[RiskEvent] = []
        self.lock = threading.Lock()
    
    def add_event(self, event: RiskEvent) -> None:
        """Add a new risk event"""
        with self.lock:
            self.recent_events.append(event)
            # Keep only recent events (last 10 minutes)
            cutoff_time = datetime.now().timestamp() - 600
            self.recent_events = [
                e for e in self.recent_events 
                if e.timestamp.timestamp() > cutoff_time
            ]
    
    def calculate_current_risk(self) -> int:
        """Calculate current overall risk score"""
        if not self.recent_events:
            return 0
        
        # Weight recent events more heavily
        now = datetime.now().timestamp()
        total_risk = 0
        
        for event in self.recent_events:
            age_seconds = now - event.timestamp.timestamp()
            # Exponential decay over 10 minutes
            weight = max(0.1, 1.0 - (age_seconds / 600))
            total_risk += event.risk_score * weight
        
        return min(100, int(total_risk))
    
    def get_threat_level(self) -> ThreatLevel:
        """Get current threat level based on risk score"""
        risk = self.calculate_current_risk()
        
        if risk >= self.config.critical_risk_threshold:
            return ThreatLevel.CRITICAL
        elif risk >= self.config.high_risk_threshold:
            return ThreatLevel.HIGH
        elif risk >= self.config.medium_risk_threshold:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

# -------------------------------
# Component Base Classes
# -------------------------------

class HorusComponent:
    """Base class for all HORUS components"""
    
    def __init__(self, name: str, config: HorusConfig, risk_calculator: RiskCalculator):
        self.name = name
        self.config = config
        self.risk_calculator = risk_calculator
        self.logger = self._setup_logger()
        self.running = False
        self.thread: Optional[threading.Thread] = None
    
    def _setup_logger(self) -> logging.Logger:
        """Setup component logger"""
        logger = logging.getLogger(f"HORUS.{self.name}")
        logger.setLevel(getattr(logging, self.config.log_level))
        return logger
    
    def start(self) -> bool:
        """Start the component"""
        if self.running:
            return True
        
        try:
            self.logger.info(f"Starting {self.name}...")
            self.running = True
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            self.logger.error(f"Failed to start {self.name}: {e}")
            self.running = False
            return False
    
    def stop(self) -> None:
        """Stop the component"""
        if not self.running:
            return
        
        self.logger.info(f"Stopping {self.name}...")
        self.running = False
        
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
    
    def _run(self) -> None:
        """Main component loop - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement _run method")
    
    def get_status(self) -> Dict[str, Any]:
        """Get component status"""
        return {
            "name": self.name,
            "running": self.running,
            "thread_alive": self.thread.is_alive() if self.thread else False
        }

# -------------------------------
# Heuristic Engine (Placeholder)
# -------------------------------

class HeuristicEngine(HorusComponent):
    """
    Monitors processes and file activity, calculates risk scores, 
    and identifies suspicious behavior patterns.
    
    TODO: Implement process monitoring, file activity tracking,
    suspicious pattern detection, and behavioral analysis.
    """
    
    def __init__(self, config: HorusConfig, risk_calculator: RiskCalculator):
        super().__init__("HeuristicEngine", config, risk_calculator)
        
        # Placeholder for heuristic rules and monitoring data
        self.process_monitors = []
        self.file_activity_monitors = []
        self.behavior_patterns = {}
    
    def _run(self) -> None:
        """Main heuristic monitoring loop"""
        self.logger.info("Heuristic Engine started - monitoring for suspicious activity")
        
        while self.running:
            try:
                # TODO: Implement actual heuristic monitoring
                # - Monitor process creation/termination
                # - Track file system activity
                # - Analyze encryption patterns
                # - Detect rapid file modifications
                # - Monitor network activity
                
                # Placeholder: Simulate occasional risk events
                if time.time() % 60 < 1:  # Once per minute
                    self._simulate_heuristic_detection()
                
                time.sleep(self.config.scan_interval)
                
            except Exception as e:
                self.logger.error(f"Error in heuristic monitoring: {e}")
                time.sleep(1)
    
    def _simulate_heuristic_detection(self) -> None:
        """Placeholder: Simulate heuristic detection"""
        # This would be replaced with actual detection logic
        import random
        if random.random() < 0.1:  # 10% chance
            event = RiskEvent(
                timestamp=datetime.now(),
                source="HeuristicEngine",
                event_type="SuspiciousProcessBehavior",
                description="Detected rapid file modification pattern",
                risk_score=random.randint(20, 60),
                details={"process": "example.exe", "files_modified": 150}
            )
            self.risk_calculator.add_event(event)
            self.logger.warning(f"Heuristic detection: {event.description}")

# -------------------------------
# Canary File Manager (Placeholder)
# -------------------------------

class CanaryFileManager(HorusComponent):
    """
    Creates and deploys randomized decoy files across sensitive directories,
    monitors them in real-time, and triggers alerts if tampered with.
    
    TODO: Implement canary file creation, deployment strategies,
    real-time monitoring, and alert triggering.
    """
    
    def __init__(self, config: HorusConfig, risk_calculator: RiskCalculator):
        super().__init__("CanaryFileManager", config, risk_calculator)
        
        # Placeholder for canary management data
        self.deployed_canaries = []
        self.file_observers = []
        self.canary_templates = {}
    
    def _run(self) -> None:
        """Main canary monitoring loop"""
        self.logger.info("Canary File Manager started - monitoring decoy files")
        
        # TODO: Deploy initial canary files
        self._deploy_canaries()
        
        while self.running:
            try:
                # TODO: Implement canary monitoring
                # - Monitor canary file access/modification
                # - Refresh canary files periodically
                # - Detect canary file tampering
                # - Generate high-priority alerts for canary triggers
                
                # Placeholder: Check canary file integrity
                self._check_canary_integrity()
                
                time.sleep(self.config.scan_interval)
                
            except Exception as e:
                self.logger.error(f"Error in canary monitoring: {e}")
                time.sleep(1)
    
    def _deploy_canaries(self) -> None:
        """Placeholder: Deploy canary files"""
        # TODO: Implement canary deployment
        self.logger.info("Deploying canary files...")
        pass
    
    def _check_canary_integrity(self) -> None:
        """Placeholder: Check canary file integrity"""
        # TODO: Implement canary integrity checking
        pass

# -------------------------------
# Decision Engine
# -------------------------------

class DecisionEngine(HorusComponent):
    """
    Evaluates risk scores from heuristics and canaries to decide 
    when and how to initiate mitigation actions.
    """
    
    def __init__(self, config: HorusConfig, risk_calculator: RiskCalculator):
        super().__init__("DecisionEngine", config, risk_calculator)
        self.last_threat_level = ThreatLevel.LOW
        self.mitigation_actions = []
    
    def _run(self) -> None:
        """Main decision engine loop"""
        self.logger.info("Decision Engine started - monitoring threat levels")
        
        while self.running:
            try:
                current_threat = self.risk_calculator.get_threat_level()
                current_risk = self.risk_calculator.calculate_current_risk()
                
                # Check if threat level has escalated
                if current_threat.value > self.last_threat_level.value:
                    self._handle_threat_escalation(current_threat, current_risk)
                elif current_threat.value < self.last_threat_level.value:
                    self._handle_threat_de_escalation(current_threat, current_risk)
                
                self.last_threat_level = current_threat
                time.sleep(2)  # Check more frequently than other components
                
            except Exception as e:
                self.logger.error(f"Error in decision engine: {e}")
                time.sleep(1)
    
    def _handle_threat_escalation(self, threat_level: ThreatLevel, risk_score: int) -> None:
        """Handle threat level escalation"""
        self.logger.warning(f"Threat escalated to {threat_level.name} (Risk: {risk_score})")
        
        # TODO: Implement mitigation decisions based on threat level
        if threat_level == ThreatLevel.CRITICAL:
            self._initiate_emergency_response()
        elif threat_level == ThreatLevel.HIGH:
            self._initiate_high_threat_response()
        elif threat_level == ThreatLevel.MEDIUM:
            self._initiate_medium_threat_response()
    
    def _handle_threat_de_escalation(self, threat_level: ThreatLevel, risk_score: int) -> None:
        """Handle threat level de-escalation"""
        self.logger.info(f"Threat de-escalated to {threat_level.name} (Risk: {risk_score})")
    
    def _initiate_emergency_response(self) -> None:
        """Initiate emergency response for critical threats"""
        self.logger.critical("EMERGENCY RESPONSE INITIATED - CRITICAL THREAT DETECTED")
        # TODO: Implement emergency response actions
    
    def _initiate_high_threat_response(self) -> None:
        """Initiate response for high threats"""
        self.logger.error("HIGH THREAT RESPONSE INITIATED")
        # TODO: Implement high threat response actions
    
    def _initiate_medium_threat_response(self) -> None:
        """Initiate response for medium threats"""
        self.logger.warning("MEDIUM THREAT RESPONSE INITIATED")
        # TODO: Implement medium threat response actions

# -------------------------------
# Mitigation Layer (Placeholder)
# -------------------------------

class MitigationLayer(HorusComponent):
    """
    Responds to detected ransomware by isolating processes, quarantining files,
    locking directories, and rolling back affected files when possible.
    
    TODO: Implement process isolation, file quarantine, directory protection,
    and file rollback capabilities.
    """
    
    def __init__(self, config: HorusConfig, risk_calculator: RiskCalculator):
        super().__init__("MitigationLayer", config, risk_calculator)
        self.quarantine_directory = Path("./horus_quarantine")
        self.quarantine_directory.mkdir(exist_ok=True)
        
    def _run(self) -> None:
        """Main mitigation monitoring loop"""
        self.logger.info("Mitigation Layer started - ready to respond to threats")
        
        while self.running:
            try:
                # TODO: Listen for mitigation requests from Decision Engine
                # TODO: Implement mitigation actions
                time.sleep(self.config.scan_interval)
                
            except Exception as e:
                self.logger.error(f"Error in mitigation layer: {e}")
                time.sleep(1)
    
    def isolate_process(self, process_id: int) -> bool:
        """Isolate suspicious process"""
        # TODO: Implement process isolation
        self.logger.warning(f"Process isolation requested for PID: {process_id}")
        return False
    
    def quarantine_file(self, file_path: str) -> bool:
        """Quarantine suspicious file"""
        # TODO: Implement file quarantine
        self.logger.warning(f"File quarantine requested for: {file_path}")
        return False
    
    def lock_directory(self, directory_path: str) -> bool:
        """Lock directory to prevent modifications"""
        # TODO: Implement directory locking
        self.logger.warning(f"Directory lock requested for: {directory_path}")
        return False

# -------------------------------
# ClamAV Integration (Placeholder)
# -------------------------------

class ClamAVIntegration(HorusComponent):
    """
    Provides signature-based malware detection to complement 
    heuristics and canaries.
    
    TODO: Implement ClamAV integration, signature updates,
    and scan scheduling.
    """
    
    def __init__(self, config: HorusConfig, risk_calculator: RiskCalculator):
        super().__init__("ClamAVIntegration", config, risk_calculator)
        self.clamav_available = False
        
    def _run(self) -> None:
        """Main ClamAV monitoring loop"""
        if not self._check_clamav_availability():
            self.logger.warning("ClamAV not available - signature scanning disabled")
            return
            
        self.logger.info("ClamAV Integration started - signature-based scanning active")
        
        while self.running:
            try:
                # TODO: Implement periodic scanning with ClamAV
                # TODO: Update virus signatures
                # TODO: Scan suspicious files identified by other components
                
                time.sleep(self.config.scan_interval * 10)  # Less frequent scanning
                
            except Exception as e:
                self.logger.error(f"Error in ClamAV integration: {e}")
                time.sleep(1)
    
    def _check_clamav_availability(self) -> bool:
        """Check if ClamAV is available"""
        # TODO: Implement ClamAV availability check
        return False
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan file with ClamAV"""
        # TODO: Implement file scanning
        return {"clean": True, "threat": None}

# -------------------------------
# Main HORUS System
# -------------------------------

class HorusSystem:
    """Main HORUS ransomware protection system"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.logger = self._setup_logging()
        self.status = SystemStatus.STOPPED
        
        # Initialize core systems
        self.risk_calculator = RiskCalculator(self.config)
        
        # Initialize components
        self.components = []
        
        if self.config.enable_heuristic_engine:
            self.components.append(HeuristicEngine(self.config, self.risk_calculator))
        
        if self.config.enable_canary_manager:
            self.components.append(CanaryFileManager(self.config, self.risk_calculator))
            
        self.components.append(DecisionEngine(self.config, self.risk_calculator))
        self.components.append(MitigationLayer(self.config, self.risk_calculator))
        
        if self.config.enable_clamav_integration:
            self.components.append(ClamAVIntegration(self.config, self.risk_calculator))
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_config(self, config_file: Optional[str]) -> HorusConfig:
        """Load configuration from file or use defaults"""
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
                return HorusConfig(**config_data)
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
        
        return HorusConfig()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup main system logging"""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.log_file),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger("HORUS.System")
    
    def start(self) -> bool:
        """Start the HORUS system"""
        if self.status != SystemStatus.STOPPED:
            self.logger.warning("System is not in stopped state")
            return False
        
        self.status = SystemStatus.STARTING
        self.logger.info("Starting HORUS Ransomware Protection System...")
        
        # Start all components
        failed_components = []
        for component in self.components:
            if not component.start():
                failed_components.append(component.name)
        
        if failed_components:
            self.logger.error(f"Failed to start components: {failed_components}")
            self.status = SystemStatus.ERROR
            return False
        
        self.status = SystemStatus.RUNNING
        self.logger.info("HORUS system started successfully")
        return True
    
    def stop(self) -> None:
        """Stop the HORUS system"""
        if self.status == SystemStatus.STOPPED:
            return
        
        self.status = SystemStatus.STOPPING
        self.logger.info("Stopping HORUS system...")
        
        # Stop all components
        for component in self.components:
            component.stop()
        
        self.status = SystemStatus.STOPPED
        self.logger.info("HORUS system stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get system status"""
        current_risk = self.risk_calculator.calculate_current_risk()
        threat_level = self.risk_calculator.get_threat_level()
        
        return {
            "system_status": self.status.value,
            "current_risk_score": current_risk,
            "threat_level": threat_level.name,
            "components": [comp.get_status() for comp in self.components],
            "recent_events": len(self.risk_calculator.recent_events)
        }
    
    def _signal_handler(self, signum, frame):
        """Handle system signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)

# -------------------------------
# GUI Interface (Optional)
# -------------------------------

class HorusGUI:
    """GUI interface for HORUS system monitoring and control"""
    
    def __init__(self, horus_system: HorusSystem):
        self.horus = horus_system
        self.root = tk.Tk()
        self.root.title("HORUS - Ransomware Protection System")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        self.setup_gui()
        self.update_status_timer()
    
    def setup_gui(self):
        """Setup the GUI layout"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="HORUS Ransomware Protection", 
                               font=("Arial", 18, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="System Control", padding="10")
        control_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.start_btn = ttk.Button(control_frame, text="Start Protection", 
                                   command=self.start_system)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Protection", 
                                  command=self.stop_system, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        
        # Status display
        status_frame = ttk.LabelFrame(main_frame, text="System Status", padding="10")
        status_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(1, weight=1)
        
        ttk.Label(status_frame, text="System Status:").grid(row=0, column=0, sticky=tk.W)
        self.status_label = ttk.Label(status_frame, text="Stopped", foreground="red")
        self.status_label.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(status_frame, text="Threat Level:").grid(row=1, column=0, sticky=tk.W)
        self.threat_label = ttk.Label(status_frame, text="LOW", foreground="green")
        self.threat_label.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(status_frame, text="Risk Score:").grid(row=2, column=0, sticky=tk.W)
        self.risk_label = ttk.Label(status_frame, text="0")
        self.risk_label.grid(row=2, column=1, sticky=tk.W)
        
        # Component status
        comp_frame = ttk.LabelFrame(main_frame, text="Component Status", padding="10")
        comp_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        comp_frame.columnconfigure(0, weight=1)
        
        self.component_tree = ttk.Treeview(comp_frame, columns=("Status",), show="tree headings")
        self.component_tree.heading("#0", text="Component")
        self.component_tree.heading("Status", text="Status")
        self.component_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Log display
        log_frame = ttk.LabelFrame(main_frame, text="System Log", padding="10")
        log_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    def start_system(self):
        """Start the HORUS system"""
        if self.horus.start():
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            messagebox.showinfo("Success", "HORUS protection started successfully")
        else:
            messagebox.showerror("Error", "Failed to start HORUS protection")
    
    def stop_system(self):
        """Stop the HORUS system"""
        self.horus.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        messagebox.showinfo("Info", "HORUS protection stopped")
    
    def update_status_timer(self):
        """Update status display periodically"""
        self.update_status_display()
        self.root.after(2000, self.update_status_timer)  # Update every 2 seconds
    
    def update_status_display(self):
        """Update the status display"""
        status = self.horus.get_status()
        
        # Update system status
        sys_status = status["system_status"]
        self.status_label.config(text=sys_status)
        
        if sys_status == "Running":
            self.status_label.config(foreground="green")
        elif sys_status == "Error":
            self.status_label.config(foreground="red")
        else:
            self.status_label.config(foreground="orange")
        
        # Update threat level
        threat_level = status["threat_level"]
        self.threat_label.config(text=threat_level)
        
        threat_colors = {
            "LOW": "green",
            "MEDIUM": "orange", 
            "HIGH": "red",
            "CRITICAL": "darkred"
        }
        self.threat_label.config(foreground=threat_colors.get(threat_level, "black"))
        
        # Update risk score
        self.risk_label.config(text=str(status["current_risk_score"]))
        
        # Update component status
        self.component_tree.delete(*self.component_tree.get_children())
        for comp_status in status["components"]:
            status_text = "Running" if comp_status["running"] else "Stopped"
            self.component_tree.insert("", tk.END, text=comp_status["name"], 
                                     values=(status_text,))
    
    def run(self):
        """Run the GUI"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle window closing"""
        if self.horus.status == SystemStatus.RUNNING:
            if messagebox.askyesno("Confirm Exit", "HORUS is running. Stop protection and exit?"):
                self.horus.stop()
                self.root.destroy()
        else:
            self.root.destroy()

# -------------------------------
# Main Entry Point
# -------------------------------

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="HORUS Ransomware Protection System")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--no-gui", action="store_true", help="Run without GUI")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon")
    
    args = parser.parse_args()
    
    # Initialize HORUS system
    horus = HorusSystem(args.config)
    
    if args.daemon:
        # Run as daemon (command-line only)
        print("Starting HORUS in daemon mode...")
        horus.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            horus.stop()
    elif args.no_gui:
        # Run without GUI
        print("Starting HORUS system...")
        horus.start()
        try:
            while True:
                status = horus.get_status()
                print(f"Status: {status['system_status']} | "
                      f"Threat: {status['threat_level']} | "
                      f"Risk: {status['current_risk_score']}")
                time.sleep(10)
        except KeyboardInterrupt:
            horus.stop()
    else:
        # Run with GUI
        gui = HorusGUI(horus)
        gui.run()

if __name__ == "__main__":
    main()