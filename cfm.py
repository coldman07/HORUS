import os
import sys
import time
import random
import string
import logging
import json
import csv
from pathlib import Path
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# -------------------------------
# Configuration
# -------------------------------
DEFAULT_CANARY_COUNT = 5
CANARY_PREFIX = "cfm_canary_"
LOG_FILE = "cfm_log.txt"

# -------------------------------
# Logger Setup
# -------------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# -------------------------------
# Realistic Content Generators
# -------------------------------
class ContentGenerator:
    @staticmethod
    def generate_text_content():
        """Generate realistic text document content"""
        templates = [
            "Project Status Report\n\nDate: {date}\nProject: Operation {code}\n\nCurrent Status: In Progress\nTeam Members: {names}\nNext Milestone: {future_date}\n\nConfidential - Internal Use Only",
            "Meeting Notes\n\nDate: {date}\nAttendees: {names}\n\nAction Items:\n- Review quarterly targets\n- Update security protocols\n- Schedule team training\n\nNext Meeting: {future_date}",
            "Financial Summary\n\nReporting Period: {date}\nAccount: {account}\nBalance: ${balance:,.2f}\n\nTransactions:\n- Incoming: ${income:,.2f}\n- Outgoing: ${expenses:,.2f}\n\nNet: ${net:,.2f}",
            "Employee Information\n\nName: {name}\nEmployee ID: {emp_id}\nDepartment: {department}\nHire Date: {date}\nSalary: ${salary:,.2f}\n\nConfidential - HR Use Only",
            "System Configuration\n\nServer: {server_name}\nIP Address: {ip}\nLast Update: {date}\nStatus: Active\n\nCredentials stored in secure vault.\nAccess Level: Administrator"
        ]
        
        template = random.choice(templates)
        names = ["Alice Johnson", "Bob Smith", "Carol Davis", "David Wilson", "Emma Brown"]
        departments = ["Engineering", "Finance", "HR", "Operations", "Security"]
        
        return template.format(
            date=datetime.now().strftime("%Y-%m-%d"),
            future_date=(datetime.now() + timedelta(days=random.randint(7, 30))).strftime("%Y-%m-%d"),
            code=random.choice(["Alpha", "Beta", "Gamma", "Delta", "Sigma"]) + str(random.randint(100, 999)),
            names=", ".join(random.sample(names, 3)),
            name=random.choice(names),
            emp_id=str(random.randint(10000, 99999)),
            department=random.choice(departments),
            account=f"ACC-{random.randint(1000, 9999)}",
            balance=random.uniform(10000, 500000),
            income=random.uniform(5000, 50000),
            expenses=random.uniform(3000, 30000),
            net=random.uniform(-5000, 20000),
            salary=random.uniform(50000, 150000),
            server_name=f"srv-{random.choice(['web', 'db', 'app'])}-{random.randint(1, 10):02d}",
            ip=f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        )
    
    @staticmethod
    def generate_csv_content():
        """Generate realistic CSV data"""
        headers = ["ID", "Name", "Department", "Salary", "Hire_Date", "Status"]
        rows = []
        
        names = ["John Doe", "Jane Smith", "Mike Johnson", "Sarah Wilson", "Tom Brown", "Lisa Davis"]
        departments = ["IT", "Finance", "HR", "Sales", "Marketing", "Operations"]
        
        for i in range(random.randint(10, 20)):
            rows.append([
                str(1000 + i),
                random.choice(names),
                random.choice(departments),
                str(random.randint(45000, 120000)),
                (datetime.now() - timedelta(days=random.randint(30, 1825))).strftime("%Y-%m-%d"),
                random.choice(["Active", "Active", "Active", "On Leave"])
            ])
        
        content = ",".join(headers) + "\n"
        for row in rows:
            content += ",".join(row) + "\n"
        
        return content
    
    @staticmethod
    def generate_json_content():
        """Generate realistic JSON configuration"""
        config_types = [
            {
                "application": "WebServer",
                "version": "2.1.4",
                "database": {
                    "host": f"db-{random.randint(1, 5)}.internal.com",
                    "port": 5432,
                    "name": "prod_db",
                    "ssl": True
                },
                "api_keys": {
                    "service_a": f"sk-{ContentGenerator.random_string(32)}",
                    "service_b": f"pk-{ContentGenerator.random_string(24)}"
                },
                "last_updated": datetime.now().isoformat()
            },
            {
                "user_preferences": {
                    "theme": "dark",
                    "notifications": True,
                    "auto_save": True,
                    "backup_frequency": "daily"
                },
                "security": {
                    "2fa_enabled": True,
                    "session_timeout": 3600,
                    "login_attempts": 3
                },
                "created": datetime.now().isoformat()
            }
        ]
        
        return json.dumps(random.choice(config_types), indent=2)
    
    @staticmethod
    def random_string(length):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# -------------------------------
# Enhanced Canary File Creator
# -------------------------------
class CanaryFileCreator:
    FILE_TYPES = {
        ".txt": ("Text Document", ContentGenerator.generate_text_content),
        ".csv": ("Data Export", ContentGenerator.generate_csv_content),
        ".json": ("Configuration", ContentGenerator.generate_json_content),
        ".log": ("System Log", ContentGenerator.generate_text_content),
        ".conf": ("Config File", ContentGenerator.generate_text_content)
    }
    
    @staticmethod
    def create_realistic_filename(extension, directory):
        """Generate realistic filenames based on file type"""
        base_names = {
            ".txt": ["meeting_notes", "project_summary", "employee_handbook", "security_policy", "budget_report"],
            ".csv": ["employee_data", "sales_report", "customer_list", "inventory", "financial_records"],
            ".json": ["app_config", "user_settings", "api_keys", "database_config", "system_params"],
            ".log": ["system", "application", "security", "access", "error"],
            ".conf": ["server", "database", "security", "backup", "network"]
        }
        
        names = base_names.get(extension, ["document", "file", "data"])
        base_name = random.choice(names)
        
        # Add date or version for realism
        if random.choice([True, False]):
            if extension in [".log"]:
                suffix = datetime.now().strftime("_%Y%m%d")
            else:
                suffix = f"_v{random.randint(1, 5)}"
            base_name += suffix
        
        # Ensure unique filename
        counter = 1
        filename = f"{CANARY_PREFIX}{base_name}{extension}"
        filepath = Path(directory) / filename
        
        while filepath.exists():
            filename = f"{CANARY_PREFIX}{base_name}_{counter}{extension}"
            filepath = Path(directory) / filename
            counter += 1
            
        return filepath
    
    @staticmethod
    def create_canary_file(directory, file_type=None):
        """Create a realistic canary file"""
        if file_type is None:
            file_type = random.choice(list(CanaryFileCreator.FILE_TYPES.keys()))
        
        filepath = CanaryFileCreator.create_realistic_filename(file_type, directory)
        content_generator = CanaryFileCreator.FILE_TYPES[file_type][1]
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content_generator())
            
            logging.info(f"Created canary file: {filepath}")
            return filepath
        except Exception as e:
            logging.error(f"Failed to create canary file {filepath}: {e}")
            return None

# -------------------------------
# Event Handler
# -------------------------------
class CanaryEventHandler(FileSystemEventHandler):
    def __init__(self, canary_files, alert_callback=None):
        self.canary_files = set(str(f) for f in canary_files)
        self.alert_callback = alert_callback
    
    def check_canary(self, event_path, event_type):
        if event_path in self.canary_files:
            alert_msg = f"Canary {event_type}: {event_path}"
            logging.warning(alert_msg)
            
            if self.alert_callback:
                self.alert_callback(alert_msg)
    
    def on_modified(self, event):
        if not event.is_directory:
            self.check_canary(event.src_path, "MODIFIED")
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.check_canary(event.src_path, "DELETED")
    
    def on_moved(self, event):
        if not event.is_directory:
            self.check_canary(event.src_path, "MOVED FROM")
            self.check_canary(event.dest_path, "MOVED TO")

# -------------------------------
# Main GUI Application
# -------------------------------
class CanaryMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Canary File Monitor - Advanced Security Tool")
        self.root.geometry("900x700")
        self.root.minsize(700, 500)
        
        # Variables
        self.monitored_directories = []
        self.canary_files = []
        self.observer = None
        self.monitoring = False
        
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the main GUI layout"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Canary File Monitor", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Directory selection frame
        dir_frame = ttk.LabelFrame(main_frame, text="Directory Selection", padding="10")
        dir_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        dir_frame.columnconfigure(1, weight=1)
        
        ttk.Button(dir_frame, text="Add Directory", command=self.add_directory).grid(row=0, column=0, padx=(0, 10))
        
        self.dir_listbox = tk.Listbox(dir_frame, height=4)
        self.dir_listbox.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Button(dir_frame, text="Remove", command=self.remove_directory).grid(row=0, column=2)
        
        # Canary settings frame
        settings_frame = ttk.LabelFrame(main_frame, text="Canary Settings", padding="10")
        settings_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        settings_frame.columnconfigure(1, weight=1)
        
        ttk.Label(settings_frame, text="Files per directory:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.count_var = tk.StringVar(value=str(DEFAULT_CANARY_COUNT))
        ttk.Entry(settings_frame, textvariable=self.count_var, width=10).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(settings_frame, text="File types:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        
        # File type checkboxes
        self.file_type_vars = {}
        type_frame = ttk.Frame(settings_frame)
        type_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(5, 0))
        
        for i, (ext, (desc, _)) in enumerate(CanaryFileCreator.FILE_TYPES.items()):
            var = tk.BooleanVar(value=True)
            self.file_type_vars[ext] = var
            ttk.Checkbutton(type_frame, text=f"{desc} ({ext})", variable=var).grid(
                row=i//3, column=i%3, sticky=tk.W, padx=(0, 20)
            )
        
        # Control buttons frame
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=3, column=0, columnspan=3, pady=(0, 10))
        
        self.deploy_btn = ttk.Button(control_frame, text="Deploy Canaries", command=self.deploy_canaries)
        self.deploy_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.monitor_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.monitor_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(control_frame, text="Clear Canaries", command=self.clear_canaries).pack(side=tk.LEFT, padx=(0, 10))
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)
        
        self.status_label = ttk.Label(status_frame, text="Ready to deploy canaries")
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        # Alert log frame
        log_frame = ttk.LabelFrame(main_frame, text="Alert Log", padding="10")
        log_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Button(log_frame, text="Clear Log", command=self.clear_log).grid(row=1, column=0, pady=(5, 0))
    
    def add_directory(self):
        """Add a directory to monitor"""
        directory = filedialog.askdirectory(title="Select Directory to Monitor")
        if directory and directory not in self.monitored_directories:
            self.monitored_directories.append(directory)
            self.dir_listbox.insert(tk.END, directory)
            self.update_status(f"Added directory: {directory}")
    
    def remove_directory(self):
        """Remove selected directory"""
        selection = self.dir_listbox.curselection()
        if selection:
            index = selection[0]
            directory = self.monitored_directories[index]
            del self.monitored_directories[index]
            self.dir_listbox.delete(index)
            self.update_status(f"Removed directory: {directory}")
    
    def deploy_canaries(self):
        """Deploy canary files in selected directories"""
        if not self.monitored_directories:
            messagebox.showwarning("No Directories", "Please select at least one directory to monitor.")
            return
        
        try:
            count = int(self.count_var.get())
            if count <= 0:
                raise ValueError("Count must be positive")
        except ValueError:
            messagebox.showerror("Invalid Count", "Please enter a valid positive number for files per directory.")
            return
        
        # Get selected file types
        selected_types = [ext for ext, var in self.file_type_vars.items() if var.get()]
        if not selected_types:
            messagebox.showwarning("No File Types", "Please select at least one file type.")
            return
        
        # Deploy canaries
        self.canary_files = []
        total_created = 0
        
        for directory in self.monitored_directories:
            os.makedirs(directory, exist_ok=True)
            
            for _ in range(count):
                file_type = random.choice(selected_types)
                canary_file = CanaryFileCreator.create_canary_file(directory, file_type)
                if canary_file:
                    self.canary_files.append(canary_file)
                    total_created += 1
        
        self.update_status(f"Deployed {total_created} canary files in {len(self.monitored_directories)} directories")
        self.log_alert(f"Deployed {total_created} canary files")
    
    def toggle_monitoring(self):
        """Start or stop monitoring"""
        if not self.monitoring:
            if not self.canary_files:
                messagebox.showwarning("No Canaries", "Please deploy canary files first.")
                return
            
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start the file system monitoring"""
        try:
            self.observer = Observer()
            event_handler = CanaryEventHandler(self.canary_files, self.log_alert)
            
            for directory in self.monitored_directories:
                self.observer.schedule(event_handler, path=directory, recursive=False)
            
            self.observer.start()
            self.monitoring = True
            self.monitor_btn.config(text="Stop Monitoring")
            self.update_status("Monitoring active - Watching for canary file access")
            self.log_alert("Monitoring started")
            
        except Exception as e:
            messagebox.showerror("Monitoring Error", f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop the file system monitoring"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        
        self.monitoring = False
        self.monitor_btn.config(text="Start Monitoring")
        self.update_status("Monitoring stopped")
        self.log_alert("Monitoring stopped")
    
    def clear_canaries(self):
        """Remove all deployed canary files"""
        if not self.canary_files:
            messagebox.showinfo("No Canaries", "No canary files to clear.")
            return
        
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to remove all canary files?"):
            removed = 0
            for canary_file in self.canary_files:
                try:
                    if Path(canary_file).exists():
                        Path(canary_file).unlink()
                        removed += 1
                except Exception as e:
                    logging.error(f"Failed to remove {canary_file}: {e}")
            
            self.canary_files = []
            self.update_status(f"Removed {removed} canary files")
            self.log_alert(f"Cleared {removed} canary files")
    
    def update_status(self, message):
        """Update the status label"""
        self.status_label.config(text=message)
        self.root.update_idletasks()
    
    def log_alert(self, message):
        """Add message to alert log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def clear_log(self):
        """Clear the alert log"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def on_closing(self):
        """Handle application closing"""
        if self.monitoring:
            self.stop_monitoring()
        self.root.destroy()

# -------------------------------
# Main Application Entry Point
# -------------------------------
def main():
    root = tk.Tk()
    app = CanaryMonitorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()