"""
Intrusion Detection System (IDS) Application

This application is a desktop GUI developed in Python using the Tkinter library. It monitors and displays network security alerts, categorizing them by severity levels. The UI is styled to resemble a modern MacBook application, with severity level indicators and interactive functionalities.

Global Variables:
    SEVERITY_COLORS (dict): Mapping of severity levels to their corresponding color codes.
    BACKGROUND_COLOR (str): Background color used throughout the application.
    TEXT_COLOR (str): Default text color used in the application.
    FONT_NAME (str): Font name used for text in the application.
    BUTTON_BG (str): Background color for buttons.
    BUTTON_FG (str): Text color for buttons.
    BUTTON_FONT (tuple): Font styling for buttons.
    BUTTON_BORDER (int): Border width for buttons.
    BUTTON_PADX (int): Horizontal padding inside buttons.
    BUTTON_PADY (int): Vertical padding inside buttons.
    ALERT_FILE (str): Path to the JSON file that stores alert data.
    SUSPICIOUS_IPS (list): List of IP addresses considered suspicious.
    LOG_FILE (str): Path to the log file containing network activity records.

Classes:
    IDSApp: Main application class.
        Methods:
            __init__(self, root): Constructor to initialize the Tkinter application.
            setup_menu(self): Sets up the top menu bar.
            setup_status_bar(self): Creates a status bar for displaying messages.
            setup_layout(self): Configures the layout of the main application window.
            style_treeview(self): Applies custom styles to the Treeview widget.
            show_about(self): Displays an 'About' dialog.
            load_alerts(self): Loads and displays alerts from ALERT_FILE.
            add_ip(self): Adds a new suspicious IP address to SUSPICIOUS_IPS.
            validate_ip(self, ip): Validates the format of an IP address.
            run_ids(self): Executes the intrusion detection process.
            is_suspicious(self, line): Checks if a log entry is suspicious.
            log_alert(self, log_entry): Logs an alert to ALERT_FILE.
            determine_severity(self, log_entry): Determines the severity level of an alert.
            on_item_click(self, event): Handles click events on the Treeview.
            display_alert_details(self, severity): Displays details of alerts for a specific severity.
"""

import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, ttk
from tkinter import Toplevel
import json
import os
import re
from datetime import datetime

# Global variable definitions
SEVERITY_COLORS = {
    'High': '#FF6347',  # Tomato red
    'Medium': '#FFD700',  # Gold
    'Low': '#90EE90'  # Light green
}
BACKGROUND_COLOR = '#FFFFFF'
TEXT_COLOR = '#333333'
FONT_NAME = 'Helvetica'
BUTTON_BG = '#0078D7'  # Blue background for buttons
BUTTON_FG = '#FFFFFF'  # White text for buttons
BUTTON_FONT = (FONT_NAME, 10, 'bold')
BUTTON_BORDER = 0
BUTTON_PADX = 10
BUTTON_PADY = 5
ALERT_FILE = 'alerts.json'
SUSPICIOUS_IPS = ['192.168.1.5', '10.0.0.2']
LOG_FILE = 'network.log'

class IDSApp:
    def __init__(self, root):
        self.root = root
        root.title("IDS Dashboard")
        root.configure(bg=BACKGROUND_COLOR)

        self.setup_menu()
        self.setup_status_bar()
        self.setup_layout()
        self.style_treeview()

    def setup_menu(self):
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

    def setup_status_bar(self):
        self.status = tk.StringVar()
        self.status_bar = tk.Label(self.root, textvariable=self.status, bd=1, relief=tk.SUNKEN, anchor=tk.W, bg=BACKGROUND_COLOR, fg=TEXT_COLOR)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status.set("Ready")

    def setup_layout(self):
        main_frame = tk.Frame(self.root, bg=BACKGROUND_COLOR)
        main_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        left_panel = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        right_panel = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
        right_panel.pack(side=tk.RIGHT, fill=tk.Y)

        self.alerts_tree = ttk.Treeview(left_panel)
        self.alerts_tree.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.alerts_tree['columns'] = ('Severity', 'Count')
        self.alerts_tree.column('#0', width=0, stretch=tk.NO)
        self.alerts_tree.column('Severity', anchor=tk.CENTER, width=80)
        self.alerts_tree.column('Count', anchor=tk.CENTER, width=80)

        self.alerts_tree.heading('#0', text='', anchor=tk.CENTER)
        self.alerts_tree.heading('Severity', text='Severity', anchor=tk.CENTER)
        self.alerts_tree.heading('Count', text='Count', anchor=tk.CENTER)

        self.alerts_tree.bind("<Double-1>", self.on_item_click)

        tk.Button(right_panel, text="Load Alerts", command=self.load_alerts, bg=BUTTON_BG, fg=BUTTON_FG, font=BUTTON_FONT, bd=BUTTON_BORDER, padx=BUTTON_PADX, pady=BUTTON_PADY).pack(pady=5)
        tk.Button(right_panel, text="Add Suspicious IP", command=self.add_ip, bg=BUTTON_BG, fg=BUTTON_FG, font=BUTTON_FONT, bd=BUTTON_BORDER, padx=BUTTON_PADX, pady=BUTTON_PADY).pack(pady=5)
        tk.Button(right_panel, text="Run IDS", command=self.run_ids, bg=BUTTON_BG, fg=BUTTON_FG, font=BUTTON_FONT, bd=BUTTON_BORDER, padx=BUTTON_PADX, pady=BUTTON_PADY).pack(pady=5)

    def style_treeview(self):
        style = ttk.Style()
        style.theme_use('default')
        style.configure('Treeview',
                        background=BACKGROUND_COLOR,
                        foreground=TEXT_COLOR,
                        rowheight=25,
                        fieldbackground=BACKGROUND_COLOR)
        style.map('Treeview', background=[('selected', TEXT_COLOR)])
        style.configure('Treeview.Heading', font=(FONT_NAME, 12, 'bold'))

    def show_about(self):
        messagebox.showinfo("About", "IDS Application\nVersion 1.0")

    def load_alerts(self):
        for i in self.alerts_tree.get_children():
            self.alerts_tree.delete(i)

        alerts_by_severity = {'High': 0, 'Medium': 0, 'Low': 0}
        if not os.path.exists(ALERT_FILE):
            self.status.set("No alerts found")
            return

        with open(ALERT_FILE, 'r') as file:
            for line in file:
                alert = json.loads(line)
                severity = alert.get('severity', 'Low')
                alerts_by_severity[severity] += 1

        for severity, count in alerts_by_severity.items():
            self.alerts_tree.insert('', tk.END, text=severity, values=(severity, count))
        self.status.set("Alerts loaded")

    def add_ip(self):
        ip = simpledialog.askstring("Input", "Enter Suspicious IP")
        if ip and self.validate_ip(ip):
            SUSPICIOUS_IPS.append(ip)
            self.status.set(f"Added IP: {ip}")
        else:
            messagebox.showerror("Error", "Invalid IP Address")

    def validate_ip(self, ip):
        return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip) is not None

    def run_ids(self):
        try:
            with open(LOG_FILE, 'r') as file:
                for line in file:
                    if self.is_suspicious(line):
                        self.log_alert(line)
            self.status.set("IDS Run Completed")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run IDS: {e}")
            self.status.set("Error running IDS")

    def is_suspicious(self, line):
        if any(ip in line for ip in SUSPICIOUS_IPS):
            return True
        if any(term in line for term in ["Unauthorized", "Suspicious packet pattern", "Potential DDoS attack"]):
            return True
        return False

    def log_alert(self, log_entry):
        severity = self.determine_severity(log_entry)
        alert_message = f"Suspicious activity detected: {log_entry}"
        try:
            with open(ALERT_FILE, "a") as alert_file:
                alert_data = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'alert': alert_message,
                    'severity': severity
                }
                json.dump(alert_data, alert_file)
                alert_file.write('\n')
        except IOError as e:
            messagebox.showerror("Error", f"Failed to write alert: {e}")

    def determine_severity(self, log_entry):
        if "Unauthorized" in log_entry or "Suspicious packet pattern" in log_entry or \
           "Potential DDoS attack" in log_entry:
            return 'High'
        elif "Login failure" in log_entry or "Connection terminated unexpectedly" in log_entry or \
             "High volume of traffic" in log_entry:
            return 'Medium'
        else:
            return 'Low'

    def on_item_click(self, event):
        item = self.alerts_tree.selection()[0]
        severity = self.alerts_tree.item(item, 'text')
        self.display_alert_details(severity)

    def display_alert_details(self, severity):
        detail_window = Toplevel(self.root)
        detail_window.title(f"Alerts - {severity}")
        detail_text = scrolledtext.ScrolledText(detail_window, font=(FONT_NAME, 10),
                                                fg=SEVERITY_COLORS.get(severity, TEXT_COLOR), bg=BACKGROUND_COLOR)
        detail_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        with open(ALERT_FILE, 'r') as file:
            for line in file:
                alert = json.loads(line)
                if alert.get('severity', 'Low') == severity:
                    detail_text.insert(tk.END, f"{alert['alert']} - Detected at {alert['timestamp']}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()
