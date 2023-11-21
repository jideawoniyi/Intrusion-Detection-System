import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, ttk
from tkinter import Toplevel
import json
import os
import re
from datetime import datetime

# Define colors and fonts
SEVERITY_COLORS = {
    'High': '#FF6347',  # Tomato red
    'Medium': '#FFD700',  # Gold
    'Low': '#90EE90'  # Light green
}
BACKGROUND_COLOR = '#FFFFFF'
TEXT_COLOR = '#333333'
FONT_NAME = 'Helvetica'

# Button style parameters
BUTTON_BG = '#0078D7'  # Blue background for buttons
BUTTON_FG = '#FFFFFF'  # White text for buttons
BUTTON_FONT = (FONT_NAME, 10, 'bold')
BUTTON_BORDER = 0
BUTTON_PADX = 10
BUTTON_PADY = 5

# Constants
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
