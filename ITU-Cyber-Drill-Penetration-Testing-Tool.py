import os
import sys
import socket
import time
import threading
import json
import subprocess
from datetime import datetime
from collections import deque
import requests
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Configuration
CONFIG_FILE = "cyberdrill_config.json"
HISTORY_FILE = "command_history.json"
MAX_HISTORY = 100
MONITOR_INTERVAL = 5  # seconds

class CyberDrillTool:
    def __init__(self):
        self.config = self.load_config()
        self.monitored_ips = set()
        self.monitoring_active = False
        self.command_history = deque(maxlen=MAX_HISTORY)
        self.load_history()
        self.packet_counts = {
            'ping_of_death': 0,
            'port_scan': 0,
            'udp_flood': 0,
            'http_flood': 0,
            'other': 0
        }
        self.attack_patterns = {
            'ping_of_death': lambda pkt: ICMP in pkt and len(pkt) > 65535,
            'port_scan': lambda pkt: TCP in pkt and pkt[TCP].flags == 2,  # SYN scan
            'udp_flood': lambda pkt: UDP in pkt and len(pkt) > 1000,
            'http_flood': lambda pkt: TCP in pkt and pkt.dport == 80 and len(pkt) > 1500
        }
        self.sniffer_thread = None
        self.gui = None

    def load_config(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                "telegram_token": "",
                "telegram_chat_id": "",
                "theme": "green_black",
                "monitored_ips": []
            }

    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)

    def load_history(self):
        try:
            with open(HISTORY_FILE, 'r') as f:
                self.command_history = deque(json.load(f), maxlen=MAX_HISTORY)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save_history(self):
        with open(HISTORY_FILE, 'w') as f:
            json.dump(list(self.command_history), f)

    def add_to_history(self, command):
        self.command_history.append(command)
        self.save_history()

    def ping_ip(self, ip):
        try:
            param = '-n' if os.name == 'nt' else '-c'
            output = subprocess.check_output(['ping', param, '4', ip])
            return output.decode('utf-8', errors='ignore')
        except subprocess.CalledProcessError as e:
            return f"Ping failed: {e.output.decode('utf-8', errors='ignore')}"

    def scan_ip(self, ip, ports="1-1024"):
        try:
            command = ['nmap', '-p', ports, ip]
            output = subprocess.check_output(command)
            return output.decode('utf-8', errors='ignore')
        except subprocess.CalledProcessError as e:
            return f"Scan failed: {e.output.decode('utf-8', errors='ignore')}"

    def traceroute(self, ip, protocol='icmp'):
        try:
            if protocol == 'icmp':
                command = ['tracert' if os.name == 'nt' else 'traceroute', ip]
            elif protocol == 'udp':
                command = ['traceroute', '-U', ip]
            elif protocol == 'tcp':
                command = ['traceroute', '-T', ip]
            output = subprocess.check_output(command)
            return output.decode('utf-8', errors='ignore')
        except subprocess.CalledProcessError as e:
            return f"Traceroute failed: {e.output.decode('utf-8', errors='ignore')}"

    def start_monitoring(self, ip):
        if ip not in self.monitored_ips:
            self.monitored_ips.add(ip)
            self.config['monitored_ips'].append(ip)
            self.save_config()
        
        if not self.monitoring_active:
            self.monitoring_active = True
            self.sniffer_thread = threading.Thread(target=self.packet_sniffer)
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()
            return f"Started monitoring {ip} for threats"
        return f"Added {ip} to monitoring list"

    def stop_monitoring(self):
        self.monitoring_active = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2)
        return "Monitoring stopped"

    def packet_sniffer(self):
        def packet_handler(packet):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if src_ip in self.monitored_ips or dst_ip in self.monitored_ips:
                    threat_detected = False
                    for threat_name, pattern_check in self.attack_patterns.items():
                        if pattern_check(packet):
                            self.packet_counts[threat_name] += 1
                            threat_detected = True
                            self.alert_threat(threat_name, src_ip, dst_ip)
                            break
                    
                    if not threat_detected and len(packet) > 1500:  # Generic large packet
                        self.packet_counts['other'] += 1
                        self.alert_threat('other', src_ip, dst_ip)
        
        while self.monitoring_active:
            sniff(prn=packet_handler, count=100, timeout=MONITOR_INTERVAL)
            if self.gui:
                self.gui.update_threat_stats()

    def alert_threat(self, threat_type, src_ip, dst_ip):
        message = f"THREAT DETECTED: {threat_type.upper()} from {src_ip} to {dst_ip} at {datetime.now()}"
        print(message)
        
        # Log to file
        with open("threat_log.txt", "a") as f:
            f.write(message + "\n")
        
        # Send Telegram alert if configured
        if self.config.get('telegram_token') and self.config.get('telegram_chat_id'):
            self.send_telegram_alert(message)

    def send_telegram_alert(self, message):
        url = f"https://api.telegram.org/bot{self.config['telegram_token']}/sendMessage"
        params = {
            'chat_id': self.config['telegram_chat_id'],
            'text': message
        }
        try:
            requests.post(url, params=params)
        except requests.RequestException as e:
            print(f"Failed to send Telegram alert: {e}")

    def test_telegram(self):
        if not self.config.get('telegram_token') or not self.config.get('telegram_chat_id'):
            return "Telegram not configured"
        
        test_msg = "CyberDrill Test Alert - This is a test message"
        self.send_telegram_alert(test_msg)
        return "Test alert sent to Telegram"

    def config_telegram_token(self, token):
        self.config['telegram_token'] = token
        self.save_config()
        return "Telegram token updated"

    def config_telegram_chat_id(self, chat_id):
        self.config['telegram_chat_id'] = chat_id
        self.save_config()
        return "Telegram chat ID updated"

    def remove_ip(self, ip):
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            if ip in self.config['monitored_ips']:
                self.config['monitored_ips'].remove(ip)
                self.save_config()
            return f"Removed {ip} from monitoring"
        return f"{ip} not in monitoring list"

    def view_stats(self):
        stats = "\n".join([f"{k.replace('_', ' ').title()}: {v}" for k, v in self.packet_counts.items()])
        return f"Threat Statistics:\n{stats}"

    def clear_stats(self):
        for key in self.packet_counts:
            self.packet_counts[key] = 0
        return "Threat statistics cleared"

    def run_command(self, command):
        self.add_to_history(command)
        parts = command.split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == "help":
            return self.help()
        elif cmd == "ping" and len(args) == 1:
            return self.ping_ip(args[0])
        elif cmd == "scan" and len(args) == 1:
            return self.scan_ip(args[0])
        elif cmd == "start" and len(args) >= 2 and args[0] == "monitoring":
            return self.start_monitoring(args[1])
        elif cmd == "stop":
            return self.stop_monitoring()
        elif cmd == "test" and len(args) == 1 and args[0] == "telegram":
            return self.test_telegram()
        elif cmd == "config" and len(args) >= 3 and args[0] == "telegram":
            if args[1] == "token":
                return self.config_telegram_token(args[2])
            elif args[1] == "chat_id":
                return self.config_telegram_chat_id(args[2])
        elif cmd == "view":
            return self.view_stats()
        elif cmd == "add" and len(args) == 1 and args[0] == "ip":
            return self.start_monitoring(args[1])
        elif cmd == "exit":
            self.stop_monitoring()
            if self.gui:
                self.gui.root.quit()
            return "Exiting..."
        elif cmd == "clear":
            return self.clear_stats()
        elif cmd == "traceroute" and len(args) == 1:
            return self.traceroute(args[0])
        elif cmd == "udptraceroute" and len(args) == 1:
            return self.traceroute(args[0], 'udp')
        elif cmd == "tcptraceroute" and len(args) == 1:
            return self.traceroute(args[0], 'tcp')
        elif cmd == "remove" and len(args) == 1 and args[0] == "ip":
            return self.remove_ip(args[1])
        elif cmd == "history":
            return "\n".join(self.command_history)
        else:
            return f"Unknown command: {command}"

    def help(self):
        return """Available Commands:
help - Show this help message
ping <ip> - Ping an IP address
scan <ip> - Scan an IP address
start monitoring <ip> - Start monitoring an IP for threats
stop - Stop monitoring
test telegram - Test Telegram alerts
config telegram token <token> - Set Telegram bot token
config telegram chat_id <id> - Set Telegram chat ID
view - View threat statistics
add ip <ip> - Add IP to monitoring
exit - Exit the program
clear - Clear threat statistics
traceroute <ip> - Trace route to IP (ICMP)
udptraceroute <ip> - Trace route using UDP
tcptraceroute <ip> - Trace route using TCP
remove ip <ip> - Remove IP from monitoring
history - View command history
"""

class CyberDrillGUI:
    def __init__(self, tool):
        self.tool = tool
        self.tool.gui = self
        self.root = tk.Tk()
        self.root.title("ITU Cyber Drill PenetrationnTesting Tool")
        self.root.geometry("1200x800")
        self.setup_theme()
        self.create_menu()
        self.create_main_interface()
        self.create_dashboard()
        self.update_threat_stats()

    def setup_theme(self):
        self.root.configure(bg='black')
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('.', background='black', foreground='#00ff00')
        style.configure('TFrame', background='black')
        style.configure('TLabel', background='black', foreground='#00ff00')
        style.configure('TButton', background='#003300', foreground='#00ff00')
        style.configure('TEntry', fieldbackground='#001100', foreground='#00ff00')
        style.configure('TCombobox', fieldbackground='#001100', foreground='#00ff00')
        style.configure('TScrollbar', background='#003300')
        style.configure('Treeview', background='#001100', foreground='#00ff00', fieldbackground='#001100')
        style.map('Treeview', background=[('selected', '#005500')])
        style.configure('TNotebook', background='black', borderwidth=0)
        style.configure('TNotebook.Tab', background='#003300', foreground='#00ff00')
        style.map('TNotebook.Tab', background=[('selected', '#005500')])

    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New", command=self.new_project)
        file_menu.add_command(label="Open", command=self.open_project)
        file_menu.add_command(label="Save", command=self.save_project)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Threat Dashboard", command=self.show_dashboard)
        view_menu.add_command(label="Command Console", command=self.show_console)
        view_menu.add_command(label="Network Map", command=self.show_network_map)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Ping Tool", command=self.open_ping_tool)
        tools_menu.add_command(label="Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="Traceroute", command=self.open_traceroute)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)

    def create_main_interface(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - Command interface
        left_frame = ttk.Frame(main_frame, width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        cmd_label = ttk.Label(left_frame, text="Command Console", font=('Courier', 12, 'bold'))
        cmd_label.pack(pady=5)
        
        self.cmd_entry = ttk.Entry(left_frame)
        self.cmd_entry.pack(fill=tk.X, pady=5)
        self.cmd_entry.bind('<Return>', self.execute_command)
        
        self.output_area = scrolledtext.ScrolledText(
            left_frame, wrap=tk.WORD, width=40, height=20,
            bg='#001100', fg='#00ff00', insertbackground='#00ff00'
        )
        self.output_area.pack(fill=tk.BOTH, expand=True)
        
        # Right panel - Dashboard
        self.right_frame = ttk.Frame(main_frame)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(
            self.root, textvariable=self.status_var,
            relief=tk.SUNKEN, anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")

    def create_dashboard(self):
        for widget in self.right_frame.winfo_children():
            widget.destroy()
        
        # Threat statistics
        stats_frame = ttk.LabelFrame(self.right_frame, text="Threat Statistics")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.threat_labels = {}
        for threat in self.tool.packet_counts:
            frame = ttk.Frame(stats_frame)
            frame.pack(fill=tk.X, padx=5, pady=2)
            
            label = ttk.Label(frame, text=threat.replace('_', ' ').title(), width=15)
            label.pack(side=tk.LEFT)
            
            value = ttk.Label(frame, text="0", width=10)
            value.pack(side=tk.LEFT)
            
            self.threat_labels[threat] = value
        
        # Graph
        graph_frame = ttk.LabelFrame(self.right_frame, text="Threat Activity")
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.figure = plt.Figure(figsize=(6, 4), dpi=100, facecolor='black')
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor('black')
        self.ax.tick_params(axis='x', colors='#00ff00')
        self.ax.tick_params(axis='y', colors='#00ff00')
        
        for spine in self.ax.spines.values():
            spine.set_color('#00ff00')
        
        self.canvas = FigureCanvasTkAgg(self.figure, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Monitored IPs
        ip_frame = ttk.LabelFrame(self.right_frame, text="Monitored IPs")
        ip_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.ip_listbox = tk.Listbox(
            ip_frame, bg='#001100', fg='#00ff00',
            selectbackground='#005500', selectforeground='#00ff00'
        )
        self.ip_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.update_ip_list()

    def update_threat_stats(self):
        for threat, count in self.tool.packet_counts.items():
            self.threat_labels[threat].config(text=str(count))
        
        # Update graph
        self.ax.clear()
        threats = list(self.tool.packet_counts.keys())
        counts = list(self.tool.packet_counts.values())
        
        bars = self.ax.bar(threats, counts, color='#00aa00')
        for bar in bars:
            bar.set_edgecolor('#00ff00')
        
        self.ax.set_title('Threat Distribution', color='#00ff00')
        self.ax.set_ylabel('Count', color='#00ff00')
        
        # Rotate x-axis labels
        plt.setp(self.ax.get_xticklabels(), rotation=45, ha='right')
        
        self.canvas.draw()
        
        if self.tool.monitoring_active:
            self.root.after(5000, self.update_threat_stats)

    def update_ip_list(self):
        self.ip_listbox.delete(0, tk.END)
        for ip in self.tool.monitored_ips:
            self.ip_listbox.insert(tk.END, ip)

    def execute_command(self, event=None):
        command = self.cmd_entry.get()
        self.cmd_entry.delete(0, tk.END)
        
        if not command:
            return
        
        self.output_area.insert(tk.END, f"> {command}\n")
        result = self.tool.run_command(command)
        self.output_area.insert(tk.END, f"{result}\n\n")
        self.output_area.see(tk.END)
        
        # Update UI based on command
        if command.startswith(('start monitoring', 'add ip', 'remove ip')):
            self.update_ip_list()
        elif command == "stop":
            pass  # Monitoring stopped
        elif command == "clear":
            self.update_threat_stats()

    def update_status(self, message):
        self.status_var.set(message)

    # Menu command implementations
    def new_project(self):
        self.tool.stop_monitoring()
        self.tool.monitored_ips.clear()
        self.tool.config['monitored_ips'] = []
        self.tool.save_config()
        self.update_ip_list()
        self.update_status("New project created")

    def open_project(self):
        filename = filedialog.askopenfilename(
            title="Open Project",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*"))
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
                    self.tool.config = data
                    self.tool.save_config()
                    self.tool.monitored_ips = set(data.get('monitored_ips', []))
                    self.update_ip_list()
                    self.update_status(f"Project loaded: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load project: {e}")

    def save_project(self):
        filename = filedialog.asksaveasfilename(
            title="Save Project",
            defaultextension=".json",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*"))
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.tool.config, f, indent=4)
                    self.update_status(f"Project saved: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save project: {e}")

    def show_dashboard(self):
        self.create_dashboard()
        self.update_status("Dashboard view activated")

    def show_console(self):
        self.update_status("Command console focused")

    def show_network_map(self):
        messagebox.showinfo("Info", "Network map feature coming in next version")
        self.update_status("Network map view requested")

    def open_ping_tool(self):
        self.cmd_entry.focus()
        self.update_status("Ping tool - type 'ping <ip>' in command console")

    def open_port_scanner(self):
        self.cmd_entry.focus()
        self.update_status("Port scanner - type 'scan <ip>' in command console")

    def open_traceroute(self):
        self.cmd_entry.focus()
        self.update_status("Traceroute - type 'traceroute <ip>' in command console")

    def open_packet_analyzer(self):
        messagebox.showinfo("Info", "Packet analyzer feature coming in next version")
        self.update_status("Packet analyzer requested")

    def show_docs(self):
        docs = """ITU Cyber Drill Advanced Security Monitor

Features:
- Real-time network threat monitoring
- IP-based security analysis
- Multiple traceroute methods
- Telegram alert integration
- Comprehensive threat statistics

Use the command console or menu items to access all features.
"""
        messagebox.showinfo("Documentation", docs)
        self.update_status("Documentation viewed")

    def show_about(self):
        about = """International Telecommunication Union Cyber Drill Penetration Testing Tool
Ian Carter Kulani
Email:iancarterkulani@gmail.com
phone:+265(0)988061969

Version 87.0

A comprehensive cybersecurity tool for real-time
network monitoring and threat detection.

Designed for international organizations and
security professionals.
"""
        messagebox.showinfo("About ITU Cyber Drill Tool", about)
        self.update_status("About dialog shown")

    def run(self):
        # Start with monitoring if IPs are configured
        if self.tool.config.get('monitored_ips'):
            for ip in self.tool.config['monitored_ips']:
                self.tool.start_monitoring(ip)
        
        self.root.mainloop()

def main():
    tool = CyberDrillTool()
    gui = CyberDrillGUI(tool)
    gui.run()

if __name__ == "__main__":
    main()