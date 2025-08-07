import sys
import time
import socket
import threading
import subprocess
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pandas as pd
import numpy as np
from scapy.all import *
import psutil
import requests
import json
from datetime import datetime
import logging
import queue
import csv
import os
from collections import defaultdict

# Constants
CONFIG_FILE = 'config.json'
HISTORY_FILE = 'command_history.txt'
LOG_FILE = 'monitoring.log'

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class CyberSecurityMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("ITU Cyber Drill Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f8ff')
        
        # Initialize variables
        self.monitoring = False
        self.monitored_ips = []
        self.attack_data = defaultdict(lambda: defaultdict(int))
        self.packet_counts = defaultdict(int)
        self.telegram_token = ""
        self.telegram_chat_id = ""
        self.command_history = []
        
        # Load config
        self.load_config()
        
        # Load command history
        self.load_history()
        
        # Setup GUI
        self.setup_gui()
        
        # Packet capture thread
        self.packet_queue = queue.Queue()
        self.capture_thread = None
        self.stop_capture = threading.Event()
        
        # Traffic analysis thread
        self.analysis_thread = None
        self.stop_analysis = threading.Event()
        
        # Start background threads
        self.start_background_threads()

    def setup_gui(self):
        # Create main menu
        self.create_menu()
        
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both')
        
        # Dashboard tab
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text='Dashboard')
        
        # Monitoring tab
        self.monitoring_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.monitoring_tab, text='Monitoring')
        
        # Tools tab
        self.tools_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.tools_tab, text='Tools')
        
        # Visualization tab
        self.visualization_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.visualization_tab, text='Visualization')
        
        # Command tab
        self.command_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.command_tab, text='Command Console')
        
        # Setup each tab
        self.setup_dashboard()
        self.setup_monitoring()
        self.setup_tools()
        self.setup_visualization()
        self.setup_command_console()
        
        # Apply blue theme
        self.apply_theme()

    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Ping", command=self.show_ping_dialog)
        tools_menu.add_command(label="Traceroute", command=self.show_traceroute_dialog)
        tools_menu.add_command(label="Port Scan", command=self.show_portscan_dialog)
        tools_menu.add_command(label="Generate Traffic", command=self.show_generate_traffic_dialog)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Attack Statistics", command=self.show_attack_stats)
        view_menu.add_command(label="Network Traffic", command=self.show_network_traffic)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)

    def setup_dashboard(self):
        # Dashboard header
        header_frame = ttk.Frame(self.dashboard_tab)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(header_frame, text="Cyber Security Dashboard", font=('Helvetica', 16, 'bold')).pack(side='left')
        
        # Status indicators
        status_frame = ttk.Frame(self.dashboard_tab)
        status_frame.pack(fill='x', padx=10, pady=10)
        
        self.monitoring_status = ttk.Label(status_frame, text="Monitoring: STOPPED", foreground='red')
        self.monitoring_status.pack(side='left', padx=10)
        
        self.monitored_ips_label = ttk.Label(status_frame, text="Monitored IPs: 0")
        self.monitored_ips_label.pack(side='left', padx=10)
        
        # Quick stats
        stats_frame = ttk.Frame(self.dashboard_tab)
        stats_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Attack summary
        attack_summary_frame = ttk.LabelFrame(stats_frame, text="Attack Summary")
        attack_summary_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        self.http_flood_label = ttk.Label(attack_summary_frame, text="HTTP Floods: 0")
        self.http_flood_label.pack(anchor='w', padx=5, pady=2)
        
        self.https_flood_label = ttk.Label(attack_summary_frame, text="HTTPS Floods: 0")
        self.https_flood_label.pack(anchor='w', padx=5, pady=2)
        
        self.udp_flood_label = ttk.Label(attack_summary_frame, text="UDP Floods: 0")
        self.udp_flood_label.pack(anchor='w', padx=5, pady=2)
        
        self.tcp_flood_label = ttk.Label(attack_summary_frame, text="TCP Floods: 0")
        self.tcp_flood_label.pack(anchor='w', padx=5, pady=2)
        
        # Recent activity
        activity_frame = ttk.LabelFrame(stats_frame, text="Recent Activity")
        activity_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        self.activity_text = tk.Text(activity_frame, height=10, width=50)
        self.activity_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.activity_text.config(state='disabled')
        
        # Quick actions
        actions_frame = ttk.LabelFrame(self.dashboard_tab, text="Quick Actions")
        actions_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(actions_frame, text="Start Monitoring", command=self.start_monitoring).pack(side='left', padx=5)
        ttk.Button(actions_frame, text="Stop Monitoring", command=self.stop_monitoring).pack(side='left', padx=5)
        ttk.Button(actions_frame, text="Add IP", command=self.show_add_ip_dialog).pack(side='left', padx=5)
        ttk.Button(actions_frame, text="Remove IP", command=self.show_remove_ip_dialog).pack(side='left', padx=5)

    def setup_monitoring(self):
        # IP monitoring list
        ip_frame = ttk.LabelFrame(self.monitoring_tab, text="Monitored IP Addresses")
        ip_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.ip_listbox = tk.Listbox(ip_frame, height=10)
        self.ip_listbox.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Packet log
        log_frame = ttk.LabelFrame(self.monitoring_tab, text="Packet Log")
        log_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.packet_log = tk.Text(log_frame, height=15)
        self.packet_log.pack(fill='both', expand=True, padx=5, pady=5)
        self.packet_log.config(state='disabled')
        
        # Controls
        controls_frame = ttk.Frame(self.monitoring_tab)
        controls_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(controls_frame, text="Clear Log", command=self.clear_packet_log).pack(side='left', padx=5)

    def setup_tools(self):
        # Tools notebook
        tools_notebook = ttk.Notebook(self.tools_tab)
        tools_notebook.pack(fill='both', expand=True)
        
        # Ping tool
        ping_frame = ttk.Frame(tools_notebook)
        tools_notebook.add(ping_frame, text="Ping")
        
        ttk.Label(ping_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        self.ping_ip_entry = ttk.Entry(ping_frame)
        self.ping_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(ping_frame, text="Ping", command=self.execute_ping).grid(row=0, column=2, padx=5, pady=5)
        
        self.ping_output = tk.Text(ping_frame, height=10)
        self.ping_output.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky='nsew')
        self.ping_output.config(state='disabled')
        
        # Traceroute tool
        trace_frame = ttk.Frame(tools_notebook)
        tools_notebook.add(trace_frame, text="Traceroute")
        
        ttk.Label(trace_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        self.trace_ip_entry = ttk.Entry(trace_frame)
        self.trace_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(trace_frame, text="Traceroute", command=self.execute_traceroute).grid(row=0, column=2, padx=5, pady=5)
        
        self.trace_output = tk.Text(trace_frame, height=10)
        self.trace_output.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky='nsew')
        self.trace_output.config(state='disabled')
        
        # Port scanner
        portscan_frame = ttk.Frame(tools_notebook)
        tools_notebook.add(portscan_frame, text="Port Scan")
        
        ttk.Label(portscan_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        self.scan_ip_entry = ttk.Entry(portscan_frame)
        self.scan_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(portscan_frame, text="Scan Ports", command=self.execute_port_scan).grid(row=0, column=2, padx=5, pady=5)
        
        self.scan_output = tk.Text(portscan_frame, height=10)
        self.scan_output.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky='nsew')
        self.scan_output.config(state='disabled')

    def setup_visualization(self):
        # Visualization frame
        self.viz_frame = ttk.Frame(self.visualization_tab)
        self.viz_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Controls
        viz_controls = ttk.Frame(self.visualization_tab)
        viz_controls.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(viz_controls, text="Attack Types", command=lambda: self.update_visualization('attack_types')).pack(side='left', padx=5)
        ttk.Button(viz_controls, text="Traffic Volume", command=lambda: self.update_visualization('traffic_volume')).pack(side='left', padx=5)
        ttk.Button(viz_controls, text="Protocol Distribution", command=lambda: self.update_visualization('protocol_dist')).pack(side='left', padx=5)
        
        # Create initial empty plots
        self.create_empty_plots()

    def setup_command_console(self):
        # Command console
        console_frame = ttk.LabelFrame(self.command_tab, text="Command Console")
        console_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.command_output = tk.Text(console_frame, height=15)
        self.command_output.pack(fill='both', expand=True, padx=5, pady=5)
        self.command_output.config(state='disabled')
        
        # Command input
        input_frame = ttk.Frame(console_frame)
        input_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(input_frame, text="Command:").pack(side='left')
        
        self.command_entry = ttk.Entry(input_frame)
        self.command_entry.pack(fill='x', expand=True, side='left', padx=5)
        self.command_entry.bind('<Return>', self.execute_command)
        
        ttk.Button(input_frame, text="Execute", command=self.execute_command).pack(side='left', padx=5)
        
        # History button
        ttk.Button(console_frame, text="Command History", command=self.show_command_history).pack(anchor='e', padx=5, pady=5)

    def apply_theme(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('.', background='#f0f8ff', foreground='black')
        style.configure('TFrame', background='#f0f8ff')
        style.configure('TLabel', background='#f0f8ff', foreground='#003366')
        style.configure('TButton', background='#4682b4', foreground='white')
        style.configure('TEntry', fieldbackground='white')
        style.configure('TNotebook', background='#f0f8ff')
        style.configure('TNotebook.Tab', background='#4682b4', foreground='white')
        style.configure('TLabelFrame', background='#f0f8ff', foreground='#003366')
        
        # Configure selected tab
        style.map('TNotebook.Tab', 
                 background=[('selected', '#003366')],
                 foreground=[('selected', 'white')])

    def create_empty_plots(self):
        # Clear existing plots
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
        
        # Create figure and subplots
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(10, 4))
        self.fig.patch.set_facecolor('#f0f8ff')
        
        # Empty bar chart
        self.ax1.bar([], [])
        self.ax1.set_title('Attack Types')
        self.ax1.set_ylabel('Count')
        
        # Empty pie chart
        self.ax2.pie([], labels=[])
        self.ax2.set_title('Protocol Distribution')
        
        # Embed in Tkinter
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.viz_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill='both', expand=True)

    def update_visualization(self, chart_type):
        if chart_type == 'attack_types':
            self.update_attack_types_chart()
        elif chart_type == 'traffic_volume':
            self.update_traffic_volume_chart()
        elif chart_type == 'protocol_dist':
            self.update_protocol_dist_chart()

    def update_attack_types_chart(self):
        attack_types = ['HTTP Flood', 'HTTPS Flood', 'UDP Flood', 'TCP Flood']
        counts = [
            sum(self.attack_data[ip]['http_flood'] for ip in self.attack_data),
            sum(self.attack_data[ip]['https_flood'] for ip in self.attack_data),
            sum(self.attack_data[ip]['udp_flood'] for ip in self.attack_data),
            sum(self.attack_data[ip]['tcp_flood'] for ip in self.attack_data)
        ]
        
        self.ax1.clear()
        bars = self.ax1.bar(attack_types, counts, color=['#4682b4', '#5f9ea0', '#6495ed', '#7b68ee'])
        self.ax1.set_title('Attack Types')
        self.ax1.set_ylabel('Count')
        
        # Add value labels
        for bar in bars:
            height = bar.get_height()
            self.ax1.text(bar.get_x() + bar.get_width()/2., height,
                         '%d' % int(height),
                         ha='center', va='bottom')
        
        self.canvas.draw()

    def update_traffic_volume_chart(self):
        ips = list(self.packet_counts.keys())
        counts = list(self.packet_counts.values())
        
        self.ax1.clear()
        bars = self.ax1.bar(ips, counts, color='#4682b4')
        self.ax1.set_title('Traffic Volume by IP')
        self.ax1.set_ylabel('Packet Count')
        self.ax1.tick_params(axis='x', rotation=45)
        
        # Add value labels
        for bar in bars:
            height = bar.get_height()
            self.ax1.text(bar.get_x() + bar.get_width()/2., height,
                         '%d' % int(height),
                         ha='center', va='bottom')
        
        self.canvas.draw()

    def update_protocol_dist_chart(self):
        protocols = ['HTTP', 'HTTPS', 'UDP', 'TCP', 'Other']
        counts = [
            sum(1 for ip in self.packet_counts if 'http' in ip.lower()),
            sum(1 for ip in self.packet_counts if 'https' in ip.lower()),
            sum(1 for ip in self.packet_counts if 'udp' in ip.lower()),
            sum(1 for ip in self.packet_counts if 'tcp' in ip.lower()),
            sum(1 for ip in self.packet_counts if not any(p in ip.lower() for p in ['http', 'https', 'udp', 'tcp']))
        ]
        
        self.ax2.clear()
        wedges, texts, autotexts = self.ax2.pie(
            counts, 
            labels=protocols, 
            autopct='%1.1f%%',
            colors=['#4682b4', '#5f9ea0', '#6495ed', '#7b68ee', '#9370db'],
            startangle=90
        )
        self.ax2.set_title('Protocol Distribution')
        
        # Make labels more readable
        for text in texts + autotexts:
            text.set_color('black')
            text.set_fontsize(8)
        
        self.canvas.draw()

    def start_background_threads(self):
        # Packet capture thread
        self.capture_thread = threading.Thread(target=self.packet_capture_loop, daemon=True)
        self.capture_thread.start()
        
        # Traffic analysis thread
        self.analysis_thread = threading.Thread(target=self.traffic_analysis_loop, daemon=True)
        self.analysis_thread.start()

    def packet_capture_loop(self):
        while not self.stop_capture.is_set():
            if self.monitoring and self.monitored_ips:
                try:
                    # Use scapy to capture packets (filter for monitored IPs)
                    packets = sniff(filter=f"host {' or host '.join(self.monitored_ips)}", count=10, timeout=1)
                    
                    for packet in packets:
                        self.packet_queue.put(packet)
                        self.packet_counts[packet[IP].src] += 1
                        
                        # Update packet log
                        packet_info = f"{datetime.now()} - {packet[IP].src} -> {packet[IP].dst} {packet.sport}->{packet.dport} {packet.__class__.__name__}\n"
                        self.update_packet_log(packet_info)
                except Exception as e:
                    logging.error(f"Packet capture error: {e}")
            
            time.sleep(0.1)

    def traffic_analysis_loop(self):
        while not self.stop_analysis.is_set():
            if not self.packet_queue.empty():
                packet = self.packet_queue.get()
                
                try:
                    # Analyze packet for flood attacks
                    if packet.haslayer(TCP):
                        if packet[TCP].dport == 80:
                            # Check for HTTP flood
                            if self.detect_http_flood(packet):
                                self.attack_data[packet[IP].src]['http_flood'] += 1
                                self.log_attack(packet[IP].src, "HTTP Flood")
                        
                        elif packet[TCP].dport == 443:
                            # Check for HTTPS flood
                            if self.detect_https_flood(packet):
                                self.attack_data[packet[IP].src]['https_flood'] += 1
                                self.log_attack(packet[IP].src, "HTTPS Flood")
                        
                        # Check for TCP flood
                        if self.detect_tcp_flood(packet):
                            self.attack_data[packet[IP].src]['tcp_flood'] += 1
                            self.log_attack(packet[IP].src, "TCP Flood")
                    
                    elif packet.haslayer(UDP):
                        # Check for UDP flood
                        if self.detect_udp_flood(packet):
                            self.attack_data[packet[IP].src]['udp_flood'] += 1
                            self.log_attack(packet[IP].src, "UDP Flood")
                
                except Exception as e:
                    logging.error(f"Traffic analysis error: {e}")
            
            # Update dashboard stats periodically
            self.update_dashboard_stats()
            time.sleep(1)

    def detect_http_flood(self, packet):
        # Simple threshold-based detection (in a real tool, this would be more sophisticated)
        src_ip = packet[IP].src
        http_count = sum(1 for p in self.packet_queue.queue if p.haslayer(TCP) and p[TCP].dport == 80 and p[IP].src == src_ip)
        return http_count > 100  # Threshold of 100 HTTP packets

    def detect_https_flood(self, packet):
        # Similar to HTTP flood detection
        src_ip = packet[IP].src
        https_count = sum(1 for p in self.packet_queue.queue if p.haslayer(TCP) and p[TCP].dport == 443 and p[IP].src == src_ip)
        return https_count > 100

    def detect_tcp_flood(self, packet):
        src_ip = packet[IP].src
        tcp_count = sum(1 for p in self.packet_queue.queue if p.haslayer(TCP) and p[IP].src == src_ip)
        return tcp_count > 500  # Higher threshold for general TCP

    def detect_udp_flood(self, packet):
        src_ip = packet[IP].src
        udp_count = sum(1 for p in self.packet_queue.queue if p.haslayer(UDP) and p[IP].src == src_ip)
        return udp_count > 500

    def log_attack(self, ip, attack_type):
        log_msg = f"{datetime.now()} - ATTACK DETECTED: {attack_type} from {ip}\n"
        logging.warning(log_msg)
        
        # Update activity log
        self.activity_text.config(state='normal')
        self.activity_text.insert('end', log_msg)
        self.activity_text.see('end')
        self.activity_text.config(state='disabled')
        
        # Send Telegram alert if configured
        if self.telegram_token and self.telegram_chat_id:
            self.send_telegram_alert(f"🚨 ATTACK DETECTED: {attack_type} from {ip}")

    def update_dashboard_stats(self):
        # Update monitoring status
        status_text = "Monitoring: RUNNING" if self.monitoring else "Monitoring: STOPPED"
        status_color = 'green' if self.monitoring else 'red'
        self.monitoring_status.config(text=status_text, foreground=status_color)
        
        # Update monitored IPs count
        self.monitored_ips_label.config(text=f"Monitored IPs: {len(self.monitored_ips)}")
        
        # Update attack counts
        http_floods = sum(self.attack_data[ip]['http_flood'] for ip in self.attack_data)
        https_floods = sum(self.attack_data[ip]['https_flood'] for ip in self.attack_data)
        udp_floods = sum(self.attack_data[ip]['udp_flood'] for ip in self.attack_data)
        tcp_floods = sum(self.attack_data[ip]['tcp_flood'] for ip in self.attack_data)
        
        self.http_flood_label.config(text=f"HTTP Floods: {http_floods}")
        self.https_flood_label.config(text=f"HTTPS Floods: {https_floods}")
        self.udp_flood_label.config(text=f"UDP Floods: {udp_floods}")
        self.tcp_flood_label.config(text=f"TCP Floods: {tcp_floods}")

    def update_packet_log(self, text):
        self.packet_log.config(state='normal')
        self.packet_log.insert('end', text)
        self.packet_log.see('end')
        self.packet_log.config(state='disabled')

    def clear_packet_log(self):
        self.packet_log.config(state='normal')
        self.packet_log.delete('1.0', 'end')
        self.packet_log.config(state='disabled')

    def start_monitoring(self):
        if not self.monitored_ips:
            messagebox.showwarning("Warning", "No IP addresses to monitor. Please add IPs first.")
            return
        
        self.monitoring = True
        logging.info("Monitoring started")
        self.update_dashboard_stats()
        self.add_to_command_history("start monitoring")

    def stop_monitoring(self):
        self.monitoring = False
        logging.info("Monitoring stopped")
        self.update_dashboard_stats()
        self.add_to_command_history("stop")

    def add_ip_to_monitor(self, ip):
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return False
        
        if ip in self.monitored_ips:
            messagebox.showwarning("Warning", "IP address is already being monitored")
            return False
        
        self.monitored_ips.append(ip)
        self.ip_listbox.insert('end', ip)
        logging.info(f"Added IP to monitor: {ip}")
        self.update_dashboard_stats()
        self.add_to_command_history(f"add ip {ip}")
        return True

    def remove_ip_from_monitor(self, ip):
        if ip not in self.monitored_ips:
            messagebox.showwarning("Warning", "IP address is not being monitored")
            return False
        
        index = self.monitored_ips.index(ip)
        self.monitored_ips.remove(ip)
        self.ip_listbox.delete(index)
        logging.info(f"Removed IP from monitoring: {ip}")
        self.update_dashboard_stats()
        self.add_to_command_history(f"remove ip {ip}")
        return True

    def validate_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def execute_ping(self, ip=None):
        if not ip:
            ip = self.ping_ip_entry.get()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address")
                return
        
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        try:
            # Windows: '-n 4', Linux/Mac: '-c 4'
            param = '-n' if sys.platform.lower() == 'win32' else '-c'
            command = ['ping', param, '4', ip]
            
            self.ping_output.config(state='normal')
            self.ping_output.delete('1.0', 'end')
            self.ping_output.insert('end', f"Pinging {ip}...\n\n")
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Read output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.ping_output.insert('end', output)
                    self.ping_output.see('end')
            
            self.ping_output.config(state='disabled')
            self.add_to_command_history(f"ping {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Ping failed: {e}")

    def execute_traceroute(self, ip=None, protocol='icmp'):
        if not ip:
            ip = self.trace_ip_entry.get()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address")
                return
        
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        try:
            self.trace_output.config(state='normal')
            self.trace_output.delete('1.0', 'end')
            self.trace_output.insert('end', f"Traceroute to {ip} using {protocol.upper()}...\n\n")
            
            if protocol == 'icmp':
                # Standard traceroute
                param = '-d' if sys.platform.lower() == 'win32' else ''
                command = ['tracert', param, ip] if sys.platform.lower() == 'win32' else ['traceroute', ip]
            elif protocol == 'udp':
                command = ['traceroute', '-U', ip]
            elif protocol == 'tcp':
                command = ['traceroute', '-T', ip]
            else:
                messagebox.showerror("Error", "Invalid protocol for traceroute")
                return
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Read output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.trace_output.insert('end', output)
                    self.trace_output.see('end')
            
            self.trace_output.config(state='disabled')
            self.add_to_command_history(f"{protocol}traceroute {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Traceroute failed: {e}")

    def execute_port_scan(self, ip=None):
        if not ip:
            ip = self.scan_ip_entry.get()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address")
                return
        
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        try:
            self.scan_output.config(state='normal')
            self.scan_output.delete('1.0', 'end')
            self.scan_output.insert('end', f"Scanning ports 1-65535 on {ip}...\nThis may take several minutes.\n\n")
            
            # Simple port scan implementation (in a real tool, use nmap or similar)
            open_ports = []
            
            def scan_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        result = s.connect_ex((ip, port))
                        if result == 0:
                            open_ports.append(port)
                            self.scan_output.insert('end', f"Port {port} is open\n")
                            self.scan_output.see('end')
                except:
                    pass
            
            # Scan common ports first
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
            
            for port in common_ports:
                scan_port(port)
                self.root.update()  # Keep GUI responsive
            
            # Scan remaining ports in batches
            for start in range(1, 65536, 100):
                end = min(start + 99, 65535)
                threads = []
                
                for port in range(start, end + 1):
                    if port not in common_ports:
                        t = threading.Thread(target=scan_port, args=(port,))
                        threads.append(t)
                        t.start()
                
                for t in threads:
                    t.join()
                
                self.root.update()  # Keep GUI responsive
            
            self.scan_output.insert('end', f"\nScan complete. Found {len(open_ports)} open ports.\n")
            self.scan_output.config(state='disabled')
            self.add_to_command_history(f"scan {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Port scan failed: {e}")

    def generate_traffic(self, ip, traffic_type, duration):
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        try:
            duration = int(duration)
            if duration <= 0:
                messagebox.showerror("Error", "Duration must be positive")
                return
            
            self.add_to_command_history(f"generate traffic {ip} {traffic_type} {duration}")
            
            if traffic_type.lower() == 'http':
                self.generate_http_traffic(ip, duration)
            elif traffic_type.lower() == 'https':
                self.generate_https_traffic(ip, duration)
            elif traffic_type.lower() == 'udp':
                self.generate_udp_traffic(ip, duration)
            elif traffic_type.lower() == 'tcp':
                self.generate_tcp_traffic(ip, duration)
            else:
                messagebox.showerror("Error", "Invalid traffic type")
        except ValueError:
            messagebox.showerror("Error", "Duration must be a number")
        except Exception as e:
            messagebox.showerror("Error", f"Traffic generation failed: {e}")

    def generate_http_traffic(self, ip, duration):
        end_time = time.time() + duration
        url = f"http://{ip}"
        
        def worker():
            while time.time() < end_time:
                try:
                    requests.get(url, timeout=1)
                except:
                    pass
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        
        messagebox.showinfo("Info", f"Generating HTTP traffic to {ip} for {duration} seconds")

    def generate_https_traffic(self, ip, duration):
        end_time = time.time() + duration
        url = f"https://{ip}"
        
        def worker():
            while time.time() < end_time:
                try:
                    requests.get(url, timeout=1, verify=False)
                except:
                    pass
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        
        messagebox.showinfo("Info", f"Generating HTTPS traffic to {ip} for {duration} seconds")

    def generate_udp_traffic(self, ip, duration):
        end_time = time.time() + duration
        port = 53  # DNS port
        
        def worker():
            while time.time() < end_time:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(b'test', (ip, port))
                except:
                    pass
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        
        messagebox.showinfo("Info", f"Generating UDP traffic to {ip}:{port} for {duration} seconds")

    def generate_tcp_traffic(self, ip, duration):
        end_time = time.time() + duration
        port = 80  # HTTP port
        
        def worker():
            while time.time() < end_time:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        s.connect((ip, port))
                        s.send(b'test')
                except:
                    pass
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        
        messagebox.showinfo("Info", f"Generating TCP traffic to {ip}:{port} for {duration} seconds")

    def configure_telegram(self, token, chat_id):
        self.telegram_token = token
        self.telegram_chat_id = chat_id
        self.save_config()
        self.add_to_command_history(f"config telegram token {token}")
        self.add_to_command_history(f"config telegram chat_id {chat_id}")
        messagebox.showinfo("Success", "Telegram configuration saved")

    def test_telegram(self):
        if not self.telegram_token or not self.telegram_chat_id:
            messagebox.showerror("Error", "Telegram token or chat ID not configured")
            return
        
        try:
            self.send_telegram_alert("Test message from Cyber Security Monitor")
            messagebox.showinfo("Success", "Test message sent to Telegram")
            self.add_to_command_history("test telegram")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send Telegram message: {e}")

    def send_telegram_alert(self, message):
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        params = {
            'chat_id': self.telegram_chat_id,
            'text': message
        }
        requests.post(url, params=params)

    def export_data_to_telegram(self):
        if not self.telegram_token or not self.telegram_chat_id:
            messagebox.showerror("Error", "Telegram token or chat ID not configured")
            return
        
        try:
            # Prepare summary data
            summary = "Cyber Security Monitor - Attack Summary\n\n"
            summary += f"HTTP Floods: {sum(self.attack_data[ip]['http_flood'] for ip in self.attack_data)}\n"
            summary += f"HTTPS Floods: {sum(self.attack_data[ip]['https_flood'] for ip in self.attack_data)}\n"
            summary += f"UDP Floods: {sum(self.attack_data[ip]['udp_flood'] for ip in self.attack_data)}\n"
            summary += f"TCP Floods: {sum(self.attack_data[ip]['tcp_flood'] for ip in self.attack_data)}\n"
            
            self.send_telegram_alert(summary)
            messagebox.showinfo("Success", "Data exported to Telegram")
            self.add_to_command_history("export data to telegram")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data to Telegram: {e}")

    def export_data(self):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
            )
            
            if file_path:
                with open(file_path, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['IP', 'HTTP Flood', 'HTTPS Flood', 'UDP Flood', 'TCP Flood'])
                    
                    for ip in self.attack_data:
                        writer.writerow([
                            ip,
                            self.attack_data[ip]['http_flood'],
                            self.attack_data[ip]['https_flood'],
                            self.attack_data[ip]['udp_flood'],
                            self.attack_data[ip]['tcp_flood']
                        ])
                
                messagebox.showinfo("Success", f"Data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {e}")

    def execute_command(self, event=None):
        command = self.command_entry.get()
        if not command:
            return
        
        self.command_entry.delete(0, 'end')
        self.add_to_command_history(command)
        
        # Process command
        parts = command.lower().split()
        self.command_output.config(state='normal')
        self.command_output.insert('end', f"> {command}\n")
        
        try:
            if parts[0] == 'help':
                self.show_help()
                self.command_output.insert('end', "Displayed help dialog\n")
            
            elif parts[0] == 'ping' and len(parts) > 1:
                self.execute_ping(parts[1])
                self.command_output.insert('end', f"Ping executed for {parts[1]}\n")
            
            elif parts[0] == 'start' and parts[1] == 'monitoring':
                if len(parts) > 2:
                    if self.add_ip_to_monitor(parts[2]):
                        self.start_monitoring()
                else:
                    self.start_monitoring()
                self.command_output.insert('end', "Monitoring started\n")
            
            elif parts[0] == 'stop':
                self.stop_monitoring()
                self.command_output.insert('end', "Monitoring stopped\n")
            
            elif parts[0] == 'view':
                if len(parts) > 1 and parts[1] == 'attacks':
                    self.update_visualization('attack_types')
                    self.command_output.insert('end', "Displayed attack statistics\n")
                elif len(parts) > 1 and parts[1] == 'traffic':
                    self.update_visualization('traffic_volume')
                    self.command_output.insert('end', "Displayed traffic volume\n")
                else:
                    self.command_output.insert('end', "Invalid view command. Use 'view attacks' or 'view traffic'\n")
            
            elif parts[0] == 'add' and parts[1] == 'ip' and len(parts) > 2:
                if self.add_ip_to_monitor(parts[2]):
                    self.command_output.insert('end', f"Added IP {parts[2]} to monitoring\n")
            
            elif parts[0] == 'remove' and parts[1] == 'ip' and len(parts) > 2:
                if self.remove_ip_from_monitor(parts[2]):
                    self.command_output.insert('end', f"Removed IP {parts[2]} from monitoring\n")
            
            elif parts[0] == 'udptraceroute' and len(parts) > 1:
                self.execute_traceroute(parts[1], 'udp')
                self.command_output.insert('end', f"UDP traceroute executed for {parts[1]}\n")
            
            elif parts[0] == 'tcptraceroute' and len(parts) > 1:
                self.execute_traceroute(parts[1], 'tcp')
                self.command_output.insert('end', f"TCP traceroute executed for {parts[1]}\n")
            
            elif parts[0] == 'traceroute' and len(parts) > 1:
                self.execute_traceroute(parts[1], 'icmp')
                self.command_output.insert('end', f"ICMP traceroute executed for {parts[1]}\n")
            
            elif parts[0] == 'config' and parts[1] == 'telegram':
                if len(parts) > 3 and parts[2] == 'token':
                    self.telegram_token = parts[3]
                    self.save_config()
                    self.command_output.insert('end', "Telegram token configured\n")
                elif len(parts) > 3 and parts[2] == 'chat_id':
                    self.telegram_chat_id = parts[3]
                    self.save_config()
                    self.command_output.insert('end', "Telegram chat ID configured\n")
                else:
                    self.command_output.insert('end', "Invalid config command. Use 'config telegram token <token>' or 'config telegram chat_id <chat_id>'\n")
            
            elif parts[0] == 'test' and parts[1] == 'telegram':
                self.test_telegram()
                self.command_output.insert('end', "Test Telegram message sent\n")
            
            elif parts[0] == 'export' and parts[1] == 'data' and parts[2] == 'to' and parts[3] == 'telegram':
                self.export_data_to_telegram()
                self.command_output.insert('end', "Data exported to Telegram\n")
            
            elif parts[0] == 'history':
                self.show_command_history()
                self.command_output.insert('end', "Displayed command history\n")
            
            elif parts[0] == 'scan' and len(parts) > 1:
                self.execute_port_scan(parts[1])
                self.command_output.insert('end', f"Port scan executed for {parts[1]}\n")
            
            elif parts[0] == 'generate' and parts[1] == 'traffic' and len(parts) > 4:
                self.generate_traffic(parts[2], parts[3], parts[4])
                self.command_output.insert('end', f"Generated {parts[3]} traffic to {parts[2]} for {parts[4]} seconds\n")
            
            else:
                self.command_output.insert('end', f"Unknown command: {command}\nType 'help' for available commands\n")
        
        except IndexError:
            self.command_output.insert('end', "Invalid command format. Type 'help' for usage\n")
        
        self.command_output.see('end')
        self.command_output.config(state='disabled')

    def show_command_history(self):
        history_window = tk.Toplevel(self.root)
        history_window.title("Command History")
        history_window.geometry("600x400")
        
        text = tk.Text(history_window)
        text.pack(fill='both', expand=True, padx=10, pady=10)
        
        text.insert('end', "\n".join(self.command_history))
        text.config(state='disabled')

    def add_to_command_history(self, command):
        self.command_history.append(command)
        with open(HISTORY_FILE, 'a') as f:
            f.write(f"{datetime.now()} - {command}\n")

    def load_history(self):
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, 'r') as f:
                    self.command_history = [line.strip() for line in f.readlines()]
        except:
            pass

    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.telegram_token = config.get('telegram_token', '')
                    self.telegram_chat_id = config.get('telegram_chat_id', '')
                    self.monitored_ips = config.get('monitored_ips', [])
                    
                    # Update IP listbox
                    for ip in self.monitored_ips:
                        self.ip_listbox.insert('end', ip)
        except:
            pass

    def save_config(self):
        try:
            config = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'monitored_ips': self.monitored_ips
            }
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")

    def show_add_ip_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add IP Address")
        dialog.geometry("300x150")
        
        ttk.Label(dialog, text="IP Address:").pack(pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(pady=5)
        
        def add_ip():
            ip = ip_entry.get()
            if self.add_ip_to_monitor(ip):
                dialog.destroy()
        
        ttk.Button(dialog, text="Add", command=add_ip).pack(pady=5)

    def show_remove_ip_dialog(self):
        if not self.monitored_ips:
            messagebox.showwarning("Warning", "No IP addresses to remove")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Remove IP Address")
        dialog.geometry("300x150")
        
        ttk.Label(dialog, text="Select IP to remove:").pack(pady=5)
        
        ip_var = tk.StringVar()
        ip_dropdown = ttk.Combobox(dialog, textvariable=ip_var, values=self.monitored_ips)
        ip_dropdown.pack(pady=5)
        
        def remove_ip():
            ip = ip_var.get()
            if self.remove_ip_from_monitor(ip):
                dialog.destroy()
        
        ttk.Button(dialog, text="Remove", command=remove_ip).pack(pady=5)

    def show_ping_dialog(self):
        self.notebook.select(self.tools_tab)
        self.notebook.select(0)  # Select ping tab

    def show_traceroute_dialog(self):
        self.notebook.select(self.tools_tab)
        self.notebook.select(1)  # Select traceroute tab

    def show_portscan_dialog(self):
        self.notebook.select(self.tools_tab)
        self.notebook.select(2)  # Select port scan tab

    def show_generate_traffic_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Traffic")
        dialog.geometry("400x250")
        
        ttk.Label(dialog, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Traffic Type:").grid(row=1, column=0, padx=5, pady=5)
        type_var = tk.StringVar()
        type_dropdown = ttk.Combobox(dialog, textvariable=type_var, values=['HTTP', 'HTTPS', 'UDP', 'TCP'])
        type_dropdown.grid(row=1, column=1, padx=5, pady=5)
        type_dropdown.current(0)
        
        ttk.Label(dialog, text="Duration (seconds):").grid(row=2, column=0, padx=5, pady=5)
        duration_entry = ttk.Entry(dialog)
        duration_entry.grid(row=2, column=1, padx=5, pady=5)
        duration_entry.insert(0, "10")
        
        def generate():
            ip = ip_entry.get()
            traffic_type = type_var.get()
            duration = duration_entry.get()
            self.generate_traffic(ip, traffic_type, duration)
            dialog.destroy()
        
        ttk.Button(dialog, text="Generate", command=generate).grid(row=3, column=0, columnspan=2, pady=10)

    def show_attack_stats(self):
        self.notebook.select(self.visualization_tab)
        self.update_visualization('attack_types')

    def show_network_traffic(self):
        self.notebook.select(self.visualization_tab)
        self.update_visualization('traffic_volume')

    def show_help(self):
        help_text = """Cyber Security Monitor - Help

Available Commands:
  help - Show this help message
  ping <ip> - Ping an IP address
  start monitoring [ip] - Start monitoring (optionally add IP)
  stop - Stop monitoring
  view attacks - View attack statistics
  view traffic - View traffic volume
  add ip <ip> - Add IP to monitor
  remove ip <ip> - Remove IP from monitor
  udptraceroute <ip> - UDP traceroute to IP
  tcptraceroute <ip> - TCP traceroute to IP
  traceroute <ip> - ICMP traceroute to IP
  config telegram token <token> - Set Telegram bot token
  config telegram chat_id <id> - Set Telegram chat ID
  test telegram - Test Telegram notification
  export data to telegram - Export data to Telegram
  history - Show command history
  scan <ip> - Scan ports on IP
  generate traffic <ip> <type> <duration> - Generate traffic

Tools:
  Use the Tools menu or tabs for ping, traceroute, and port scanning.
"""
        messagebox.showinfo("Help", help_text)

    def show_about(self):
        about_text = """ITU Cyber Drill Tool
Version 91.0
Email:iancarterkulani@gmail.com
phone:+265(0)988061969

A comprehensive tool for monitoring and analyzing network traffic
to detect various types of flood attacks.

Features:
- Real-time packet capture and analysis
- Detection of HTTP, HTTPS, UDP, and TCP floods
- Visualization of attack statistics
- Network diagnostic tools
- Telegram alert integration
"""
        messagebox.showinfo("About", about_text)

    def on_close(self):
        self.stop_monitoring()
        self.stop_capture.set()
        self.stop_analysis.set()
        
        if self.capture_thread:
            self.capture_thread.join()
        
        if self.analysis_thread:
            self.analysis_thread.join()
        
        self.save_config()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberSecurityMonitor(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()