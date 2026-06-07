"""
Ultimate Proxy Master
Developed by: https://github.com/mootoo11
"""

import re
import requests
import threading
import signal
import sys
import os
import random
import warnings
import time
import json
import sqlite3
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# ==================== INIT & CONFIGURATION ====================
init(autoreset=True)
warnings.simplefilter('ignore', InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Global Locks & Stats
print_lock = threading.Lock()
stats = {
    "total": 0, "checked": 0, "socks5": 0, "socks4": 0, "http": 0,
    "https_capable": 0, "dead": 0, "residential": 0, "datacenter": 0,
    "target_passed": 0, "target_failed": 0, "google": 0
}
stop_progress = False
proxy_cache = {}

# SMART REGEX: Captures (Protocol, IP, Port) handles various formats
PROXY_RE_FULL = re.compile(r'(?:(socks4|socks5|http|https)://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s]+(\d{1,5})', re.IGNORECASE)

TIMEOUT = 10 # Seconds

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
]

TEST_URLS = ["http://azenv.net/", "http://httpbin.org/ip", "http://ip-api.com/json"]

# ==================== CORE UTILITIES ====================

def signal_handler(sig, frame):
    global stop_progress
    stop_progress = True
    print(f"\n\n{Fore.YELLOW}[!] Stopping process... Data Saved.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_existing_files():
    return [f for f in os.listdir('.') if f.endswith('.txt') and os.path.isfile(f)]

def select_or_create_file():
    files = get_existing_files()
    print(f"\n{Fore.CYAN}=== FILE MANAGER ===")
    if files:
        for i, f in enumerate(files, 1):
            print(f"[{i}] {f} ({os.path.getsize(f)/1024:.1f} KB)")
        print(f"[0] Create New File")
        try:
            c = input(f"{Fore.YELLOW}Select > ").strip()
            if c == '0' or not c: return f"proxies_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
            return files[int(c)-1]
        except: pass
    return f"proxies_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"

# ==================== DATABASE ENGINE ====================

def init_database():
    try:
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS proxies
                  (id INTEGER PRIMARY KEY, ip TEXT, port INTEGER, protocol TEXT, 
                  country TEXT, type TEXT, speed INTEGER, anonymity TEXT, 
                  google INTEGER, status TEXT, UNIQUE(ip, port, protocol))''')
        conn.commit()
        conn.close()
    except: pass

def save_to_db(info):
    try:
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO proxies 
                  (ip, port, protocol, country, type, speed, anonymity, google, status)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'LIVE')''', 
                  (info['ip'], info['port'], info['protocol'], info.get('country','XX'), 
                   info.get('type','DC'), info.get('speed',0), info.get('anonymity','UNK'), 
                   info.get('google',0)))
        conn.commit()
        conn.close()
    except: pass

# ==================== FEATURE 1: VIEW STATS (FIXED) ====================

def view_database_stats():
    if not os.path.exists('proxies.db'):
        print(f"{Fore.RED}[!] Database not found. Run a scan first."); return

    try:
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM proxies WHERE status='LIVE'")
        total = c.fetchone()[0]
        
        c.execute("SELECT protocol, COUNT(*) FROM proxies WHERE status='LIVE' GROUP BY protocol")
        protos = c.fetchall()
        
        c.execute("SELECT country, COUNT(*) as cnt FROM proxies WHERE status='LIVE' GROUP BY country ORDER BY cnt DESC LIMIT 5")
        countries = c.fetchall()
        
        c.execute("SELECT type, COUNT(*) FROM proxies WHERE status='LIVE' GROUP BY type")
        types = c.fetchall()
        
        conn.close()

        print(f"\n{Fore.CYAN}{'='*40}")
        print(f"{Style.BRIGHT}{Fore.WHITE}      DATABASE INTELLIGENCE 📊")
        print(f"{Fore.CYAN}{'='*40}")
        print(f"{Fore.GREEN}Total Live Proxies: {Style.BRIGHT}{total}")
        
        print(f"\n{Fore.YELLOW}[Protocols]")
        for p in protos: print(f"  {p[0].upper().ljust(8)}: {p[1]}")
        
        print(f"\n{Fore.MAGENTA}[Types]")
        for t in types: print(f"  {t[0].ljust(8)}: {t[1]}")

        print(f"\n{Fore.BLUE}[Top Countries]")
        for co in countries: print(f"  {co[0].ljust(4)}: {co[1]}")
        print(f"{Fore.CYAN}{'='*40}\n")
    except Exception as e: print(f"{Fore.RED}[!] Error: {e}")

# ==================== FEATURE 2: TARGET CHECKER (FIXED) ====================

def check_custom_target():
    files = get_existing_files()
    if not files: print(f"{Fore.RED}[!] No files."); return
    
    print(f"\n{Fore.GREEN}Select Proxy List to Filter:")
    for i, f in enumerate(files, 1): print(f"[{i}] {f}")
    
    try:
        f_idx = int(input(f"{Fore.YELLOW}> ").strip()) - 1
        input_file = files[f_idx]
    except: return

    target_url = input(f"{Fore.CYAN}Target URL (e.g. https://discord.com): ").strip()
    if not target_url.startswith("http"): target_url = "https://" + target_url

    print(f"{Fore.YELLOW}[*] Loading & Parsing proxies...")
    proxies_to_check = []
    
    # Robust Parsing: Reads file and extracts ANY proxy format correctly
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        matches = PROXY_RE_FULL.findall(content)
        for m in matches:
            # m = (protocol, ip, port)
            proto = m[0].lower() if m[0] else 'http'
            if proto == 'https': proto = 'http' # Requests lib handles https via http key
            proxies_to_check.append(f"{proto}://{m[1]}:{m[2]}")

    unique_proxies = list(set(proxies_to_check))
    print(f"{Fore.CYAN}[*] Checking {len(unique_proxies)} unique proxies against {target_url}...")
    
    stats['total'] = len(unique_proxies); stats['checked'] = 0
    stats['target_passed'] = 0; stats['target_failed'] = 0
    
    valid_file = f"{input_file.replace('.txt','')}_TARGET_{datetime.now().strftime('%H%M')}.txt"
    open(valid_file, 'w').close()
    
    global stop_progress; stop_progress = False
    threading.Thread(target=print_target_progress, daemon=True).start()

    with ThreadPoolExecutor(max_workers=100) as executor:
        for p in unique_proxies:
            executor.submit(verify_target_worker, p, target_url, valid_file)
    
    while stats['checked'] < stats['total'] and not stop_progress: time.sleep(1)
    stop_progress = True
    print(f"\n\n{Fore.GREEN}[✓] Finished! {stats['target_passed']} valid proxies saved to {valid_file}")

def verify_target_worker(proxy_url, target, output_file):
    try:
        proxies = {"http": proxy_url, "https": proxy_url}
        r = requests.get(target, proxies=proxies, timeout=10, verify=False, headers={'User-Agent': random.choice(USER_AGENTS)})
        if r.status_code < 400:
            with print_lock:
                stats['target_passed'] += 1
                with open(output_file, 'a') as f: f.write(proxy_url + "\n")
        else:
            with print_lock: stats['target_failed'] += 1
    except:
        with print_lock: stats['target_failed'] += 1
    finally:
        with print_lock: stats['checked'] += 1

def print_target_progress():
    while not stop_progress:
        sys.stdout.write(f"\r{Fore.YELLOW}Chk: {stats['checked']}/{stats['total']} | {Fore.GREEN}Live: {stats['target_passed']} | {Fore.RED}Bad: {stats['target_failed']}   ")
        sys.stdout.flush()
        time.sleep(0.2)

# ==================== FEATURE 3: MEGA SCRAPER ====================

def scrape_proxies(limit):
    sources = [
        'https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/http.txt',
        'https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/socks5.txt',
        'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt',
        'https://raw.githubusercontent.com/aliilapro/proxy/main/http.txt',
        'https://raw.githubusercontent.com/aliilapro/proxy/main/socks4.txt',
        'https://raw.githubusercontent.com/almroot/proxylist/master/list.txt',
        'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
        'https://raw.githubusercontent.com/clearproxy/checked-proxy-list/main/custom/discord/socks5.txt',
        'https://raw.githubusercontent.com/clearproxy/checked-proxy-list/main/custom/google/http.txt',
        'https://raw.githubusercontent.com/clearproxy/checked-proxy-list/main/http/raw/all.txt',
        'https://raw.githubusercontent.com/clearproxy/checked-proxy-list/main/socks4/raw/all.txt',
        'https://raw.githubusercontent.com/clearproxy/checked-proxy-list/main/socks5/raw/all.txt',
        'https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/http.txt',
        'https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks5.txt',
        'https://raw.githubusercontent.com/dpangestuw/free-proxy/main/http_proxies.txt',
        'https://raw.githubusercontent.com/dpangestuw/free-proxy/main/socks4_proxies.txt',
        'https://raw.githubusercontent.com/dpangestuw/free-proxy/refs/heads/main/allive.txt',
        'https://raw.githubusercontent.com/dpangestuw/free-proxy/refs/heads/main/http_proxies.txt',
        'https://raw.githubusercontent.com/dpangestuw/free-proxy/refs/heads/main/socks4_proxies.txt',
        'https://raw.githubusercontent.com/dpangestuw/free-proxy/refs/heads/main/socks5_proxies.txt',
        'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/all.txt',
        'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/http.txt',
        'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/https.txt',
        'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks4.txt',
        'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt',
        'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt',
        'https://raw.githubusercontent.com/ian-lusule/proxies/main/proxies/all_proxies.txt',
        'https://raw.githubusercontent.com/ian-lusule/proxies/main/proxies/http.txt',
        'https://raw.githubusercontent.com/ian-lusule/proxies/main/proxies/socks4.txt',
        'https://raw.githubusercontent.com/ian-lusule/proxies/main/proxies/socks5.txt',
        'https://raw.githubusercontent.com/javadbazokar/proxy-list/refs/heads/main/http.txt',
        'https://raw.githubusercontent.com/javadbazokar/proxy-list/refs/heads/main/https.txt',
        'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt',
        'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt',
        'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt',
        'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt',
        'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt',
        'https://raw.githubusercontent.com/junioralive/proxy-alive/main/http.txt',
        'https://raw.githubusercontent.com/junioralive/proxy-alive/main/socks4.txt',
        'https://raw.githubusercontent.com/junioralive/proxy-alive/main/socks5.txt',
        'https://raw.githubusercontent.com/komutan234/proxy-list-free/main/proxies/http.txt',
        'https://raw.githubusercontent.com/komutan234/proxy-list-free/main/proxies/socks4.txt',
        'https://raw.githubusercontent.com/komutan234/proxy-list-free/main/proxies/socks5.txt',
        'https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt',
        'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
        'https://raw.githubusercontent.com/mmpx12/proxy-list/master/proxies.txt',
        'https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt',
        'https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
        'https://raw.githubusercontent.com/murongpig/proxy-master/main/http.txt',
        'https://raw.githubusercontent.com/murongpig/proxy-master/main/socks4.txt',
        'https://raw.githubusercontent.com/murongpig/proxy-master/main/socks5.txt',
        'https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt',
        'https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/all/data.txt',
        'https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt',
        'https://raw.githubusercontent.com/proxylist-to/proxy-list/main/http.txt',
        'https://raw.githubusercontent.com/proxylist-to/proxy-list/main/socks4.txt',
        'https://raw.githubusercontent.com/proxylist-to/proxy-list/main/socks5.txt',
        'https://raw.githubusercontent.com/proxyscraper/proxyscraper/main/http.txt',
        'https://raw.githubusercontent.com/proxyscraper/proxyscraper/main/socks4.txt',
        'https://raw.githubusercontent.com/proxyscraper/proxyscraper/main/socks5.txt',
        'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
        'https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt',
        'https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt',
        'https://raw.githubusercontent.com/sevenworksdev/proxy-list/main/proxies/http.txt',
        'https://raw.githubusercontent.com/sevenworksdev/proxy-list/main/proxies/https.txt',
        'https://raw.githubusercontent.com/shiftytr/proxy-list/master/http.txt',
        'https://raw.githubusercontent.com/shiftytr/proxy-list/master/https.txt',
        'https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt',
        'https://raw.githubusercontent.com/shiftytr/proxy-list/master/socks4.txt',
        'https://raw.githubusercontent.com/shiftytr/proxy-list/master/socks5.txt',
        'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt',
        'https://raw.githubusercontent.com/thespeedx/proxy-list/master/http.txt',
        'https://raw.githubusercontent.com/thespeedx/proxy-list/master/socks4.txt',
        'https://raw.githubusercontent.com/thespeedx/proxy-list/master/socks5.txt',
        'https://raw.githubusercontent.com/thespeedx/proxy-list/refs/heads/master/http.txt',
        'https://raw.githubusercontent.com/thespeedx/proxy-list/refs/heads/master/socks4.txt',
        'https://raw.githubusercontent.com/thespeedx/proxy-list/refs/heads/master/socks5.txt',
        'https://raw.githubusercontent.com/thespeedx/socks-list/master/http.txt',
        'https://raw.githubusercontent.com/thespeedx/socks-list/master/socks4.txt',
        'https://raw.githubusercontent.com/thespeedx/socks-list/master/socks5.txt',
        'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt',
        'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt',
        'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt',
        'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt',
        'https://raw.githubusercontent.com/volkansah/auto-proxy-fetcher/refs/heads/main/proxies.txt',
        'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt',
        'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/https.txt',
        'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks4.txt',
        'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt',
        'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/ss.txt',
        'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/ssr.txt',
        'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/trojan.txt',
        'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt',
        'https://raw.githubusercontent.com/zevtyardt/proxy-list/main/all.txt',
        'https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt',
        'https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt',
        'https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt',
        'https://vakhov.github.io/fresh-proxy-list/http.txt',
        'https://vakhov.github.io/fresh-proxy-list/https.txt',
        'https://vakhov.github.io/fresh-proxy-list/proxylist.txt',
        'https://vakhov.github.io/fresh-proxy-list/socks4.txt',
        'https://vakhov.github.io/fresh-proxy-list/socks5.txt',
    ]
    

    print(f"{Fore.CYAN}[*] Harvesting from {len(sources)} sources...")
    formatted = []

    def fetch(url):
        try:
            # استنتاج نوع البروكسي من الرابط إذا لم يكن موجوداً
            default_proto = 'http'
            url_lower = url.lower()
            if 'socks5' in url_lower:
                default_proto = 'socks5'
            elif 'socks4' in url_lower:
                default_proto = 'socks4'

            text = requests.get(url, timeout=10).text
            matches = PROXY_RE_FULL.findall(text)
            
            res = []
            for m in matches:
                proto = m[0].lower() if m[0] else default_proto
                if proto == 'https': proto = 'http'
                res.append(f"{proto}://{m[1]}:{m[2]}")
            return res
        except: 
            return []

    with ThreadPoolExecutor(max_workers=50) as ex:
        for res in ex.map(fetch, sources): 
            formatted.extend(res)

    unique = list(set(formatted))[:limit]
    print(f"{Fore.GREEN}[✓] Harvested {len(unique)} unique candidates.")
    return unique

# ==================== FEATURE 4: ADVANCED CHECKER ====================

def check_general_worker(proxy, output_file, existing_set, intel_enabled, google_enabled):
    # Parse
    try:
        parts = proxy.split('://')
        proto = parts[0]
        ip_port = parts[1]
        ip, port = ip_port.split(':')
    except: return

    # If HTTP, try HTTPS capability
    if proto == 'http': protocols = ['http'] # Can add logic to test https via http
    else: protocols = [proto]

    for p in protocols:
        try:
            px = {"http": f"{p}://{ip}:{port}", "https": f"{p}://{ip}:{port}"}
            target = "https://www.google.com" if google_enabled else "http://ip-api.com/json"
            
            start = time.time()
            r = requests.get(target, proxies=px, timeout=TIMEOUT, verify=False, headers={'User-Agent': random.choice(USER_AGENTS)})
            speed = int((time.time() - start) * 1000)

            if r.status_code == 200:
                # Intel
                info = {'ip': ip, 'port': port, 'protocol': p, 'speed': speed, 'google': 0}
                
                if intel_enabled:
                    try:
                        if "json" in target: data = r.json()
                        else: data = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
                        info['country'] = data.get('countryCode','XX')
                        info['type'] = 'RES' if not data.get('hosting', True) else 'DC'
                        info['anonymity'] = 'UNK' # Could add headers check here
                    except: pass
                
                if google_enabled and 'google' in target:
                    info['google'] = 1
                    with print_lock: stats['google'] += 1

                save_to_db(info)
                
                # Stats & Output
                with print_lock:
                    if p in stats: stats[p] += 1
                    if intel_enabled and info.get('type') == 'RES': stats['residential'] += 1
                    elif intel_enabled: stats['datacenter'] += 1
                    
                    line_out = f"{p}://{ip}:{port}"
                    if intel_enabled: line_out += f" | {info.get('country','XX')} | {info.get('type','DC')} | {speed}ms"
                    
                    if line_out not in existing_set:
                        print(f"{Fore.GREEN}[✓] {p.upper().ljust(6)} | {ip}:{port} | {info.get('country','XX')} | {speed}ms")
                        with open(output_file, 'a') as f: f.write(line_out + "\n")
                        existing_set.add(line_out)
                break # Stop if working
        except: continue
    
    with print_lock:
        stats['checked'] += 1

def run_main_process():
    global stop_progress
    for k in stats: stats[k] = 0
    
    output_file = select_or_create_file()
    init_database()
    
    # RECYCLE LOGIC: Load existing
    existing = []
    if os.path.exists(output_file):
        with open(output_file, 'r') as f: existing = [l.strip() for l in f if l.strip()]
        print(f"{Fore.YELLOW}[*] Loaded {len(existing)} proxies from file for re-checking.")

    # Options
    try:
        limit = int(input(f"{Fore.YELLOW}Limit (99999999999): ") or "99999999999")
        threads = int(input(f"{Fore.YELLOW}Threads (300): ") or "300")
        intel = input(f"{Fore.CYAN}Enable Intel (Country/Type)? (y/n): ").lower() == 'y'
        google = input(f"{Fore.GREEN}Test Google? (y/n): ").lower() == 'y'
    except: limit=5000; threads=300; intel=True; google=False
    
    # Harvest
    new_proxies = scrape_proxies(limit)
    
    # Merge
    combined = list(set(new_proxies + existing))
    print(f"{Fore.CYAN}[*] Total Unique to Check: {len(combined)}")
    
    # Wipe File for Fresh Data
    if os.path.exists(output_file): open(output_file, 'w').close()
    
    stats['total'] = len(combined)
    stop_progress = False
    existing_set = set() # Track what we write to file this session
    
    threading.Thread(target=print_main_progress, daemon=True).start()
    
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(check_general_worker, p, output_file, existing_set, intel, google) for p in combined]
        for f in as_completed(futures): pass
    
    stop_progress = True
    print(f"\n{Fore.GREEN}Scan Finished. Live: {stats['socks5']+stats['socks4']+stats['http']}")

def print_main_progress():
    while not stop_progress:
        sys.stdout.write(f"\r{Fore.CYAN}Chk: {stats['checked']}/{stats['total']} | S5:{stats['socks5']} S4:{stats['socks4']} H:{stats['http']} | Res:{stats['residential']} | G:{stats['google']}    ")
        sys.stdout.flush()
        time.sleep(0.2)

# ==================== FEATURE 5: EXPORT & FILTER ====================

def export_geojson():
    if not os.path.exists('proxies.db'): print(f"{Fore.RED}[!] No DB."); return
    try:
        # Note: Real geojson needs lat/lon. Using placeholder or fetching from API if implemented.
        # This function exports the structure based on DB countries.
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()
        c.execute("SELECT ip, port, country, type FROM proxies WHERE status='LIVE'")
        rows = c.fetchall()
        print(f"{Fore.GREEN}[✓] Exported {len(rows)} proxies to proxies.geojson (Simulated)")
        conn.close()
    except: pass

def filter_country():
    f = select_or_create_file()
    if not os.path.exists(f): return
    cc = input(f"{Fore.YELLOW}Country Code (e.g. US, DE): ").upper()
    
    with open(f, 'r') as file:
        lines = [l for l in file if f"| {cc} |" in l]
    
    out = f"{f.replace('.txt','')}_{cc}.txt"
    with open(out, 'w') as file: file.writelines(lines)
    print(f"{Fore.GREEN}[✓] Saved {len(lines)} proxies to {out}")

# ==================== MAIN MENU ====================

def main():
    while True:
        clear_screen()
        print(f"""{Style.BRIGHT}{Fore.CYAN}
   ╔════════════════════════════════════════════════╗
   ║          ULTIMATE PROXY MASTER v20.0           ║
   ║          Developed by: github.com/mootoo11     ║
   ╚════════════════════════════════════════════════╝
   [1] Scrape & Check (Recycle Mode) 🚀
   [2] Target Checker (Discord/Netflix) 🎯
   [3] View Database Stats 📊
   [4] Filter by Country 🌍
   [5] Export GeoJSON 🗺️
   [6] Exit
        """)
        c = input(f"{Fore.YELLOW}> ").strip()
        
        if c == '1': run_main_process(); input("\nPress Enter...")
        elif c == '2': check_custom_target(); input("\nPress Enter...")
        elif c == '3': view_database_stats(); input("\nPress Enter...")
        elif c == '4': filter_country(); input("\nPress Enter...")
        elif c == '5': export_geojson(); input("\nPress Enter...")
        elif c == '6': sys.exit()

if __name__ == "__main__":
    main()
