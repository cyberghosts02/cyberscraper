#!/usr/bin/env python3

import os, sys, time, random, socket, signal, requests, hashlib
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from colorama import Fore, Style, init
import pyfiglet
import configparser
import exifread
import PyPDF2
from docx import Document

init(autoreset=True)

signal.signal(signal.SIGINT, lambda sig, frame: (print(Fore.RED + "\n[!] Exiting..."), sys.exit(0)))

# Create folders
for folder in ["scraped", "wordlists"]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Config file
CONFIG_FILE = "config.ini"
if not os.path.exists(CONFIG_FILE):
    config = configparser.ConfigParser()
    config['DEFAULT'] = {
        'UserAgent': 'Mozilla/5.0 (X11; Linux x86_64)',
        'DelayMin': '1.5',
        'DelayMax': '4.5',
        'WordlistPath': 'wordlists/common.txt',
        'OutputDir': 'scraped'
    }
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)

config = configparser.ConfigParser()
config.read(CONFIG_FILE)
settings = config['DEFAULT']

def clear():
    os.system("clear" if os.name == "posix" else "cls")

def banner(title="CyberScraper"):
    print(Fore.LIGHTCYAN_EX + pyfiglet.figlet_format(title, font="slant"))
    print(Fore.LIGHTBLACK_EX + "="*70)
    print(Fore.YELLOW + "[!] Professional Hacking CLI Toolkit")
    print(Fore.LIGHTBLACK_EX + "="*70 + "\n")

def developer_info():
    clear()
    banner("SIG-X")
    print(Fore.LIGHTGREEN_EX + "Toolkit: CYBER ALPHA")
    print(Fore.LIGHTGREEN_EX + "Contact: kamikazexcyberghosts@proton.me")
    input("\nPress Enter to return to menu...")

def config_info():
    clear()
    banner("Config")
    print(Fore.YELLOW + "User-Agent:", settings['UserAgent'])
    print(Fore.YELLOW + "Delay Range:", settings['DelayMin'], "-", settings['DelayMax'])
    print(Fore.YELLOW + "Wordlist Path:", settings['WordlistPath'])
    input("\nPress Enter to return to menu...")

def main_menu():
    clear()
    banner("CyberScraper")
    print(Fore.CYAN + "[1] Web Scraper")
    print(Fore.CYAN + "[2] IP & Port Scanner")
    print(Fore.CYAN + "[3] Subdomain Finder")
    print(Fore.CYAN + "[4] Directory Bruteforcer")
    print(Fore.CYAN + "[5] XSS Scanner")
    print(Fore.CYAN + "[6] Metadata/File Parser")
    print(Fore.CYAN + "[7] SQLi Scanner")
    print(Fore.CYAN + "[8] WHOIS & GeoIP Lookup")
    print(Fore.CYAN + "[9] CMS Detector")
    print(Fore.CYAN + "[10] WAF Detector")
    print(Fore.CYAN + "[11] Hash Identifier")
    print(Fore.MAGENTA + "[C] Config Info")
    print(Fore.MAGENTA + "[D] Developer Info")
    print(Fore.RED + "[12] Exit")
    print(Fore.LIGHTBLACK_EX + "="*70)
    return input(Fore.YELLOW + "[?] Select an option: ").strip()

# 5. XSS Scanner
def xss_scanner():
    clear()
    banner("XSS Scanner")
    url = input("Enter target URL (with param): ")
    payloads = ["<script>alert(1)</script>", "\"'><svg/onload=alert(1)>", "<img src=javascript:alert('XSS')>"]
    for payload in payloads:
        try:
            r = requests.get(url + payload)
            if payload in r.text:
                print(Fore.GREEN + f"[+] XSS Found with payload: {payload}")
                host = urlparse(url).netloc
                with open(f"scraped/xss_{host}.txt", "a") as f:
                    f.write(f"Payload: {payload}\n")
        except:
            pass
    input("\nPress Enter to return...")

# 6. Metadata Parser
def metadata_parser():
    clear()
    banner("Metadata Parser")
    filepath = input("Enter file path: ")
    output_file = f"scraped/meta_{os.path.basename(filepath)}.txt"
    try:
        with open(filepath, 'rb') as f:
            ext = filepath.lower().split('.')[-1]
            with open(output_file, 'w') as out:
                if ext in ['jpg', 'jpeg']:
                    tags = exifread.process_file(f)
                    for tag in tags:
                        out.write(f"{tag}: {tags[tag]}\n")
                elif ext == 'pdf':
                    pdf = PyPDF2.PdfReader(f)
                    info = pdf.metadata
                    for k, v in info.items():
                        out.write(f"{k}: {v}\n")
                elif ext == 'docx':
                    doc = Document(filepath)
                    cp = doc.core_properties
                    for attr in dir(cp):
                        if not attr.startswith('_') and not callable(getattr(cp, attr)):
                            out.write(f"{attr}: {getattr(cp, attr)}\n")
        print(Fore.GREEN + f"[✓] Saved to {output_file}")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")
    input("\nPress Enter...")

# 7. SQLi Scanner
def sqli_scanner():
    clear()
    banner("SQLi Scanner")
    url = input("Target URL with param (e.g. site.com/index.php?id=): ")
    payloads = ["'", "'--", "\" OR 1=1 --"]
    errors = ["SQL syntax", "mysql_fetch", "ORA-", "ODBC"]
    host = urlparse(url).netloc
    out = open(f"scraped/sqlscan_{host}.txt", 'w')
    for payload in payloads:
        try:
            full_url = url + payload
            r = requests.get(full_url)
            for err in errors:
                if err.lower() in r.text.lower():
                    print(Fore.RED + f"[!] SQLi Detected at {full_url}")
                    out.write(f"{full_url}\n")
        except:
            pass
    out.close()
    input("\nPress Enter...")

# 8. WHOIS Lookup
def whois_lookup():
    clear()
    banner("WHOIS & GeoIP")
    domain = input("Enter domain (e.g. example.com): ")
    host = domain.replace("http://", "").replace("https://", "").split("/")[0]
    try:
        w = whois.whois(host)
        with open(f"scraped/whois_{host}.txt", 'w') as f:
            for k, v in w.items():
                f.write(f"{k}: {v}\n")
        print(Fore.GREEN + f"[✓] Saved to whois_{host}.txt")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")
    input("\nPress Enter...")

# 9. CMS Detector
def cms_detector():
    clear()
    banner("CMS Detector")
    url = input("Enter site URL: ")
    try:
        r = requests.get(url)
        result = "Unknown"
        if "wp-content" in r.text:
            result = "WordPress"
        elif "/sites/default" in r.text:
            result = "Drupal"
        elif "Joomla" in r.text or "com_content" in r.text:
            result = "Joomla"
        print(Fore.CYAN + f"[✓] CMS Detected: {result}")
        with open(f"scraped/cms_{urlparse(url).netloc}.txt", 'w') as f:
            f.write(f"Detected CMS: {result}\n")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")
    input("\nPress Enter...")

# 10. WAF Detector
def waf_detector():
    clear()
    banner("WAF Detector")
    url = input("Enter target URL: ")
    try:
        r = requests.get(url)
        headers = r.headers
        waf = "None"
        if "cf-ray" in headers or "Cloudflare" in headers.get("Server", ""):
            waf = "Cloudflare"
        elif "sucuri" in headers.get("Server", "").lower():
            waf = "Sucuri"
        elif "Akamai" in headers.get("Server", ""):
            waf = "Akamai"
        print(Fore.YELLOW + f"[✓] WAF Detected: {waf}")
        with open(f"scraped/waf_{urlparse(url).netloc}.txt", 'w') as f:
            f.write(f"Detected WAF: {waf}\n")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")
    input("\nPress Enter...")

# 11. Hash Identifier
def hash_identifier():
    clear()
    banner("Hash Identifier")
    h = input("Enter hash: ")
    hash_types = {
        32: "MD5",
        40: "SHA-1",
        64: "SHA-256",
        128: "SHA-512"
    }
    guess = hash_types.get(len(h), "Unknown")
    if h.startswith("$2a") or h.startswith("$2b"):
        guess = "bcrypt"
    elif h.startswith("$1$"):
        guess = "MD5 Crypt"
    print(Fore.CYAN + f"[+] Hash Type: {guess}")
    with open(f"scraped/hash_id_{int(time.time())}.txt", 'w') as f:
        f.write(f"Hash: {h}\nGuess: {guess}\n")
    input("\nPress Enter...")

# MAIN LOOP
while True:
    opt = main_menu()
    if opt == '1':
        print("[!] Web Scraper coming soon...")
        input("Press Enter...")
    elif opt == '2':
        print("[!] Port Scanner coming soon...")
        input("Press Enter...")
    elif opt == '3':
        print("[!] Subdomain Finder coming soon...")
        input("Press Enter...")
    elif opt == '4':
        print("[!] Dir Bruteforce coming soon...")
        input("Press Enter...")
    elif opt == '5':
        xss_scanner()
    elif opt == '6':
        metadata_parser()
    elif opt == '7':
        sqli_scanner()
    elif opt == '8':
        whois_lookup()
    elif opt == '9':
        cms_detector()
    elif opt == '10':
        waf_detector()
    elif opt == '11':
        hash_identifier()
    elif opt.lower() == 'c':
        config_info()
    elif opt.lower() == 'd':
        developer_info()
    elif opt == '12':
        print(Fore.RED + "[!] Exiting...")
        break
    else:
        print(Fore.RED + "[!] Invalid choice.")
        time.sleep(1)
