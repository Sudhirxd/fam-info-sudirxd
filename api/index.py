"""
IMPDS Deduplication — JSON API Server (v2.0 — Zero Friction)
=============================================================
Reverse-engineered from https://impds.nic.in/impdsdeduplication/

v2.0 Features:
  - AUTO CAPTCHA SOLVING via OCR (easyocr)
  - SESSION PERSISTENCE — login once, cookies saved to disk
  - TRANSPARENT RE-AUTH — search methods auto-login if session drops
  - Full REST JSON API via FastAPI

Usage:
  pip install fastapi uvicorn requests pycryptodome beautifulsoup4 easyocr
  python impds_api.py

  # Zero-friction mode (auto-login, auto-captcha):
  python impds_api.py --auto --user YOUR_EMAIL --pass YOUR_PASSWORD

Endpoints:
  GET  /api/health              — Check if session is active
  POST /api/login               — Login (manual captcha)
  POST /api/auto-login          — Login (auto-solves captcha via OCR)
  POST /api/search/ration-card  — Search by ration card (auto-reauth)
  POST /api/search/aadhaar      — Search by Aadhaar (auto-reauth)
  GET  /api/reports             — List available report endpoints
"""

import hashlib
import requests
import urllib3
import base64
import re
import json
import os
import sys
import time
import threading
import pickle
from pathlib import Path
from html.parser import HTMLParser
from datetime import datetime

# ── Optional: Try to use FastAPI, fall back to Flask-style if not available ──
from flask import Flask, jsonify, request, abort
from flask_cors import CORS
USE_FASTAPI = False

try:
    from bs4 import BeautifulSoup
    USE_BS4 = True
except ImportError:
    USE_BS4 = False
    print("[!] BeautifulSoup not found. Install with: pip install beautifulsoup4")
    print("[!] HTML parsing will be basic.")

try:
    import easyocr
    USE_OCR = True
    _ocr_reader = None  # Lazy-loaded, heavy init
except ImportError:
    USE_OCR = False
    _ocr_reader = None
    print("[!] easyocr not found. Install with: pip install easyocr")
    print("[!] Auto-captcha solving disabled. Manual captcha still works.")


def _get_ocr_reader():
    """Lazy-init the OCR reader (first call takes ~2s to load models)."""
    global _ocr_reader
    if _ocr_reader is None and USE_OCR:
        print("[*] Loading OCR model (first time only)...")
        _ocr_reader = easyocr.Reader(['en'], gpu=False, verbose=False)
    return _ocr_reader


def solve_captcha_ocr(captcha_base64: str) -> str:
    """
    Auto-solve a captcha image using OCR.
    NIC captchas are typically 6 uppercase alphanumeric chars.
    """
    reader = _get_ocr_reader()
    if not reader:
        return ""
    
    img_bytes = base64.b64decode(captcha_base64)
    results = reader.readtext(img_bytes, detail=0, allowlist='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
    
    if results:
        # Join all detected text chunks, strip spaces
        solved = ''.join(results).replace(' ', '').strip()
        return solved
    return ""


# ═══════════════════════════════════════════════════════════════════════════
# SESSION PERSISTENCE — Save/load cookies + auth state to disk
# ═══════════════════════════════════════════════════════════════════════════

if os.environ.get("VERCEL"):
    SESSION_FILE = Path('/tmp') / '.impds_session.pkl'
else:
    SESSION_FILE = Path(__file__).parent.parent / '.impds_session.pkl'


def save_session_to_disk(session_obj, metadata: dict):
    """Persist cookies + metadata so we skip login next time."""
    data = {
        'cookies': dict(session_obj.cookies),
        'metadata': metadata,
        'saved_at': datetime.now().isoformat()
    }
    try:
        with open(SESSION_FILE, 'wb') as f:
            pickle.dump(data, f)
    except Exception as e:
        print(f"[!] Warning: Could not save session to disk: {e}")


def load_session_from_disk() -> dict | None:
    """Load saved session if it exists and isn't too old."""
    if not SESSION_FILE.exists():
        return None
    try:
        with open(SESSION_FILE, 'rb') as f:
            data = pickle.load(f)
        # Check if session is less than 4 hours old
        saved = datetime.fromisoformat(data['saved_at'])
        age_hours = (datetime.now() - saved).total_seconds() / 3600
        if age_hours > 4:
            SESSION_FILE.unlink(missing_ok=True)
            return None
        return data
    except Exception:
        SESSION_FILE.unlink(missing_ok=True)
        return None


COOKIE_TXT_FILE = Path(__file__).parent.parent / 'cookie.txt'


def load_cookies_from_netscape(file_path: Path) -> list | None:
    """
    Parses a Netscape/curl cookie.txt file and returns a list of (name, value, domain, path) tuples.
    Handles '#HttpOnly_' prefixes properly.
    """
    if not file_path.exists():
        return None
    cookies = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or (line.startswith('#') and not line.startswith('#HttpOnly_')):
                    continue
                if line.startswith('#HttpOnly_'):
                    line = line[len('#HttpOnly_'):]
                parts = line.split('\t')
                if len(parts) >= 7:
                    domain, flag, path, secure, expiration, name, value = parts[:7]
                    cookies.append((name, value, domain, path))
        return cookies if cookies else None
    except Exception as e:
        print(f"[!] Error reading cookie.txt: {e}")
        return None


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://impds.nic.in/impdsdeduplication"

# ═══════════════════════════════════════════════════════════════════════════
# AES ENCRYPTION — Replicating CryptoJS.AES.encrypt(data, passphrase)
# ═══════════════════════════════════════════════════════════════════════════
# CryptoJS with a string passphrase uses OpenSSL-compatible key derivation:
#   - Random 8-byte salt
#   - MD5-based EVP_BytesToKey to derive 32-byte key + 16-byte IV
#   - AES-256-CBC encryption
#   - Output: "Salted__" + salt + ciphertext, then base64 encoded

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib as _hashlib

ENCRYPTION_KEY = 'nic@impds#dedup05613'


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    """
    OpenSSL's EVP_BytesToKey with MD5 — this is exactly what CryptoJS uses
    under the hood when you pass a string passphrase.
    """
    d = b''
    d_i = b''
    while len(d) < key_len + iv_len:
        d_i = _hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len + iv_len]


def encrypt_cryptojs_aes(plaintext: str, passphrase: str = ENCRYPTION_KEY) -> str:
    """
    Exact replica of CryptoJS.AES.encrypt(plaintext, passphrase).toString()
    Returns base64 string identical to what the browser JS produces.
    """
    salt = get_random_bytes(8)
    key, iv = _evp_bytes_to_key(passphrase.encode('utf-8'), salt)
    
    # PKCS7 padding
    pad_len = 16 - (len(plaintext.encode('utf-8')) % 16)
    padded = plaintext.encode('utf-8') + bytes([pad_len] * pad_len)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)
    
    # CryptoJS format: "Salted__" + salt + ciphertext, all base64'd
    encrypted = b'Salted__' + salt + ciphertext
    return base64.b64encode(encrypted).decode('utf-8')


def clean_parsed_search_results(result: dict) -> dict:
    """
    Post-processes the raw table search results and flattens them into a clean,
    well-structured JSON schema with easy-to-use fields.
    Supports both Search Result layout and RcReportSummary (RcSummaryPage) layout.
    """
    cleaned = {
        "success": result.get("success", False),
        "timestamp": result.get("timestamp"),
        "api_by": "t.me/Sudhirxd",
        "website": "www.sudhirxd.in",
        "message": result.get("message", ""),
        "card_details": {
            "ration_card_number": None,
            "state_name": None,
            "district_name": None,
            "scheme_name": None,
            "card_type": None,
            "issue_date": None,
            "address": None,
            "home_fps": None
        },
        "members": [],
        "status_metrics": {},
        "raw_tables": result.get("raw_tables", [])
    }
    
    if result.get("message"):
        cleaned["success"] = False
        return cleaned
        
    raw_tables = result.get("raw_tables", [])
    members_table = None
    status_table = None
    info_table = None
    
    # Identify tables by checking headers
    for table in raw_tables:
        headers = [str(h).lower().strip() for h in table.get("headers", [])]
        
        # 1. Check if it's the members table
        if "member name" in headers or "ration card no." in headers or "member id" in headers:
            members_table = table
        # 2. Check if it's the status metrics table
        elif "name" in headers and "remark" in headers:
            status_table = table
        # 3. Check if it's the info summary table (from RcReportSummary)
        elif any("ration card id:" in h or "card type:" in h or "scheme:" in h for h in headers):
            info_table = table
            
    # Parse Info Table if present (from RcReportSummary / RcSummaryPage layout)
    if info_table:
        headers = info_table.get("headers", [])
        rows = info_table.get("rows", [])
        
        # Parse headers (e.g. "Ration Card ID:102310142424684400000551")
        for h in headers:
            if ":" in h:
                key, val = h.split(":", 1)
                key_clean = key.strip().lower()
                val_clean = val.strip()
                if "ration card id" in key_clean:
                    cleaned["card_details"]["ration_card_number"] = val_clean
                elif "card type" in key_clean:
                    cleaned["card_details"]["card_type"] = val_clean
                elif "scheme" in key_clean:
                    cleaned["card_details"]["scheme_name"] = val_clean
                elif "issue date" in key_clean:
                    cleaned["card_details"]["issue_date"] = val_clean
                    
        # Parse rows (e.g. key: "State:BIHAR")
        if rows:
            for k, v in rows[0].items():
                for part in [k, v]:
                    if ":" in part:
                        key, val = part.split(":", 1)
                        key_clean = key.strip().lower()
                        val_clean = val.strip()
                        if "state" in key_clean:
                            cleaned["card_details"]["state_name"] = val_clean
                        elif "district" in key_clean:
                            cleaned["card_details"]["district_name"] = val_clean
                        elif "address" in key_clean:
                            cleaned["card_details"]["address"] = val_clean
                        elif "home fps" in key_clean:
                            cleaned["card_details"]["home_fps"] = val_clean
 
    # Parse Members Table
    if members_table:
        rows = members_table.get("rows", [])
        if rows:
            first_row = rows[0]
            
            # If not already populated by info_table, get basic details from search result row
            if not cleaned["card_details"]["ration_card_number"]:
                cleaned["card_details"]["ration_card_number"] = first_row.get("Ration Card No.")
            if not cleaned["card_details"]["state_name"]:
                cleaned["card_details"]["state_name"] = first_row.get("State Name")
            if not cleaned["card_details"]["district_name"]:
                cleaned["card_details"]["district_name"] = first_row.get("District Name")
            if not cleaned["card_details"]["scheme_name"]:
                cleaned["card_details"]["scheme_name"] = first_row.get("Scheme name")
            
            seen_member_ids = set()
            for idx, row in enumerate(rows):
                row_lower = {str(k).lower().strip(): v for k, v in row.items()}
                
                # S.No.
                s_no_val = row_lower.get("s.no.")
                s_no = int(s_no_val) if (s_no_val is not None and str(s_no_val).isdigit()) else (idx + 1)
                
                member_id = row_lower.get("member id") or row_lower.get("member_id")
                member_name = row_lower.get("member name") or row_lower.get("member_name")
                
                # Deduplicate members by member_id or member_name
                if member_id:
                    member_id_str = str(member_id).strip()
                    if member_id_str in seen_member_ids:
                        continue
                    seen_member_ids.add(member_id_str)
                elif member_name:
                    name_key = f"name_{str(member_name).lower().strip()}"
                    if name_key in seen_member_ids:
                        continue
                    seen_member_ids.add(name_key)
                
                member = {
                    "s_no": s_no,
                    "member_id": member_id,
                    "member_name": member_name,
                    "gender": row_lower.get("gender"),
                    "uid": row_lower.get("uid"),
                    "relationship": (
                        row_lower.get("relationship") or 
                        row_lower.get("relationship status") or 
                        row_lower.get("relationship_status") or 
                        row_lower.get("relation") or 
                        row_lower.get("relations")
                    ),

                    "ekyc_status": (
                        row_lower.get("ekyc status") or 
                        row_lower.get("ekyc_status") or 
                        row_lower.get("ekyc")
                    ),
                    "cr_last_updated": (
                        row_lower.get("cr last updated") or 
                        row_lower.get("cr_last_updated") or 
                        row_lower.get("last updated") or 
                        row_lower.get("last_updated")
                    ),
                    "remark": row_lower.get("remark", "")
                }
                
                cleaned["members"].append(member)
                
    # Parse Status Table
    if status_table:
        for row in status_table.get("rows", []):
            name = row.get("Name")
            remark = row.get("Remark")
            if name and remark:
                val = remark
                if remark.lower() == 'yes':
                    val = True
                elif remark.lower() == 'no':
                    val = False
                
                metric_key = name.lower().strip()
                metric_key = metric_key.replace("impds", "impds").replace("/", "_").replace("-", "_")
                metric_key = "_".join(metric_key.split())
                metric_key = "".join([c for c in metric_key if c.isalnum() or c == "_"])
                cleaned["status_metrics"][metric_key] = val
 
    if not cleaned["members"] and not cleaned["card_details"]["ration_card_number"]:
        if not cleaned["message"]:
            cleaned["message"] = "No matching records found."
        cleaned["success"] = False
 
    return cleaned


def parse_search_results(html: str) -> dict:
    """
    Parse the HTML response from the search endpoint.
    Extracts any tables into structured JSON.
    """
    result = {
        "success": True,
        "timestamp": datetime.now().isoformat(),
        "data": [],
        "raw_tables": [],
        "message": ""
    }
    
    if USE_BS4:
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check for error messages
        error_span = soup.find('span', id='spanFormError')
        if error_span and error_span.text.strip():
            result["message"] = error_span.text.strip()
        
        # Find the page title/heading
        heading = soup.find('h3')
        if heading:
            result["page_title"] = heading.text.strip()
        
        # Extract ALL tables
        tables = soup.find_all('table')
        for table_idx, table in enumerate(tables):
            headers = []
            rows_data = []
            
            # Get headers from <th> tags
            header_row = table.find('tr')
            if header_row:
                for th in header_row.find_all(['th']):
                    headers.append(th.get_text(strip=True))
            
            # If no <th>, try first row of <td>
            if not headers and header_row:
                for td in header_row.find_all('td'):
                    headers.append(td.get_text(strip=True))
            
            # Get data rows
            all_rows = table.find_all('tr')
            start = 1 if headers else 0
            
            for row in all_rows[start:]:
                cells = row.find_all(['td', 'th'])
                row_data = [cell.get_text(strip=True) for cell in cells]
                
                if row_data and any(cell.strip() for cell in row_data):
                    if headers and len(row_data) == len(headers):
                        rows_data.append(dict(zip(headers, row_data)))
                    else:
                        rows_data.append(row_data)
            
            if rows_data:
                result["raw_tables"].append({
                    "table_index": table_idx,
                    "headers": headers,
                    "rows": rows_data,
                    "row_count": len(rows_data)
                })
        
        # Also extract any standalone data (divs with key-value pairs)
        panels = soup.find_all('div', class_='panel-body')
        for panel in panels:
            text = panel.get_text(strip=True)
            if text and len(text) > 10:
                result["data"].append(text)
        
        if not result["raw_tables"] and not result["data"]:
            # Try to get any meaningful content from the body
            body = soup.find('div', class_='bodytwo')
            if body:
                all_text = body.get_text(separator='\n', strip=True)
                if all_text:
                    result["message"] = all_text[:1000]
            if not result["message"]:
                result["message"] = "No results found"
                result["success"] = False
    else:
        # Fallback: basic regex parsing
        table_pattern = re.compile(r'<table[^>]*>(.*?)</table>', re.DOTALL | re.IGNORECASE)
        td_pattern = re.compile(r'<t[dh][^>]*>(.*?)</t[dh]>', re.DOTALL | re.IGNORECASE)
        tag_stripper = re.compile(r'<[^>]+>')
        
        for match in table_pattern.finditer(html):
            table_html = match.group(1)
            rows = re.findall(r'<tr[^>]*>(.*?)</tr>', table_html, re.DOTALL | re.IGNORECASE)
            table_data = []
            for row in rows:
                cells = [tag_stripper.sub('', cell).strip() for cell in td_pattern.findall(row)]
                if cells and any(c for c in cells):
                    table_data.append(cells)
            if table_data:
                result["raw_tables"].append({"rows": table_data, "row_count": len(table_data)})
    
    return clean_parsed_search_results(result)


# ═══════════════════════════════════════════════════════════════════════════
# IMPDS SESSION CLIENT — Manages authentication & searches
# ═══════════════════════════════════════════════════════════════════════════

class IMPDSSession:
    """Manages a persistent authenticated session with the IMPDS portal."""
    
    def __init__(self, auto_credentials: dict = None):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': f'{BASE_URL}/',
        })
        self.csrf_token = None
        self.salt = None
        self.logged_in = False
        self.username = None
        self.password = None  # Stored for auto-reauth
        self.state_name = None
        self.login_time = None
        self._lock = threading.Lock()
        self._auto_creds = auto_credentials  # {username, password} for zero-friction mode
        
        self._initialized = False
    
    def _lazy_init(self):
        """Perform delayed initialization (session restore & keep-alive thread)."""
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    self._initialized = True
                    # Try to restore a saved session from disk
                    self._try_restore_session()
                    # Start keep-alive background thread
                    self._start_keepalive()

    def _try_restore_session(self):
        """Attempt to restore a previously saved session."""
        # 1. Try to load from cookie.txt first if it exists
        cookies = load_cookies_from_netscape(COOKIE_TXT_FILE)
        if cookies:
            print(f"[*] Attempting to restore session from cookie.txt...")
            self.session.cookies.clear()
            for name, value, domain, path in cookies:
                self.session.cookies.set(name, value, domain=domain, path=path)
            
            # Verify the session is still alive by hitting UserHome
            try:
                r = self.session.get(f"{BASE_URL}/UserHome", allow_redirects=False)
                if r.status_code == 200 and 'WELCOME' in r.text:
                    self.logged_in = True
                    self.username = "session_cookie_user"
                    try:
                        state_match = re.search(r'WELCOME.*?\s+([\w\s]+)$', 
                                              r.text.split('WELCOME')[1].split('</li>')[0].strip())
                        if state_match:
                            self.state_name = state_match.group(1).strip()
                    except:
                        pass
                    self.login_time = datetime.now().isoformat()
                    print(f"[+] Restored session from cookie.txt successfully! (State: {self.state_name})")
                    return
            except Exception as e:
                print(f"[!] Failed to verify cookie.txt session: {e}")
            
            print("[*] cookie.txt session invalid or expired, falling back to cached pickle session.")
            self.session.cookies.clear()
            
        # 2. Fall back to the existing pickle file session loader
        saved = load_session_from_disk()
        if saved:
            for name, value in saved['cookies'].items():
                self.session.cookies.set(name, value)
            meta = saved['metadata']
            self.username = meta.get('username')
            self.password = meta.get('password')
            self.state_name = meta.get('state_name')
            self.login_time = meta.get('login_time')
            
            # Verify the session is still alive by hitting UserHome
            try:
                r = self.session.get(f"{BASE_URL}/UserHome", allow_redirects=False)
                if r.status_code == 200 and 'WELCOME' in r.text:
                    self.logged_in = True
                    print(f"[+] Restored saved session for {self.username}")
                    return
            except:
                pass
            print("[*] Saved session expired, need fresh login")
            
    def _start_keepalive(self):
        """Starts a background thread to keep the session alive."""
        self._keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        self._keepalive_thread.start()

    def _keepalive_loop(self):
        """Background loop that pings the portal to keep the session active."""
        print("[*] Starting session keep-alive daemon thread...")
        while True:
            time.sleep(180)  # Ping every 3 minutes
            if not self.logged_in:
                continue
            try:
                with self._lock:
                    # Perform a lightweight request to reset the session idle timer
                    r = self.session.get(f"{BASE_URL}/UserHome", allow_redirects=False, timeout=10)
                    if r.status_code == 200 and 'WELCOME' in r.text:
                        # Session is still valid
                        pass
                    else:
                        print("[!] Keep-alive: Session has expired or is invalid.")
                        self.logged_in = False
            except Exception as e:
                print(f"[!] Keep-alive error: {e}")
    
    def _save_session(self):
        """Save current session to disk for reuse."""
        if self.logged_in:
            save_session_to_disk(self.session, {
                'username': self.username,
                'password': self.password,
                'state_name': self.state_name,
                'login_time': self.login_time,
            })
    
    def get_login_page(self) -> dict:
        """Fetch login page, extract CSRF + salt."""
        self._lazy_init()
        r = self.session.get(f"{BASE_URL}/")
        r.raise_for_status()
        
        csrf_match = re.search(r'name="REQ_CSRF_TOKEN"[^>]*value="([^"]+)"', r.text)
        salt_match = re.search(r"USER_SALT\s*=\s*'([^']+)'", r.text)
        
        if csrf_match:
            self.csrf_token = csrf_match.group(1)
        if salt_match:
            self.salt = salt_match.group(1)
        
        return {"csrf_token": self.csrf_token, "salt": self.salt}
    
    def get_captcha(self) -> dict:
        """Fetch captcha image as base64."""
        r = self.session.post(f"{BASE_URL}/ReloadCaptcha")
        data = r.json()
        return {
            "captcha_base64": data.get('captchaBase64', ''),
            "format": "image/jpg"
        }
    
    def login(self, username: str, password: str, captcha: str) -> dict:
        """Perform login with hashed password."""
        self._lazy_init()
        with self._lock:
            if not self.csrf_token or not self.salt:
                self.get_login_page()
            
            hashed_pwd = hash_password(self.salt, password)
            
            payload = {
                'userName': username,
                'password': hashed_pwd,
                'captcha': captcha,
                'REQ_CSRF_TOKEN': self.csrf_token,
            }
            
            r = self.session.post(
                f"{BASE_URL}/UserLogin",
                data=payload,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest',
                }
            )
            
            try:
                resp = r.json()
                if resp.get('athenticationError'):
                    errors = resp.get('errors', {})
                    # Update tokens for next attempt
                    if 'captchaBase64' in resp:
                        self.salt = resp.get('userSalt', self.salt)
                        self.csrf_token = resp.get('RES_CSRF_TOKEN', self.csrf_token)
                    
                    error_msg = "Unknown error"
                    if errors.get('invalidCaptchaError'):
                        error_msg = "Invalid captcha"
                    elif errors.get('csrfTokenError'):
                        error_msg = "CSRF token mismatch"
                    elif errors.get('mendateError'):
                        error_msg = "Username, password & captcha are required"
                    elif errors.get('sessionAlreadyRunningError'):
                        error_msg = "Already logged in from another session"
                    else:
                        error_msg = "Username/password mismatch"
                    
                    return {"success": False, "error": error_msg}
                else:
                    self.logged_in = True
                    self.username = username
                    self.password = password
                    self.login_time = datetime.now().isoformat()
                    
                    # Extract state from UserHome
                    try:
                        home = self.session.get(f"{BASE_URL}/UserHome")
                        state_match = re.search(r'WELCOME.*?\s+([\w\s]+)$', 
                                              home.text.split('WELCOME')[1].split('</li>')[0].strip())
                        if state_match:
                            self.state_name = state_match.group(1).strip()
                    except:
                        pass
                    
                    # Save session to disk for persistence
                    self._save_session()
                    
                    return {
                        "success": True,
                        "message": "Login successful",
                        "username": username,
                        "state": self.state_name,
                        "session_id": self.session.cookies.get('JSESSIONID', '')
                    }
            except Exception:
                if r.status_code == 302 or 'UserHome' in r.text:
                    self.logged_in = True
                    self.username = username
                    self.password = password
                    self.login_time = datetime.now().isoformat()
                    self._save_session()
                    return {"success": True, "message": "Login successful (redirect)"}
                return {"success": False, "error": f"Unexpected response: {r.status_code}"}
    
    def auto_login(self, username: str = None, password: str = None, max_retries: int = 3) -> dict:
        """
        ZERO-FRICTION LOGIN — auto-solves captcha with OCR.
        Retries up to max_retries times if OCR misreads the captcha.
        """
        self._lazy_init()
        username = username or (self._auto_creds or {}).get('username') or self.username
        password = password or (self._auto_creds or {}).get('password') or self.password
        
        if not username or not password:
            return {"success": False, "error": "No credentials provided. Pass username/password or set --user/--pass"}
        
        if not USE_OCR:
            return {"success": False, "error": "easyocr not installed. Run: pip install easyocr"}
        
        for attempt in range(1, max_retries + 1):
            print(f"[*] Auto-login attempt {attempt}/{max_retries}...")
            
            # Fresh login page for each attempt (new CSRF, salt)
            self.get_login_page()
            captcha_data = self.get_captcha()
            
            # OCR solve the captcha
            solved = solve_captcha_ocr(captcha_data['captcha_base64'])
            if not solved:
                print(f"    [!] OCR returned empty, retrying...")
                continue
            
            print(f"    [*] OCR solved captcha: '{solved}'")
            
            result = self.login(username, password, solved)
            
            if result.get('success'):
                print(f"    [+] Auto-login SUCCESS on attempt {attempt}!")
                return result
            
            error = result.get('error', '')
            if 'captcha' in error.lower():
                print(f"    [!] Captcha wrong (OCR misread), retrying...")
                continue
            else:
                # Real auth error, don't retry
                print(f"    [-] Auth error: {error}")
                return result
        
        return {"success": False, "error": f"Auto-login failed after {max_retries} attempts (captcha OCR unreliable)"}
    
    def _ensure_logged_in(self) -> bool:
        """
        Ensure we have an active session. Auto-reauth if needed.
        Returns True if logged in, False if we can't auto-login.
        """
        self._lazy_init()
        if self.logged_in:
            # Verify session is still alive
            try:
                r = self.session.get(f"{BASE_URL}/UserHome", allow_redirects=False)
                if r.status_code == 200 and 'WELCOME' in r.text:
                    return True
            except:
                pass
            self.logged_in = False
        
        # If not logged in, try to recheck cookie.txt (it might have been updated)
        self._try_restore_session()
        if self.logged_in:
            return True
        
        # Try auto-login if we have credentials
        if self.password and self.username and self.username != "session_cookie_user":
            if USE_OCR:
                result = self.auto_login(self.username, self.password)
                return result.get('success', False)
        
        return False
    
    def search_by_ration_card(self, card_number: str) -> dict:
        """Search by ration card number. Auto-reauths if session expired."""
        if not self._ensure_logged_in():
            return {"success": False, "error": "Not logged in and auto-login failed"}
        
        encrypted_card = encrypt_cryptojs_aes(card_number)
        
        payload = {
            'search': 'R',
            'card': encrypted_card,
            'aadhar': ''
        }
        
        try:
            r = self.session.post(f"{BASE_URL}/search", data=payload, timeout=15)
            if r.status_code == 200:
                result = parse_search_results(r.text)
                
                # Fetch full summary details
                r_summary = self.session.post(
                    f"{BASE_URL}/RcReportSummary",
                    data={'rationcardId': card_number},
                    timeout=15
                )
                if r_summary.status_code == 200:
                    summary_result = parse_search_results(r_summary.text)
                    
                    # Merge status metrics from the basic search page
                    summary_result["status_metrics"] = result.get("status_metrics", {})
                    
                    summary_result["search_type"] = "ration_card"
                    summary_result["search_value"] = card_number
                    return summary_result
                
                result["search_type"] = "ration_card"
                result["search_value"] = card_number
                result["encrypted_value"] = encrypted_card
                return result
            else:
                return {"success": False, "error": f"HTTP {r.status_code}", "search_type": "ration_card"}
        except Exception as e:
            return {"success": False, "error": str(e), "search_type": "ration_card"}
    
    def search_by_aadhaar(self, aadhaar_number: str) -> dict:
        """Search by Aadhaar number. Auto-reauths if session expired."""
        if not self._ensure_logged_in():
            return {"success": False, "error": "Not logged in and auto-login failed"}
        
        if len(aadhaar_number) != 12:
            return {"success": False, "error": "Aadhaar must be exactly 12 digits"}
        
        encrypted_aadhaar = encrypt_cryptojs_aes(aadhaar_number)
        
        payload = {
            'search': 'A',
            'card': '',
            'aadhar': encrypted_aadhaar
        }
        
        try:
            r = self.session.post(f"{BASE_URL}/search", data=payload, timeout=15)
            if r.status_code == 200:
                result = parse_search_results(r.text)
                
                rc_number = result.get("card_details", {}).get("ration_card_number") or result.get("ration_card_number")
                if rc_number:
                    # Fetch full summary details using the resolved ration card number
                    r_summary = self.session.post(
                        f"{BASE_URL}/RcReportSummary",
                        data={'rationcardId': rc_number},
                        timeout=15
                    )
                    if r_summary.status_code == 200:
                        summary_result = parse_search_results(r_summary.text)
                        
                        # Merge status metrics from the basic search page
                        summary_result["status_metrics"] = result.get("status_metrics", {})
                        
                        summary_result["search_type"] = "aadhaar"
                        summary_result["search_value"] = aadhaar_number[:4] + "****" + aadhaar_number[-4:]
                        return summary_result
                
                result["search_type"] = "aadhaar"
                result["search_value"] = aadhaar_number[:4] + "****" + aadhaar_number[-4:]
                return result
            else:
                return {"success": False, "error": f"HTTP {r.status_code}", "search_type": "aadhaar"}
        except Exception as e:
            return {"success": False, "error": str(e), "search_type": "aadhaar"}
    
    def get_report(self, report_path: str) -> dict:
        """Fetch any report page and parse it. Auto-reauths if needed."""
        if not self._ensure_logged_in():
            return {"success": False, "error": "Not logged in and auto-login failed"}
        
        r = self.session.get(f"{BASE_URL}/{report_path}")
        if r.status_code == 200:
            return parse_search_results(r.text)
        return {"success": False, "error": f"HTTP {r.status_code}"}
    
    def get_status(self) -> dict:
        """Check current session status."""
        self._lazy_init()
        return {
            "logged_in": self.logged_in,
            "username": self.username,
            "state": self.state_name,
            "login_time": self.login_time,
            "session_id": self.session.cookies.get('JSESSIONID', ''),
        }
    
    def logout(self) -> dict:
        """Logout from the portal."""
        self._lazy_init()
        if self.logged_in:
            try:
                self.session.get(f"{BASE_URL}/logout")
            except:
                pass
        self.logged_in = False
        self.username = None
        self.state_name = None
        return {"success": True, "message": "Logged out"}


# ═══════════════════════════════════════════════════════════════════════════
# AVAILABLE REPORTS — Discovered from the portal navigation
# ═══════════════════════════════════════════════════════════════════════════

AVAILABLE_REPORTS = [
    {"path": "totalrecordsreport", "name": "Ration Card Data Report Summary"},
    {"path": "duplicaterecordsreport", "name": "Duplicate Records Report"},
    {"path": "genduprep", "name": "Duplicate UID Beneficiary Data (IntraState)"},
    {"path": "genduprepinterstate", "name": "Duplicate UID Beneficiary Data (InterState)"},
    {"path": "search", "name": "Search by Ration Card / Aadhaar Number"},
    {"path": "totalrcdetails", "name": "Incremental Ration Card Data Summary (NFSA)"},
    {"path": "totalrecordsReportTesting", "name": "RC Data Summary in Central Repo (Datewise)"},
    {"path": "totalrecordsreportNew", "name": "State Ration Card Data Report Summary"},
    {"path": "downloadRcCopy", "name": "Download Ration Card Copy from Central Repo"},
    {"path": "incrementaldatasummaryreport", "name": "State Incremental RC Data (Non NFSA)"},
    {"path": "DuplicateBeneficiaryFpsWisePage", "name": "Duplicate Beneficiary Field Report Form"},
    {"path": "duplicatememberremark", "name": "Duplicate Beneficiary (Ration card wise)"},
    {"path": "DuplicateBeneficiaryCSV", "name": "Duplicate Beneficiary Field Survey Report"},
    {"path": "DuplicateBeneficiaryStateSummaryReport", "name": "Duplicate Beneficiary Summary Report"},
    {"path": "totalFpsrecordsReport", "name": "Available FPS Data Report"},
    {"path": "fpsDetailRecordsReport", "name": "Available FPS Data Detail Report"},
    {"path": "UidBulkAuthReport", "name": "UID Demo Auth Status"},
    {"path": "RcSummaryPage", "name": "Ration Card Information"},
]


# ═══════════════════════════════════════════════════════════════════════════


# Default credentials — server auto-logs in on startup
DEFAULT_CREDS = {
    'username': 'dsoaligarh12@gmail.com',
    'password': 'Dso@2023'
}

# Global session instance (with auto-credentials)
impds = IMPDSSession(auto_credentials=DEFAULT_CREDS)

app = Flask(__name__)
CORS(app)

@app.route("/docs", methods=["GET"])
def custom_docs():
    """Returns all available API endpoints with author credits in JSON format."""
    return jsonify({
        "success": True,
        "api_by": "t.me/Sudhirxd",
        "website": "www.sudhirxd.in",
        "endpoints": [
            "/aadhaar/<aadhaar_number>",
            "/rc/<card_number>",
            "/rc/summary/<card_number>"
        ]
    })

@app.route("/api/health", methods=["GET"])
def health():
    """Check API health and session status."""
    status = impds.get_status()
    status["api_version"] = "1.0.0"
    status["encryption_method"] = "CryptoJS AES-256-CBC"
    return jsonify(status)

@app.route("/api/captcha", methods=["GET"])
def get_captcha():
    """
    Get a fresh captcha image. Call this before /api/login.
    Returns base64-encoded JPG image.
    """
    impds.get_login_page()  # Also refreshes CSRF
    captcha = impds.get_captcha()
    return jsonify({
        "captcha_image": f"data:image/jpg;base64,{captcha['captcha_base64']}",
        "captcha_base64": captcha["captcha_base64"],
        "instructions": "Decode the image and send the text to POST /api/login"
    })

@app.route("/api/login", methods=["POST"])
def login_handler():
    """
    Login to IMPDS portal (manual captcha).
    First call GET /api/captcha, solve it, then POST here.
    """
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    captcha = data.get("captcha")
    
    if not username or not password or not captcha:
        return jsonify({"success": False, "error": "username, password, and captcha are required"}), 400
        
    result = impds.login(username, password, captcha)
    if not result.get("success"):
        return jsonify(result), 401
    return jsonify(result)

@app.route("/api/auto-login", methods=["POST"])
def auto_login_handler():
    """
    ZERO-FRICTION LOGIN — auto-solves captcha via OCR.
    No need to manually solve captcha. Retries if OCR misreads.
    """
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    max_retries = data.get("max_retries", 3)
    
    if not username or not password:
        return jsonify({"success": False, "error": "username and password are required"}), 400
        
    result = impds.auto_login(username, password, max_retries)
    if not result.get("success"):
        return jsonify(result), 401
    return jsonify(result)

@app.route("/api/search/ration-card", methods=["POST"])
def search_ration_card_handler():
    """Search deduplication records by ration card number. Auto-reauths if session expired."""
    data = request.json or {}
    card_number = data.get("card_number")
    
    if not card_number:
        return jsonify({"success": False, "error": "card_number is required"}), 400
        
    result = impds.search_by_ration_card(card_number)
    if result.get('error') and 'not logged in' in result['error'].lower():
        return jsonify(result), 401
    return jsonify(result)

@app.route("/api/search/aadhaar", methods=["POST"])
def search_aadhaar_handler():
    """Search deduplication records by 12-digit Aadhaar number. Auto-reauths if session expired."""
    data = request.json or {}
    aadhaar_number = data.get("aadhaar_number")
    
    if not aadhaar_number:
        return jsonify({"success": False, "error": "aadhaar_number is required"}), 400
        
    result = impds.search_by_aadhaar(aadhaar_number)
    if result.get('error') and 'not logged in' in result['error'].lower():
        return jsonify(result), 401
    return jsonify(result)

@app.route("/aadhaar/<aadhaar_number>", methods=["GET"])
def direct_aadhaar_search(aadhaar_number):
    """
    DIRECT SEARCH — Just hit this URL with a 12-digit Aadhaar.
    """
    if len(aadhaar_number) != 12 or not aadhaar_number.isdigit():
        return jsonify({"success": False, "error": "Aadhaar must be exactly 12 digits"}), 400
        
    user = request.args.get("user")
    pwd = request.args.get("pwd")
    
    # Store credentials if provided (one-time setup)
    if user and pwd:
        impds.username = user
        impds.password = pwd
        impds._auto_creds = {'username': user, 'password': pwd}
        if not impds.logged_in:
            result = impds.auto_login(user, pwd)
            if not result.get('success'):
                return jsonify(result), 401
                
    result = impds.search_by_aadhaar(aadhaar_number)
    if result.get('error') and 'not logged in' in result['error'].lower():
        return jsonify({"success": False, "error": "Not logged in. Add ?user=YOUR_EMAIL&pwd=YOUR_PASSWORD to the URL"}), 401
    return jsonify(result)

@app.route("/rc/<card_number>", methods=["GET"])
def direct_ration_card_search(card_number):
    """
    DIRECT SEARCH — Just hit this URL with a ration card number.
    """
    user = request.args.get("user")
    pwd = request.args.get("pwd")
    
    # Store credentials if provided (one-time setup)
    if user and pwd:
        impds.username = user
        impds.password = pwd
        impds._auto_creds = {'username': user, 'password': pwd}
        if not impds.logged_in:
            result = impds.auto_login(user, pwd)
            if not result.get('success'):
                return jsonify(result), 401
                
    result = impds.search_by_ration_card(card_number)
    if result.get('error') and 'not logged in' in result['error'].lower():
        return jsonify({"success": False, "error": "Not logged in. Add ?user=YOUR_EMAIL&pwd=YOUR_PASSWORD to the URL"}), 401
    return jsonify(result)

@app.route("/rc/summary/<card_number>", methods=["GET"])
def direct_rc_summary(card_number):
    """
    DIRECT RATION CARD SUMMARY — Fetches details from RcReportSummary.
    """
    user = request.args.get("user")
    pwd = request.args.get("pwd")
    
    # Store credentials if provided (one-time setup)
    if user and pwd:
        impds.username = user
        impds.password = pwd
        impds._auto_creds = {'username': user, 'password': pwd}
        if not impds.logged_in:
            result = impds.auto_login(user, pwd)
            if not result.get('success'):
                return jsonify(result), 401
                
    # Ensure we are logged in
    if not impds._ensure_logged_in():
        return jsonify({"success": False, "error": "Not logged in and auto-login failed"}), 401
        
    try:
        r = impds.session.post(
            f"{BASE_URL}/RcReportSummary",
            data={'rationcardId': card_number},
            timeout=15
        )
        if r.status_code == 200:
            result = parse_search_results(r.text)
            return jsonify(result)
        else:
            return jsonify({"success": False, "error": f"Upstream portal returned HTTP {r.status_code}"}), r.status_code
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/reports", methods=["GET"])
def list_reports():
    """List all available report endpoints."""
    return jsonify({
        "reports": AVAILABLE_REPORTS,
        "usage": "POST /api/report with {\"report_path\": \"<path>\"} to fetch any report"
    })

@app.route("/api/report", methods=["POST"])
def get_report_handler():
    """Fetch any report from the portal and return parsed JSON. Auto-reauths if needed."""
    data = request.json or {}
    report_path = data.get("report_path")
    if not report_path:
        return jsonify({"success": False, "error": "report_path is required"}), 400
        
    result = impds.get_report(report_path)
    if result.get('error') and 'not logged in' in result['error'].lower():
        return jsonify(result), 401
    return jsonify(result)

@app.route("/api/logout", methods=["POST"])
def logout_handler():
    """Logout from the portal."""
    return jsonify(impds.logout())


# ===========================================================================
# CLI MODE
# ===========================================================================

def cli_mode():
    """Interactive CLI for testing the API."""
    print("-------------------------------------------------------------")
    print("     IMPDS Deduplication — JSON API (CLI Mode)            ")
    print("     Reverse-engineered search with AES encryption        ")
    print("-------------------------------------------------------------\n")
    
    client = IMPDSSession()
    
    # Step 1: Login
    print("[*] Step 1: Fetching login page...")
    client.get_login_page()
    
    print("[*] Step 2: Getting captcha...")
    captcha_data = client.get_captcha()
    
    # Save captcha
    img_bytes = base64.b64decode(captcha_data['captcha_base64'])
    captcha_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captcha.jpg")
    with open(captcha_path, 'wb') as f:
        f.write(img_bytes)
    print(f"[+] Captcha saved -> {captcha_path}")
    
    username = input("\n  Username: ").strip()
    password = input("  Password: ").strip()
    captcha_text = input("  Captcha:  ").strip()
    
    result = client.login(username, password, captcha_text)
    print(f"\n[*] Login result: {json.dumps(result, indent=2)}")
    
    if not result.get('success'):
        print("[-] Login failed!")
        return
    
    # Step 2: Search loop
    while True:
        print("\n" + "="*50)
        print("  1. Search by Ration Card")
        print("  2. Search by Aadhaar")
        print("  3. Fetch a Report")
        print("  4. List Reports")
        print("  5. Logout & Exit")
        print("="*50)
        
        choice = input("  Choice: ").strip()
        
        if choice == '1':
            card = input("  Ration Card Number: ").strip()
            result = client.search_by_ration_card(card)
            print(f"\n{json.dumps(result, indent=2, ensure_ascii=False)}")
        
        elif choice == '2':
            aadhaar = input("  Aadhaar Number (12 digits): ").strip()
            result = client.search_by_aadhaar(aadhaar)
            print(f"\n{json.dumps(result, indent=2, ensure_ascii=False)}")
        
        elif choice == '3':
            path = input("  Report path: ").strip()
            result = client.get_report(path)
            print(f"\n{json.dumps(result, indent=2, ensure_ascii=False)}")
        
        elif choice == '4':
            print("\n  Available Reports:")
            for r in AVAILABLE_REPORTS:
                print(f"    {r['path']:45s} -> {r['name']}")
        
        elif choice == '5':
            client.logout()
            print("[+] Logged out. Bye!")
            break
        
        else:
            print("  Invalid choice.")


# ===========================================================================
# MAIN
# ===========================================================================

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='IMPDS Deduplication JSON API')
    parser.add_argument('--cli', action='store_true', help='Run in interactive CLI mode')
    parser.add_argument('--auto', action='store_true', help='Auto-login on startup (OCR captcha)')
    parser.add_argument('--user', type=str, help='IMPDS username/email')
    parser.add_argument('--pass', dest='pwd', type=str, help='IMPDS password')
    parser.add_argument('--port', type=int, default=8000, help='API server port')
    args = parser.parse_args()
    
    if args.cli:
        cli_mode()
    else:
        # Configure auto-credentials if provided
        if args.auto and args.user and args.pwd:
            impds._auto_creds = {'username': args.user, 'password': args.pwd}
            impds.username = args.user
            impds.password = args.pwd
            
            # Auto-login before starting server
            if not impds.logged_in:
                print("[*] Auto-login mode enabled, logging in...")
                result = impds.auto_login(args.user, args.pwd)
                if result.get('success'):
                    print(f"[+] Auto-logged in as {args.user}")
                else:
                    print(f"[!] Auto-login failed: {result.get('error')}")
                    print("[!] Server will start anyway. Use /api/auto-login to retry.")
        
        print("-------------------------------------------------------------")
        print("   IMPDS Deduplication — Flask API Server v2.0")
        print(f"   http://localhost:{args.port}/docs  — API Documentation JSON")
        print("-------------------------------------------------------------")
        app.run(host="0.0.0.0", port=args.port)
