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
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://impds.nic.in/impdsdeduplication"
ENCRYPTION_KEY = "nic@impds#dedup05613"

HARDCODED_SESSION = {
    "JSESSIONID": "0F22E34F4090586926482D8FC26AE182",
    "PDS_SESSION_ID": "DEB403FD13C5381EAEEE25F0C5F6E8B4"
}


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    d = b""
    d_i = b""
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len + iv_len]


def encrypt_cryptojs_aes(plaintext: str, passphrase: str = ENCRYPTION_KEY) -> str:
    salt = get_random_bytes(8)
    key, iv = _evp_bytes_to_key(passphrase.encode("utf-8"), salt)
    pad_len = 16 - (len(plaintext.encode("utf-8")) % 16)
    padded = plaintext.encode("utf-8") + bytes([pad_len] * pad_len)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)
    encrypted = b"Salted__" + salt + ciphertext
    return base64.b64encode(encrypted).decode("utf-8")


def clean_parsed_search_results(result: dict) -> dict:
    cleaned = {
        "success": True,
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
        "members": []
    }

    raw_tables = result.get("raw_tables", [])
    members_table = None
    info_table = None

    for table in raw_tables:
        headers = [str(h).lower().strip() for h in table.get("headers", [])]
        if "member name" in headers or "ration card no." in headers or "member id" in headers:
            members_table = table
        elif any("ration card id:" in h or "card type:" in h or "scheme:" in h for h in headers):
            info_table = table

    if info_table:
        headers = info_table.get("headers", [])
        rows = info_table.get("rows", [])
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

    if members_table:
        rows = members_table.get("rows", [])
        if rows:
            first_row = rows[0]
            if not cleaned["card_details"]["ration_card_number"]:
                cleaned["card_details"]["ration_card_number"] = first_row.get("Ration Card No.")
            if not cleaned["card_details"]["state_name"]:
                cleaned["card_details"]["state_name"] = first_row.get("State Name")
            if not cleaned["card_details"]["district_name"]:
                cleaned["card_details"]["district_name"] = first_row.get("District Name")
            if not cleaned["card_details"]["scheme_name"]:
                cleaned["card_details"]["scheme_name"] = first_row.get("Scheme name")

            seen_ids = set()
            for row in rows:
                row_lower = {str(k).lower().strip(): v for k, v in row.items()}
                member_id = row_lower.get("member id") or row_lower.get("member_id")
                member_name = row_lower.get("member name") or row_lower.get("member_name")

                id_key = str(member_id).strip() if member_id else f"name_{str(member_name).lower().strip()}"
                if id_key in seen_ids:
                    continue
                seen_ids.add(id_key)

                raw_gender = str(row_lower.get("gender") or "").strip().lower()
                if raw_gender.startswith("m"):
                    gender = "Male"
                elif raw_gender.startswith("f"):
                    gender = "Female"
                else:
                    gender = row_lower.get("gender") or ""

                raw_kyc = str(
                    row_lower.get("ekyc status") or
                    row_lower.get("ekyc_status") or
                    row_lower.get("ekyc") or
                    ""
                ).strip().lower()

                if raw_kyc in ["yes", "y", "true", "done", "complete", "completed"]:
                    kyc_status = "Yes"
                elif raw_kyc in ["no", "n", "false", "pending"]:
                    kyc_status = "No"
                else:
                    kyc_status = "Yes" if "yes" in raw_kyc else "No"

                relationship = (
                    row_lower.get("relationship") or
                    row_lower.get("relationship status") or
                    row_lower.get("relationship_status") or
                    row_lower.get("relation") or
                    row_lower.get("relations") or
                    ""
                )

                member = {
                    "name": member_name,
                    "relationship": relationship,
                    "gender": gender,
                    "member_id": member_id,
                    "aadhaar_number": row_lower.get("uid") or "",
                    "kyc_status": kyc_status
                }
                cleaned["members"].append(member)

    if not cleaned["members"] and not cleaned["card_details"]["ration_card_number"]:
        return {"success": False, "error": "No matching records found"}

    return cleaned


def parse_search_results(html_content: str) -> dict:
    result = {"raw_tables": []}
    soup = BeautifulSoup(html_content, "html.parser")
    tables = soup.find_all("table")

    for table in tables:
        headers = []
        rows_data = []
        header_row = table.find("tr")
        if header_row:
            for th in header_row.find_all(["th"]):
                headers.append(th.get_text(strip=True))
        if not headers and header_row:
            for td in header_row.find_all("td"):
                headers.append(td.get_text(strip=True))

        all_rows = table.find_all("tr")
        start = 1 if headers else 0

        for row in all_rows[start:]:
            cells = row.find_all(["td", "th"])
            row_data = [cell.get_text(strip=True) for cell in cells]
            if row_data and any(c.strip() for c in row_data):
                if headers and len(row_data) == len(headers):
                    rows_data.append(dict(zip(headers, row_data)))
                else:
                    rows_data.append(row_data)

        if rows_data:
            result["raw_tables"].append({"headers": headers, "rows": rows_data})

    return clean_parsed_search_results(result)


class IMPDSSession:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": f"{BASE_URL}/",
        })
        self.logged_in = False
        self._lock = threading.Lock()
        self._initialized = False
        self.apply_cookies(HARDCODED_SESSION["JSESSIONID"], HARDCODED_SESSION["PDS_SESSION_ID"])

    def apply_cookies(self, jsessionid: str, pds_session_id: str = None):
        with self._lock:
            self.session.cookies.set("JSESSIONID", jsessionid.strip(), domain="impds.nic.in", path="/impdsdeduplication")
            if pds_session_id:
                self.session.cookies.set("PDS_SESSION_ID", pds_session_id.strip(), domain="impds.nic.in", path="/")
            self.logged_in = True

    def _lazy_init(self):
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    self._initialized = True
                    self._verify_session()
                    self._start_keepalive()

    def _verify_session(self):
        try:
            r = self.session.get(f"{BASE_URL}/UserHome", allow_redirects=False, timeout=12)
            if r.status_code == 200 and "WELCOME" in r.text:
                self.logged_in = True
        except Exception:
            pass

    def _start_keepalive(self):
        t = threading.Thread(target=self._keepalive_loop, daemon=True)
        t.start()

    def _keepalive_loop(self):
        fail_count = 0
        while True:
            time.sleep(60)
            if not self.logged_in:
                self.apply_cookies(HARDCODED_SESSION["JSESSIONID"], HARDCODED_SESSION["PDS_SESSION_ID"])
            try:
                with self._lock:
                    r = self.session.get(f"{BASE_URL}/UserHome", allow_redirects=False, timeout=15)
                    if r.status_code == 200 and "WELCOME" in r.text:
                        fail_count = 0
                    elif r.status_code == 302 or "login" in r.text.lower():
                        fail_count += 1
                        if fail_count >= 5:
                            self.logged_in = False
                    else:
                        fail_count += 1
            except Exception:
                fail_count += 1

    def _ensure_logged_in(self) -> bool:
        self._lazy_init()
        if self.logged_in:
            return True
        self._verify_session()
        return self.logged_in

    def search_by_ration_card(self, card_number: str) -> dict:
        if not self._ensure_logged_in():
            return {"success": False, "error": "Session expired"}

        encrypted_card = encrypt_cryptojs_aes(card_number)
        payload = {"search": "R", "card": encrypted_card, "aadhar": ""}

        try:
            r = self.session.post(f"{BASE_URL}/search", data=payload, timeout=15)
            if r.status_code == 200:
                result = parse_search_results(r.text)
                r_summary = self.session.post(f"{BASE_URL}/RcReportSummary", data={"rationcardId": card_number}, timeout=15)
                if r_summary.status_code == 200:
                    summary_result = parse_search_results(r_summary.text)
                    if summary_result.get("success"):
                        return summary_result
                return result
            return {"success": False, "error": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def search_by_aadhaar(self, aadhaar_number: str) -> dict:
        if not self._ensure_logged_in():
            return {"success": False, "error": "Session expired"}

        if len(aadhaar_number) != 12:
            return {"success": False, "error": "Aadhaar must be 12 digits"}

        encrypted_aadhaar = encrypt_cryptojs_aes(aadhaar_number)
        payload = {"search": "A", "card": "", "aadhar": encrypted_aadhaar}

        try:
            r = self.session.post(f"{BASE_URL}/search", data=payload, timeout=15)
            if r.status_code == 200:
                result = parse_search_results(r.text)
                rc_number = result.get("card_details", {}).get("ration_card_number")
                if rc_number:
                    r_summary = self.session.post(f"{BASE_URL}/RcReportSummary", data={"rationcardId": rc_number}, timeout=15)
                    if r_summary.status_code == 200:
                        summary_result = parse_search_results(r_summary.text)
                        if summary_result.get("success"):
                            return summary_result
                return result
            return {"success": False, "error": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}


impds = IMPDSSession()

app = Flask(__name__)
CORS(app)


@app.route("/health", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health():
    impds._lazy_init()
    is_alive = False
    try:
        r = impds.session.get(f"{BASE_URL}/UserHome", allow_redirects=False, timeout=10)
        if r.status_code == 200 and "WELCOME" in r.text:
            is_alive = True
            impds.logged_in = True
    except Exception:
        pass

    return jsonify({
        "status": "healthy" if is_alive else "degraded",
        "alive": is_alive,
        "timestamp": datetime.now().isoformat()
    })


@app.route("/rc/<card_number>", methods=["GET"])
@app.route("/rc/summary/<card_number>", methods=["GET"])
def direct_ration_card_search(card_number):
    clean_rc = card_number.strip()
    return jsonify(impds.search_by_ration_card(clean_rc))


@app.route("/aadhaar/<aadhaar_number>", methods=["GET"])
def direct_aadhaar_search(aadhaar_number):
    clean_aadhaar = aadhaar_number.strip()
    if len(clean_aadhaar) != 12 or not clean_aadhaar.isdigit():
        return jsonify({"success": False, "error": "Aadhaar must be 12 digits"}), 400
    return jsonify(impds.search_by_aadhaar(clean_aadhaar))


@app.route("/api/search/ration-card", methods=["POST"])
def search_ration_card_handler():
    data = request.json or {}
    card_number = data.get("card_number")
    if not card_number:
        return jsonify({"success": False, "error": "card_number is required"}), 400
    return jsonify(impds.search_by_ration_card(str(card_number).strip()))


@app.route("/api/search/aadhaar", methods=["POST"])
def search_aadhaar_handler():
    data = request.json or {}
    aadhaar_number = data.get("aadhaar_number")
    if not aadhaar_number:
        return jsonify({"success": False, "error": "aadhaar_number is required"}), 400
    return jsonify(impds.search_by_aadhaar(str(aadhaar_number).strip()))


@app.route("/api/update-session", methods=["GET", "POST"])
def update_session_handler():
    data = request.json or {}
    jsessionid = request.args.get("jsessionid") or data.get("jsessionid") or data.get("JSESSIONID")
    pds_session_id = request.args.get("pds_session_id") or data.get("pds_session_id") or data.get("PDS_SESSION_ID")

    if not jsessionid:
        return jsonify({"success": False, "error": "jsessionid is required"}), 400

    impds.apply_cookies(jsessionid, pds_session_id)
    try:
        r = impds.session.get(f"{BASE_URL}/UserHome", allow_redirects=False, timeout=10)
        alive = (r.status_code == 200 and "WELCOME" in r.text)
        return jsonify({"success": True, "alive": alive})
    except Exception as e:
        return jsonify({"success": True, "alive": False, "error": str(e)})


@app.route("/docs", methods=["GET"])
def docs():
    return jsonify({
        "endpoints": [
            "GET /rc/<card_number>",
            "GET /aadhaar/<aadhaar_number>",
            "POST /api/search/ration-card",
            "POST /api/search/aadhaar",
            "GET /health",
            "GET /api/update-session?jsessionid=...&pds_session_id=..."
        ]
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
